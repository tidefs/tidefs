#![forbid(unsafe_code)]

//! SWIM suspicion-accumulation state machine.
//!
//! Accumulates per-member suspicion validation from direct-ping failures,
//! indirect-ping relay results, and success feedback. Applies time-based
//! score decay and configurable thresholds to drive the
//! Alive → Suspected → Failed lifecycle, producing `SuspicionEvent`
//! outputs for upstream consumers (gossip batcher, transport peer manager).
//!
//! ## SWIM suspicion lifecycle
//!
//! 1. Validation arrives: `DirectPingFailure`, `IndirectPingFailure`,
//!    or `IndirectPingSuccess`.
//! 2. Each piece of validation adds or subtracts a weighted amount from
//!    the member's accumulated `SuspicionScore`.
//! 3. `tick()` applies time-based decay (configurable `decay_interval`
//!    and `decay_rate`) and evaluates threshold crossings:
//!    - Score ≥ `suspect_threshold` → transition to `Suspected`.
//!    - Score ≥ `failure_threshold` (and already Suspected) → `Failed`.
//!    - Score drops to 0 after suspicion → `SuspicionCleared`.
//! 4. `SuspicionEvent` outputs drive the gossip batcher's
//!    `SuspicionChange` path and transport peer manager teardown.
//!
//! ## Config semantics
//!
//! - `suspect_threshold`: score at which a healthy member becomes Suspected.
//! - `failure_threshold`: score at which a Suspected member becomes Failed.
//! - `decay_interval`: number of `tick()` calls between decay applications.
//! - `decay_rate`: amount subtracted from each member's score per decay
//!   interval.
//! - `direct_ping_weight`: score added for each direct-ping failure.
//! - `indirect_ping_weight`: score added per relay-response failure.
//! - `success_reduction`: score subtracted when any relay confirms
//!   reachability.
//!
//! ## Data integrity
//!
//! The accumulator exposes `state_root()` which produces a BLAKE3-256
//! digest over all per-member scores, states, and the config hash
//! (domain: `"tidefs-membership-live-suspicion-accumulator-v1"`).
//! Consumers can verify that suspicion state hasn't been tampered with.
//!
//! ## Integration
//!
//! - Receives `record_validation()` calls from `FailureDetector` after
//!   processing ping results.
//! - Feeds `SuspicionEvent` outputs to `GossipBatcher`'s
//!   `SuspicionChange` and to the transport peer manager (#5671).

use blake3::Hasher;
use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// Domain separation constant
// ---------------------------------------------------------------------------

const DOMAIN: &str = "tidefs-membership-live-suspicion-accumulator-v1";

// ---------------------------------------------------------------------------
// SuspicionConfig
// ---------------------------------------------------------------------------

/// Configuration for the suspicion accumulator.
#[derive(Clone, Debug, PartialEq)]
pub struct SuspicionConfig {
    /// Score threshold at which a Healthy member becomes Suspected.
    pub suspect_threshold: u64,
    /// Score threshold at which a Suspected member becomes Failed.
    pub failure_threshold: u64,
    /// Number of `tick()` calls between decay applications.
    pub decay_interval: u64,
    /// Amount subtracted from each member's score per decay interval.
    pub decay_rate: u64,
    /// Score added for each direct-ping-failure validation.
    pub direct_ping_weight: u64,
    /// Score added per indirect-ping-failure relay response.
    pub indirect_ping_weight: u64,
    /// Score subtracted when any relay confirms reachability
    /// (IndirectPingSuccess).
    pub success_reduction: u64,
    /// Maximum number of members tracked.  Excess validation is dropped.
    pub max_members: usize,
}

impl Default for SuspicionConfig {
    fn default() -> Self {
        Self {
            suspect_threshold: 30,
            failure_threshold: 100,
            decay_interval: 5,
            decay_rate: 5,
            direct_ping_weight: 10,
            indirect_ping_weight: 5,
            success_reduction: 20,
            max_members: 256,
        }
    }
}

impl SuspicionConfig {
    /// Produce a BLAKE3-256 config hash for inclusion in the state root.
    pub fn config_hash(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key(DOMAIN);
        h.update(b"config");
        h.update(&self.suspect_threshold.to_le_bytes());
        h.update(&self.failure_threshold.to_le_bytes());
        h.update(&self.decay_interval.to_le_bytes());
        h.update(&self.decay_rate.to_le_bytes());
        h.update(&self.direct_ping_weight.to_le_bytes());
        h.update(&self.indirect_ping_weight.to_le_bytes());
        h.update(&self.success_reduction.to_le_bytes());
        h.update(&self.max_members.to_le_bytes());
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// SuspicionValidation — what the accumulator consumes
// ---------------------------------------------------------------------------

/// Validation fed into the suspicion accumulator from the failure detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspicionValidation {
    /// A direct ping to the member timed out in the given ping round.
    DirectPingFailure { round: u64 },
    /// An indirect ping via `relayed_by` returned failure.
    IndirectPingFailure { relayed_by: MemberId },
    /// Any relay peer confirmed reachability — reduces suspicion.
    IndirectPingSuccess,
}

// ---------------------------------------------------------------------------
// SuspicionScore
// ---------------------------------------------------------------------------

/// Accumulated weighted score for a single member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuspicionScore {
    /// Current accumulated score.
    pub score: u64,
    /// Total validation items recorded since the member was registered.
    pub total_validation_count: u64,
    /// Monotonic tick counter for this member (used for decay tracking).
    tick_count: u64,
}

impl Default for SuspicionScore {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspicionScore {
    pub fn new() -> Self {
        Self {
            score: 0,
            total_validation_count: 0,
            tick_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SuspicionState — per-member lifecycle state
// ---------------------------------------------------------------------------

/// The current suspicion state of a tracked member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspicionState {
    /// Member is healthy with no suspicion.
    Alive,
    /// Member has crossed the suspect threshold.
    Suspected {
        /// Score when suspicion started.
        score: u64,
        /// Tick count when suspicion started.
        since_tick: u64,
        /// Total validation items that caused this state.
        validation_count: u64,
    },
    /// Member has been confirmed failed.
    Failed {
        /// Tick count when failure was confirmed.
        confirmed_at_tick: u64,
        /// Final score at time of failure.
        final_score: u64,
    },
}

// ---------------------------------------------------------------------------
// SuspicionEvent — what the accumulator emits
// ---------------------------------------------------------------------------

/// State-transition events emitted by the accumulator for upstream consumers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspicionEvent {
    /// A healthy member crossed the suspect threshold.
    MemberSuspected { member: MemberId, score: u64 },
    /// A suspected member crossed the failure threshold.
    MemberFailed { member: MemberId, final_score: u64 },
    /// A suspected member's score decayed to zero — false-positive resolved.
    SuspicionCleared { member: MemberId },
}

// ---------------------------------------------------------------------------
// MemberTracker — internal per-member bookkeeping
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MemberTracker {
    score: SuspicionScore,
    state: SuspicionState,
}

impl MemberTracker {
    fn new() -> Self {
        Self {
            score: SuspicionScore::new(),
            state: SuspicionState::Alive,
        }
    }
}

// ---------------------------------------------------------------------------
// SuspicionAccumulator
// ---------------------------------------------------------------------------

/// Accumulates suspicion validation per member, applies score decay, and
/// drives Alive → Suspected → Failed lifecycle transitions.
#[derive(Clone, Debug)]
pub struct SuspicionAccumulator {
    config: SuspicionConfig,
    members: BTreeMap<MemberId, MemberTracker>,
    /// Global monotonic tick counter.
    global_tick: u64,
    /// Accumulated events since last `drain_events()`.
    events: Vec<SuspicionEvent>,
}

impl SuspicionAccumulator {
    /// Create a new accumulator with the given config.
    pub fn new(config: SuspicionConfig) -> Self {
        Self {
            config,
            members: BTreeMap::new(),
            global_tick: 0,
            events: Vec::new(),
        }
    }

    /// Return a reference to the current config.
    pub fn config(&self) -> &SuspicionConfig {
        &self.config
    }

    /// Register a member for suspicion tracking.  Idempotent.
    pub fn register_member(&mut self, member: MemberId) {
        if self.members.len() >= self.config.max_members {
            return;
        }
        self.members
            .entry(member)
            .or_insert_with(MemberTracker::new);
    }

    /// Remove a member from tracking (e.g., on graceful leave).
    pub fn remove_member(&mut self, member: MemberId) {
        self.members.remove(&member);
    }

    /// Return the current suspicion state for a member, if tracked.
    pub fn state(&self, member: MemberId) -> Option<&SuspicionState> {
        self.members.get(&member).map(|t| &t.state)
    }

    /// Return the current suspicion score for a member, if tracked.
    pub fn score(&self, member: MemberId) -> Option<&SuspicionScore> {
        self.members.get(&member).map(|t| &t.score)
    }

    /// Return the number of tracked members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Record a piece of suspicion validation for a member.
    ///
    /// Unknown members are ignored.  Events are queued for `drain_events()`.
    pub fn record_validation(&mut self, member: MemberId, validation: SuspicionValidation) {
        let tracker = match self.members.get_mut(&member) {
            Some(t) => t,
            None => return,
        };

        // Failed members are immutable.
        if matches!(tracker.state, SuspicionState::Failed { .. }) {
            return;
        }

        match validation {
            SuspicionValidation::DirectPingFailure { .. } => {
                tracker.score.score = tracker
                    .score
                    .score
                    .saturating_add(self.config.direct_ping_weight);
                tracker.score.total_validation_count =
                    tracker.score.total_validation_count.saturating_add(1);
            }
            SuspicionValidation::IndirectPingFailure { .. } => {
                tracker.score.score = tracker
                    .score
                    .score
                    .saturating_add(self.config.indirect_ping_weight);
                tracker.score.total_validation_count =
                    tracker.score.total_validation_count.saturating_add(1);
            }
            SuspicionValidation::IndirectPingSuccess => {
                tracker.score.score = tracker
                    .score
                    .score
                    .saturating_sub(self.config.success_reduction);
                tracker.score.total_validation_count =
                    tracker.score.total_validation_count.saturating_add(1);
            }
        }

        // Check for transition and apply; re-evaluate from new state
        // to catch cascade transitions (e.g. Alive→Suspected→Failed when
        // thresholds are zero or very close).
        let score = tracker.score.score;
        let mut event = check_transition(&self.config, member, &tracker.state, score);
        while let Some(ev) = event.take() {
            apply_transition(self.global_tick, tracker, ev, &mut self.events);
            // Re-evaluate from the new state (score unchanged).
            event = check_transition(&self.config, member, &tracker.state, tracker.score.score);
        }
    }

    /// Advance time by one tick: apply decay and re-evaluate thresholds.
    pub fn tick(&mut self) {
        self.global_tick = self.global_tick.saturating_add(1);

        let apply_decay = self.global_tick % self.config.decay_interval == 0;

        // Collect member IDs to avoid borrow conflicts.
        let member_ids: Vec<MemberId> = self.members.keys().copied().collect();

        for member_id in member_ids {
            let tracker = self.members.get_mut(&member_id).unwrap();
            tracker.score.tick_count = tracker.score.tick_count.saturating_add(1);

            if apply_decay
                && matches!(
                    tracker.state,
                    SuspicionState::Alive | SuspicionState::Suspected { .. }
                )
            {
                tracker.score.score = tracker.score.score.saturating_sub(self.config.decay_rate);
            }

            let score = tracker.score.score;
            let mut event = check_transition(&self.config, member_id, &tracker.state, score);
            while let Some(ev) = event.take() {
                apply_transition(self.global_tick, tracker, ev, &mut self.events);
                // Re-evaluate from the new state.
                event =
                    check_transition(&self.config, member_id, &tracker.state, tracker.score.score);
            }
        }
    }

    /// Drain and return all queued events.
    pub fn drain_events(&mut self) -> Vec<SuspicionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Return the current global tick count.
    pub fn tick_count(&self) -> u64 {
        self.global_tick
    }

    /// Produce a BLAKE3-256 state root covering all per-member scores,
    /// states, and the config hash.
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key(DOMAIN);
        h.update(b"state");
        h.update(&self.config.config_hash());
        h.update(&self.global_tick.to_le_bytes());

        for (member, tracker) in &self.members {
            h.update(&member.0.to_le_bytes());
            h.update(&tracker.score.score.to_le_bytes());
            h.update(&tracker.score.total_validation_count.to_le_bytes());
            h.update(&tracker.score.tick_count.to_le_bytes());

            match &tracker.state {
                SuspicionState::Alive => {
                    h.update(&[0u8]);
                }
                SuspicionState::Suspected {
                    score,
                    since_tick,
                    validation_count,
                } => {
                    h.update(&[1u8]);
                    h.update(&score.to_le_bytes());
                    h.update(&since_tick.to_le_bytes());
                    h.update(&validation_count.to_le_bytes());
                }
                SuspicionState::Failed {
                    confirmed_at_tick,
                    final_score,
                } => {
                    h.update(&[2u8]);
                    h.update(&confirmed_at_tick.to_le_bytes());
                    h.update(&final_score.to_le_bytes());
                }
            }
        }

        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Free functions: transition logic (avoid borrow conflicts)
// ---------------------------------------------------------------------------

/// Check whether a member's current score triggers a state transition.
fn check_transition(
    config: &SuspicionConfig,
    member: MemberId,
    current_state: &SuspicionState,
    score: u64,
) -> Option<SuspicionEvent> {
    match current_state {
        SuspicionState::Alive => {
            if score >= config.suspect_threshold {
                Some(SuspicionEvent::MemberSuspected { member, score })
            } else {
                None
            }
        }
        SuspicionState::Suspected { .. } => {
            if score >= config.failure_threshold {
                Some(SuspicionEvent::MemberFailed {
                    member,
                    final_score: score,
                })
            } else if score == 0 {
                Some(SuspicionEvent::SuspicionCleared { member })
            } else {
                None
            }
        }
        SuspicionState::Failed { .. } => None,
    }
}

/// Apply a state transition to the tracker and queue the event.
fn apply_transition(
    global_tick: u64,
    tracker: &mut MemberTracker,
    event: SuspicionEvent,
    events: &mut Vec<SuspicionEvent>,
) {
    match &event {
        SuspicionEvent::MemberSuspected { score, .. } => {
            tracker.state = SuspicionState::Suspected {
                score: *score,
                since_tick: global_tick,
                validation_count: tracker.score.total_validation_count,
            };
        }
        SuspicionEvent::MemberFailed { final_score, .. } => {
            tracker.state = SuspicionState::Failed {
                confirmed_at_tick: global_tick,
                final_score: *final_score,
            };
        }
        SuspicionEvent::SuspicionCleared { .. } => {
            tracker.state = SuspicionState::Alive;
        }
    }
    events.push(event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId(id)
    }

    // -----------------------------------------------------------------------
    // SuspicionConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let c = SuspicionConfig::default();
        assert_eq!(c.suspect_threshold, 30);
        assert_eq!(c.failure_threshold, 100);
        assert_eq!(c.decay_interval, 5);
        assert_eq!(c.decay_rate, 5);
        assert_eq!(c.direct_ping_weight, 10);
        assert_eq!(c.indirect_ping_weight, 5);
        assert_eq!(c.success_reduction, 20);
        assert_eq!(c.max_members, 256);
    }

    #[test]
    fn config_hash_deterministic() {
        let c = SuspicionConfig::default();
        let h1 = c.config_hash();
        let h2 = c.config_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn config_hash_differs_when_fields_change() {
        let c1 = SuspicionConfig::default();
        let c2 = SuspicionConfig {
            suspect_threshold: 50,
            ..Default::default()
        };
        assert_ne!(c1.config_hash(), c2.config_hash());
    }

    // -----------------------------------------------------------------------
    // SuspicionAccumulator basic operations
    // -----------------------------------------------------------------------

    #[test]
    fn new_accumulator_empty() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        assert_eq!(a.member_count(), 0);
        assert_eq!(a.tick_count(), 0);
        assert!(a.drain_events().is_empty());
    }

    #[test]
    fn register_and_remove_member() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        assert_eq!(a.member_count(), 1);
        assert!(a.state(mid(1)).is_some());
        a.remove_member(mid(1));
        assert_eq!(a.member_count(), 0);
        assert!(a.state(mid(1)).is_none());
    }

    #[test]
    fn register_member_idempotent() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.register_member(mid(1));
        assert_eq!(a.member_count(), 1);
    }

    #[test]
    fn register_respects_max_members() {
        let config = SuspicionConfig {
            max_members: 3,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        a.register_member(mid(2));
        a.register_member(mid(3));
        a.register_member(mid(4)); // should be dropped
        assert_eq!(a.member_count(), 3);
    }

    #[test]
    fn validation_for_unknown_member_is_ignored() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.record_validation(
            mid(999),
            SuspicionValidation::DirectPingFailure { round: 1 },
        );
        assert!(a.drain_events().is_empty());
    }

    #[test]
    fn validation_for_failed_member_is_ignored() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        // Force into Failed state.
        for i in 0..10 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events = a.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, SuspicionEvent::MemberFailed { .. })));

        // Additional validation should be ignored.
        a.record_validation(
            mid(1),
            SuspicionValidation::DirectPingFailure { round: 100 },
        );
        assert!(a.drain_events().is_empty());
    }

    // -----------------------------------------------------------------------
    // Score accumulation
    // -----------------------------------------------------------------------

    #[test]
    fn single_direct_ping_failure_increments_score() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        assert_eq!(a.score(mid(1)).unwrap().score, 10);
    }

    #[test]
    fn single_indirect_ping_failure_increments_score() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.record_validation(
            mid(1),
            SuspicionValidation::IndirectPingFailure { relayed_by: mid(2) },
        );
        assert_eq!(a.score(mid(1)).unwrap().score, 5);
    }

    #[test]
    fn indirect_ping_success_reduces_score() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        for i in 0..4 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        assert_eq!(a.score(mid(1)).unwrap().score, 40);
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        assert_eq!(a.score(mid(1)).unwrap().score, 20);
    }

    #[test]
    fn score_never_goes_below_zero() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        assert_eq!(a.score(mid(1)).unwrap().score, 0);
    }

    #[test]
    fn score_saturates_on_overflow() {
        let config = SuspicionConfig {
            direct_ping_weight: u64::MAX,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        assert_eq!(a.score(mid(1)).unwrap().score, u64::MAX);
    }

    // -----------------------------------------------------------------------
    // Threshold transitions
    // -----------------------------------------------------------------------

    #[test]
    fn suspect_threshold_crossing_emits_member_suspected() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events = a.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            SuspicionEvent::MemberSuspected {
                member: MemberId(1),
                score: 30
            }
        ));
    }

    #[test]
    fn failure_threshold_crossing_emits_member_failed() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        for i in 0..10 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events = a.drain_events();
        let suspected = events
            .iter()
            .find(|e| matches!(e, SuspicionEvent::MemberSuspected { .. }));
        let failed = events
            .iter()
            .find(|e| matches!(e, SuspicionEvent::MemberFailed { .. }));
        assert!(suspected.is_some(), "expected MemberSuspected event");
        if let Some(SuspicionEvent::MemberFailed {
            member: MemberId(m),
            final_score,
        }) = failed
        {
            assert_eq!(*m, 1);
            assert_eq!(*final_score, 100);
        } else {
            panic!("expected MemberFailed event, got {failed:?}");
        }
    }

    #[test]
    fn suspicion_cleared_when_score_decays_to_zero() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        // Reach Suspected at score 30.
        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events();

        // Reduce score to 0 with success validation.
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        let events = a.drain_events();
        assert!(
            events.iter().any(|e| matches!(
                e,
                SuspicionEvent::SuspicionCleared {
                    member: MemberId(1)
                }
            )),
            "expected SuspicionCleared event, got {events:?}"
        );
    }

    #[test]
    fn re_escalation_after_cleared() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        // First escalation cycle.
        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events(); // Suspected
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        a.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        let _ = a.drain_events(); // Cleared

        // Re-escalation.
        for i in 0..3 {
            a.record_validation(
                mid(1),
                SuspicionValidation::DirectPingFailure { round: i + 100 },
            );
        }
        let events = a.drain_events();
        assert!(
            events.iter().any(|e| matches!(
                e,
                SuspicionEvent::MemberSuspected {
                    member: MemberId(1),
                    ..
                }
            )),
            "expected re-escalation to Suspected"
        );
    }

    // -----------------------------------------------------------------------
    // Config boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn zero_thresholds_immediate_transition() {
        let config = SuspicionConfig {
            suspect_threshold: 0,
            failure_threshold: 0,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        let events = a.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, SuspicionEvent::MemberSuspected { .. })));
        assert!(events
            .iter()
            .any(|e| matches!(e, SuspicionEvent::MemberFailed { .. })));
    }

    #[test]
    fn max_weights_dont_overflow() {
        let config = SuspicionConfig {
            direct_ping_weight: u64::MAX,
            indirect_ping_weight: u64::MAX,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        a.record_validation(
            mid(1),
            SuspicionValidation::IndirectPingFailure { relayed_by: mid(2) },
        );
        assert_eq!(a.score(mid(1)).unwrap().score, u64::MAX);
    }

    #[test]
    fn disabled_decay() {
        let config = SuspicionConfig {
            decay_rate: 0,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events();
        let score_before = a.score(mid(1)).unwrap().score;
        for _ in 0..100 {
            a.tick();
        }
        assert_eq!(a.score(mid(1)).unwrap().score, score_before);
    }

    // -----------------------------------------------------------------------
    // Time-based decay
    // -----------------------------------------------------------------------

    #[test]
    fn decay_applied_after_interval_ticks() {
        let config = SuspicionConfig {
            decay_interval: 5,
            decay_rate: 3,
            suspect_threshold: 100,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        for i in 0..5 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events();
        assert_eq!(a.score(mid(1)).unwrap().score, 50);

        // Tick 4 times — no decay.
        for _ in 0..4 {
            a.tick();
        }
        assert_eq!(a.score(mid(1)).unwrap().score, 50);

        // 5th tick — decay.
        a.tick();
        assert_eq!(a.score(mid(1)).unwrap().score, 47);

        // 10th tick — second decay.
        for _ in 0..5 {
            a.tick();
        }
        assert_eq!(a.score(mid(1)).unwrap().score, 44);
    }

    #[test]
    fn decay_does_not_affect_failed_members() {
        let config = SuspicionConfig {
            decay_rate: 5,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        for i in 0..10 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events();
        let score_before = a.score(mid(1)).unwrap().score;
        for _ in 0..10 {
            a.tick();
        }
        assert_eq!(a.score(mid(1)).unwrap().score, score_before);
    }

    // -----------------------------------------------------------------------
    // BLAKE3 state root
    // -----------------------------------------------------------------------

    #[test]
    fn empty_accumulator_state_root() {
        let a = SuspicionAccumulator::new(SuspicionConfig::default());
        let root = a.state_root();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn state_root_deterministic() {
        let mut a1 = SuspicionAccumulator::new(SuspicionConfig::default());
        let mut a2 = SuspicionAccumulator::new(SuspicionConfig::default());

        a1.register_member(mid(1));
        a2.register_member(mid(1));

        for i in 0..5 {
            a1.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
            a2.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }

        assert_eq!(a1.state_root(), a2.state_root());
    }

    #[test]
    fn state_root_different_for_different_scores() {
        let mut a1 = SuspicionAccumulator::new(SuspicionConfig::default());
        let mut a2 = SuspicionAccumulator::new(SuspicionConfig::default());

        a1.register_member(mid(1));
        a2.register_member(mid(1));

        a1.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        // a2 has no validation.

        assert_ne!(a1.state_root(), a2.state_root());
    }

    // -----------------------------------------------------------------------
    // Multi-member isolation
    // -----------------------------------------------------------------------

    #[test]
    fn validation_against_a_does_not_affect_b() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.register_member(mid(2));

        for i in 0..5 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }

        assert_eq!(a.score(mid(2)).unwrap().score, 0);
        assert!(matches!(a.state(mid(2)).unwrap(), SuspicionState::Alive));
    }

    #[test]
    fn members_do_not_cross_contaminate_events() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        a.register_member(mid(2));

        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events = a.drain_events();
        assert!(events.iter().all(|e| match e {
            SuspicionEvent::MemberSuspected {
                member: MemberId(m),
                ..
            } => *m == 1,
            _ => false,
        }));
    }

    // -----------------------------------------------------------------------
    // Event ordering
    // -----------------------------------------------------------------------

    #[test]
    fn suspected_before_failed_ordering() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));

        for i in 0..10 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events = a.drain_events();

        let suspected_pos = events
            .iter()
            .position(|e| matches!(e, SuspicionEvent::MemberSuspected { .. }));
        let failed_pos = events
            .iter()
            .position(|e| matches!(e, SuspicionEvent::MemberFailed { .. }));

        assert!(
            suspected_pos.is_some() && failed_pos.is_some() && suspected_pos < failed_pos,
            "Suspected must come before Failed"
        );
    }

    // -----------------------------------------------------------------------
    // Indirect-ping failure k=3 relay
    // -----------------------------------------------------------------------

    #[test]
    fn indirect_ping_failures_from_multiple_relays_accumulate() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));

        for relay in &[2u64, 3, 4] {
            a.record_validation(
                mid(1),
                SuspicionValidation::IndirectPingFailure {
                    relayed_by: MemberId(*relay),
                },
            );
        }
        assert_eq!(a.score(mid(1)).unwrap().score, 15);
    }

    // -----------------------------------------------------------------------
    // Duplicate validation
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_validation_accumulates_normally() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));

        for _ in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        assert_eq!(a.score(mid(1)).unwrap().score, 30);
    }

    // -----------------------------------------------------------------------
    // Tick and decay integration
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_ticks_increment_global_counter() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        for _ in 0..10 {
            a.tick();
        }
        assert_eq!(a.tick_count(), 10);
    }

    #[test]
    fn tick_triggers_decay_across_multiple_members() {
        let config = SuspicionConfig {
            decay_interval: 2,
            decay_rate: 3,
            suspect_threshold: 200,
            ..Default::default()
        };
        let mut a = SuspicionAccumulator::new(config);
        a.register_member(mid(1));
        a.register_member(mid(2));

        for i in 0..5 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
            a.record_validation(mid(2), SuspicionValidation::DirectPingFailure { round: i });
        }
        let _ = a.drain_events();
        assert_eq!(a.score(mid(1)).unwrap().score, 50);
        assert_eq!(a.score(mid(2)).unwrap().score, 50);

        a.tick(); // not yet
        assert_eq!(a.score(mid(1)).unwrap().score, 50);
        a.tick(); // decay now
        assert_eq!(a.score(mid(1)).unwrap().score, 47);
        assert_eq!(a.score(mid(2)).unwrap().score, 47);
    }

    // -----------------------------------------------------------------------
    // drain_events clears buffer
    // -----------------------------------------------------------------------

    #[test]
    fn drain_events_clears_buffer() {
        let mut a = SuspicionAccumulator::new(SuspicionConfig::default());
        a.register_member(mid(1));
        for i in 0..3 {
            a.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: i });
        }
        let events1 = a.drain_events();
        assert!(!events1.is_empty());
        let events2 = a.drain_events();
        assert!(events2.is_empty());
    }
}
