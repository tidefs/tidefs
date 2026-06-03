#![forbid(unsafe_code)]

//! Failure escalation pipeline bridging suspicion accumulation to epoch
//! proposal construction.
//!
//! `EscalationEngine` polls the
//! [`super::suspicion_accumulator::SuspicionAccumulator`] on a configurable
//! interval, applies consecutive-interval gating and cooldown enforcement,
//! and emits [`EscalationProposalRequest`]s when a member is confirmed
//! Failed — closing the gap between failure detection (#5683) and membership
//! reconfiguration (#5727).
//!
//! ## Data integrity
//!
//! Every state change is reflected in a BLAKE3-256 domain-separated digest
//! (domain `tidefs-membership-escalation-v1`) covering all per-member
//! escalation states, the config hash, and the engine tick.

use blake3::Hasher;
use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

use super::roster::MembershipRoster;
use super::suspicion_accumulator::SuspicionAccumulator;

// ---------------------------------------------------------------------------
// Domain separation constant
// ---------------------------------------------------------------------------

const DOMAIN: &str = "tidefs-membership-escalation-v1";

// ---------------------------------------------------------------------------
// EscalationThreshold
// ---------------------------------------------------------------------------

/// Configuration for the failure escalation engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationThreshold {
    /// Score ceiling for Suspected escalation.
    pub suspect_score_ceiling: u64,
    /// Score ceiling for Failed escalation.
    pub failed_score_ceiling: u64,
    /// Number of consecutive poll intervals the score must remain above the
    /// relevant ceiling before the engine commits the state transition.
    pub consecutive_intervals: u64,
    /// Number of engine ticks a member stays in cooldown after de-escalation.
    pub cooldown_ticks: u64,
}

impl Default for EscalationThreshold {
    fn default() -> Self {
        Self {
            suspect_score_ceiling: 30,
            failed_score_ceiling: 100,
            consecutive_intervals: 3,
            cooldown_ticks: 10,
        }
    }
}

impl EscalationThreshold {
    /// Produce a BLAKE3-256 config hash for inclusion in the state digest.
    pub fn config_hash(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key(DOMAIN);
        h.update(b"config");
        h.update(&self.suspect_score_ceiling.to_le_bytes());
        h.update(&self.failed_score_ceiling.to_le_bytes());
        h.update(&self.consecutive_intervals.to_le_bytes());
        h.update(&self.cooldown_ticks.to_le_bytes());
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// EscalationMemberState
// ---------------------------------------------------------------------------

/// Per-member escalation tracking state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EscalationMemberState {
    /// Score is below all escalation ceilings.
    BelowThreshold,
    /// Score has crossed a ceiling; counting consecutive confirmations.
    PendingEscalation {
        /// Number of consecutive poll intervals where score has been above
        /// the triggering ceiling.
        consecutive_count: u64,
    },
    /// Confirmed as Suspected after `consecutive_intervals` polls.
    EscalatedToSuspected {
        /// Engine tick when this state was entered.
        since_tick: u64,
    },
    /// Confirmed as Failed — terminal escalation state.
    EscalatedToFailed {
        /// Engine tick when this state was committed.
        since_tick: u64,
    },
}

impl EscalationMemberState {
    fn discriminant(&self) -> u8 {
        match self {
            Self::BelowThreshold => 0,
            Self::PendingEscalation { .. } => 1,
            Self::EscalatedToSuspected { .. } => 2,
            Self::EscalatedToFailed { .. } => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// EscalationProposalRequest
// ---------------------------------------------------------------------------

/// Output of the escalation engine: a request to construct an epoch proposal
/// that removes the failed member from the roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationProposalRequest {
    /// The member that has been confirmed Failed and should be removed.
    pub member_to_remove: MemberId,
    /// The current member set at the time of escalation (from roster poll).
    pub current_members: Vec<MemberId>,
    /// Engine tick when this request was generated.
    pub trigger_tick: u64,
}

// ---------------------------------------------------------------------------
// EscalationEngine
// ---------------------------------------------------------------------------

/// Polls the [`SuspicionAccumulator`] and drives the per-member escalation
/// state machine, emitting [`EscalationProposalRequest`]s when members are
/// confirmed Failed.
#[derive(Clone, Debug)]
pub struct EscalationEngine {
    config: EscalationThreshold,
    member_states: BTreeMap<MemberId, EscalationMemberState>,
    engine_tick: u64,
    poll_interval: u64,
    cooldowns: BTreeMap<MemberId, u64>,
    pending_requests: Vec<EscalationProposalRequest>,
}

impl EscalationEngine {
    /// Create a new escalation engine.
    ///
    /// `poll_interval` controls how many `poll()` calls must elapse between
    /// actual suspicion-accumulator evaluations. Set to 1 for every-call
    /// polling.
    pub fn new(config: EscalationThreshold, poll_interval: u64) -> Self {
        assert!(poll_interval > 0, "poll_interval must be >= 1");
        Self {
            config,
            member_states: BTreeMap::new(),
            engine_tick: 0,
            poll_interval,
            cooldowns: BTreeMap::new(),
            pending_requests: Vec::new(),
        }
    }

    /// Return a reference to the current threshold configuration.
    pub fn config(&self) -> &EscalationThreshold {
        &self.config
    }

    /// Return the current engine tick.
    pub fn tick_count(&self) -> u64 {
        self.engine_tick
    }

    /// Return the escalation state for a member, if tracked.
    pub fn member_state(&self, member: MemberId) -> Option<&EscalationMemberState> {
        self.member_states.get(&member)
    }

    /// Poll the suspicion accumulator and roster, driving the escalation
    /// state machine.
    ///
    /// Only performs evaluation when `engine_tick % poll_interval == 0`.
    /// Returns any new [`EscalationProposalRequest`]s generated during this
    /// poll. Use [`Self::drain_requests`] to collect all pending requests.
    pub fn poll(
        &mut self,
        accumulator: &SuspicionAccumulator,
        roster: &MembershipRoster,
    ) -> Vec<EscalationProposalRequest> {
        self.engine_tick = self.engine_tick.saturating_add(1);

        // Expire cooldowns that have elapsed.
        self.cooldowns
            .retain(|_member, until_tick| *until_tick > self.engine_tick);

        // Only evaluate on poll-interval boundaries.
        if self.engine_tick % self.poll_interval != 0 {
            return Vec::new();
        }

        let mut new_requests: Vec<EscalationProposalRequest> = Vec::new();

        // Collect member IDs from the roster (sorted for determinism).
        let mut member_ids: Vec<MemberId> = roster.iter().map(|(id, _state)| *id).collect();
        member_ids.sort_by_key(|m| m.0);

        let current_members: Vec<MemberId> = member_ids.clone();

        for member_id in member_ids {
            if self.cooldowns.contains_key(&member_id) {
                continue;
            }

            let acc_score = accumulator.score(member_id);
            let score = acc_score.map(|s| s.score).unwrap_or(0);

            let current = self
                .member_states
                .get(&member_id)
                .cloned()
                .unwrap_or(EscalationMemberState::BelowThreshold);

            let next = self.evaluate_member(member_id, score, &current);

            // Always track the member state.
            let is_transition = next != current;
            if is_transition {
                if let EscalationMemberState::EscalatedToFailed { .. } = &next {
                    if !matches!(current, EscalationMemberState::EscalatedToFailed { .. }) {
                        new_requests.push(EscalationProposalRequest {
                            member_to_remove: member_id,
                            current_members: current_members.clone(),
                            trigger_tick: self.engine_tick,
                        });
                    }
                }

                if next == EscalationMemberState::BelowThreshold
                    && !matches!(current, EscalationMemberState::BelowThreshold)
                    && self.config.cooldown_ticks > 0
                {
                    self.cooldowns
                        .insert(member_id, self.engine_tick + self.config.cooldown_ticks);
                }
            }
            self.member_states.insert(member_id, next);
        }

        self.pending_requests.extend(new_requests.clone());
        new_requests
    }

    /// Internal: evaluate the next escalation state for a member.
    fn evaluate_member(
        &self,
        _member_id: MemberId,
        score: u64,
        current: &EscalationMemberState,
    ) -> EscalationMemberState {
        let suspect = self.config.suspect_score_ceiling;
        let failed = self.config.failed_score_ceiling;
        let need = self.config.consecutive_intervals;

        match current {
            EscalationMemberState::BelowThreshold => {
                if score >= suspect {
                    EscalationMemberState::PendingEscalation {
                        consecutive_count: 1,
                    }
                } else {
                    EscalationMemberState::BelowThreshold
                }
            }
            EscalationMemberState::PendingEscalation { consecutive_count } => {
                if score < suspect {
                    EscalationMemberState::BelowThreshold
                } else {
                    let new_count = consecutive_count.saturating_add(1);
                    if new_count >= need {
                        if score >= failed {
                            EscalationMemberState::EscalatedToFailed {
                                since_tick: self.engine_tick,
                            }
                        } else {
                            EscalationMemberState::EscalatedToSuspected {
                                since_tick: self.engine_tick,
                            }
                        }
                    } else {
                        EscalationMemberState::PendingEscalation {
                            consecutive_count: new_count,
                        }
                    }
                }
            }
            EscalationMemberState::EscalatedToSuspected { .. } => {
                if score < suspect {
                    EscalationMemberState::BelowThreshold
                } else if score >= failed {
                    EscalationMemberState::PendingEscalation {
                        consecutive_count: 1,
                    }
                } else {
                    current.clone()
                }
            }
            EscalationMemberState::EscalatedToFailed { .. } => current.clone(),
        }
    }

    /// Drain and return all pending proposal requests.
    pub fn drain_requests(&mut self) -> Vec<EscalationProposalRequest> {
        std::mem::take(&mut self.pending_requests)
    }

    /// Produce a BLAKE3-256 state digest covering all per-member states,
    /// cooldowns, the config hash, and the engine tick.
    pub fn state_digest(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key(DOMAIN);
        h.update(b"state");
        h.update(&self.config.config_hash());
        h.update(&self.engine_tick.to_le_bytes());
        h.update(&self.poll_interval.to_le_bytes());

        let mut ids: Vec<MemberId> = self.member_states.keys().copied().collect();
        ids.sort_by_key(|m| m.0);
        for id in &ids {
            let state = &self.member_states[id];
            h.update(&id.0.to_le_bytes());
            h.update(&[state.discriminant()]);
            match state {
                EscalationMemberState::BelowThreshold => {}
                EscalationMemberState::PendingEscalation { consecutive_count } => {
                    h.update(&consecutive_count.to_le_bytes());
                }
                EscalationMemberState::EscalatedToSuspected { since_tick } => {
                    h.update(&since_tick.to_le_bytes());
                }
                EscalationMemberState::EscalatedToFailed { since_tick } => {
                    h.update(&since_tick.to_le_bytes());
                }
            }
        }

        let mut cd_ids: Vec<MemberId> = self.cooldowns.keys().copied().collect();
        cd_ids.sort_by_key(|m| m.0);
        for id in &cd_ids {
            h.update(&id.0.to_le_bytes());
            h.update(&self.cooldowns[id].to_le_bytes());
        }

        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::roster::MembershipRoster;
    use super::super::suspicion_accumulator::{
        SuspicionAccumulator, SuspicionConfig, SuspicionValidation,
    };
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId(id)
    }

    fn setup_engine(interval: u64) -> (EscalationEngine, SuspicionAccumulator, MembershipRoster) {
        let engine = EscalationEngine::new(EscalationThreshold::default(), interval);
        let acc = SuspicionAccumulator::new(SuspicionConfig::default());
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));
        roster.add_member(mid(3));
        (engine, acc, roster)
    }

    // ── EscalationThreshold ────────────────────────────────────────

    #[test]
    fn threshold_default_values() {
        let t = EscalationThreshold::default();
        assert_eq!(t.suspect_score_ceiling, 30);
        assert_eq!(t.failed_score_ceiling, 100);
        assert_eq!(t.consecutive_intervals, 3);
        assert_eq!(t.cooldown_ticks, 10);
    }

    #[test]
    fn threshold_config_hash_deterministic() {
        let t = EscalationThreshold::default();
        assert_eq!(t.config_hash(), t.config_hash());
    }

    #[test]
    fn threshold_config_hash_differs_when_fields_change() {
        let t1 = EscalationThreshold::default();
        let t2 = EscalationThreshold {
            suspect_score_ceiling: 50,
            ..Default::default()
        };
        assert_ne!(t1.config_hash(), t2.config_hash());
    }

    // ── EscalationEngine: basic ─────────────────────────────────────

    #[test]
    fn new_engine_empty() {
        let mut engine = EscalationEngine::new(EscalationThreshold::default(), 1);
        assert_eq!(engine.tick_count(), 0);
        assert!(engine.drain_requests().is_empty());
    }

    #[test]
    fn poll_on_non_interval_skips_evaluation() {
        let (mut engine, acc, roster) = setup_engine(5);
        let reqs = engine.poll(&acc, &roster);
        assert!(reqs.is_empty());
        assert_eq!(engine.tick_count(), 1);
    }

    #[test]
    fn poll_on_interval_evaluates() {
        let (mut engine, acc, roster) = setup_engine(1);
        let reqs = engine.poll(&acc, &roster);
        assert!(reqs.is_empty());
        assert_eq!(engine.tick_count(), 1);
    }

    // ── Single-member threshold crossing ──────────────────────────

    #[test]
    fn single_member_crossing_suspect_threshold_enters_pending() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        let reqs = engine.poll(&acc, &roster);
        assert!(reqs.is_empty());
        let state = engine.member_state(mid(1)).unwrap();
        assert!(matches!(
            state,
            EscalationMemberState::PendingEscalation { .. }
        ));
    }

    // ── Consecutive-interval gating ────────────────────────────────

    #[test]
    fn consecutive_interval_gating_requires_multiple_polls() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::PendingEscalation {
                consecutive_count: 1
            }
        ));
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::PendingEscalation {
                consecutive_count: 2
            }
        ));
        let reqs = engine.poll(&acc, &roster);
        assert!(reqs.is_empty());
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToSuspected { .. }
        ));
    }

    #[test]
    fn single_spike_below_interval_count_resets() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
    }

    // ── Failed threshold triggers proposal ─────────────────────────

    #[test]
    fn failed_threshold_triggers_proposal_request() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..10 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].member_to_remove, mid(1));
        assert_eq!(reqs[0].current_members, vec![mid(1), mid(2), mid(3)]);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToFailed { .. }
        ));
    }

    #[test]
    fn failed_terminal_no_repeat_proposal() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..10 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        assert_eq!(reqs.len(), 1);
        let reqs2 = engine.poll(&acc, &roster);
        assert!(reqs2.is_empty());
    }

    // ── Multi-member independent escalation ────────────────────────

    #[test]
    fn multi_member_independent_escalation() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        acc.register_member(mid(2));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
            acc.record_validation(mid(2), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToSuspected { .. }
        ));
        assert!(matches!(
            engine.member_state(mid(2)).unwrap(),
            EscalationMemberState::EscalatedToSuspected { .. }
        ));
    }

    #[test]
    fn members_do_not_cross_contaminate() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        acc.register_member(mid(2));
        for _ in 0..10 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].member_to_remove, mid(1));
        assert!(matches!(
            engine.member_state(mid(2)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
    }

    // ── Cooldown enforcement ───────────────────────────────────────

    #[test]
    fn cooldown_blocks_re_escalation() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 100 });
        }
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
    }

    #[test]
    fn cooldown_expires_allows_re_escalation() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        engine.poll(&acc, &roster);
        for _ in 0..10 {
            engine.poll(&acc, &roster);
        }
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 200 });
        }
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::PendingEscalation { .. }
        ));
    }

    // ── Below-threshold recovery ───────────────────────────────────

    #[test]
    fn below_threshold_recovery_resets_state() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::PendingEscalation { .. }
        ));
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
    }

    #[test]
    fn recovery_from_suspected_drops_to_below_threshold() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToSuspected { .. }
        ));
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        acc.record_validation(mid(1), SuspicionValidation::IndirectPingSuccess);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::BelowThreshold
        ));
    }

    // ── BLAKE3 state digest ────────────────────────────────────────

    #[test]
    fn empty_engine_state_digest() {
        let engine = EscalationEngine::new(EscalationThreshold::default(), 1);
        let digest = engine.state_digest();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn state_digest_deterministic() {
        let (mut engine1, mut acc1, roster1) = setup_engine(1);
        let (mut engine2, mut acc2, _roster2) = setup_engine(1);
        acc1.register_member(mid(1));
        acc2.register_member(mid(1));
        for _ in 0..3 {
            acc1.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
            acc2.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine1.poll(&acc1, &roster1);
        engine2.poll(&acc2, &roster1);
        assert_eq!(engine1.state_digest(), engine2.state_digest());
    }

    #[test]
    fn state_digest_changes_on_transition() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        let d1 = engine.state_digest();
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        let d2 = engine.state_digest();
        assert_ne!(d1, d2);
    }

    // ── drain_requests ─────────────────────────────────────────────

    #[test]
    fn drain_requests_clears_buffer() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..10 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        assert!(!reqs.is_empty());
        let drained = engine.drain_requests();
        assert!(!drained.is_empty());
        let drained2 = engine.drain_requests();
        assert!(drained2.is_empty());
    }

    // ── Suspected to Failed escalation ─────────────────────────────

    #[test]
    fn escalation_from_suspected_to_failed_emits_proposal() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..3 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToSuspected { .. }
        ));
        for _ in 0..7 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 2 });
        }
        engine.poll(&acc, &roster);
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::PendingEscalation {
                consecutive_count: 1
            }
        ));
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].member_to_remove, mid(1));
        assert!(matches!(
            engine.member_state(mid(1)).unwrap(),
            EscalationMemberState::EscalatedToFailed { .. }
        ));
    }

    // ── Proposal current_members accuracy ──────────────────────────

    #[test]
    fn proposal_request_includes_correct_current_members() {
        let (mut engine, mut acc, roster) = setup_engine(1);
        acc.register_member(mid(1));
        for _ in 0..10 {
            acc.record_validation(mid(1), SuspicionValidation::DirectPingFailure { round: 1 });
        }
        engine.poll(&acc, &roster);
        engine.poll(&acc, &roster);
        let reqs = engine.poll(&acc, &roster);
        let members = &reqs[0].current_members;
        assert_eq!(members.len(), 3);
        assert!(members.contains(&mid(1)));
        assert!(members.contains(&mid(2)));
        assert!(members.contains(&mid(3)));
    }
}
