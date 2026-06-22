// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// WitnessStateMachine: state transitions for witness set lifecycle
// with invariant validation.
//
// Tracks the collective health and reconfiguration state of a witness set.
// States: Active, Degraded, Expanding, Shrinking, Collapsed.
// Every transition validates invariants before committing.

use crate::witness_set::WitnessSet;

/// Operational state of a witness set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessState {
    Active,
    Degraded,
    Expanding,
    Shrinking,
    Collapsed,
}

/// Reason a state transition was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    IllegalTransition {
        from: WitnessState,
        to: WitnessState,
    },
    InvariantViolation(String),
    EmptySet,
    QuorumLoss,
}

/// Allowed state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Degrade,
    Recover,
    BeginExpand,
    CommitExpand,
    BeginShrink,
    CommitShrink,
    Collapse,
}

impl Transition {
    fn is_legal_from(self, state: WitnessState) -> bool {
        matches!(
            (state, self),
            (WitnessState::Active, Transition::Degrade)
                | (WitnessState::Active, Transition::BeginExpand)
                | (WitnessState::Active, Transition::BeginShrink)
                | (WitnessState::Active, Transition::Collapse)
                | (WitnessState::Degraded, Transition::Recover)
                | (WitnessState::Degraded, Transition::BeginExpand)
                | (WitnessState::Degraded, Transition::BeginShrink)
                | (WitnessState::Degraded, Transition::Collapse)
                | (WitnessState::Expanding, Transition::CommitExpand)
                | (WitnessState::Expanding, Transition::Collapse)
                | (WitnessState::Shrinking, Transition::CommitShrink)
                | (WitnessState::Shrinking, Transition::Collapse)
        )
    }

    fn target_state(self) -> WitnessState {
        match self {
            Transition::Degrade => WitnessState::Degraded,
            Transition::Recover => WitnessState::Active,
            Transition::BeginExpand => WitnessState::Expanding,
            Transition::CommitExpand => WitnessState::Active,
            Transition::BeginShrink => WitnessState::Shrinking,
            Transition::CommitShrink => WitnessState::Active,
            Transition::Collapse => WitnessState::Collapsed,
        }
    }
}

/// State machine governing witness set lifecycle transitions.
#[derive(Clone, Debug)]
pub struct WitnessStateMachine {
    state: WitnessState,
    witness_set: WitnessSet,
    offline_count: usize,
    pending_additions: Vec<u64>,
    pending_removals: Vec<u64>,
}

impl WitnessStateMachine {
    pub fn new(witness_set: WitnessSet) -> Self {
        let state = if witness_set.is_empty() {
            WitnessState::Collapsed
        } else {
            WitnessState::Active
        };
        Self {
            state,
            witness_set,
            offline_count: 0,
            pending_additions: Vec::new(),
            pending_removals: Vec::new(),
        }
    }

    pub fn state(&self) -> WitnessState {
        self.state
    }
    pub fn witness_set(&self) -> &WitnessSet {
        &self.witness_set
    }
    pub fn witness_set_mut(&mut self) -> &mut WitnessSet {
        &mut self.witness_set
    }
    pub fn offline_count(&self) -> usize {
        self.offline_count
    }
    pub fn pending_additions(&self) -> &[u64] {
        &self.pending_additions
    }
    pub fn pending_removals(&self) -> &[u64] {
        &self.pending_removals
    }

    /// Apply a state transition with invariant validation.
    pub fn apply(&mut self, transition: Transition) -> Result<WitnessState, TransitionError> {
        if !transition.is_legal_from(self.state) {
            return Err(TransitionError::IllegalTransition {
                from: self.state,
                to: transition.target_state(),
            });
        }
        self.validate_invariant(&transition)?;
        let new_state = transition.target_state();
        self.state = new_state;
        Ok(new_state)
    }

    /// Mark a witness as offline. May trigger Degrade or Collapse.
    pub fn witness_went_offline(&mut self, _node_id: u64) -> Result<WitnessState, TransitionError> {
        self.offline_count += 1;
        let online = self.witness_set.len().saturating_sub(self.offline_count);
        let total = self.witness_set.len();
        let threshold = self.witness_set.threshold();
        if online == 0 || !threshold.is_satisfied(online, total) {
            if self.state != WitnessState::Collapsed {
                return self.apply(Transition::Collapse);
            }
        } else if self.state == WitnessState::Active {
            return self.apply(Transition::Degrade);
        }
        Ok(self.state)
    }

    /// Mark a witness as recovered (back online).
    pub fn witness_recovered(&mut self, _node_id: u64) -> Result<WitnessState, TransitionError> {
        if self.offline_count > 0 {
            self.offline_count -= 1;
        }
        if self.state == WitnessState::Degraded {
            let online = self.witness_set.len().saturating_sub(self.offline_count);
            let total = self.witness_set.len();
            if self.witness_set.threshold().is_satisfied(online, total) {
                return self.apply(Transition::Recover);
            }
        }
        Ok(self.state)
    }

    /// Begin adding a witness.
    pub fn begin_add_witness(&mut self, node_id: u64) -> Result<WitnessState, TransitionError> {
        // Transition to Expanding if not already in Active, Degraded, or Expanding.
        if self.state != WitnessState::Active
            && self.state != WitnessState::Degraded
            && self.state != WitnessState::Expanding
        {
            return Err(TransitionError::IllegalTransition {
                from: self.state,
                to: WitnessState::Expanding,
            });
        }
        if self.state != WitnessState::Expanding {
            self.apply(Transition::BeginExpand)?;
        }
        if self.witness_set.contains(node_id) || self.pending_additions.contains(&node_id) {
            return Err(TransitionError::InvariantViolation(format!(
                "witness {node_id} is already a member"
            )));
        }
        self.pending_additions.push(node_id);
        Ok(self.state)
    }

    /// Commit pending additions.
    pub fn commit_additions(&mut self) -> Result<WitnessState, TransitionError> {
        if self.pending_additions.is_empty() {
            return Err(TransitionError::InvariantViolation(
                "no pending additions to commit".into(),
            ));
        }
        for &node_id in &self.pending_additions {
            if let Err(err) = self.witness_set.validate_witness_eligibility(node_id) {
                return Err(TransitionError::InvariantViolation(format!(
                    "pending witness {node_id} is not eligible in current membership epoch: {err}"
                )));
            }
        }
        // Validate the transition before consuming the pending list.
        self.apply(Transition::CommitExpand)?;
        for &node_id in &self.pending_additions {
            self.witness_set.add_witness(node_id);
        }
        self.pending_additions.clear();
        let online = self.witness_set.len().saturating_sub(self.offline_count);
        let total = self.witness_set.len();
        if !self.witness_set.threshold().is_satisfied(online, total) {
            self.state = WitnessState::Collapsed;
            return Ok(self.state);
        }
        Ok(self.state)
    }

    /// Begin removing a witness.
    pub fn begin_remove_witness(&mut self, node_id: u64) -> Result<WitnessState, TransitionError> {
        // Transition to Shrinking if not already in Active, Degraded, or Shrinking.
        if self.state != WitnessState::Active
            && self.state != WitnessState::Degraded
            && self.state != WitnessState::Shrinking
        {
            return Err(TransitionError::IllegalTransition {
                from: self.state,
                to: WitnessState::Shrinking,
            });
        }
        if self.state != WitnessState::Shrinking {
            self.apply(Transition::BeginShrink)?;
        }
        if !self.witness_set.contains(node_id) {
            return Err(TransitionError::InvariantViolation(format!(
                "witness {node_id} is not a member"
            )));
        }
        self.pending_removals.push(node_id);
        Ok(self.state)
    }

    /// Commit pending removals.
    pub fn commit_removals(&mut self) -> Result<WitnessState, TransitionError> {
        if self.pending_removals.is_empty() {
            return Err(TransitionError::InvariantViolation(
                "no pending removals to commit".into(),
            ));
        }
        // Validate the transition before consuming the pending list.
        self.apply(Transition::CommitShrink)?;
        for &node_id in &self.pending_removals {
            self.witness_set.remove_witness(node_id);
        }
        self.pending_removals.clear();
        if self.witness_set.is_empty() {
            self.state = WitnessState::Collapsed;
            return Ok(self.state);
        }
        let online = self.witness_set.len().saturating_sub(self.offline_count);
        let total = self.witness_set.len();
        if !self.witness_set.threshold().is_satisfied(online, total) {
            self.state = WitnessState::Collapsed;
            return Ok(self.state);
        }
        Ok(self.state)
    }

    fn validate_invariant(&self, transition: &Transition) -> Result<(), TransitionError> {
        match transition {
            Transition::Degrade => {
                if self.witness_set.is_empty() {
                    return Err(TransitionError::EmptySet);
                }
            }
            Transition::Recover => {
                if self.witness_set.is_empty() {
                    return Err(TransitionError::EmptySet);
                }
                let online = self.witness_set.len().saturating_sub(self.offline_count);
                if !self
                    .witness_set
                    .threshold()
                    .is_satisfied(online, self.witness_set.len())
                {
                    return Err(TransitionError::QuorumLoss);
                }
            }
            Transition::BeginExpand => {
                if self.state == WitnessState::Collapsed {
                    return Err(TransitionError::InvariantViolation(
                        "cannot expand a collapsed witness set".into(),
                    ));
                }
            }
            Transition::CommitExpand => {
                // Validated by caller before consuming pending_additions.
            }
            Transition::BeginShrink => {
                if self.witness_set.is_empty() {
                    return Err(TransitionError::EmptySet);
                }
            }
            Transition::CommitShrink => {
                // Validated by caller; quorum-loss is checked after removals.
            }
            Transition::Collapse => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness_set::QuorumThreshold;
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn add_voters(ws: &mut WitnessSet, ids: &[u64]) {
        let voter_ids: Vec<MemberId> = ids.iter().copied().map(MemberId::new).collect();
        ws.install_voter_ids_for_epoch(EpochId::new(ws.epoch()), &voter_ids);
        for id in ids {
            assert!(ws.add_witness(*id), "voter {id} must be accepted");
        }
    }

    fn install_voters(ws: &mut WitnessSet, ids: &[u64]) {
        let voter_ids: Vec<MemberId> = ids.iter().copied().map(MemberId::new).collect();
        ws.install_voter_ids_for_epoch(EpochId::new(ws.epoch()), &voter_ids);
    }

    fn make_ws(count: usize) -> WitnessSet {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        let ids: Vec<u64> = (1..=count as u64).collect();
        add_voters(&mut ws, &ids);
        ws
    }

    #[test]
    fn test_new_active_for_nonempty() {
        let sm = WitnessStateMachine::new(make_ws(3));
        assert_eq!(sm.state(), WitnessState::Active);
    }

    #[test]
    fn test_new_collapsed_for_empty() {
        let sm = WitnessStateMachine::new(WitnessSet::new(QuorumThreshold::StrictMajority));
        assert_eq!(sm.state(), WitnessState::Collapsed);
    }

    #[test]
    fn test_degrade_and_recover() {
        let mut sm = WitnessStateMachine::new(make_ws(5));
        assert_eq!(sm.witness_went_offline(1).unwrap(), WitnessState::Degraded);
        assert_eq!(sm.witness_recovered(1).unwrap(), WitnessState::Active);
    }

    #[test]
    fn test_degrade_collapse_when_quorum_impossible() {
        let mut sm = WitnessStateMachine::new(make_ws(5));
        sm.witness_went_offline(1).unwrap();
        sm.witness_went_offline(2).unwrap();
        assert_eq!(sm.witness_went_offline(3).unwrap(), WitnessState::Collapsed);
    }

    #[test]
    fn test_expand_add_and_commit() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        install_voters(sm.witness_set_mut(), &[1, 2, 3, 10, 20]);
        sm.begin_add_witness(10).unwrap();
        sm.begin_add_witness(20).unwrap();
        assert_eq!(sm.state(), WitnessState::Expanding);
        assert_eq!(sm.commit_additions().unwrap(), WitnessState::Active);
        assert_eq!(sm.witness_set().len(), 5);
    }

    #[test]
    fn test_expand_duplicate_rejected() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        sm.begin_add_witness(10).unwrap();
        assert!(sm.begin_add_witness(10).is_err());
    }

    #[test]
    fn test_commit_additions_empty_pending() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        sm.apply(Transition::BeginExpand).unwrap();
        assert!(sm.commit_additions().is_err());
    }

    #[test]
    fn test_expand_collapsed_rejected() {
        let mut sm = WitnessStateMachine::new(WitnessSet::new(QuorumThreshold::StrictMajority));
        assert!(sm.apply(Transition::BeginExpand).is_err());
    }

    #[test]
    fn test_shrink_remove_and_commit() {
        let mut sm = WitnessStateMachine::new(make_ws(5));
        sm.begin_remove_witness(1).unwrap();
        sm.begin_remove_witness(2).unwrap();
        assert_eq!(sm.state(), WitnessState::Shrinking);
        assert_eq!(sm.commit_removals().unwrap(), WitnessState::Active);
        assert_eq!(sm.witness_set().len(), 3);
        assert!(!sm.witness_set().contains(1));
    }

    #[test]
    fn test_shrink_non_member_rejected() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        assert!(sm.begin_remove_witness(99).is_err());
    }

    #[test]
    fn test_shrink_all_leaves_collapsed() {
        let mut sm = WitnessStateMachine::new(make_ws(2));
        sm.begin_remove_witness(1).unwrap();
        sm.begin_remove_witness(2).unwrap();
        sm.commit_removals().unwrap();
        assert_eq!(sm.state(), WitnessState::Collapsed);
    }

    #[test]
    fn test_collapsed_rejects_all() {
        let mut sm = WitnessStateMachine::new(WitnessSet::new(QuorumThreshold::StrictMajority));
        for t in [
            Transition::Degrade,
            Transition::Recover,
            Transition::BeginExpand,
            Transition::BeginShrink,
        ] {
            assert!(sm.apply(t).is_err());
        }
    }

    #[test]
    fn test_illegal_transitions() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        assert!(sm.apply(Transition::Recover).is_err());
        assert!(sm.apply(Transition::CommitExpand).is_err());
        assert!(sm.apply(Transition::CommitShrink).is_err());
    }

    #[test]
    fn test_offline_count_accurate() {
        let mut sm = WitnessStateMachine::new(make_ws(5));
        sm.witness_went_offline(1).unwrap();
        sm.witness_went_offline(2).unwrap();
        assert_eq!(sm.offline_count(), 2);
        sm.witness_recovered(1).unwrap();
        assert_eq!(sm.offline_count(), 1);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        assert_eq!(sm.state(), WitnessState::Active);
        sm.witness_went_offline(1).unwrap();
        assert_eq!(sm.state(), WitnessState::Degraded);
        install_voters(sm.witness_set_mut(), &[1, 2, 3, 10]);
        sm.begin_add_witness(10).unwrap();
        sm.commit_additions().unwrap();
        assert_eq!(sm.state(), WitnessState::Active);
        sm.begin_remove_witness(10).unwrap();
        sm.commit_removals().unwrap();
        assert_eq!(sm.state(), WitnessState::Active);
    }

    #[test]
    fn test_begin_add_from_degraded_forces_expanding() {
        let mut sm = WitnessStateMachine::new(make_ws(3));
        sm.witness_went_offline(1).unwrap();
        assert_eq!(sm.state(), WitnessState::Degraded);
        install_voters(sm.witness_set_mut(), &[1, 2, 3, 10]);
        sm.begin_add_witness(10).unwrap();
        assert_eq!(sm.state(), WitnessState::Expanding);
        sm.commit_additions().unwrap();
        assert_eq!(sm.state(), WitnessState::Active);
    }
}
