//! PublicationPipelineEpochGate: epoch-gated publication admission during
//! network partitions. Freezes publication on the minority side while
//! allowing the quorum side to continue with a new epoch.

use crate::split_brain_guard::SplitBrainGuard;
use crate::types::{now_millis, PartitionState};
use tidefs_membership_epoch::EpochId;

/// Gates publication admission based on partition state and epoch fencing.
///
/// When a partition is detected:
/// - **Quorum side**: publications continue, but under a new epoch that
///   excludes minority members. The gate admits publications tagged with
///   the new quorum-side epoch.
/// - **Minority side**: the gate freezes all publication admission.
///   Fenced publications are held, not rejected, to be replayed on heal.
/// - **Ambiguous**: the gate freezes admission on both sides.
///
/// On heal, the quorum side resumes normal admission under a joint config
/// epoch. Minority-side publications that were fenced are replayed through
/// the healing protocol.
pub struct PublicationPipelineEpochGate {
    /// Whether publication admission is currently frozen.
    pub frozen: bool,
    /// The epoch under which publications are currently admitted.
    /// During a partition on the quorum side, this is the new
    /// quorum-only epoch.
    pub active_epoch: Option<EpochId>,
    /// The epoch before the partition (for rollback/replay on heal).
    pub pre_partition_epoch: Option<EpochId>,
    /// Publications fenced during the partition (held, not rejected).
    pub fenced_publication_count: usize,
    /// Timestamp of when the gate was last raised (frozen).
    pub frozen_at_millis: u64,
    /// Timestamp of when the gate was last lowered (thawed).
    pub thawed_at_millis: u64,
}

impl PublicationPipelineEpochGate {
    /// Create a new gate, initially open.
    pub fn new() -> Self {
        Self {
            frozen: false,
            active_epoch: None,
            pre_partition_epoch: None,
            fenced_publication_count: 0,
            frozen_at_millis: 0,
            thawed_at_millis: 0,
        }
    }

    /// Evaluate the gate state from the partition state and guard.
    ///
    /// On quorum side with a new epoch: gate opens under new epoch.
    /// On minority side: gate freezes.
    /// On ambiguous halt: gate freezes.
    /// On connected/healing: gate opens.
    pub fn evaluate(
        &mut self,
        partition_state: &PartitionState,
        guard: &SplitBrainGuard,
    ) -> PublicationGateResult {
        let was_frozen = self.frozen;

        match partition_state {
            PartitionState::Connected => {
                self.frozen = false;
                self.active_epoch = None;
                if was_frozen {
                    self.thawed_at_millis = crate::types::now_millis();
                }
            }
            PartitionState::Suspecting { .. } => {
                if self.frozen {
                    self.open(guard.epoch);
                }
            }
            PartitionState::QuorumSideActive { ref new_epoch, .. } => {
                if self.frozen {
                    self.open(*new_epoch);
                } else {
                    self.pre_partition_epoch = self.active_epoch;
                    self.active_epoch = Some(*new_epoch);
                }
            }
            PartitionState::MinorityFenced { .. } => {
                self.freeze();
            }
            PartitionState::AmbiguousHalted { .. } => {
                self.freeze();
            }
            PartitionState::Healing {
                ref joint_epoch, ..
            } => {
                self.open(*joint_epoch);
            }
        }

        PublicationGateResult {
            frozen: self.frozen,
            active_epoch: self.active_epoch,
            was_frozen,
            is_now_frozen: self.frozen,
            fenced_count: self.fenced_publication_count,
        }
    }

    /// Check whether a publication with the given epoch should be admitted.
    #[must_use]
    pub fn admit(&self, publication_epoch: EpochId) -> bool {
        if self.frozen {
            return false;
        }
        match self.active_epoch {
            Some(active) => publication_epoch == active,
            None => true,
        }
    }

    /// Record a fenced publication (held, not rejected).
    pub fn record_fenced(&mut self) {
        self.fenced_publication_count += 1;
    }

    /// Whether the gate is currently frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Get the count of fenced publications (to be replayed on heal).
    #[must_use]
    pub fn fenced_publication_count(&self) -> usize {
        self.fenced_publication_count
    }

    /// Open the gate under the given epoch.
    fn open(&mut self, epoch: EpochId) {
        if self.frozen {
            self.thawed_at_millis = now_millis();
        }
        self.frozen = false;
        self.active_epoch = Some(epoch);
    }

    /// Freeze the gate.
    fn freeze(&mut self) {
        if !self.frozen {
            self.frozen_at_millis = now_millis();
        }
        self.frozen = true;
    }

    /// Reset the gate (on heal completion).
    pub fn reset(&mut self) {
        self.frozen = false;
        self.active_epoch = None;
        self.pre_partition_epoch = None;
        self.fenced_publication_count = 0;
        self.frozen_at_millis = 0;
        self.thawed_at_millis = 0;
    }
}

impl Default for PublicationPipelineEpochGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of evaluating the publication gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationGateResult {
    /// Whether admission is currently frozen.
    pub frozen: bool,
    /// The active epoch for admitted publications (if any).
    pub active_epoch: Option<EpochId>,
    /// Whether the gate was frozen before this evaluation.
    pub was_frozen: bool,
    /// Whether the gate is now frozen after this evaluation.
    pub is_now_frozen: bool,
    /// Number of fenced publications.
    pub fenced_count: usize,
}

impl PublicationGateResult {
    /// Whether a state transition occurred (frozen ↔ open).
    #[must_use]
    pub fn transitioned(&self) -> bool {
        self.was_frozen != self.is_now_frozen
    }

    /// Whether the gate just froze (transition from open to frozen).
    #[must_use]
    pub fn just_froze(&self) -> bool {
        !self.was_frozen && self.is_now_frozen
    }

    /// Whether the gate just thawed (transition from frozen to open).
    #[must_use]
    pub fn just_thawed(&self) -> bool {
        self.was_frozen && !self.is_now_frozen
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::MemberId;

    #[test]
    fn test_gate_open_initially() {
        let gate = PublicationPipelineEpochGate::new();
        assert!(!gate.is_frozen());
        assert!(gate.admit(EpochId::new(1)));
    }

    #[test]
    fn test_gate_freezes_on_minority() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);
        let state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 1000,
        };
        let result = gate.evaluate(&state, &guard);
        assert!(result.frozen);
        assert!(result.just_froze());
        assert!(!gate.admit(EpochId::new(1)));
    }

    #[test]
    fn test_gate_opens_on_quorum_side() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);

        // First freeze
        let minority_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 1000,
        };
        gate.evaluate(&minority_state, &guard);
        assert!(gate.is_frozen());

        // Then become quorum side
        let quorum_state = PartitionState::QuorumSideActive {
            minority_members: vec![MemberId::new(2)],
            new_epoch: EpochId::new(5),
            since_millis: 2000,
        };
        let result = gate.evaluate(&quorum_state, &guard);
        assert!(!result.frozen);
        assert!(result.just_thawed());
        assert!(gate.admit(EpochId::new(5)));
        assert!(!gate.admit(EpochId::new(4)));
    }

    #[test]
    fn test_gate_freezes_on_ambiguous() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);
        let state = PartitionState::AmbiguousHalted {
            sides: vec![
                vec![MemberId::new(1), MemberId::new(2)],
                vec![MemberId::new(3), MemberId::new(4)],
            ],
            since_millis: 1000,
        };
        let result = gate.evaluate(&state, &guard);
        assert!(result.frozen);
        assert!(!gate.admit(EpochId::new(1)));
    }

    #[test]
    fn test_gate_opens_during_healing() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);

        // Freeze first
        let state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 1000,
        };
        gate.evaluate(&state, &guard);
        assert!(gate.is_frozen());

        // Then heal
        let heal_state = PartitionState::Healing {
            joint_epoch: EpochId::new(6),
            rejoining_members: vec![MemberId::new(2)],
            since_millis: 2000,
        };
        let result = gate.evaluate(&heal_state, &guard);
        assert!(!result.frozen);
        assert!(result.just_thawed());
        assert!(gate.admit(EpochId::new(6)));
    }

    #[test]
    fn test_fenced_count_increments() {
        let mut gate = PublicationPipelineEpochGate::new();
        assert_eq!(gate.fenced_publication_count(), 0);
        gate.record_fenced();
        gate.record_fenced();
        assert_eq!(gate.fenced_publication_count(), 2);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);
        let state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 1000,
        };
        gate.evaluate(&state, &guard);
        gate.record_fenced();

        gate.reset();
        assert!(!gate.is_frozen());
        assert_eq!(gate.fenced_publication_count(), 0);
        assert!(gate.active_epoch.is_none());
    }

    #[test]
    fn test_gate_no_transition_when_already_frozen() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);
        let state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 1000,
        };

        let result1 = gate.evaluate(&state, &guard);
        assert!(result1.just_froze());

        let result2 = gate.evaluate(&state, &guard);
        assert!(!result2.transitioned());
    }

    #[test]
    fn test_no_epoch_gating_when_connected() {
        let mut gate = PublicationPipelineEpochGate::new();
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 3);
        let state = PartitionState::Connected;
        gate.evaluate(&state, &guard);
        assert!(gate.admit(EpochId::new(5)));
    }
}
