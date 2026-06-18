// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Membership epoch fence: rejects inbound messages from peers not in the
//! current roster or carrying stale epochs.
//!
//! ## Problem
//!
//! After a peer is removed from the roster — via graceful departure (#6142)
//! or unreachability-triggered removal (#6137) — its still-open transport
//! sessions can deliver stale protocol messages. Without epoch fencing,
//! these messages are dispatched to handlers without validation, creating
//! a window where departed peers can inject outdated state.
//!
//! ## Solution
//!
//! [`MembershipEpochFence`] holds the current committed epoch and the active
//! member set. Before dispatch, each inbound [`MembershipMessage`] is checked:
//!
//! 1. The sender must be in the current member set.
//! 2. If the message carries an epoch, it must be >= the current fence epoch
//!    (messages from stale epochs are rejected).
//!
//! ## Integration
//!
//! The fence implements [`EpochCommitSubscriber`] so it is automatically
//! updated whenever the [`EpochAdvanceCoordinator`] commits a new epoch view.
//! This covers both leave-coordinator epoch advancement and
//! unreachability-triggered roster removal.
//!
//! [`EpochCommitSubscriber`]: crate::epoch_coordinator::EpochCommitSubscriber
//! [`EpochAdvanceCoordinator`]: crate::epoch_coordinator::EpochAdvanceCoordinator

use std::collections::BTreeSet;
use std::sync::RwLock;
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};

// ---------------------------------------------------------------------------
// FenceError
// ---------------------------------------------------------------------------

/// Reasons an inbound message is rejected by the epoch fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceError {
    /// The sender is not in the current roster.
    NotInRoster {
        sender_id: MemberId,
        current_epoch: EpochId,
    },
    /// The message carries an epoch that is stale (below the current
    /// fence epoch). The sender may be operating on outdated membership
    /// state.
    StaleEpoch {
        sender_id: MemberId,
        message_epoch: u64,
        current_epoch: EpochId,
    },
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInRoster {
                sender_id,
                current_epoch,
            } => {
                write!(
                    f,
                    "sender {} not in current roster (epoch {})",
                    sender_id.0, current_epoch.0,
                )
            }
            Self::StaleEpoch {
                sender_id,
                message_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "sender {} message epoch {} is stale (current epoch {})",
                    sender_id.0, message_epoch, current_epoch.0,
                )
            }
        }
    }
}

impl std::error::Error for FenceError {}

// ---------------------------------------------------------------------------
// FenceState
// ---------------------------------------------------------------------------

/// Internal state protected by the fence's [`RwLock`].
#[derive(Clone, Debug)]
struct FenceState {
    /// Current committed epoch number.
    epoch: EpochId,
    /// Sorted set of member node IDs in the current roster.
    member_set: BTreeSet<u64>,
    /// Millisecond timestamp of the last update.
    updated_at_millis: u64,
}

impl FenceState {
    fn new(epoch: EpochId, members: Vec<u64>, updated_at_millis: u64) -> Self {
        Self {
            epoch,
            member_set: members.into_iter().collect(),
            updated_at_millis,
        }
    }

    fn contains(&self, member_id: MemberId) -> bool {
        self.member_set.contains(&member_id.0)
    }
}

// ---------------------------------------------------------------------------
// MembershipEpochFence
// ---------------------------------------------------------------------------

/// A consultable fence holding the current committed epoch and member set,
/// updated atomically on roster changes.
///
/// Used by the inbound message dispatch path to reject messages from
/// departed peers before they reach subsystem handlers.
///
/// # Thread safety
///
/// The fence uses [`RwLock`] internally: reads (the common case for
/// inbound dispatch checks) are concurrent; writes (roster updates)
/// are exclusive.
///
/// # Example
///
/// ```ignore
/// let fence = MembershipEpochFence::new();
/// fence.update_from_view(&epoch_view);
///
/// let result = fence.check(sender_id, Some(message_epoch));
/// if let Err(FenceError::NotInRoster { .. }) = result {
///     // reject message
/// }
/// ```
pub struct MembershipEpochFence {
    state: RwLock<FenceState>,
}

impl MembershipEpochFence {
    /// Create a new fence with an empty member set at epoch 0.
    ///
    /// The fence rejects all messages until [`update_from_view`] is
    /// called with a populated roster.
    ///
    /// [`update_from_view`]: MembershipEpochFence::update_from_view
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(FenceState::new(EpochId::ZERO, Vec::new(), 0)),
        }
    }

    /// Update the fence from an [`EpochView`] produced by the
    /// [`EpochAdvanceCoordinator`].
    ///
    /// Called automatically when the fence is registered as an
    /// [`EpochCommitSubscriber`].
    pub fn update_from_view(&self, view: &EpochView) {
        let mut state = self.state.write().unwrap();
        state.epoch = view.epoch_number;
        state.member_set = view.member_set.iter().map(|m| m.0).collect();
        state.updated_at_millis = view.created_at_millis;
    }

    /// Check whether a message from `sender_id` with optional
    /// `message_epoch` should be accepted.
    ///
    /// # Errors
    ///
    /// - [`FenceError::NotInRoster`] when the sender is not in the
    ///   current member set.
    /// - [`FenceError::StaleEpoch`] when `message_epoch` is present
    ///   and strictly less than the current fence epoch.
    ///
    /// Messages without an epoch (e.g., `EpochCatchUpResponse`,
    /// `ProposalAck`) are only checked for roster membership.
    pub fn check(&self, sender_id: MemberId, message_epoch: Option<u64>) -> Result<(), FenceError> {
        let state = self.state.read().unwrap();

        // Sender must be in the current member set.
        if !state.contains(sender_id) {
            return Err(FenceError::NotInRoster {
                sender_id,
                current_epoch: state.epoch,
            });
        }

        // If the message carries an epoch, it must not be stale.
        if let Some(msg_epoch) = message_epoch {
            if msg_epoch < state.epoch.0 {
                return Err(FenceError::StaleEpoch {
                    sender_id,
                    message_epoch: msg_epoch,
                    current_epoch: state.epoch,
                });
            }
        }

        Ok(())
    }

    /// Return the current fence epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.state.read().unwrap().epoch
    }

    /// Return the current member count.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.state.read().unwrap().member_set.len()
    }

    /// Return whether a specific member is in the current roster.
    #[must_use]
    pub fn contains(&self, member_id: MemberId) -> bool {
        self.state.read().unwrap().contains(member_id)
    }

    /// Return a snapshot of the current member set (sorted).
    #[must_use]
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.state
            .read()
            .unwrap()
            .member_set
            .iter()
            .map(|n| MemberId::new(*n))
            .collect()
    }
}

impl Default for MembershipEpochFence {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EpochCommitSubscriber impl — auto-update on roster changes
// ---------------------------------------------------------------------------

impl EpochCommitSubscriber for MembershipEpochFence {
    fn on_epoch_committed(&self, view: &EpochView) {
        self.update_from_view(view);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn view(epoch: u64, members: &[u64], ts: u64) -> EpochView {
        EpochView::new(
            EpochId::new(epoch),
            members.iter().map(|n| MemberId::new(*n)).collect(),
            ts,
        )
    }

    // ------------------------------------------------------------------
    // Creation / defaults
    // ------------------------------------------------------------------

    #[test]
    fn new_fence_is_empty() {
        let fence = MembershipEpochFence::new();
        assert_eq!(fence.current_epoch(), EpochId::ZERO);
        assert_eq!(fence.member_count(), 0);
        assert!(!fence.contains(mid(1)));
    }

    #[test]
    fn default_fence_is_empty() {
        let fence = MembershipEpochFence::default();
        assert_eq!(fence.member_count(), 0);
    }

    // ------------------------------------------------------------------
    // Update from view
    // ------------------------------------------------------------------

    #[test]
    fn update_from_view_sets_members() {
        let fence = MembershipEpochFence::new();
        let v = view(5, &[1, 2, 3], 1000);
        fence.update_from_view(&v);

        assert_eq!(fence.current_epoch(), EpochId::new(5));
        assert_eq!(fence.member_count(), 3);
        assert!(fence.contains(mid(1)));
        assert!(fence.contains(mid(2)));
        assert!(fence.contains(mid(3)));
        assert!(!fence.contains(mid(4)));
    }

    #[test]
    fn update_from_view_replaces_previous_state() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(1, &[10, 20], 100));
        assert_eq!(fence.member_count(), 2);
        assert!(fence.contains(mid(10)));

        // New view replaces old
        fence.update_from_view(&view(2, &[30, 40, 50], 200));
        assert_eq!(fence.current_epoch(), EpochId::new(2));
        assert_eq!(fence.member_count(), 3);
        assert!(!fence.contains(mid(10)));
        assert!(fence.contains(mid(30)));
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber integration
    // ------------------------------------------------------------------

    #[test]
    fn subscriber_updates_fence() {
        let fence = MembershipEpochFence::new();
        let v = view(7, &[1, 2], 500);

        // Call through the subscriber trait
        EpochCommitSubscriber::on_epoch_committed(&fence, &v);

        assert_eq!(fence.current_epoch(), EpochId::new(7));
        assert_eq!(fence.member_count(), 2);
    }

    // ------------------------------------------------------------------
    // Check: roster membership
    // ------------------------------------------------------------------

    #[test]
    fn check_accepts_message_from_current_member() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(3, &[1, 2, 3], 0));

        let result = fence.check(mid(2), Some(3));
        assert!(result.is_ok());
    }

    #[test]
    fn check_rejects_message_from_non_member() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(3, &[1, 2, 3], 0));

        let result = fence.check(mid(99), Some(3));
        match result {
            Err(FenceError::NotInRoster {
                sender_id,
                current_epoch,
            }) => {
                assert_eq!(sender_id, mid(99));
                assert_eq!(current_epoch, EpochId::new(3));
            }
            other => panic!("expected NotInRoster, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_message_from_departed_member() {
        let fence = MembershipEpochFence::new();
        // Member 1 was in epoch 1, removed in epoch 2
        fence.update_from_view(&view(2, &[2, 3], 0));

        let result = fence.check(mid(1), Some(1));
        match result {
            Err(FenceError::NotInRoster { sender_id, .. }) => {
                assert_eq!(sender_id, mid(1));
            }
            other => panic!("expected NotInRoster, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Check: epoch freshness
    // ------------------------------------------------------------------

    #[test]
    fn check_rejects_stale_epoch_from_current_member() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(5, &[1, 2, 3], 0));

        // Current member, but message epoch 3 is stale (current is 5)
        let result = fence.check(mid(2), Some(3));
        match result {
            Err(FenceError::StaleEpoch {
                sender_id,
                message_epoch,
                current_epoch,
            }) => {
                assert_eq!(sender_id, mid(2));
                assert_eq!(message_epoch, 3);
                assert_eq!(current_epoch, EpochId::new(5));
            }
            other => panic!("expected StaleEpoch, got {other:?}"),
        }
    }

    #[test]
    fn check_accepts_message_epoch_equal_to_current() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(5, &[1, 2], 0));

        let result = fence.check(mid(1), Some(5));
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_message_epoch_greater_than_current() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(5, &[1, 2], 0));

        // A message from a future epoch (e.g., the sender advanced ahead)
        let result = fence.check(mid(2), Some(6));
        assert!(result.is_ok());
    }

    // ------------------------------------------------------------------
    // Check: no epoch (roster-only validation)
    // ------------------------------------------------------------------

    #[test]
    fn check_accepts_message_without_epoch_from_current_member() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(3, &[1, 2], 0));

        let result = fence.check(mid(2), None);
        assert!(result.is_ok());
    }

    #[test]
    fn check_rejects_message_without_epoch_from_non_member() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(3, &[1, 2], 0));

        let result = fence.check(mid(99), None);
        assert!(result.is_err());
        assert!(matches!(result, Err(FenceError::NotInRoster { .. })));
    }

    // ------------------------------------------------------------------
    // Check: empty fence rejects all
    // ------------------------------------------------------------------

    #[test]
    fn empty_fence_rejects_all_messages() {
        let fence = MembershipEpochFence::new();

        let result = fence.check(mid(1), Some(0));
        assert!(matches!(result, Err(FenceError::NotInRoster { .. })));
    }

    // ------------------------------------------------------------------
    // Member set snapshot
    // ------------------------------------------------------------------

    #[test]
    fn member_ids_returns_sorted_members() {
        let fence = MembershipEpochFence::new();
        fence.update_from_view(&view(1, &[3, 1, 2], 0));

        let ids = fence.member_ids();
        assert_eq!(ids, vec![mid(1), mid(2), mid(3)]);
    }

    // ------------------------------------------------------------------
    // FenceError Display
    // ------------------------------------------------------------------

    #[test]
    fn fence_error_display_not_in_roster() {
        let e = FenceError::NotInRoster {
            sender_id: mid(42),
            current_epoch: EpochId::new(7),
        };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("not in current roster"));
        assert!(s.contains("7"));
    }

    #[test]
    fn fence_error_display_stale_epoch() {
        let e = FenceError::StaleEpoch {
            sender_id: mid(42),
            message_epoch: 3,
            current_epoch: EpochId::new(7),
        };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("stale"));
        assert!(s.contains("3"));
        assert!(s.contains("7"));
    }

    #[test]
    fn fence_error_is_std_error() {
        let e = FenceError::NotInRoster {
            sender_id: mid(1),
            current_epoch: EpochId::new(0),
        };
        let _: &dyn std::error::Error = &e;
    }
}
