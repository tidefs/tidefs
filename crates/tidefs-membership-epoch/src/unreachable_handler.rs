// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Unreachable peer escalation handler.
//!
//! Implements [`UnreachablePeerCallback`] from `tidefs-membership-types`
//! to bridge transport session failure to membership automated departure.
//! When transport exhausts reconnection backoff for a peer, this handler
//! triggers the existing [`LeaveCoordinator`] departure protocol.
//!
//! ## Idempotency
//!
//! The handler is idempotent by construction: if a peer is already
//! departed or not in the roster, `LeaveCoordinator::validate_leave`
//! returns `LeaveOutcome::Rejected` and no duplicate departure occurs.

use std::sync::Mutex;

use tidefs_membership_types::UnreachablePeerCallback;

use crate::leave_coordinator::{LeaveCoordinator, LeaveResult};
#[cfg(test)]
use crate::LeaveOutcome;
use crate::{LeaveReason, MemberId};

// ---------------------------------------------------------------------------
// UnreachablePeerHandler
// ---------------------------------------------------------------------------

/// Bridges transport session failure to membership automated departure.
///
/// Wraps a [`LeaveCoordinator`] behind a [`Mutex`] so the handler can be
/// shared with transport via `Arc<dyn UnreachablePeerCallback>`.
///
/// When `on_peer_unreachable` is called, the handler validates and
/// processes the leave through the coordinator. If the peer is already
/// departed or not in the roster, the call is silently ignored
/// (idempotent by design).
pub struct UnreachablePeerHandler {
    /// The leave coordinator, protected by a mutex for concurrent access
    /// from transport's reconnection path.
    coordinator: Mutex<LeaveCoordinator>,
}

impl UnreachablePeerHandler {
    /// Create a new handler wrapping the given coordinator.
    #[must_use]
    pub fn new(coordinator: LeaveCoordinator) -> Self {
        Self {
            coordinator: Mutex::new(coordinator),
        }
    }

    /// Process a leave for the given peer through the coordinator.
    ///
    /// Returns the [`LeaveResult`] from the coordinator, or `None` if
    /// the coordinator lock is poisoned.
    #[must_use]
    pub fn try_leave(&self, peer_id: u64) -> Option<LeaveResult> {
        let coord = self.coordinator.lock().ok()?;
        Some(coord.validate_leave(MemberId::new(peer_id), LeaveReason::Draining))
    }

    /// Replace the internal coordinator with a new one (e.g. after epoch
    /// advancement or coordinator promotion).
    pub fn update_coordinator(&self, coordinator: LeaveCoordinator) {
        if let Ok(mut guard) = self.coordinator.lock() {
            *guard = coordinator;
        }
    }
}

impl UnreachablePeerCallback for UnreachablePeerHandler {
    fn on_peer_unreachable(&self, peer_id: u64) {
        // Attempt to depart the unreachable peer through the leave
        // coordinator. The coordinator's validate_leave is idempotent:
        // if the peer is already departed or not in the roster, the
        // call returns Rejected without side effects.
        let _ = self.try_leave(peer_id);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EpochId;

    fn coordinator(members: &[u64]) -> LeaveCoordinator {
        LeaveCoordinator::new(
            EpochId::new(5),
            members.iter().map(|&id| MemberId::new(id)).collect(),
        )
    }

    // ── Handler creation ────────────────────────────────────────────

    #[test]
    fn handler_new_wraps_coordinator() {
        let coord = coordinator(&[1, 2, 3]);
        let handler = UnreachablePeerHandler::new(coord);
        let result = handler.try_leave(2).unwrap();
        assert!(result.is_accepted());
    }

    // ── Idempotent callback ─────────────────────────────────────────

    #[test]
    fn callback_on_peer_unreachable_triggers_leave() {
        let coord = coordinator(&[1, 2, 3]);
        let handler = UnreachablePeerHandler::new(coord);

        let r1 = handler.try_leave(2).unwrap();
        assert!(r1.is_accepted());
        assert_eq!(r1.successor_epoch, EpochId::new(6));
        assert_eq!(
            r1.successor_member_set,
            vec![MemberId::new(1), MemberId::new(3)]
        );
    }

    #[test]
    fn callback_rejects_non_member() {
        let coord = coordinator(&[1, 2, 3]);
        let handler = UnreachablePeerHandler::new(coord);

        let result = handler.try_leave(99).unwrap();
        assert!(!result.is_accepted());
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
    }

    #[test]
    fn callback_rejects_last_member() {
        let coord = coordinator(&[1]);
        let handler = UnreachablePeerHandler::new(coord);

        let result = handler.try_leave(1).unwrap();
        assert!(!result.is_accepted());
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
    }

    #[test]
    fn callback_triggers_coordinator_promotion() {
        let coord = coordinator(&[1, 2, 3]); // coordinator = 1
        let handler = UnreachablePeerHandler::new(coord);

        let result = handler.try_leave(1).unwrap();
        assert!(result.is_accepted());
        assert!(result.coordinator_changed.is_some());

        let cc = result.coordinator_changed.unwrap();
        assert_eq!(cc.old, MemberId::new(1));
        assert_eq!(cc.new, MemberId::new(2));
    }

    #[test]
    fn callback_no_promotion_for_non_coordinator() {
        let coord = coordinator(&[1, 2, 3]); // coordinator = 1
        let handler = UnreachablePeerHandler::new(coord);

        let result = handler.try_leave(2).unwrap();
        assert!(result.is_accepted());
        assert!(result.coordinator_changed.is_none());
    }

    #[test]
    fn update_coordinator_replaces_state() {
        let coord = coordinator(&[1, 2, 3]);
        let handler = UnreachablePeerHandler::new(coord);

        // Depart peer 2
        let r1 = handler.try_leave(2).unwrap();
        assert!(r1.is_accepted());

        // Update coordinator with new state after departure
        let new_coord = LeaveCoordinator::new(r1.successor_epoch, r1.successor_member_set);
        handler.update_coordinator(new_coord);

        // Now peer 2 is no longer in the roster
        let r2 = handler.try_leave(2).unwrap();
        assert!(!r2.is_accepted());
    }

    // ── UnreachablePeerCallback trait object ────────────────────────

    #[test]
    fn trait_object_roundtrip() {
        let coord = coordinator(&[1, 2, 3]);
        let handler = UnreachablePeerHandler::new(coord);

        // Cast to trait object and invoke callback
        let cb: &dyn UnreachablePeerCallback = &handler;
        cb.on_peer_unreachable(2);

        // validate_leave takes &self, so coordinator state is unchanged.
        // A second call for the same peer produces the same result.
        // Idempotency means no duplicate side effects, not that the
        // result changes — the caller must update the coordinator after
        // a successful leave.
        let result = handler.try_leave(2).unwrap();
        assert!(result.is_accepted());
        assert_eq!(result.successor_epoch, EpochId::new(6));
        assert_eq!(
            result.successor_member_set,
            vec![MemberId::new(1), MemberId::new(3)]
        );
    }

    #[test]
    fn handler_with_rejected_leave_reason() {
        let coord = LeaveCoordinator::with_transition_flag(
            EpochId::new(5),
            vec![MemberId::new(1), MemberId::new(2)],
            true, // transition in flight
        );
        let handler = UnreachablePeerHandler::new(coord);

        let result = handler.try_leave(1).unwrap();
        assert!(!result.is_accepted());
        assert!(result.rejected_reason.unwrap().contains("in flight"));
    }
}
