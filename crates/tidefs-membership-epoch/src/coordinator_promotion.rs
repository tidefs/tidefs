#![forbid(unsafe_code)]

//! Deterministic coordinator promotion using `MemberId` sort order.
//!
//! The coordinator is the member with the lowest `MemberId` in the roster.
//! When the current coordinator departs, the next-lowest `MemberId` becomes
//! the new coordinator. This module integrates with [`crate::leave_coordinator::LeaveCoordinator`]
//! so that accepted coordinator departures automatically compute a successor
//! and include a [`CoordinatorChanged`] payload in the leave result.

use crate::MemberId;

// ---------------------------------------------------------------------------
// CoordinatorChanged
// ---------------------------------------------------------------------------

/// Result of a coordinator promotion: old and new coordinator identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorChanged {
    /// The departing coordinator.
    pub old: MemberId,
    /// The successor coordinator.
    pub new: MemberId,
}

// ---------------------------------------------------------------------------
// CoordinatorPromotion
// ---------------------------------------------------------------------------

/// Stateless coordinator promotion logic.
///
/// Determines the current coordinator as the member with the minimum
/// `MemberId` in the roster, and computes the successor when the
/// current coordinator departs.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoordinatorPromotion;

impl CoordinatorPromotion {
    /// Returns the current coordinator: the member with the lowest `MemberId`.
    ///
    /// Returns `None` when the roster is empty.
    #[must_use]
    pub fn current_coordinator(roster: &[MemberId]) -> Option<MemberId> {
        roster.iter().min().copied()
    }

    /// If `departed` is the current coordinator, returns the successor.
    ///
    /// Returns `None` when:
    /// - The roster is empty.
    /// - `departed` is not the current coordinator.
    /// - No successor exists (last member departing; roster would be empty).
    #[must_use]
    pub fn promote_on_departure(
        roster: &[MemberId],
        departed: MemberId,
    ) -> Option<CoordinatorChanged> {
        let current = Self::current_coordinator(roster)?;
        if current != departed {
            return None;
        }
        let successor = roster.iter().filter(|&&m| m != departed).min().copied()?;
        Some(CoordinatorChanged {
            old: current,
            new: successor,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // ── current_coordinator ──────────────────────────────────────────

    #[test]
    fn current_coordinator_single_member() {
        let roster = &[member(5)];
        assert_eq!(
            CoordinatorPromotion::current_coordinator(roster),
            Some(member(5))
        );
    }

    #[test]
    fn current_coordinator_lowest_id() {
        let roster = &[member(10), member(3), member(7)];
        assert_eq!(
            CoordinatorPromotion::current_coordinator(roster),
            Some(member(3))
        );
    }

    #[test]
    fn current_coordinator_empty_roster() {
        assert_eq!(CoordinatorPromotion::current_coordinator(&[]), None);
    }

    #[test]
    fn current_coordinator_unsorted_input() {
        // Order doesn't matter — min() finds the lowest.
        let roster = &[member(99), member(1), member(50)];
        assert_eq!(
            CoordinatorPromotion::current_coordinator(roster),
            Some(member(1))
        );
    }

    #[test]
    fn current_coordinator_tie_returns_first_min() {
        // MemberId ordering is by u64 value; identical ids are the same member.
        let roster = &[member(2), member(2)];
        assert_eq!(
            CoordinatorPromotion::current_coordinator(roster),
            Some(member(2))
        );
    }

    // ── promote_on_departure ─────────────────────────────────────────

    #[test]
    fn promote_when_coordinator_departs() {
        let roster = &[member(1), member(2), member(3)]; // coordinator = 1
        let result = CoordinatorPromotion::promote_on_departure(roster, member(1));
        assert!(result.is_some());
        let cc = result.unwrap();
        assert_eq!(cc.old, member(1));
        assert_eq!(cc.new, member(2)); // next lowest after 1
    }

    #[test]
    fn no_promotion_when_non_coordinator_departs() {
        let roster = &[member(1), member(5), member(10)]; // coordinator = 1
        let result = CoordinatorPromotion::promote_on_departure(roster, member(5));
        assert!(result.is_none());
    }

    #[test]
    fn no_promotion_empty_roster() {
        let result = CoordinatorPromotion::promote_on_departure(&[], member(1));
        assert!(result.is_none());
    }

    #[test]
    fn no_promotion_last_member() {
        // Last member can't depart (would be caught by LeaveCoordinator's
        // last-member guard), but the promotion function returns None
        // because no successor exists.
        let roster = &[member(1)];
        let result = CoordinatorPromotion::promote_on_departure(roster, member(1));
        assert!(result.is_none());
    }

    #[test]
    fn promote_skips_departed_member() {
        // Coordinator 2 departs; successors are 5, 7 — next is 5.
        let roster = &[member(2), member(5), member(7)];
        let result = CoordinatorPromotion::promote_on_departure(roster, member(2));
        assert!(result.is_some());
        let cc = result.unwrap();
        assert_eq!(cc.old, member(2));
        assert_eq!(cc.new, member(5));
    }

    #[test]
    fn promote_with_gaps_in_ids() {
        let roster = &[member(3), member(100), member(200)]; // coordinator = 3
        let result = CoordinatorPromotion::promote_on_departure(roster, member(3));
        assert!(result.is_some());
        let cc = result.unwrap();
        assert_eq!(cc.old, member(3));
        assert_eq!(cc.new, member(100));
    }

    #[test]
    fn coordinator_changed_equality() {
        let a = CoordinatorChanged {
            old: member(1),
            new: member(3),
        };
        let b = CoordinatorChanged {
            old: member(1),
            new: member(3),
        };
        assert_eq!(a, b);
        let c = CoordinatorChanged {
            old: member(1),
            new: member(5),
        };
        assert_ne!(a, c);
    }
}
