#![forbid(unsafe_code)]

//! Monotonic coordinator incarnation tracker.
//!
//! Every coordinator transition (promotion, lease acquisition, election win)
//! increments the incarnation counter. Inbound membership messages that carry
//! an incarnation lower than the current value are rejected as stale, closing
//! the split-brain window where a partitioned former coordinator could issue
//! stale epoch-advance or departure commands.
//!
//! ## Validation rules
//!
//! - `msg.incarnation < current` → `StaleIncarnation` (reject)
//! - `msg.incarnation >= current` → accept
//! - Increment on coordinator promotion (bump and persist)

use tidefs_membership_types::Incarnation;

/// Error returned when an inbound message carries a stale incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleIncarnation {
    /// The incarnation carried by the rejected message.
    pub msg_incarnation: Incarnation,
    /// The current local incarnation (always > msg_incarnation).
    pub current_incarnation: Incarnation,
}

impl std::fmt::Display for StaleIncarnation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stale incarnation: msg={} current={}",
            self.msg_incarnation, self.current_incarnation
        )
    }
}

impl std::error::Error for StaleIncarnation {}

/// Tracks the current coordinator incarnation and validates inbound messages.
///
/// The incarnation is a monotonically increasing counter. It starts at
/// [`Incarnation::ZERO`] (genesis) and is incremented on each coordinator
/// transition. Persisted alongside epoch snapshots so restarted coordinators
/// resume at the correct value.
#[derive(Clone, Debug, Default)]
pub struct IncarnationTracker {
    current: Incarnation,
}

impl IncarnationTracker {
    /// Create a new tracker at the given incarnation.
    #[must_use]
    pub fn new(start: Incarnation) -> Self {
        Self { current: start }
    }

    /// Create a new tracker starting at genesis (zero).
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            current: Incarnation::ZERO,
        }
    }

    /// Create a tracker from a snapshot-persisted incarnation value.
    #[must_use]
    pub fn with_incarnation(value: Incarnation) -> Self {
        Self { current: value }
    }

    /// Return the current incarnation.
    #[must_use]
    pub fn current(&self) -> Incarnation {
        self.current
    }

    /// Increment the incarnation and return the new value.
    ///
    /// Called on coordinator promotion, lease acquisition, or election win.
    pub fn increment(&mut self) -> Incarnation {
        self.current = self.current.next();
        self.current
    }

    /// Bump and return the next incarnation without mutating state.
    ///
    /// Useful for computing the incarnation that will be used after promotion
    /// before committing to it.
    #[must_use]
    pub fn peek_next(&self) -> Incarnation {
        self.current.next()
    }

    /// Validate an inbound message incarnation against the current value.
    ///
    /// # Errors
    ///
    /// Returns [`StaleIncarnation`] if `msg_incarnation < self.current`.
    pub fn validate(&self, msg_incarnation: Incarnation) -> Result<(), StaleIncarnation> {
        if msg_incarnation < self.current {
            return Err(StaleIncarnation {
                msg_incarnation,
                current_incarnation: self.current,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── construction ────────────────────────────────────────────────

    #[test]
    fn genesis_starts_at_zero() {
        let tracker = IncarnationTracker::genesis();
        assert_eq!(tracker.current(), Incarnation::ZERO);
    }

    #[test]
    fn new_starts_at_given_value() {
        let tracker = IncarnationTracker::new(Incarnation(5));
        assert_eq!(tracker.current(), Incarnation(5));
    }

    #[test]
    fn with_incarnation_is_construction_alias() {
        let t1 = IncarnationTracker::new(Incarnation(3));
        let t2 = IncarnationTracker::with_incarnation(Incarnation(3));
        assert_eq!(t1.current(), t2.current());
    }

    // ── increment ───────────────────────────────────────────────────

    #[test]
    fn increment_bumps_by_one() {
        let mut tracker = IncarnationTracker::genesis();
        assert_eq!(tracker.current(), Incarnation(0));

        let new = tracker.increment();
        assert_eq!(new, Incarnation(1));
        assert_eq!(tracker.current(), Incarnation(1));

        let new = tracker.increment();
        assert_eq!(new, Incarnation(2));
        assert_eq!(tracker.current(), Incarnation(2));
    }

    #[test]
    fn increment_monotonic() {
        let mut tracker = IncarnationTracker::new(Incarnation(100));
        for i in 101..=110 {
            assert_eq!(tracker.increment(), Incarnation(i));
        }
    }

    #[test]
    fn peek_next_does_not_mutate() {
        let tracker = IncarnationTracker::new(Incarnation(7));
        assert_eq!(tracker.peek_next(), Incarnation(8));
        assert_eq!(tracker.current(), Incarnation(7)); // unchanged
    }

    // ── validate ────────────────────────────────────────────────────

    #[test]
    fn validate_accepts_equal() {
        let tracker = IncarnationTracker::new(Incarnation(3));
        assert!(tracker.validate(Incarnation(3)).is_ok());
    }

    #[test]
    fn validate_accepts_greater() {
        let tracker = IncarnationTracker::new(Incarnation(3));
        assert!(tracker.validate(Incarnation(5)).is_ok());
        assert!(tracker.validate(Incarnation(100)).is_ok());
    }

    #[test]
    fn validate_rejects_lower() {
        let tracker = IncarnationTracker::new(Incarnation(5));
        let result = tracker.validate(Incarnation(3));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.msg_incarnation, Incarnation(3));
        assert_eq!(err.current_incarnation, Incarnation(5));
    }

    #[test]
    fn validate_genesis_accepts_any() {
        let tracker = IncarnationTracker::genesis();
        assert!(tracker.validate(Incarnation(0)).is_ok());
        assert!(tracker.validate(Incarnation(1)).is_ok());
        assert!(tracker.validate(Incarnation(u64::MAX)).is_ok());
    }

    #[test]
    fn stale_incarnation_display() {
        let err = StaleIncarnation {
            msg_incarnation: Incarnation(2),
            current_incarnation: Incarnation(5),
        };
        let s = format!("{err}");
        assert!(s.contains("incarnation.2"));
        assert!(s.contains("incarnation.5"));
        assert!(s.contains("stale"));
    }
}
