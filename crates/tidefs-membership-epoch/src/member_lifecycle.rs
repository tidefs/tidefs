#![forbid(unsafe_code)]

//! Peer lifecycle state machine with monotonic transition enforcement.
//!
//! [`MemberLifecycle`] is the single authority for per-peer state tracking
//! across the membership subsystem. Each state transition is validated
//! against a legal transition table; illegal moves are rejected with
//! a [`TransitionError`]. Idempotent same-state transitions are no-ops.
//!
//! ## State Diagram
//!
//! ```text
//!                          ┌──────────┐
//!                          │  Unknown │
//!                          └────┬─────┘
//!                               │ join
//!                               ▼
//!                          ┌──────────┐
//!                   ┌──────│ Joining  │──────┐
//!                   │      └────┬─────┘      │
//!                   │ failback   │ accept     │
//!                   ▼           ▼            │
//!              ┌──────────┐ ┌──────────┐     │
//!              │  Unknown │ │  Active  │     │
//!              └──────────┘ └──┬───┬───┘     │
//!                              │   │         │
//!                    leave ┌───┘   └──┐ evict│
//!                           ▼          ▼     │
//!                    ┌──────────┐ ┌──────────┐│
//!              ┌─────│ Leaving  │ │ Evicted  ││
//!              │     └────┬─────┘ └────┬─────┘│
//!              │ depart   │ depart     │      │
//!              │          ▼            ▼      │
//!              │     ┌──────────────────────┐ │
//!              └────►│      Departed        │◄┘
//!                    └──────────────────────┘
//! ```
//!
//! ## Transition Table
//!
//! | From      | To        | Result        |
//! |-----------|-----------|---------------|
//! | Unknown   | Joining   | Ok(Joining)   |
//! | Joining   | Active    | Ok(Active)    |
//! | Joining   | Unknown   | Ok(Unknown)   |
//! | Active    | Leaving   | Ok(Leaving)   |
//! | Active    | Evicted   | Ok(Evicted)   |
//! | Leaving   | Departed  | Ok(Departed)  |
//! | Leaving   | Active    | Ok(Active)    |
//! | Evicted   | Departed  | Ok(Departed)  |
//! | Departed  | *         | Err           |
//! | *         | * (same)  | Ok(same)      |
//! | *         | * (other) | Err           |
//!
//! ## Integration
//!
//! Callers in membership-live (join initiator, departure coordinator,
//! eviction tracker) wrap their state management through
//! [`MemberLifecycle::transition`] to ensure monotonic enforcement
//! without requiring each path to duplicate the validation logic.

use std::fmt;

// ── MemberState ──────────────────────────────────────────────────────

/// The discrete states a peer can occupy in the membership lifecycle.
///
/// States are ordered so that, with the exception of bootstrap fallback
/// (`Joining → Unknown`), the lifecycle progresses forward through
/// monotonically increasing stages. [`Departed`] is terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MemberState {
    /// Initial state: peer has never been observed or is not tracked.
    Unknown,
    /// Peer is in the process of joining the cluster.
    Joining,
    /// Peer is a fully participating member of the cluster.
    Active,
    /// Peer is voluntarily leaving the cluster.
    Leaving,
    /// Peer has been evicted by the coordinator (health failure, etc.).
    Evicted,
    /// Terminal state: peer has departed the cluster and cannot re-enter
    /// this lifecycle.
    Departed,
}

impl fmt::Display for MemberState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Joining => write!(f, "Joining"),
            Self::Active => write!(f, "Active"),
            Self::Leaving => write!(f, "Leaving"),
            Self::Evicted => write!(f, "Evicted"),
            Self::Departed => write!(f, "Departed"),
        }
    }
}

impl MemberState {
    /// Return `true` if this state is terminal (no further transitions
    /// are legal).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Departed)
    }

    /// Return `true` if the peer in this state is currently a
    /// participating cluster member.
    #[must_use]
    pub fn is_active_member(self) -> bool {
        matches!(self, Self::Active)
    }
}

// ── TransitionError ──────────────────────────────────────────────────

/// Error returned when a lifecycle transition is illegal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionError {
    /// The state the peer was in before the attempted transition.
    pub from: MemberState,
    /// The state the caller attempted to transition to.
    pub to: MemberState,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal lifecycle transition: {} → {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

// ── MemberLifecycle ──────────────────────────────────────────────────

/// Per-peer lifecycle tracker enforcing monotonic state transitions.
///
/// Wraps the current [`MemberState`] and exposes [`transition`] as the
/// sole mutation point. Every attempted move is checked against the
/// legal transition table; illegal moves return [`TransitionError`].
/// Same-state transitions are idempotent and return the current state.
///
/// [`transition`]: MemberLifecycle::transition
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberLifecycle {
    state: MemberState,
}

impl Default for MemberLifecycle {
    fn default() -> Self {
        Self {
            state: MemberState::Unknown,
        }
    }
}

impl MemberLifecycle {
    /// Create a new lifecycle tracker starting at `Unknown`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a lifecycle tracker at a specific starting state.
    ///
    /// Useful when replaying persisted state or when a peer is
    /// observed mid-lifecycle.
    #[must_use]
    pub fn with_state(state: MemberState) -> Self {
        Self { state }
    }

    /// Return the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> MemberState {
        self.state
    }

    /// Attempt to transition the peer to `new_state`.
    ///
    /// # Returns
    ///
    /// * `Ok(MemberState)` — the new state if the transition is legal.
    ///   For same-state transitions, returns the current state
    ///   unchanged.
    /// * `Err(TransitionError)` — the transition is not allowed.
    ///
    /// Legal transitions:
    ///
    /// * `Unknown → Joining`
    /// * `Joining → Active | Unknown`
    /// * `Active → Leaving | Evicted`
    /// * `Leaving → Departed | Active`
    /// * `Evicted → Departed`
    /// * `Departed →` (terminal: all transitions rejected)
    pub fn transition(&mut self, new_state: MemberState) -> Result<MemberState, TransitionError> {
        // Same-state transitions are idempotent no-ops.
        if self.state == new_state {
            return Ok(self.state);
        }

        // Departed is terminal.
        if self.state.is_terminal() {
            return Err(TransitionError {
                from: self.state,
                to: new_state,
            });
        }

        // Validate against the legal transition table.
        let legal = is_legal_transition(self.state, new_state);
        if !legal {
            return Err(TransitionError {
                from: self.state,
                to: new_state,
            });
        }

        self.state = new_state;
        Ok(new_state)
    }
}

// ── Transition Table ─────────────────────────────────────────────────

/// Return `true` if `from → to` is a legal lifecycle transition.
///
/// Same-state transitions are handled by the caller ([`MemberLifecycle::transition`])
/// and are not checked here.
const fn is_legal_transition(from: MemberState, to: MemberState) -> bool {
    matches!(
        (from, to),
        (MemberState::Unknown, MemberState::Joining)
            | (MemberState::Joining, MemberState::Active)
            | (MemberState::Joining, MemberState::Unknown)
            | (MemberState::Active, MemberState::Leaving)
            | (MemberState::Active, MemberState::Evicted)
            | (MemberState::Leaving, MemberState::Departed)
            | (MemberState::Leaving, MemberState::Active)
            | (MemberState::Evicted, MemberState::Departed)
    )
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ─────────────────────────────────────────────────

    #[test]
    fn new_starts_at_unknown() {
        let lc = MemberLifecycle::new();
        assert_eq!(lc.state(), MemberState::Unknown);
    }

    #[test]
    fn default_starts_at_unknown() {
        let lc = MemberLifecycle::default();
        assert_eq!(lc.state(), MemberState::Unknown);
    }

    #[test]
    fn with_state_starts_at_given() {
        let lc = MemberLifecycle::with_state(MemberState::Active);
        assert_eq!(lc.state(), MemberState::Active);
    }

    #[test]
    fn with_state_any_non_terminal() {
        for s in &[
            MemberState::Unknown,
            MemberState::Joining,
            MemberState::Active,
            MemberState::Leaving,
            MemberState::Evicted,
        ] {
            let lc = MemberLifecycle::with_state(*s);
            assert_eq!(lc.state(), *s);
        }
    }

    // ── Individual Legal Transitions ─────────────────────────────────

    #[test]
    fn unknown_to_joining() {
        let mut lc = MemberLifecycle::new();
        let result = lc.transition(MemberState::Joining);
        assert_eq!(result, Ok(MemberState::Joining));
        assert_eq!(lc.state(), MemberState::Joining);
    }

    #[test]
    fn joining_to_active() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        let result = lc.transition(MemberState::Active);
        assert_eq!(result, Ok(MemberState::Active));
        assert_eq!(lc.state(), MemberState::Active);
    }

    #[test]
    fn joining_to_unknown_fallback() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        let result = lc.transition(MemberState::Unknown);
        assert_eq!(result, Ok(MemberState::Unknown));
        assert_eq!(lc.state(), MemberState::Unknown);
    }

    #[test]
    fn active_to_leaving() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        let result = lc.transition(MemberState::Leaving);
        assert_eq!(result, Ok(MemberState::Leaving));
        assert_eq!(lc.state(), MemberState::Leaving);
    }

    #[test]
    fn active_to_evicted() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        let result = lc.transition(MemberState::Evicted);
        assert_eq!(result, Ok(MemberState::Evicted));
        assert_eq!(lc.state(), MemberState::Evicted);
    }

    #[test]
    fn leaving_to_departed() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        let result = lc.transition(MemberState::Departed);
        assert_eq!(result, Ok(MemberState::Departed));
        assert_eq!(lc.state(), MemberState::Departed);
    }

    #[test]
    fn leaving_to_active_abort() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        let result = lc.transition(MemberState::Active);
        assert_eq!(result, Ok(MemberState::Active));
        assert_eq!(lc.state(), MemberState::Active);
    }

    #[test]
    fn evicted_to_departed() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        let result = lc.transition(MemberState::Departed);
        assert_eq!(result, Ok(MemberState::Departed));
        assert_eq!(lc.state(), MemberState::Departed);
    }

    // ── Idempotent Same-State Transitions ────────────────────────────

    #[test]
    fn same_state_unknown_noop() {
        let mut lc = MemberLifecycle::new();
        let result = lc.transition(MemberState::Unknown);
        assert_eq!(result, Ok(MemberState::Unknown));
        assert_eq!(lc.state(), MemberState::Unknown);
    }

    #[test]
    fn same_state_joining_noop() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        let result = lc.transition(MemberState::Joining);
        assert_eq!(result, Ok(MemberState::Joining));
        assert_eq!(lc.state(), MemberState::Joining);
    }

    #[test]
    fn same_state_active_noop() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        let result = lc.transition(MemberState::Active);
        assert_eq!(result, Ok(MemberState::Active));
    }

    #[test]
    fn same_state_leaving_noop() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        let result = lc.transition(MemberState::Leaving);
        assert_eq!(result, Ok(MemberState::Leaving));
    }

    #[test]
    fn same_state_evicted_noop() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        let result = lc.transition(MemberState::Evicted);
        assert_eq!(result, Ok(MemberState::Evicted));
    }

    #[test]
    fn same_state_departed_noop() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        let result = lc.transition(MemberState::Departed);
        assert_eq!(result, Ok(MemberState::Departed));
    }

    // ── Illegal Transitions ──────────────────────────────────────────

    #[test]
    fn unknown_to_active_illegal() {
        let mut lc = MemberLifecycle::new();
        let result = lc.transition(MemberState::Active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.from, MemberState::Unknown);
        assert_eq!(err.to, MemberState::Active);
        // state unchanged
        assert_eq!(lc.state(), MemberState::Unknown);
    }

    #[test]
    fn unknown_to_leaving_illegal() {
        let mut lc = MemberLifecycle::new();
        assert!(lc.transition(MemberState::Leaving).is_err());
    }

    #[test]
    fn unknown_to_evicted_illegal() {
        let mut lc = MemberLifecycle::new();
        assert!(lc.transition(MemberState::Evicted).is_err());
    }

    #[test]
    fn unknown_to_departed_illegal() {
        let mut lc = MemberLifecycle::new();
        assert!(lc.transition(MemberState::Departed).is_err());
    }

    #[test]
    fn joining_to_leaving_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        assert!(lc.transition(MemberState::Leaving).is_err());
    }

    #[test]
    fn joining_to_evicted_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        assert!(lc.transition(MemberState::Evicted).is_err());
    }

    #[test]
    fn joining_to_departed_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Joining);
        assert!(lc.transition(MemberState::Departed).is_err());
    }

    #[test]
    fn active_to_unknown_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn active_to_joining_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        assert!(lc.transition(MemberState::Joining).is_err());
    }

    #[test]
    fn active_to_departed_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        assert!(lc.transition(MemberState::Departed).is_err());
    }

    #[test]
    fn leaving_to_unknown_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn leaving_to_joining_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        assert!(lc.transition(MemberState::Joining).is_err());
    }

    #[test]
    fn leaving_to_evicted_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Leaving);
        assert!(lc.transition(MemberState::Evicted).is_err());
    }

    #[test]
    fn evicted_to_unknown_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn evicted_to_joining_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        assert!(lc.transition(MemberState::Joining).is_err());
    }

    #[test]
    fn evicted_to_active_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        assert!(lc.transition(MemberState::Active).is_err());
    }

    #[test]
    fn evicted_to_leaving_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Evicted);
        assert!(lc.transition(MemberState::Leaving).is_err());
    }

    // ── Departed is Terminal ─────────────────────────────────────────

    #[test]
    fn departed_to_unknown_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn departed_to_joining_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        assert!(lc.transition(MemberState::Joining).is_err());
    }

    #[test]
    fn departed_to_active_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        assert!(lc.transition(MemberState::Active).is_err());
    }

    #[test]
    fn departed_to_leaving_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        assert!(lc.transition(MemberState::Leaving).is_err());
    }

    #[test]
    fn departed_to_evicted_illegal() {
        let mut lc = MemberLifecycle::with_state(MemberState::Departed);
        assert!(lc.transition(MemberState::Evicted).is_err());
    }

    // ── Bulk Scenario Tests ──────────────────────────────────────────

    #[test]
    fn full_lifecycle_join_leave_depart() {
        let mut lc = MemberLifecycle::new();
        assert_eq!(lc.state(), MemberState::Unknown);

        // Unknown → Joining
        assert_eq!(
            lc.transition(MemberState::Joining),
            Ok(MemberState::Joining)
        );

        // Joining → Active
        assert_eq!(lc.transition(MemberState::Active), Ok(MemberState::Active));

        // Active → Leaving
        assert_eq!(
            lc.transition(MemberState::Leaving),
            Ok(MemberState::Leaving)
        );

        // Leaving → Departed
        assert_eq!(
            lc.transition(MemberState::Departed),
            Ok(MemberState::Departed)
        );

        // Departed is terminal
        assert!(lc.transition(MemberState::Active).is_err());
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn join_failure_rollback() {
        let mut lc = MemberLifecycle::new();
        assert_eq!(lc.state(), MemberState::Unknown);

        // Unknown → Joining
        assert_eq!(
            lc.transition(MemberState::Joining),
            Ok(MemberState::Joining)
        );

        // Joining → Unknown (bootstrap failure fallback)
        assert_eq!(
            lc.transition(MemberState::Unknown),
            Ok(MemberState::Unknown)
        );

        // Can retry join
        assert_eq!(
            lc.transition(MemberState::Joining),
            Ok(MemberState::Joining)
        );
        assert_eq!(lc.transition(MemberState::Active), Ok(MemberState::Active));
    }

    #[test]
    fn eviction_path() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);

        // Active → Evicted
        assert_eq!(
            lc.transition(MemberState::Evicted),
            Ok(MemberState::Evicted)
        );

        // Evicted → Departed
        assert_eq!(
            lc.transition(MemberState::Departed),
            Ok(MemberState::Departed)
        );

        // Terminal
        assert!(lc.transition(MemberState::Unknown).is_err());
    }

    #[test]
    fn leave_abort_fallback() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);

        // Active → Leaving
        assert_eq!(
            lc.transition(MemberState::Leaving),
            Ok(MemberState::Leaving)
        );

        // Leaving → Active (abort departure)
        assert_eq!(lc.transition(MemberState::Active), Ok(MemberState::Active));

        // Can now leave again or be evicted
        assert_eq!(
            lc.transition(MemberState::Leaving),
            Ok(MemberState::Leaving)
        );
        assert_eq!(
            lc.transition(MemberState::Departed),
            Ok(MemberState::Departed)
        );
    }

    #[test]
    fn two_join_attempts_after_fallback() {
        let mut lc = MemberLifecycle::new();
        // First attempt fails
        lc.transition(MemberState::Joining).unwrap();
        lc.transition(MemberState::Unknown).unwrap();
        // Second attempt
        lc.transition(MemberState::Joining).unwrap();
        lc.transition(MemberState::Active).unwrap();
        assert_eq!(lc.state(), MemberState::Active);
    }

    #[test]
    fn state_not_mutated_on_illegal_transition() {
        let mut lc = MemberLifecycle::with_state(MemberState::Active);
        let state_before = lc.state();
        let _ = lc.transition(MemberState::Unknown); // illegal
        assert_eq!(lc.state(), state_before, "state should not change on error");
    }

    // ── MemberState Helpers ──────────────────────────────────────────

    #[test]
    fn is_terminal_departed() {
        assert!(!MemberState::Unknown.is_terminal());
        assert!(!MemberState::Joining.is_terminal());
        assert!(!MemberState::Active.is_terminal());
        assert!(!MemberState::Leaving.is_terminal());
        assert!(!MemberState::Evicted.is_terminal());
        assert!(MemberState::Departed.is_terminal());
    }

    #[test]
    fn is_active_member() {
        assert!(!MemberState::Unknown.is_active_member());
        assert!(!MemberState::Joining.is_active_member());
        assert!(MemberState::Active.is_active_member());
        assert!(!MemberState::Leaving.is_active_member());
        assert!(!MemberState::Evicted.is_active_member());
        assert!(!MemberState::Departed.is_active_member());
    }

    #[test]
    fn member_state_display() {
        assert_eq!(format!("{}", MemberState::Unknown), "Unknown");
        assert_eq!(format!("{}", MemberState::Joining), "Joining");
        assert_eq!(format!("{}", MemberState::Active), "Active");
        assert_eq!(format!("{}", MemberState::Leaving), "Leaving");
        assert_eq!(format!("{}", MemberState::Evicted), "Evicted");
        assert_eq!(format!("{}", MemberState::Departed), "Departed");
    }

    // ── TransitionError Display ──────────────────────────────────────

    #[test]
    fn transition_error_display() {
        let err = TransitionError {
            from: MemberState::Active,
            to: MemberState::Joining,
        };
        let s = format!("{err}");
        assert!(s.contains("illegal"));
        assert!(s.contains("Active"));
        assert!(s.contains("Joining"));
    }

    // ── Ordering ─────────────────────────────────────────────────────

    #[test]
    fn member_state_ordering() {
        // States should be ordered by their discriminant.
        assert!(MemberState::Unknown < MemberState::Joining);
        assert!(MemberState::Joining < MemberState::Active);
        assert!(MemberState::Active < MemberState::Leaving);
        assert!(MemberState::Leaving < MemberState::Evicted);
        assert!(MemberState::Evicted < MemberState::Departed);
    }
}
