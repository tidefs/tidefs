//! Cluster lease state machine with grant, revoke, renew, and expiry transitions.
//!
//! Provides the coordination primitive for single-writer arbitration in the
//! deterministic multi-node userspace harness. Each lease tracks a holder,
//! TTL, and wall-clock grant time; `tick()` checks for expiry.
//!
//! # State diagram
//!
//! ```text
//!          grant(holder, ttl)
//! Idle ──────────────────────────> Granted
//!                                     │  │  │
//!                          revoke()   │  │  │ fence()
//!                                     │  │  │
//!                    ┌────────────────┘  │  └──────────────┐
//!                    │                   │                  │
//!                    ▼                   ▼                  ▼
//!                Revoked             Granted            Fenced
//!               (terminal)       (updated TTL)       (terminal)
//!
//!          tick() on expiry
//! Granted ─────────────────────────> Expired
//!                                     (terminal)
//! ```

use std::time::{Duration, Instant};
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// LeaseHolder
// ---------------------------------------------------------------------------

/// Identifies the holder of a lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseHolder {
    pub member_id: MemberId,
}

impl LeaseHolder {
    pub fn new(member_id: MemberId) -> Self {
        Self { member_id }
    }
}

// ---------------------------------------------------------------------------
// LeaseState
// ---------------------------------------------------------------------------

/// The current state of a single lease within an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// No lease held, ready for grant.
    Idle,
    /// Active lease with an expiry deadline.
    Granted {
        holder: LeaseHolder,
        ttl: Duration,
        granted_at: Instant,
    },
    /// Lease forcibly fenced (coordinator failover or epoch advance);
    /// terminal but distinguished from Revoked for re-acquisition semantics.
    Fenced,
    /// Lease forcibly withdrawn; terminal for this epoch.
    Revoked,
    /// TTL exhausted without renewal; terminal for this epoch.
    Expired,
}

impl LeaseState {
    /// Returns true if this state is terminal (Fenced, Revoked, or Expired).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Fenced | Self::Revoked | Self::Expired)
    }
}

// ---------------------------------------------------------------------------
// TransitionError
// ---------------------------------------------------------------------------

/// Errors returned by lease state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// `grant()` called when the machine is not in Idle state.
    NotIdle,
    /// `fence()` called but the machine is not in Granted state.
    NotGrantedForFence,
    /// Operation requires the Granted state but the machine is Idle or Revoked.
    NotGranted,
    /// Operation attempted on an already-expired lease.
    AlreadyExpired,
    /// The supplied holder does not match the current lease holder.
    HolderMismatch,
}

// ---------------------------------------------------------------------------
// LeaseStateMachine
// ---------------------------------------------------------------------------

/// Cluster lease state machine governing lifecycle transitions.
///
/// Manages a single lease through its lifecycle: idle → granted → (renewed |
/// revoked | expired). The machine is deliberately small and deterministic;
/// it is the engine that wire protocol handlers drive.
#[derive(Clone, Debug)]
pub struct LeaseStateMachine {
    state: LeaseState,
}

impl LeaseStateMachine {
    /// Create a new state machine in the Idle state.
    pub fn new() -> Self {
        Self {
            state: LeaseState::Idle,
        }
    }

    /// Return the current lease state.
    pub fn state(&self) -> &LeaseState {
        &self.state
    }

    /// Grant a lease to `holder` with the given `ttl`.
    ///
    /// Transitions Idle → Granted.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::NotIdle`] if the machine is not in Idle.
    pub fn grant(&mut self, holder: LeaseHolder, ttl: Duration) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Idle => {
                self.state = LeaseState::Granted {
                    holder,
                    ttl,
                    granted_at: Instant::now(),
                };
                Ok(())
            }
            _ => Err(TransitionError::NotIdle),
        }
    }

    /// Grant a lease using an explicit `now` instant (for deterministic
    /// testing).
    pub fn grant_at(
        &mut self,
        holder: LeaseHolder,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Idle => {
                self.state = LeaseState::Granted {
                    holder,
                    ttl,
                    granted_at: now,
                };
                Ok(())
            }
            _ => Err(TransitionError::NotIdle),
        }
    }

    /// Revoke the active lease.
    ///
    /// Transitions Granted → Revoked.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::AlreadyExpired`] if the lease is already
    /// Expired, or [`TransitionError::NotGranted`] for Idle or Revoked.
    pub fn revoke(&mut self) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Granted { .. } => {
                self.state = LeaseState::Revoked;
                Ok(())
            }
            LeaseState::Expired => Err(TransitionError::AlreadyExpired),
            _ => Err(TransitionError::NotGranted),
        }
    }

    /// Renew the lease with a new TTL.
    ///
    /// Transitions Granted → Granted with an updated timestamp and TTL.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::HolderMismatch`] if `holder` does not
    /// match the current holder, [`TransitionError::AlreadyExpired`] if the
    /// state is Expired, or [`TransitionError::NotGranted`] for Idle or
    /// Revoked.
    pub fn renew(&mut self, holder: &LeaseHolder, ttl: Duration) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Granted { holder: ref h, .. } => {
                if h != holder {
                    return Err(TransitionError::HolderMismatch);
                }
                self.state = LeaseState::Granted {
                    holder: holder.clone(),
                    ttl,
                    granted_at: Instant::now(),
                };
                Ok(())
            }
            LeaseState::Expired => Err(TransitionError::AlreadyExpired),
            _ => Err(TransitionError::NotGranted),
        }
    }

    /// Renew using an explicit `now` instant (for deterministic testing).
    pub fn renew_at(
        &mut self,
        holder: &LeaseHolder,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Granted { holder: ref h, .. } => {
                if h != holder {
                    return Err(TransitionError::HolderMismatch);
                }
                self.state = LeaseState::Granted {
                    holder: holder.clone(),
                    ttl,
                    granted_at: now,
                };
                Ok(())
            }
            LeaseState::Expired => Err(TransitionError::AlreadyExpired),
            _ => Err(TransitionError::NotGranted),
        }
    }

    /// Fence the active lease (coordinator failover / epoch advance).
    ///
    /// Transitions Granted → Fenced. Unlike `revoke()`, which is an
    /// authoritative withdrawal by the current coordinator, `fence()` is
    /// triggered by epoch advancement or leader failover and signals that
    /// the lease is invalidated but the domain may be re-acquired in a
    /// new epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::AlreadyExpired`] if the lease is already
    /// Expired, or [`TransitionError::NotGrantedForFence`] for Idle, Fenced,
    /// or Revoked.
    pub fn fence(&mut self) -> Result<(), TransitionError> {
        match &self.state {
            LeaseState::Granted { .. } => {
                self.state = LeaseState::Fenced;
                Ok(())
            }
            LeaseState::Expired => Err(TransitionError::AlreadyExpired),
            _ => Err(TransitionError::NotGrantedForFence),
        }
    }

    /// Evaluate TTL expiration.
    ///
    /// If the current state is Granted and the TTL has elapsed relative to
    /// `granted_at`, transitions Granted → Expired. Otherwise a no-op.
    pub fn tick(&mut self) {
        if let LeaseState::Granted {
            ttl, granted_at, ..
        } = self.state
        {
            if granted_at.elapsed() >= ttl {
                self.state = LeaseState::Expired;
            }
        }
    }

    /// Evaluate TTL expiration against an explicit `now` instant.
    pub fn tick_at(&mut self, now: Instant) {
        if let LeaseState::Granted {
            ttl, granted_at, ..
        } = self.state
        {
            let elapsed = now.duration_since(granted_at);
            if elapsed >= ttl {
                self.state = LeaseState::Expired;
            }
        }
    }

    /// Returns `true` iff the machine is in Granted state with an
    /// unexpired TTL.
    pub fn is_active(&self) -> bool {
        match &self.state {
            LeaseState::Granted {
                ttl, granted_at, ..
            } => granted_at.elapsed() < *ttl,
            _ => false,
        }
    }

    /// Returns `true` iff the machine is in Granted state with an
    /// unexpired TTL relative to `now`.
    pub fn is_active_at(&self, now: Instant) -> bool {
        match &self.state {
            LeaseState::Granted {
                ttl, granted_at, ..
            } => now.duration_since(*granted_at) < *ttl,
            _ => false,
        }
    }
}

impl Default for LeaseStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn holder(id: u64) -> LeaseHolder {
        LeaseHolder::new(MemberId::new(id))
    }

    fn origin() -> Instant {
        Instant::now()
    }

    fn after(t: Instant, ms: u64) -> Instant {
        t + Duration::from_millis(ms)
    }

    // ── Valid transitions and post-conditions ─────────────────────────

    #[test]
    fn idle_to_granted() {
        let mut sm = LeaseStateMachine::new();
        let h = holder(1);
        let ttl = Duration::from_millis(100);
        sm.grant(h.clone(), ttl).unwrap();
        assert!(sm.is_active());
        match sm.state() {
            LeaseState::Granted {
                holder: ref h2,
                ttl: t2,
                ..
            } => {
                assert_eq!(h2, &h);
                assert_eq!(*t2, ttl);
            }
            _ => panic!("expected Granted"),
        }
    }

    #[test]
    fn granted_to_revoked() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        assert_eq!(*sm.state(), LeaseState::Revoked);
        assert!(!sm.is_active());
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn granted_to_fenced() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.fence().unwrap();
        assert_eq!(*sm.state(), LeaseState::Fenced);
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn granted_to_expired_via_tick() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(100), t0)
            .unwrap();
        assert!(sm.is_active_at(t0));

        // Just before expiry
        sm.tick_at(after(t0, 99));
        assert!(sm.is_active_at(after(t0, 99)));
        assert!(matches!(sm.state(), LeaseState::Granted { .. }));

        // At or after expiry
        sm.tick_at(after(t0, 100));
        assert_eq!(*sm.state(), LeaseState::Expired);
        assert!(!sm.is_active_at(after(t0, 100)));
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn granted_to_renewed() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        let h = holder(1);
        sm.grant_at(h.clone(), Duration::from_millis(100), t0)
            .unwrap();

        // Renew at 50ms with a fresh 200ms TTL
        let t1 = after(t0, 50);
        sm.renew_at(&h, Duration::from_millis(200), t1).unwrap();
        assert!(sm.is_active_at(t1));

        match sm.state() {
            LeaseState::Granted {
                holder: ref h2,
                ttl,
                granted_at,
            } => {
                assert_eq!(h2, &h);
                assert_eq!(*ttl, Duration::from_millis(200));
                assert_eq!(*granted_at, t1);
            }
            _ => panic!("expected Granted"),
        }
    }

    // ── Invalid transitions ───────────────────────────────────────────

    #[test]
    fn grant_when_granted_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        let err = sm.grant(holder(2), Duration::from_millis(200)).unwrap_err();
        assert_eq!(err, TransitionError::NotIdle);
    }

    #[test]
    fn grant_when_revoked_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        let err = sm.grant(holder(2), Duration::from_millis(200)).unwrap_err();
        assert_eq!(err, TransitionError::NotIdle);
    }

    #[test]
    fn grant_when_fenced_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.fence().unwrap();
        let err = sm.grant(holder(2), Duration::from_millis(200)).unwrap_err();
        assert_eq!(err, TransitionError::NotIdle);
    }

    #[test]
    fn grant_when_expired_fails() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(100), t0)
            .unwrap();
        sm.tick_at(after(t0, 100));
        let err = sm
            .grant_at(holder(2), Duration::from_millis(200), after(t0, 200))
            .unwrap_err();
        assert_eq!(err, TransitionError::NotIdle);
    }

    #[test]
    fn revoke_when_idle_fails() {
        let mut sm = LeaseStateMachine::new();
        let err = sm.revoke().unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn revoke_when_revoked_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        let err = sm.revoke().unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn revoke_when_expired_fails() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(100), t0)
            .unwrap();
        sm.tick_at(after(t0, 100));
        let err = sm.revoke().unwrap_err();
        assert_eq!(err, TransitionError::AlreadyExpired);
    }

    #[test]
    fn revoke_when_fenced_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.fence().unwrap();
        let err = sm.revoke().unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn renew_when_idle_fails() {
        let mut sm = LeaseStateMachine::new();
        let err = sm
            .renew(&holder(1), Duration::from_millis(100))
            .unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn renew_when_revoked_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        let err = sm
            .renew(&holder(1), Duration::from_millis(100))
            .unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn renew_when_fenced_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.fence().unwrap();
        let err = sm
            .renew(&holder(1), Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(err, TransitionError::NotGranted);
    }

    #[test]
    fn renew_when_expired_fails() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(100), t0)
            .unwrap();
        sm.tick_at(after(t0, 100));
        let err = sm
            .renew_at(&holder(1), Duration::from_millis(200), after(t0, 200))
            .unwrap_err();
        assert_eq!(err, TransitionError::AlreadyExpired);
    }

    #[test]
    fn renew_with_wrong_holder_fails() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        let err = sm
            .renew(&holder(2), Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(err, TransitionError::HolderMismatch);
    }

    // ── TTL boundary tests ────────────────────────────────────────────

    #[test]
    fn ttl_boundary_exactly_at_deadline() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_nanos(1), t0).unwrap();

        // Exactly at deadline — elapsed >= ttl
        let t1 = t0 + Duration::from_nanos(1);
        sm.tick_at(t1);
        assert_eq!(*sm.state(), LeaseState::Expired);
    }

    #[test]
    fn ttl_boundary_one_ns_before() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_nanos(10), t0)
            .unwrap();

        let t1 = t0 + Duration::from_nanos(9);
        sm.tick_at(t1);
        assert!(matches!(sm.state(), LeaseState::Granted { .. }));
        assert!(sm.is_active_at(t1));
    }

    #[test]
    fn ttl_boundary_one_ns_after() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_nanos(10), t0)
            .unwrap();

        let t1 = t0 + Duration::from_nanos(10);
        sm.tick_at(t1);
        assert_eq!(*sm.state(), LeaseState::Expired);
    }

    // ── Rapid grant-revoke-grant cycle ────────────────────────────────

    #[test]
    fn grant_revoke_grant_with_fresh_machine() {
        // Verify that a new machine can go Idle→Granted→Revoked and a
        // *sibling* machine can start fresh Idle→Granted (simulating a
        // new epoch).
        let t0 = origin();
        let mut sm_a = LeaseStateMachine::new();
        sm_a.grant_at(holder(1), Duration::from_millis(50), t0)
            .unwrap();
        sm_a.revoke().unwrap();
        assert_eq!(*sm_a.state(), LeaseState::Revoked);

        let mut sm_b = LeaseStateMachine::new();
        let h2 = holder(2);
        sm_b.grant_at(h2.clone(), Duration::from_millis(50), after(t0, 20))
            .unwrap();
        assert!(sm_b.is_active_at(after(t0, 20)));
        match sm_b.state() {
            LeaseState::Granted { holder: ref h, .. } => assert_eq!(h, &h2),
            _ => panic!("expected Granted"),
        }
    }

    // ── Fence-then-new-machine test ──────────────────────────────────

    #[test]
    fn fence_then_new_machine_can_grant() {
        // After fencing (coordinator failover), a *new* machine should be
        // able to grant a fresh lease (new epoch semantics).
        let t0 = origin();
        let mut sm_a = LeaseStateMachine::new();
        sm_a.grant_at(holder(1), Duration::from_millis(50), t0)
            .unwrap();
        sm_a.fence().unwrap();
        assert_eq!(*sm_a.state(), LeaseState::Fenced);

        let mut sm_b = LeaseStateMachine::new();
        sm_b.grant(holder(2), Duration::from_millis(100)).unwrap();
        assert!(sm_b.is_active());
    }

    // ── Renew extends deadline correctly ──────────────────────────────

    #[test]
    fn renew_extends_deadline() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        let h = holder(1);
        sm.grant_at(h.clone(), Duration::from_millis(100), t0)
            .unwrap();

        // At t=80ms, renew with 200ms TTL → active until t=280ms
        let t1 = after(t0, 80);
        sm.renew_at(&h, Duration::from_millis(200), t1).unwrap();

        // Still active at t=279ms
        assert!(sm.is_active_at(after(t0, 279)));
        sm.tick_at(after(t0, 279));
        assert!(matches!(sm.state(), LeaseState::Granted { .. }));

        // Expired at t=280ms
        sm.tick_at(after(t0, 280));
        assert_eq!(*sm.state(), LeaseState::Expired);
    }

    #[test]
    fn double_renew_is_idempotent() {
        // Calling renew twice with the same holder should succeed both times
        // and produce the same result (latest TTL / grant time wins).
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        let h = holder(1);
        sm.grant_at(h.clone(), Duration::from_millis(100), t0)
            .unwrap();

        let t1 = after(t0, 30);
        sm.renew_at(&h, Duration::from_millis(200), t1).unwrap();

        let t2 = after(t0, 60);
        sm.renew_at(&h, Duration::from_millis(200), t2).unwrap();

        match sm.state() {
            LeaseState::Granted {
                granted_at, ttl, ..
            } => {
                assert_eq!(*granted_at, t2);
                assert_eq!(*ttl, Duration::from_millis(200));
            }
            _ => panic!("expected Granted"),
        }
    }

    // ── tick() no-op on non-Granted states ────────────────────────────

    #[test]
    fn tick_noop_on_idle() {
        let mut sm = LeaseStateMachine::new();
        sm.tick();
        assert_eq!(*sm.state(), LeaseState::Idle);
    }

    #[test]
    fn tick_noop_on_fenced() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(10)).unwrap();
        sm.fence().unwrap();
        sm.tick();
        assert_eq!(*sm.state(), LeaseState::Fenced);
    }

    #[test]
    fn tick_noop_on_revoked() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        sm.tick();
        assert_eq!(*sm.state(), LeaseState::Revoked);
    }

    #[test]
    fn tick_noop_on_expired() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(10), t0)
            .unwrap();
        sm.tick_at(after(t0, 10));
        assert_eq!(*sm.state(), LeaseState::Expired);
        // tick again should not change state
        sm.tick_at(after(t0, 100));
        assert_eq!(*sm.state(), LeaseState::Expired);
    }

    // ── is_active checks ──────────────────────────────────────────────

    #[test]
    fn is_active_false_for_idle() {
        let sm = LeaseStateMachine::new();
        assert!(!sm.is_active());
    }

    #[test]
    fn is_active_false_for_fenced() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.fence().unwrap();
        assert!(!sm.is_active());
    }

    #[test]
    fn is_active_false_for_revoked() {
        let mut sm = LeaseStateMachine::new();
        sm.grant(holder(1), Duration::from_millis(100)).unwrap();
        sm.revoke().unwrap();
        assert!(!sm.is_active());
    }

    #[test]
    fn is_active_false_for_expired() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(10), t0)
            .unwrap();
        sm.tick_at(after(t0, 10));
        assert!(!sm.is_active_at(after(t0, 10)));
    }

    #[test]
    fn is_active_true_when_ttl_not_exhausted() {
        let t0 = origin();
        let mut sm = LeaseStateMachine::new();
        sm.grant_at(holder(1), Duration::from_millis(100), t0)
            .unwrap();
        assert!(sm.is_active_at(after(t0, 50)));
        // tick does not expire yet
        sm.tick_at(after(t0, 50));
        assert!(sm.is_active_at(after(t0, 50)));
    }

    // ── Determinism ───────────────────────────────────────────────────

    #[test]
    fn state_machine_determinism_same_input_same_output() {
        // Two machines starting from the same initial state receiving the
        // same input sequence must produce identical outputs.
        let t0 = origin();
        let run = |t0: Instant| -> (LeaseState, bool, LeaseState, bool) {
            let mut sm = LeaseStateMachine::new();
            let h = holder(1);
            sm.grant_at(h.clone(), Duration::from_millis(100), t0)
                .unwrap();
            let s0 = sm.state().clone();
            let a0 = sm.is_active_at(t0);

            sm.tick_at(after(t0, 50));
            sm.renew_at(&h, Duration::from_millis(200), after(t0, 60))
                .unwrap();

            sm.tick_at(after(t0, 250));
            let s2 = sm.state().clone();
            let a2 = sm.is_active_at(after(t0, 250));

            (s0, a0, s2, a2)
        };

        let (s0_a, a0_a, s2_a, a2_a) = run(t0);
        let (s0_b, a0_b, s2_b, a2_b) = run(t0);

        assert_eq!(s0_a, s0_b);
        assert_eq!(a0_a, a0_b);
        assert_eq!(s2_a, s2_b);
        assert_eq!(a2_a, a2_b);
    }

    // ── LeaseHolder equality and clone ────────────────────────────────

    #[test]
    fn lease_holder_equality() {
        let a = holder(1);
        let b = holder(1);
        let c = holder(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn lease_holder_clone() {
        let h = holder(42);
        let h2 = h.clone();
        assert_eq!(h, h2);
    }

    // ── Default impl ──────────────────────────────────────────────────

    #[test]
    fn default_is_idle() {
        let sm = LeaseStateMachine::default();
        assert_eq!(*sm.state(), LeaseState::Idle);
        assert!(!sm.is_active());
    }

    // ── LeaseState::is_terminal ───────────────────────────────────────

    #[test]
    fn lease_state_is_terminal() {
        assert!(!LeaseState::Idle.is_terminal());
        assert!(!LeaseState::Granted {
            holder: holder(1),
            ttl: Duration::from_millis(100),
            granted_at: origin(),
        }
        .is_terminal());
        assert!(LeaseState::Fenced.is_terminal());
        assert!(LeaseState::Revoked.is_terminal());
        assert!(LeaseState::Expired.is_terminal());
    }
}
