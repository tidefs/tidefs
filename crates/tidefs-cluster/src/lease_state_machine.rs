// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic membership lease state machine with BLAKE3-verified state
//! integrity.
//!
//! Each cluster member drives this state machine to manage its membership
//! slot lease. The machine is deliberately small and deterministic: every
//! state transition produces a new BLAKE3-256 digest (domain
//! `tidefs-cluster-membership-lease-v1`) covering the full machine state,
//! enabling peer verification without relying on wall-clock trust.
//!
//! # State diagram
//!
//! ```text
//!                    acquire()
//! Unleased ─────────────────────────> Acquiring
//!    ▲                                     │
//!    │                          grant()    │ timeout() / reject()
//!    │                                     │
//!    │ release()                  ┌────────┘
//!    │                            ▼
//!    │                          Held ──────────────┐
//!    │                            │                 │
//!    │                  renew()   │   expire()      │
//!    │                            ▼                 │
//!    │                         Renewing ────────────┘
//!    │                            │
//!    │                renew_ack() │  renew_nack()
//!    │                            │
//!    │                            ▼
//!    │                          Held
//!    │                            │
//!    │                 release()  │
//!    │                            ▼
//!    └────────────────────── Released
//!
//!                         Expiring ── expire()
//!                             ▲
//!   Held ─────────────────────┘
//!   Renewing ─────────────────┘
//! ```

use blake3::Hasher;
use tidefs_membership_epoch::EpochId;

use crate::types::{LeaseState, LeaseTransitionError, MembershipLease};

/// Domain separation tag for BLAKE3 membership lease state hashing.
const DOMAIN: &str = "tidefs-cluster-membership-lease-v1";

/// The deterministic membership lease state machine.
#[derive(Clone, Debug)]
pub struct LeaseStateMachine {
    node_id: u64,
    state: LeaseState,
    lease: Option<MembershipLease>,
    current_epoch: EpochId,
    state_digest: [u8; 32],
    /// Number of transitions applied since creation.
    transition_count: u64,
}

impl LeaseStateMachine {
    /// Create a new state machine for the given node, initially Unleased.
    pub fn new(node_id: u64, current_epoch: EpochId) -> Self {
        let mut sm = Self {
            node_id,
            state: LeaseState::Unleased,
            lease: None,
            current_epoch,
            state_digest: [0u8; 32],
            transition_count: 0,
        };
        sm.state_digest = sm.compute_digest();
        sm
    }

    /// Return the current lease state.
    pub fn state(&self) -> LeaseState {
        self.state
    }

    /// Return the current lease, if any.
    pub fn lease(&self) -> Option<&MembershipLease> {
        self.lease.as_ref()
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Return the BLAKE3 state digest.
    pub fn state_digest(&self) -> [u8; 32] {
        self.state_digest
    }

    /// Return the transition count.
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    // ── Transitions ────────────────────────────────────────────────

    /// Begin lease acquisition.
    ///
    /// Transitions Unleased → Acquiring.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::AlreadyHolding`] if a lease is held,
    /// [`LeaseTransitionError::AlreadyAcquiring`] if acquisition is already
    /// in progress.
    pub fn acquire(
        &mut self,
        epoch: EpochId,
        lease_term_ms: u64,
        slot: u64,
        lease_id: u64,
        now_ms: u64,
    ) -> Result<(), LeaseTransitionError> {
        self.check_epoch(epoch)?;

        match self.state {
            LeaseState::Unleased | LeaseState::Released => {
                self.lease = Some(MembershipLease::new(
                    self.node_id,
                    epoch,
                    lease_term_ms,
                    slot,
                    lease_id,
                    now_ms,
                ));
                self.state = LeaseState::Acquiring;
                self.bump();
                Ok(())
            }
            LeaseState::Held | LeaseState::Renewing => Err(LeaseTransitionError::AlreadyHolding),
            LeaseState::Acquiring => Err(LeaseTransitionError::AlreadyAcquiring),
            LeaseState::Expiring => {
                // Allow re-acquire from expiring (treat as recovery)
                self.lease = Some(MembershipLease::new(
                    self.node_id,
                    epoch,
                    lease_term_ms,
                    slot,
                    lease_id,
                    now_ms,
                ));
                self.state = LeaseState::Acquiring;
                self.bump();
                Ok(())
            }
        }
    }

    /// Confirm acquisition with a grant, transitioning to Held.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Acquiring state.
    pub fn grant(&mut self) -> Result<(), LeaseTransitionError> {
        if self.state != LeaseState::Acquiring {
            return Err(LeaseTransitionError::NotHeld);
        }
        self.state = LeaseState::Held;
        self.bump();
        Ok(())
    }

    /// Reject an acquisition attempt, returning to Unleased.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Acquiring state.
    pub fn reject(&mut self) -> Result<(), LeaseTransitionError> {
        if self.state != LeaseState::Acquiring {
            return Err(LeaseTransitionError::NotHeld);
        }
        self.lease = None;
        self.state = LeaseState::Unleased;
        self.bump();
        Ok(())
    }

    /// Begin lease renewal.
    ///
    /// Transitions Held → Renewing.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Held state,
    /// [`LeaseTransitionError::AlreadyRenewing`] if already renewing.
    pub fn renew(&mut self, epoch: EpochId, now_ms: u64) -> Result<(), LeaseTransitionError> {
        self.check_epoch(epoch)?;

        match self.state {
            LeaseState::Held => {
                if let Some(ref mut lease) = self.lease {
                    lease.renew(now_ms);
                }
                self.state = LeaseState::Renewing;
                self.bump();
                Ok(())
            }
            LeaseState::Renewing => Err(LeaseTransitionError::AlreadyRenewing),
            _ => Err(LeaseTransitionError::NotHeld),
        }
    }

    /// Confirm renewal, returning to Held.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Renewing state.
    pub fn renew_ack(&mut self) -> Result<(), LeaseTransitionError> {
        if self.state != LeaseState::Renewing {
            return Err(LeaseTransitionError::NotHeld);
        }
        self.state = LeaseState::Held;
        self.bump();
        Ok(())
    }

    /// Renewal was rejected; transition to Expiring.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Renewing state.
    pub fn renew_nack(&mut self) -> Result<(), LeaseTransitionError> {
        if self.state != LeaseState::Renewing {
            return Err(LeaseTransitionError::NotHeld);
        }
        self.state = LeaseState::Expiring;
        self.bump();
        Ok(())
    }

    /// Voluntarily release the lease.
    ///
    /// Transitions Held → Released.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeldForRelease`] if not in a
    /// releasable state (Held, Renewing, or Expiring).
    pub fn release(&mut self) -> Result<(), LeaseTransitionError> {
        match self.state {
            LeaseState::Held | LeaseState::Renewing | LeaseState::Expiring => {
                self.lease = None;
                self.state = LeaseState::Released;
                self.bump();
                Ok(())
            }
            _ => Err(LeaseTransitionError::NotHeldForRelease),
        }
    }

    /// Force expiry of the lease.
    ///
    /// Transitions Held or Renewing → Expiring.
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in a state that can
    /// expire (Held or Renewing).
    pub fn expire(&mut self) -> Result<(), LeaseTransitionError> {
        match self.state {
            LeaseState::Held | LeaseState::Renewing => {
                self.state = LeaseState::Expiring;
                self.bump();
                Ok(())
            }
            _ => Err(LeaseTransitionError::NotHeld),
        }
    }

    /// Transition from Expiring to Released (terminal expiry).
    ///
    /// # Errors
    /// Returns [`LeaseTransitionError::NotHeld`] if not in Expiring state.
    pub fn expire_to_released(&mut self) -> Result<(), LeaseTransitionError> {
        if self.state != LeaseState::Expiring {
            return Err(LeaseTransitionError::NotHeld);
        }
        self.lease = None;
        self.state = LeaseState::Released;
        self.bump();
        Ok(())
    }

    /// Update the current epoch, triggering renegotiation if needed.
    ///
    /// If holding or renewing a lease from an older epoch, transitions to
    /// Expiring.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        if let Some(ref lease) = self.lease {
            if lease.epoch.0 < new_epoch.0
                && matches!(self.state, LeaseState::Held | LeaseState::Renewing)
            {
                self.state = LeaseState::Expiring;
            }
        }
        self.bump();
    }

    /// Tick the state machine: check for deadline-driven expiry.
    ///
    /// If in Held or Renewing state and the lease has expired, transition to
    /// Expiring.
    pub fn tick(&mut self, now_ms: u64) {
        if let Some(ref lease) = self.lease {
            if lease.is_expired_at(now_ms)
                && matches!(self.state, LeaseState::Held | LeaseState::Renewing)
            {
                self.state = LeaseState::Expiring;
                self.bump();
            }
        }
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn check_epoch(&self, epoch: EpochId) -> Result<(), LeaseTransitionError> {
        if epoch != self.current_epoch {
            return Err(LeaseTransitionError::EpochMismatch {
                lease_epoch: epoch,
                current_epoch: self.current_epoch,
            });
        }
        Ok(())
    }

    fn bump(&mut self) {
        self.transition_count += 1;
        self.state_digest = self.compute_digest();
    }

    /// Compute a deterministic BLAKE3-256 digest over the full machine state.
    fn compute_digest(&self) -> [u8; 32] {
        let mut h = Hasher::new_derive_key(DOMAIN);
        h.update(&self.node_id.to_le_bytes());
        h.update(&[self.state as u8]);
        h.update(&self.current_epoch.0.to_le_bytes());
        h.update(&self.transition_count.to_le_bytes());

        // Include lease fields if present
        if let Some(ref lease) = self.lease {
            h.update(&lease.node_id.to_le_bytes());
            h.update(&lease.epoch.0.to_le_bytes());
            h.update(&lease.lease_term_ms.to_le_bytes());
            h.update(&lease.expiration_deadline_ms.to_le_bytes());
            h.update(&lease.slot.to_le_bytes());
            h.update(&lease.lease_id.to_le_bytes());
        } else {
            // Represent absence with zeroed block
            h.update(&[0u8; 48]); // 6 × 8 bytes
        }

        h.finalize().into()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;

    fn epoch(id: u64) -> EpochId {
        EpochId(id)
    }

    #[test]
    fn new_machine_is_unleased() {
        let sm = LeaseStateMachine::new(1, epoch(1));
        assert_eq!(sm.state(), LeaseState::Unleased);
        assert!(sm.lease().is_none());
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn acquire_unleased_to_acquiring() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        assert_eq!(sm.state(), LeaseState::Acquiring);
        assert!(sm.lease().is_some());
        assert_eq!(sm.lease().unwrap().lease_id, 100);
    }

    #[test]
    fn grant_acquiring_to_held() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        assert_eq!(sm.state(), LeaseState::Held);
    }

    #[test]
    fn renew_held_to_renewing() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.renew(epoch(1), 10_000).unwrap();
        assert_eq!(sm.state(), LeaseState::Renewing);
    }

    #[test]
    fn renew_ack_to_held() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.renew(epoch(1), 10_000).unwrap();
        sm.renew_ack().unwrap();
        assert_eq!(sm.state(), LeaseState::Held);
    }

    #[test]
    fn renew_nack_to_expiring() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.renew(epoch(1), 10_000).unwrap();
        sm.renew_nack().unwrap();
        assert_eq!(sm.state(), LeaseState::Expiring);
    }

    #[test]
    fn release_held_to_released() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.release().unwrap();
        assert_eq!(sm.state(), LeaseState::Released);
        assert!(sm.lease().is_none());
    }

    #[test]
    fn expire_held_to_expiring() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.expire().unwrap();
        assert_eq!(sm.state(), LeaseState::Expiring);
    }

    #[test]
    fn expire_to_released_from_expiring() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.expire().unwrap();
        sm.expire_to_released().unwrap();
        assert_eq!(sm.state(), LeaseState::Released);
        assert!(sm.lease().is_none());
    }

    #[test]
    fn duplicate_acquire_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        let err = sm.acquire(epoch(1), 30_000, 0, 101, 0).unwrap_err();
        assert_eq!(err, LeaseTransitionError::AlreadyHolding);
    }

    #[test]
    fn double_acquire_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        let err = sm.acquire(epoch(1), 30_000, 0, 101, 0).unwrap_err();
        assert_eq!(err, LeaseTransitionError::AlreadyAcquiring);
    }

    #[test]
    fn renew_not_held_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        let err = sm.renew(epoch(1), 0).unwrap_err();
        assert_eq!(err, LeaseTransitionError::NotHeld);
    }

    #[test]
    fn grant_not_acquiring_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        let err = sm.grant().unwrap_err();
        assert_eq!(err, LeaseTransitionError::NotHeld);
    }

    #[test]
    fn release_not_held_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        let err = sm.release().unwrap_err();
        assert_eq!(err, LeaseTransitionError::NotHeldForRelease);
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let mut sm = LeaseStateMachine::new(1, epoch(2));
        let err = sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap_err();
        assert_eq!(
            err,
            LeaseTransitionError::EpochMismatch {
                lease_epoch: epoch(1),
                current_epoch: epoch(2),
            }
        );
    }

    #[test]
    fn tick_expires_held_lease() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 1_000, 0, 100, 0).unwrap(); // deadline at 1000
        sm.grant().unwrap();

        // At time 500, not yet expired
        sm.tick(500);
        assert_eq!(sm.state(), LeaseState::Held);

        // At time 1000, expired
        sm.tick(1000);
        assert_eq!(sm.state(), LeaseState::Expiring);
    }

    #[test]
    fn epoch_transition_expires_old_lease() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();

        sm.on_epoch_transition(epoch(2));
        assert_eq!(sm.state(), LeaseState::Expiring);
        assert_eq!(sm.current_epoch(), epoch(2));
    }

    #[test]
    fn reacquire_from_expiring() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 1_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.tick(1000);
        assert_eq!(sm.state(), LeaseState::Expiring);

        // Re-acquire from expiring state
        sm.acquire(epoch(1), 5_000, 0, 200, 2000).unwrap();
        assert_eq!(sm.state(), LeaseState::Acquiring);
        sm.grant().unwrap();
        assert_eq!(sm.state(), LeaseState::Held);
    }

    #[test]
    fn released_to_reacquire() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm.grant().unwrap();
        sm.release().unwrap();
        assert_eq!(sm.state(), LeaseState::Released);

        sm.acquire(epoch(1), 30_000, 1, 101, 0).unwrap();
        assert_eq!(sm.state(), LeaseState::Acquiring);
        sm.grant().unwrap();
        assert_eq!(sm.state(), LeaseState::Held);
    }

    // ── BLAKE3 digest tests ─────────────────────────────────────────

    #[test]
    fn state_digest_is_32_bytes() {
        let sm = LeaseStateMachine::new(1, epoch(1));
        assert_eq!(sm.state_digest().len(), 32);
    }

    #[test]
    fn state_digest_nonzero_after_transition() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        let d0 = sm.state_digest();
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        let d1 = sm.state_digest();
        assert_ne!(d0, d1, "digest must change on transition");
    }

    #[test]
    fn state_digest_deterministic() {
        let mut sm1 = LeaseStateMachine::new(1, epoch(1));
        sm1.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm1.grant().unwrap();

        let mut sm2 = LeaseStateMachine::new(1, epoch(1));
        sm2.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        sm2.grant().unwrap();

        assert_eq!(sm1.state_digest(), sm2.state_digest());
    }

    #[test]
    fn state_digest_differs_by_node_id() {
        let mut sm1 = LeaseStateMachine::new(1, epoch(1));
        sm1.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();

        let mut sm2 = LeaseStateMachine::new(2, epoch(1));
        sm2.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();

        assert_ne!(sm1.state_digest(), sm2.state_digest());
    }

    #[test]
    fn transition_count_increments() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));
        assert_eq!(sm.transition_count(), 0);

        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        assert_eq!(sm.transition_count(), 1);

        sm.grant().unwrap();
        assert_eq!(sm.transition_count(), 2);

        sm.renew(epoch(1), 10_000).unwrap();
        assert_eq!(sm.transition_count(), 3);

        sm.renew_ack().unwrap();
        assert_eq!(sm.transition_count(), 4);

        sm.release().unwrap();
        assert_eq!(sm.transition_count(), 5);
    }

    #[test]
    fn full_lifecycle_all_states() {
        let mut sm = LeaseStateMachine::new(1, epoch(1));

        // Unleased -> Acquiring
        assert_eq!(sm.state(), LeaseState::Unleased);
        sm.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();

        // Acquiring -> Held
        assert_eq!(sm.state(), LeaseState::Acquiring);
        sm.grant().unwrap();

        // Held -> Renewing
        assert_eq!(sm.state(), LeaseState::Held);
        sm.renew(epoch(1), 10_000).unwrap();

        // Renewing -> Held (renew_ack)
        assert_eq!(sm.state(), LeaseState::Renewing);
        sm.renew_ack().unwrap();

        // Held -> Released
        assert_eq!(sm.state(), LeaseState::Held);
        sm.release().unwrap();
        assert_eq!(sm.state(), LeaseState::Released);

        // Released -> Acquiring
        sm.acquire(epoch(1), 30_000, 0, 200, 0).unwrap();
        sm.grant().unwrap();

        // Held -> Expiring (via expire)
        sm.expire().unwrap();
        assert_eq!(sm.state(), LeaseState::Expiring);

        // Expiring -> Released
        sm.expire_to_released().unwrap();
        assert_eq!(sm.state(), LeaseState::Released);
    }

    #[test]
    fn concurrent_lease_isolation_three_peers() {
        // Three independent state machines should not interfere
        let mut n1 = LeaseStateMachine::new(1, epoch(1));
        let mut n2 = LeaseStateMachine::new(2, epoch(1));
        let mut n3 = LeaseStateMachine::new(3, epoch(1));

        n1.acquire(epoch(1), 30_000, 0, 100, 0).unwrap();
        n2.acquire(epoch(1), 30_000, 1, 200, 0).unwrap();
        n3.acquire(epoch(1), 30_000, 2, 300, 0).unwrap();

        n1.grant().unwrap();
        n2.grant().unwrap();
        n3.grant().unwrap();

        assert_eq!(n1.state(), LeaseState::Held);
        assert_eq!(n2.state(), LeaseState::Held);
        assert_eq!(n3.state(), LeaseState::Held);

        assert_eq!(n1.lease().unwrap().lease_id, 100);
        assert_eq!(n2.lease().unwrap().lease_id, 200);
        assert_eq!(n3.lease().unwrap().lease_id, 300);

        // Digest isolation
        assert_ne!(n1.state_digest(), n2.state_digest());
        assert_ne!(n2.state_digest(), n3.state_digest());
        assert_ne!(n1.state_digest(), n3.state_digest());
    }
}
