//! Cluster membership lease authority — slot assignment and grant/nack
//! decision logic for incoming lease protocol requests.
//!
//! The [`LeaseAuthority`] tracks slot occupancy and issued leases, making
//! deterministic grant/nack decisions for Acquire, Renew, and Release
//! requests. It is designed to be embedded in a node that acts as the
//! lease granter for a set of membership slots.
//!
//! ## Design
//!
//! - Slot occupancy is tracked via a `BTreeMap<u64, OccupiedSlot>` keyed by
//!   slot index.
//! - Acquire succeeds when the slot is free or held by the same node
//!   (re-acquire).
//! - Renew succeeds when the lease exists and the epoch matches.
//! - Release frees the slot unconditionally.
//! - Every decision includes an epoch check; cross-epoch requests are
//!   rejected.

use std::collections::BTreeMap;
use tidefs_membership_epoch::EpochId;

use crate::protocol::{
    AcquireAck, AcquireNack, AcquireRequest, ExpireNotify, ReleaseAck, ReleaseRequest, RenewAck,
    RenewNack, RenewRequest,
};

/// Records a granted lease for a slot.
#[derive(Clone, Debug)]
struct OccupiedSlot {
    node_id: u64,
    lease_id: u64,
    epoch: EpochId,
    #[allow(dead_code)]
    deadline_ms: u64,
}

/// Outcome of an acquire request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcquireOutcome {
    /// Slot granted.
    Ack(AcquireAck),
    /// Slot denied.
    Nack(AcquireNack),
}

/// Outcome of a renew request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewOutcome {
    /// Renewal accepted.
    Ack(RenewAck),
    /// Renewal denied.
    Nack(RenewNack),
}

/// The cluster membership lease authority.
///
/// Tracks slot occupancy and issues deterministic grant/nack decisions.
#[derive(Clone, Debug, Default)]
pub struct LeaseAuthority {
    /// Map from slot index to occupied slot record.
    slots: BTreeMap<u64, OccupiedSlot>,
    /// Current epoch. Requests from other epochs are rejected.
    current_epoch: EpochId,
    /// Next lease ID to assign.
    next_lease_id: u64,
}

impl LeaseAuthority {
    /// Initialize the lease authority from a bootstrapped cluster authority

    /// snapshot.  Sets the current epoch to the snapshot's membership

    /// epoch and resets all slot records (slots are assigned at runtime

    /// during lease acquisition, not pre-populated from the snapshot).

    pub fn from_snapshot(snapshot: &crate::cluster_authority_snapshot::ClusterAuthoritySnapshot) -> Self {

        Self {

            slots: BTreeMap::new(),

            current_epoch: EpochId(snapshot.membership_epoch),

            next_lease_id: 1,

        }

    }
    /// Create a new lease authority for the given epoch.
    pub fn new(current_epoch: EpochId) -> Self {
        Self {
            slots: BTreeMap::new(),
            current_epoch,
            next_lease_id: 1,
        }
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Advance to a new epoch, clearing all slot records.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        self.slots.clear();
    }

    /// Handle an acquire request: grant if slot is free, nack otherwise.
    pub fn handle_acquire(&mut self, req: &AcquireRequest) -> AcquireOutcome {
        if req.epoch != self.current_epoch {
            return AcquireOutcome::Nack(AcquireNack {
                request_id: req.request_id,
                reason: format!(
                    "epoch mismatch: request={:?} authority={:?}",
                    req.epoch, self.current_epoch
                ),
            });
        }

        if let Some(occupied) = self.slots.get(&req.slot) {
            // Re-acquire by same node is allowed (lease refresh)
            if occupied.node_id == req.node_id && occupied.epoch == req.epoch {
                let lease_id = occupied.lease_id;
                let deadline_ms = req.lease_term_ms;
                self.slots.insert(
                    req.slot,
                    OccupiedSlot {
                        node_id: req.node_id,
                        lease_id,
                        epoch: req.epoch,
                        deadline_ms,
                    },
                );
                return AcquireOutcome::Ack(AcquireAck {
                    request_id: req.request_id,
                    lease_id,
                    epoch: req.epoch,
                    slot: req.slot,
                    lease_term_ms: req.lease_term_ms,
                    deadline_ms,
                });
            }
            return AcquireOutcome::Nack(AcquireNack {
                request_id: req.request_id,
                reason: format!("slot {} occupied by node {}", req.slot, occupied.node_id),
            });
        }

        let lease_id = self.next_lease_id;
        self.next_lease_id += 1;
        let deadline_ms = req.lease_term_ms;

        self.slots.insert(
            req.slot,
            OccupiedSlot {
                node_id: req.node_id,
                lease_id,
                epoch: req.epoch,
                deadline_ms,
            },
        );

        AcquireOutcome::Ack(AcquireAck {
            request_id: req.request_id,
            lease_id,
            epoch: req.epoch,
            slot: req.slot,
            lease_term_ms: req.lease_term_ms,
            deadline_ms,
        })
    }

    /// Handle a renew request: ack if the lease is known and valid, nack otherwise.
    pub fn handle_renew(&mut self, req: &RenewRequest, new_deadline_ms: u64) -> RenewOutcome {
        if req.epoch != self.current_epoch {
            return RenewOutcome::Nack(RenewNack {
                lease_id: req.lease_id,
                reason: format!(
                    "epoch mismatch: request={:?} authority={:?}",
                    req.epoch, self.current_epoch
                ),
            });
        }

        // Find the slot containing this lease
        let slot_entry = self
            .slots
            .iter()
            .find(|(_, occ)| occ.lease_id == req.lease_id && occ.node_id == req.node_id);

        if let Some((slot_idx, _occupied)) = slot_entry {
            let slot_idx = *slot_idx;
            self.slots.insert(
                slot_idx,
                OccupiedSlot {
                    node_id: req.node_id,
                    lease_id: req.lease_id,
                    epoch: req.epoch,
                    deadline_ms: new_deadline_ms,
                },
            );
            RenewOutcome::Ack(RenewAck {
                lease_id: req.lease_id,
                new_deadline_ms,
            })
        } else {
            RenewOutcome::Nack(RenewNack {
                lease_id: req.lease_id,
                reason: format!("lease {} not found for node {}", req.lease_id, req.node_id),
            })
        }
    }

    /// Handle a release request: free the slot unconditionally.
    pub fn handle_release(&mut self, req: &ReleaseRequest) -> ReleaseAck {
        self.slots
            .retain(|_slot, occ| !(occ.node_id == req.node_id && occ.lease_id == req.lease_id));
        ReleaseAck {
            lease_id: req.lease_id,
        }
    }

    /// Handle an expire notification: free the slot.
    pub fn handle_expire(&mut self, notify: &ExpireNotify) {
        self.slots.retain(|_slot, occ| {
            !(occ.node_id == notify.node_id && occ.lease_id == notify.lease_id)
        });
    }

    /// Check if a slot is occupied.
    pub fn is_slot_occupied(&self, slot: u64) -> bool {
        self.slots.contains_key(&slot)
    }

    /// Return the number of occupied slots.
    pub fn occupied_count(&self) -> usize {
        self.slots.len()
    }

    /// Return the node_id occupying a slot, if any.
    pub fn slot_owner(&self, slot: u64) -> Option<u64> {
        self.slots.get(&slot).map(|o| o.node_id)
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
    fn new_authority_has_no_slots() {
        let auth = LeaseAuthority::new(epoch(1));
        assert_eq!(auth.occupied_count(), 0);
    }

    #[test]
    fn acquire_free_slot_grants() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let req = AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        };
        let outcome = auth.handle_acquire(&req);
        match outcome {
            AcquireOutcome::Ack(ack) => {
                assert_eq!(ack.request_id, 1);
                assert_eq!(ack.lease_id, 1);
                assert_eq!(ack.slot, 0);
                assert_eq!(ack.epoch, epoch(1));
                assert_eq!(ack.lease_term_ms, 30_000);
                assert_eq!(ack.deadline_ms, 30_000);
            }
            AcquireOutcome::Nack(_) => panic!("expected ack"),
        }
        assert!(auth.is_slot_occupied(0));
        assert_eq!(auth.slot_owner(0), Some(10));
        assert_eq!(auth.occupied_count(), 1);
    }

    #[test]
    fn acquire_occupied_slot_nacks() {
        let mut auth = LeaseAuthority::new(epoch(1));
        auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        });

        let outcome = auth.handle_acquire(&AcquireRequest {
            node_id: 20,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 2,
        });
        match outcome {
            AcquireOutcome::Nack(nack) => {
                assert_eq!(nack.request_id, 2);
                assert!(nack.reason.contains("occupied"));
            }
            AcquireOutcome::Ack(_) => panic!("expected nack"),
        }
        assert_eq!(auth.occupied_count(), 1);
    }

    #[test]
    fn acquire_same_node_same_slot_reacquires() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let ack1 = match auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        }) {
            AcquireOutcome::Ack(a) => a,
            _ => panic!(),
        };
        let lease_id = ack1.lease_id;

        let outcome = auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 60_000,
            request_id: 2,
        });
        match outcome {
            AcquireOutcome::Ack(ack) => {
                assert_eq!(ack.lease_id, lease_id);
                assert_eq!(ack.lease_term_ms, 60_000);
            }
            AcquireOutcome::Nack(_) => panic!("expected ack"),
        }
        assert_eq!(auth.occupied_count(), 1);
    }

    #[test]
    fn acquire_epoch_mismatch_nacks() {
        let mut auth = LeaseAuthority::new(epoch(2));
        let outcome = auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        });
        match outcome {
            AcquireOutcome::Nack(nack) => {
                assert!(nack.reason.contains("epoch mismatch"));
            }
            AcquireOutcome::Ack(_) => panic!("expected nack"),
        }
    }

    #[test]
    fn renew_valid_lease_acks() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let ack = match auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        }) {
            AcquireOutcome::Ack(a) => a,
            _ => panic!(),
        };

        let outcome = auth.handle_renew(
            &RenewRequest {
                node_id: 10,
                lease_id: ack.lease_id,
                epoch: epoch(1),
            },
            60_000,
        );
        match outcome {
            RenewOutcome::Ack(ack) => {
                assert_eq!(ack.lease_id, 1);
                assert_eq!(ack.new_deadline_ms, 60_000);
            }
            RenewOutcome::Nack(_) => panic!("expected ack"),
        }
    }

    #[test]
    fn renew_unknown_lease_nacks() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let outcome = auth.handle_renew(
            &RenewRequest {
                node_id: 10,
                lease_id: 999,
                epoch: epoch(1),
            },
            60_000,
        );
        match outcome {
            RenewOutcome::Nack(nack) => {
                assert_eq!(nack.lease_id, 999);
            }
            RenewOutcome::Ack(_) => panic!("expected nack"),
        }
    }

    #[test]
    fn renew_epoch_mismatch_nacks() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let ack = match auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        }) {
            AcquireOutcome::Ack(a) => a,
            _ => panic!(),
        };

        let outcome = auth.handle_renew(
            &RenewRequest {
                node_id: 10,
                lease_id: ack.lease_id,
                epoch: epoch(2),
            },
            60_000,
        );
        match outcome {
            RenewOutcome::Nack(nack) => {
                assert!(nack.reason.contains("epoch mismatch"));
            }
            RenewOutcome::Ack(_) => panic!("expected nack"),
        }
    }

    #[test]
    fn release_frees_slot() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let ack = match auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        }) {
            AcquireOutcome::Ack(a) => a,
            _ => panic!(),
        };
        assert!(auth.is_slot_occupied(0));

        let rel_ack = auth.handle_release(&ReleaseRequest {
            node_id: 10,
            lease_id: ack.lease_id,
            epoch: epoch(1),
        });
        assert_eq!(rel_ack.lease_id, ack.lease_id);
        assert!(!auth.is_slot_occupied(0));
        assert_eq!(auth.occupied_count(), 0);
    }

    #[test]
    fn expire_frees_slot() {
        let mut auth = LeaseAuthority::new(epoch(1));
        let ack = match auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        }) {
            AcquireOutcome::Ack(a) => a,
            _ => panic!(),
        };
        assert!(auth.is_slot_occupied(0));

        auth.handle_expire(&ExpireNotify {
            node_id: 10,
            lease_id: ack.lease_id,
            epoch: epoch(1),
        });
        assert!(!auth.is_slot_occupied(0));
    }

    #[test]
    fn advance_epoch_clears_all_slots() {
        let mut auth = LeaseAuthority::new(epoch(1));
        auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        });
        auth.handle_acquire(&AcquireRequest {
            node_id: 20,
            epoch: epoch(1),
            slot: 1,
            lease_term_ms: 30_000,
            request_id: 2,
        });
        assert_eq!(auth.occupied_count(), 2);

        auth.advance_epoch(epoch(2));
        assert_eq!(auth.occupied_count(), 0);
        assert_eq!(auth.current_epoch(), epoch(2));
    }

    #[test]
    fn multiple_slots_independent() {
        let mut auth = LeaseAuthority::new(epoch(1));

        auth.handle_acquire(&AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        });
        auth.handle_acquire(&AcquireRequest {
            node_id: 20,
            epoch: epoch(1),
            slot: 1,
            lease_term_ms: 30_000,
            request_id: 2,
        });

        assert_eq!(auth.slot_owner(0), Some(10));
        assert_eq!(auth.slot_owner(1), Some(20));

        auth.handle_release(&ReleaseRequest {
            node_id: 10,
            lease_id: 1,
            epoch: epoch(1),
        });

        assert_eq!(auth.slot_owner(0), None);
        assert_eq!(auth.slot_owner(1), Some(20));
        assert_eq!(auth.occupied_count(), 1);
    }
}
