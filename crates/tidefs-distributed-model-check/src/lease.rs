// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Lease grant/revoke model for the distributed model checker.
//!
//! Models lease lifecycle: requested, granted, renewed, fenced,
//! released, expired, and revoked.  All transitions are deterministic.

use serde::{Deserialize, Serialize};

/// Lease lifecycle states (mirrors `tidefs-lease::LeaseLifecycle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseLifecycleModel {
    Requested,
    Granted,
    Renewing,
    Fenced,
    Released,
    Expired,
    Revoked,
}

impl LeaseLifecycleModel {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Fenced | Self::Released | Self::Expired | Self::Revoked)
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Granted | Self::Renewing)
    }
}

/// Per-node lease state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseState {
    pub lease_id: u64,
    pub object_key: String,
    pub holder: u64,
    pub epoch: u64,
    pub granted: bool,
    pub revoked: bool,
}

/// Outcome of a lease operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseOutcome {
    Granted { lease_id: u64 },
    Revoked { lease_id: u64 },
    Conflict { lease_id: u64, reason: String },
    StaleEpoch { lease_id: u64, request_epoch: u64, current_epoch: u64 },
}

/// Lease model — maintains global lease table for conflict detection.
#[derive(Clone, Debug)]
pub struct LeaseModel {
    /// All leases ever granted, keyed by lease_id.
    pub leases: Vec<LeaseState>,
    /// Object → holder mapping for current epoch.
    pub object_holders: std::collections::BTreeMap<String, u64>,
}

impl LeaseModel {
    #[must_use]
    pub fn new() -> Self {
        Self { leases: Vec::new(), object_holders: std::collections::BTreeMap::new() }
    }

    /// Attempt to grant a lease.  Returns `Conflict` if another node
    /// already holds a lease on the same object in the same epoch.
    #[must_use]
    pub fn try_grant(
        &mut self,
        lease_id: u64,
        object_key: &str,
        holder: u64,
        epoch: u64,
        current_epoch: u64,
    ) -> LeaseOutcome {
        if epoch < current_epoch {
            return LeaseOutcome::StaleEpoch { lease_id, request_epoch: epoch, current_epoch };
        }
        if let Some(&existing_holder) = self.object_holders.get(object_key) {
            if existing_holder != holder {
                return LeaseOutcome::Conflict {
                    lease_id,
                    reason: format!("object {object_key} already held by node {existing_holder}"),
                };
            }
        }
        let ls = LeaseState {
            lease_id, object_key: object_key.to_string(),
            holder, epoch, granted: true, revoked: false,
        };
        self.leases.push(ls.clone());
        self.object_holders.insert(object_key.to_string(), holder);
        LeaseOutcome::Granted { lease_id }
    }

    /// Revoke a lease by id.
    pub fn revoke(&mut self, lease_id: u64) -> LeaseOutcome {
        if let Some(ls) = self.leases.iter_mut().find(|l| l.lease_id == lease_id) {
            ls.granted = false;
            ls.revoked = true;
            self.object_holders.remove(&ls.object_key);
            LeaseOutcome::Revoked { lease_id }
        } else {
            LeaseOutcome::Revoked { lease_id } // idempotent
        }
    }
}
