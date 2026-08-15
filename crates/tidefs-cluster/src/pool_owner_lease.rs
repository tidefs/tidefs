// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Live single-writer ownership leases for one clustered Pool.
//!
//! This authority is driven by the storage-node's committed membership view.
//! It grants at most one writer for each Pool GUID, keeps renewal bound to the
//! exact current token, and issues a strictly newer write fence on every live
//! ownership handoff.

use std::collections::BTreeMap;

use tidefs_membership_epoch::EpochId;

use crate::{PoolLeaseToken, WriteFence};

/// A refusal from the live Pool owner lease authority.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PoolOwnerLeaseError {
    #[error("membership epoch is not committed")]
    UncommittedEpoch,
    #[error("membership epoch regressed from {current_epoch} to {proposed_epoch}")]
    StaleEpoch {
        current_epoch: u64,
        proposed_epoch: u64,
    },
    #[error("lease term must be greater than zero")]
    InvalidLeaseTerm,
    #[error("lease or write-fence identifier space is exhausted")]
    AuthorityExhausted,
    #[error("pool is owned by node {owner_node_id} until {expiration_deadline_ms}")]
    Owned {
        owner_node_id: u64,
        expiration_deadline_ms: u64,
    },
    #[error("pool has no active owner lease")]
    NotOwned,
    #[error("owner lease token does not match current authority")]
    StaleToken,
    #[error("owner lease expired at {expiration_deadline_ms}")]
    Expired { expiration_deadline_ms: u64 },
    #[error("membership handoff is fenced until {blocked_until_ms}")]
    EpochHandoffPending { blocked_until_ms: u64 },
}

/// Live authority for Pool-scoped single-writer ownership.
#[derive(Clone, Debug)]
pub struct PoolOwnerLeaseAuthority {
    current_epoch: EpochId,
    lease_term_ms: u64,
    next_lease_id: u64,
    next_fence_generation: u64,
    active: BTreeMap<[u8; 16], PoolLeaseToken>,
    epoch_handoff_fence: BTreeMap<[u8; 16], u64>,
}

impl PoolOwnerLeaseAuthority {
    pub fn new(current_epoch: EpochId, lease_term_ms: u64) -> Result<Self, PoolOwnerLeaseError> {
        if current_epoch.0 == 0 {
            return Err(PoolOwnerLeaseError::UncommittedEpoch);
        }
        if lease_term_ms == 0 {
            return Err(PoolOwnerLeaseError::InvalidLeaseTerm);
        }
        Ok(Self {
            current_epoch,
            lease_term_ms,
            next_lease_id: 1,
            next_fence_generation: 1,
            active: BTreeMap::new(),
            epoch_handoff_fence: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Apply a newly committed membership epoch and revoke all old authority.
    pub fn advance_epoch(
        &mut self,
        epoch: EpochId,
        now_ms: u64,
    ) -> Result<(), PoolOwnerLeaseError> {
        if epoch.0 == 0 {
            return Err(PoolOwnerLeaseError::UncommittedEpoch);
        }
        if epoch < self.current_epoch {
            return Err(PoolOwnerLeaseError::StaleEpoch {
                current_epoch: self.current_epoch.0,
                proposed_epoch: epoch.0,
            });
        }
        if epoch > self.current_epoch {
            for (pool_guid, token) in &self.active {
                if token.expiration_deadline_ms > now_ms {
                    self.epoch_handoff_fence
                        .entry(*pool_guid)
                        .and_modify(|deadline| {
                            *deadline = (*deadline).max(token.expiration_deadline_ms)
                        })
                        .or_insert(token.expiration_deadline_ms);
                }
            }
            self.current_epoch = epoch;
            self.active.clear();
        }
        Ok(())
    }

    /// Acquire one Pool's writer lease for an admitted membership node.
    pub fn acquire(
        &mut self,
        pool_guid: [u8; 16],
        owner_node_id: u64,
        now_ms: u64,
    ) -> Result<PoolLeaseToken, PoolOwnerLeaseError> {
        self.expire_pool(pool_guid, now_ms);
        if let Some(blocked_until_ms) = self.epoch_handoff_fence.get(&pool_guid).copied() {
            if now_ms < blocked_until_ms {
                return Err(PoolOwnerLeaseError::EpochHandoffPending { blocked_until_ms });
            }
            self.epoch_handoff_fence.remove(&pool_guid);
        }
        if let Some(current) = self.active.get(&pool_guid) {
            if current.node_id != owner_node_id {
                return Err(PoolOwnerLeaseError::Owned {
                    owner_node_id: current.node_id,
                    expiration_deadline_ms: current.expiration_deadline_ms,
                });
            }
            return self.renew(current.clone(), now_ms);
        }

        let lease_id = self.next_lease_id;
        let next_lease_id = lease_id
            .checked_add(1)
            .ok_or(PoolOwnerLeaseError::AuthorityExhausted)?;
        let fence_generation = self.next_fence_generation;
        let next_fence_generation = fence_generation
            .checked_add(1)
            .ok_or(PoolOwnerLeaseError::AuthorityExhausted)?;
        let expiration_deadline_ms = now_ms.saturating_add(self.lease_term_ms);
        if expiration_deadline_ms <= now_ms {
            return Err(PoolOwnerLeaseError::AuthorityExhausted);
        }
        let token = PoolLeaseToken::new(
            owner_node_id,
            pool_guid,
            self.current_epoch,
            lease_id,
            0,
            WriteFence::new(self.current_epoch, fence_generation),
            expiration_deadline_ms,
        );
        self.next_lease_id = next_lease_id;
        self.next_fence_generation = next_fence_generation;
        self.active.insert(pool_guid, token.clone());
        Ok(token)
    }

    /// Renew the exact current token without changing its writer or fence.
    pub fn renew(
        &mut self,
        token: PoolLeaseToken,
        now_ms: u64,
    ) -> Result<PoolLeaseToken, PoolOwnerLeaseError> {
        let current = self
            .active
            .get(&token.pool_guid)
            .ok_or(PoolOwnerLeaseError::NotOwned)?;
        if current.is_expired_at(now_ms) {
            let deadline = current.expiration_deadline_ms;
            self.active.remove(&token.pool_guid);
            return Err(PoolOwnerLeaseError::Expired {
                expiration_deadline_ms: deadline,
            });
        }
        if current != &token || token.epoch != self.current_epoch {
            return Err(PoolOwnerLeaseError::StaleToken);
        }

        let mut renewed = token;
        let successor_deadline = renewed
            .expiration_deadline_ms
            .checked_add(1)
            .ok_or(PoolOwnerLeaseError::AuthorityExhausted)?;
        renewed.expiration_deadline_ms = now_ms
            .saturating_add(self.lease_term_ms)
            .max(successor_deadline);
        self.active.insert(renewed.pool_guid, renewed.clone());
        Ok(renewed)
    }

    /// Release only the exact current owner token.
    pub fn release(&mut self, token: &PoolLeaseToken) -> Result<(), PoolOwnerLeaseError> {
        let current = self
            .active
            .get(&token.pool_guid)
            .ok_or(PoolOwnerLeaseError::NotOwned)?;
        if current != token || token.epoch != self.current_epoch {
            return Err(PoolOwnerLeaseError::StaleToken);
        }
        self.active.remove(&token.pool_guid);
        Ok(())
    }

    #[must_use]
    pub fn active_token(&mut self, pool_guid: [u8; 16], now_ms: u64) -> Option<PoolLeaseToken> {
        self.expire_pool(pool_guid, now_ms);
        self.active.get(&pool_guid).cloned()
    }

    fn expire_pool(&mut self, pool_guid: [u8; 16], now_ms: u64) {
        if self
            .active
            .get(&pool_guid)
            .is_some_and(|token| token.is_expired_at(now_ms))
        {
            self.active.remove(&pool_guid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: [u8; 16] = [0x47; 16];

    fn authority() -> PoolOwnerLeaseAuthority {
        PoolOwnerLeaseAuthority::new(EpochId::new(7), 30_000).unwrap()
    }

    #[test]
    fn pool_owner_lease_refuses_second_live_writer() {
        let mut authority = authority();
        let first = authority.acquire(POOL, 11, 1_000).unwrap();
        let error = authority.acquire(POOL, 12, 2_000).unwrap_err();
        assert_eq!(
            error,
            PoolOwnerLeaseError::Owned {
                owner_node_id: 11,
                expiration_deadline_ms: first.expiration_deadline_ms,
            }
        );
    }

    #[test]
    fn pool_owner_lease_renewal_preserves_identity_and_fence() {
        let mut authority = authority();
        let first = authority.acquire(POOL, 11, 1_000).unwrap();
        let renewed = authority.renew(first.clone(), 20_000).unwrap();
        assert_eq!(renewed.node_id, first.node_id);
        assert_eq!(renewed.lease_id, first.lease_id);
        assert_eq!(renewed.write_fence, first.write_fence);
        assert_eq!(renewed.expiration_deadline_ms, 50_000);
        assert_eq!(authority.active_token(POOL, 20_000), Some(renewed));
    }

    #[test]
    fn pool_owner_lease_release_allows_newer_fence_handoff() {
        let mut authority = authority();
        let first = authority.acquire(POOL, 11, 1_000).unwrap();
        authority.release(&first).unwrap();
        let second = authority.acquire(POOL, 12, 2_000).unwrap();
        assert!(second.write_fence.is_later_than(&first.write_fence));
        assert_ne!(second.lease_id, first.lease_id);
    }

    #[test]
    fn pool_owner_lease_expiry_allows_newer_fence_handoff() {
        let mut authority = authority();
        let first = authority.acquire(POOL, 11, 1_000).unwrap();
        let second = authority
            .acquire(POOL, 12, first.expiration_deadline_ms)
            .unwrap();
        assert!(second.write_fence.is_later_than(&first.write_fence));
    }

    #[test]
    fn pool_owner_lease_epoch_change_revokes_old_token() {
        let mut authority = authority();
        let old = authority.acquire(POOL, 11, 1_000).unwrap();
        authority.advance_epoch(EpochId::new(8), 2_000).unwrap();
        assert_eq!(
            authority.renew(old.clone(), 2_000),
            Err(PoolOwnerLeaseError::NotOwned)
        );
        assert_eq!(
            authority.acquire(POOL, 12, 2_000),
            Err(PoolOwnerLeaseError::EpochHandoffPending {
                blocked_until_ms: old.expiration_deadline_ms,
            })
        );
        let new = authority
            .acquire(POOL, 12, old.expiration_deadline_ms)
            .unwrap();
        assert_eq!(new.epoch, EpochId::new(8));
    }

    #[test]
    fn pool_owner_lease_refuses_membership_epoch_regression() {
        let mut authority = authority();
        let token = authority.acquire(POOL, 11, 1_000).unwrap();

        assert_eq!(
            authority.advance_epoch(EpochId::new(6), 2_000),
            Err(PoolOwnerLeaseError::StaleEpoch {
                current_epoch: 7,
                proposed_epoch: 6,
            })
        );
        assert_eq!(authority.active_token(POOL, 2_000), Some(token));
    }

    #[test]
    fn pool_owner_lease_refuses_identifier_and_deadline_exhaustion() {
        let mut identifier_exhausted = authority();
        identifier_exhausted.next_lease_id = u64::MAX;
        assert_eq!(
            identifier_exhausted.acquire(POOL, 11, 1_000),
            Err(PoolOwnerLeaseError::AuthorityExhausted)
        );

        let mut deadline_exhausted = authority();
        let mut token = deadline_exhausted.acquire(POOL, 11, 1_000).unwrap();
        token.expiration_deadline_ms = u64::MAX;
        deadline_exhausted.active.insert(POOL, token.clone());
        assert_eq!(
            deadline_exhausted.renew(token, 2_000),
            Err(PoolOwnerLeaseError::AuthorityExhausted)
        );
    }
}
