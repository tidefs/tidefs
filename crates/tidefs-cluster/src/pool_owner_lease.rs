// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Live single-writer ownership leases for one clustered Pool.
//!
//! This authority is driven by the storage-node's committed membership view.
//! It grants at most one writer for each Pool GUID, keeps renewal bound to the
//! exact current token, and issues a strictly newer write fence on every live
//! ownership handoff.

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::EpochId;

use crate::{PoolLeaseToken, WriteFence};

const POOL_OWNER_LEASE_CHECKPOINT_MAGIC: &[u8; 8] = b"TPOLCK01";
const POOL_OWNER_LEASE_CHECKPOINT_VERSION: u32 = 1;
const POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN: usize = 8 + 4 + 8;
const POOL_OWNER_LEASE_CHECKPOINT_CHECKSUM_LEN: usize = 32;

/// A malformed or incompatible durable Pool-owner authority checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum PoolOwnerLeaseCheckpointError {
    #[error("encode Pool owner lease checkpoint: {0}")]
    Encode(String),
    #[error("invalid Pool owner lease checkpoint: {0}")]
    Invalid(String),
    #[error(
        "Pool owner lease checkpoint term {checkpoint_lease_term_ms}ms does not match configured term {configured_lease_term_ms}ms"
    )]
    LeaseTermMismatch {
        checkpoint_lease_term_ms: u64,
        configured_lease_term_ms: u64,
    },
    #[error("recover Pool owner lease checkpoint: {0}")]
    Recovery(#[from] PoolOwnerLeaseError),
}

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolOwnerLeaseAuthority {
    current_epoch: EpochId,
    lease_term_ms: u64,
    next_lease_id: u64,
    next_fence_generation: u64,
    active: BTreeMap<[u8; 16], PoolLeaseToken>,
    epoch_handoff_fence: BTreeMap<[u8; 16], u64>,
}

#[derive(Deserialize, Serialize)]
struct PoolOwnerLeaseCheckpointV1 {
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

    /// Encode the complete committed authority state for durable restart.
    pub fn encode_checkpoint(&self) -> Result<Vec<u8>, PoolOwnerLeaseCheckpointError> {
        self.validate_checkpoint_state(self.lease_term_ms)?;
        let checkpoint = PoolOwnerLeaseCheckpointV1 {
            current_epoch: self.current_epoch,
            lease_term_ms: self.lease_term_ms,
            next_lease_id: self.next_lease_id,
            next_fence_generation: self.next_fence_generation,
            active: self.active.clone(),
            epoch_handoff_fence: self.epoch_handoff_fence.clone(),
        };
        let payload = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&checkpoint)
            .map_err(|error| PoolOwnerLeaseCheckpointError::Encode(error.to_string()))?;
        let payload_len = u64::try_from(payload.len()).map_err(|_| {
            PoolOwnerLeaseCheckpointError::Encode("checkpoint payload is too large".to_string())
        })?;
        let mut encoded = Vec::with_capacity(
            POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN
                + payload.len()
                + POOL_OWNER_LEASE_CHECKPOINT_CHECKSUM_LEN,
        );
        encoded.extend_from_slice(POOL_OWNER_LEASE_CHECKPOINT_MAGIC);
        encoded.extend_from_slice(&POOL_OWNER_LEASE_CHECKPOINT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&payload);
        let checksum = blake3::hash(&encoded);
        encoded.extend_from_slice(checksum.as_bytes());
        Ok(encoded)
    }

    /// Recover committed state without reusing prior process-monotonic time.
    ///
    /// Every active or pending Pool is held until one full configured lease
    /// term after this process's restart point. Active tokens receive fresh
    /// lease identifiers so no pre-restart token can renew.
    pub fn recover_checkpoint(
        encoded: &[u8],
        configured_lease_term_ms: u64,
        restart_now_ms: u64,
    ) -> Result<Self, PoolOwnerLeaseCheckpointError> {
        if configured_lease_term_ms == 0 {
            return Err(PoolOwnerLeaseError::InvalidLeaseTerm.into());
        }
        let minimum_len =
            POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN + POOL_OWNER_LEASE_CHECKPOINT_CHECKSUM_LEN;
        if encoded.len() < minimum_len {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "checkpoint is truncated".to_string(),
            ));
        }
        if &encoded[..POOL_OWNER_LEASE_CHECKPOINT_MAGIC.len()] != POOL_OWNER_LEASE_CHECKPOINT_MAGIC
        {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "checkpoint magic does not match".to_string(),
            ));
        }
        let version = u32::from_le_bytes(encoded[8..12].try_into().expect("fixed version field"));
        if version != POOL_OWNER_LEASE_CHECKPOINT_VERSION {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(format!(
                "unsupported checkpoint version {version}"
            )));
        }
        let payload_len_u64 =
            u64::from_le_bytes(encoded[12..20].try_into().expect("fixed length field"));
        let payload_len = usize::try_from(payload_len_u64).map_err(|_| {
            PoolOwnerLeaseCheckpointError::Invalid(
                "checkpoint payload length does not fit this host".to_string(),
            )
        })?;
        let payload_end = POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| {
                PoolOwnerLeaseCheckpointError::Invalid(
                    "checkpoint payload length overflows framing".to_string(),
                )
            })?;
        let expected_len = payload_end
            .checked_add(POOL_OWNER_LEASE_CHECKPOINT_CHECKSUM_LEN)
            .ok_or_else(|| {
                PoolOwnerLeaseCheckpointError::Invalid(
                    "checkpoint total length overflows framing".to_string(),
                )
            })?;
        if encoded.len() != expected_len {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(format!(
                "checkpoint length {} does not match framed length {expected_len}",
                encoded.len()
            )));
        }
        let expected_checksum = blake3::hash(&encoded[..payload_end]);
        if encoded[payload_end..] != expected_checksum.as_bytes()[..] {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "checkpoint checksum does not match".to_string(),
            ));
        }
        let checkpoint: PoolOwnerLeaseCheckpointV1 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&encoded[POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN..payload_end])
            .map_err(|error| {
                PoolOwnerLeaseCheckpointError::Invalid(format!(
                    "checkpoint payload cannot be decoded: {error}"
                ))
            })?;
        if checkpoint.lease_term_ms != configured_lease_term_ms {
            return Err(PoolOwnerLeaseCheckpointError::LeaseTermMismatch {
                checkpoint_lease_term_ms: checkpoint.lease_term_ms,
                configured_lease_term_ms,
            });
        }

        let mut authority = Self {
            current_epoch: checkpoint.current_epoch,
            lease_term_ms: checkpoint.lease_term_ms,
            next_lease_id: checkpoint.next_lease_id,
            next_fence_generation: checkpoint.next_fence_generation,
            active: checkpoint.active,
            epoch_handoff_fence: checkpoint.epoch_handoff_fence,
        };
        authority.validate_checkpoint_state(configured_lease_term_ms)?;

        let restart_quarantine_deadline = restart_now_ms
            .checked_add(configured_lease_term_ms)
            .filter(|deadline| *deadline > restart_now_ms)
            .ok_or(PoolOwnerLeaseError::AuthorityExhausted)?;
        for token in authority.active.values_mut() {
            let recovered_lease_id = authority.next_lease_id;
            authority.next_lease_id = recovered_lease_id
                .checked_add(1)
                .ok_or(PoolOwnerLeaseError::AuthorityExhausted)?;
            token.lease_id = recovered_lease_id;
            token.expiration_deadline_ms = restart_quarantine_deadline;
        }
        for deadline in authority.epoch_handoff_fence.values_mut() {
            *deadline = restart_quarantine_deadline;
        }
        authority.validate_checkpoint_state(configured_lease_term_ms)?;
        Ok(authority)
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

    fn validate_checkpoint_state(
        &self,
        configured_lease_term_ms: u64,
    ) -> Result<(), PoolOwnerLeaseCheckpointError> {
        if self.current_epoch.0 == 0 {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "current membership epoch is zero".to_string(),
            ));
        }
        if self.lease_term_ms == 0 {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "lease term is zero".to_string(),
            ));
        }
        if self.lease_term_ms != configured_lease_term_ms {
            return Err(PoolOwnerLeaseCheckpointError::LeaseTermMismatch {
                checkpoint_lease_term_ms: self.lease_term_ms,
                configured_lease_term_ms,
            });
        }
        if self.next_lease_id == 0 || self.next_fence_generation == 0 {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "lease or fence frontier is zero".to_string(),
            ));
        }

        let mut lease_ids = BTreeSet::new();
        let mut fence_generations = BTreeSet::new();
        for (pool_guid, token) in &self.active {
            if token.pool_guid != *pool_guid {
                return Err(PoolOwnerLeaseCheckpointError::Invalid(
                    "active Pool map key does not match token Pool GUID".to_string(),
                ));
            }
            if !token.is_valid()
                || token.epoch != self.current_epoch
                || token.slot != 0
                || token.write_fence.epoch != self.current_epoch
                || token.write_fence.generation == 0
                || token.expiration_deadline_ms == 0
            {
                return Err(PoolOwnerLeaseCheckpointError::Invalid(
                    "active Pool token identity is invalid".to_string(),
                ));
            }
            if token.lease_id >= self.next_lease_id
                || token.write_fence.generation >= self.next_fence_generation
            {
                return Err(PoolOwnerLeaseCheckpointError::Invalid(
                    "active Pool token is not below the persisted identifier frontiers".to_string(),
                ));
            }
            if !lease_ids.insert(token.lease_id)
                || !fence_generations.insert(token.write_fence.generation)
            {
                return Err(PoolOwnerLeaseCheckpointError::Invalid(
                    "active Pool tokens reuse a lease or fence identifier".to_string(),
                ));
            }
            if self.epoch_handoff_fence.contains_key(pool_guid) {
                return Err(PoolOwnerLeaseCheckpointError::Invalid(
                    "Pool is both actively owned and handoff-fenced".to_string(),
                ));
            }
        }
        if self
            .epoch_handoff_fence
            .values()
            .any(|deadline| *deadline == 0)
        {
            return Err(PoolOwnerLeaseCheckpointError::Invalid(
                "epoch handoff deadline is zero".to_string(),
            ));
        }
        Ok(())
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

    #[test]
    fn pool_owner_checkpoint_round_trip_stales_old_token_and_quarantines_full_term() {
        let mut authority = authority();
        let old = authority.acquire(POOL, 11, 1_000).unwrap();
        let encoded = authority.encode_checkpoint().unwrap();

        let restart_now_ms = 90_000;
        let quarantine_deadline = restart_now_ms + authority.lease_term_ms;
        let mut recovered = PoolOwnerLeaseAuthority::recover_checkpoint(
            &encoded,
            authority.lease_term_ms,
            restart_now_ms,
        )
        .unwrap();
        let recovered_token = recovered
            .active_token(POOL, restart_now_ms)
            .expect("restored owner remains quarantined");

        assert_eq!(recovered.current_epoch(), authority.current_epoch());
        assert_eq!(recovered_token.node_id, old.node_id);
        assert_eq!(recovered_token.write_fence, old.write_fence);
        assert!(recovered_token.lease_id > old.lease_id);
        assert_eq!(recovered_token.expiration_deadline_ms, quarantine_deadline);
        assert_eq!(
            recovered.renew(old.clone(), restart_now_ms),
            Err(PoolOwnerLeaseError::StaleToken)
        );
        assert_eq!(
            recovered.acquire(POOL, 12, quarantine_deadline - 1),
            Err(PoolOwnerLeaseError::Owned {
                owner_node_id: 11,
                expiration_deadline_ms: quarantine_deadline,
            })
        );

        let handed_off = recovered.acquire(POOL, 12, quarantine_deadline).unwrap();
        assert!(handed_off.lease_id > recovered_token.lease_id);
        assert!(handed_off.write_fence.is_later_than(&old.write_fence));
    }

    #[test]
    fn pool_owner_checkpoint_rebases_pending_epoch_handoff() {
        let mut authority = authority();
        let old = authority.acquire(POOL, 11, 1_000).unwrap();
        authority.advance_epoch(EpochId::new(8), 2_000).unwrap();
        let encoded = authority.encode_checkpoint().unwrap();

        let restart_now_ms = 400_000;
        let quarantine_deadline = restart_now_ms + authority.lease_term_ms;
        let mut recovered = PoolOwnerLeaseAuthority::recover_checkpoint(
            &encoded,
            authority.lease_term_ms,
            restart_now_ms,
        )
        .unwrap();
        assert_eq!(recovered.current_epoch(), EpochId::new(8));
        assert_eq!(
            recovered.acquire(POOL, 12, quarantine_deadline - 1),
            Err(PoolOwnerLeaseError::EpochHandoffPending {
                blocked_until_ms: quarantine_deadline,
            })
        );
        let handed_off = recovered.acquire(POOL, 12, quarantine_deadline).unwrap();
        assert!(handed_off.lease_id > old.lease_id);
        assert!(handed_off.write_fence.is_later_than(&old.write_fence));
    }

    #[test]
    fn pool_owner_checkpoint_refuses_corruption_version_truncation_and_term_mismatch() {
        let mut authority = authority();
        authority.acquire(POOL, 11, 1_000).unwrap();
        let encoded = authority.encode_checkpoint().unwrap();

        let mut corrupt = encoded.clone();
        corrupt[POOL_OWNER_LEASE_CHECKPOINT_HEADER_LEN] ^= 0x80;
        assert!(matches!(
            PoolOwnerLeaseAuthority::recover_checkpoint(
                &corrupt,
                authority.lease_term_ms,
                50_000
            ),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("checksum")
        ));

        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            PoolOwnerLeaseAuthority::recover_checkpoint(
                truncated,
                authority.lease_term_ms,
                50_000
            ),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("length")
        ));

        let mut incompatible = encoded.clone();
        incompatible[8..12].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            PoolOwnerLeaseAuthority::recover_checkpoint(
                &incompatible,
                authority.lease_term_ms,
                50_000
            ),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("version")
        ));

        assert!(matches!(
            PoolOwnerLeaseAuthority::recover_checkpoint(&encoded, 10_000, 50_000),
            Err(PoolOwnerLeaseCheckpointError::LeaseTermMismatch {
                checkpoint_lease_term_ms: 30_000,
                configured_lease_term_ms: 10_000,
            })
        ));
    }

    #[test]
    fn pool_owner_checkpoint_validates_identity_and_identifier_frontiers() {
        let mut authority = authority();
        let token = authority.acquire(POOL, 11, 1_000).unwrap();

        authority.active.remove(&POOL);
        authority.active.insert([0x48; 16], token.clone());
        assert!(matches!(
            authority.encode_checkpoint(),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("map key")
        ));

        authority.active.clear();
        authority.active.insert(POOL, token);
        authority.next_lease_id = 1;
        assert!(matches!(
            authority.encode_checkpoint(),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("identifier frontiers")
        ));

        let mut slot_authority = PoolOwnerLeaseAuthority::new(EpochId::new(7), 30_000).unwrap();
        let mut token = slot_authority.acquire(POOL, 11, 1_000).unwrap();
        token.slot = 1;
        slot_authority.active.insert(POOL, token);
        assert!(matches!(
            slot_authority.encode_checkpoint(),
            Err(PoolOwnerLeaseCheckpointError::Invalid(error))
                if error.contains("token identity")
        ));
    }

    #[test]
    fn pool_owner_checkpoint_fails_closed_when_recovery_cannot_reserve_fresh_id() {
        let mut authority = authority();
        authority.acquire(POOL, 11, 1_000).unwrap();
        authority.next_lease_id = u64::MAX;
        let encoded = authority.encode_checkpoint().unwrap();

        assert!(matches!(
            PoolOwnerLeaseAuthority::recover_checkpoint(&encoded, authority.lease_term_ms, 50_000),
            Err(PoolOwnerLeaseCheckpointError::Recovery(
                PoolOwnerLeaseError::AuthorityExhausted
            ))
        ));
    }
}
