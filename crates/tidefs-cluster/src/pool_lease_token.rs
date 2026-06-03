//! Pool lease token: an opaque proof that the caller holds a valid cluster
//! membership lease for a specific pool.
//!
//! The [`PoolLeaseToken`] bridges the cluster lease runtime to the pool
//! import path. Before importing a clustered pool read-write, the caller
//! must acquire a membership lease and present the resulting token. The
//! pool import layer verifies the token fields and refuses import when
//! the token is absent or invalid.
//!
//! ## Relationship to WriteFence
//!
//! The token carries a [`WriteFence`] issued by the [`FenceAuthority`]
//! when the lease was acquired. The transport layer uses the corresponding
//! [`FenceValidator`] to reject writes from nodes that no longer hold the
//! lease, preventing split-brain corruption.
//!
//! ## Lifecycle
//!
//! 1. `ClusterLeaseRuntime` acquires a membership lease (Acquire → AcquireAck → Held).
//! 2. On transition to Held, the runtime calls `FenceAuthority::issue_fence()`
//!    and constructs a `PoolLeaseToken` from the lease + fence.
//! 3. The caller passes the token to `PoolImporter::import_pool_clustered()`.
//! 4. On lease expiry or release, the token is invalidated and writes are fenced.

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::EpochId;

use crate::write_fence::WriteFence;

/// A token proving the holder has acquired a cluster membership lease for
/// a specific pool.
///
/// The token is produced by [`ClusterLeaseRuntime`] when the lease state
/// machine transitions to `Held`, and is consumed by
/// `PoolImporter::import_pool_clustered()` to authorize cluster-aware import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolLeaseToken {
    /// The node that holds the lease.
    pub node_id: u64,
    /// The pool this lease is scoped to.
    pub pool_guid: [u8; 16],
    /// The epoch this lease is valid for.
    pub epoch: EpochId,
    /// The lease identifier assigned by the lease authority.
    pub lease_id: u64,
    /// The membership slot held by this node.
    pub slot: u64,
    /// The write fence token issued when the lease was acquired.
    /// Writes carrying a stale (older) fence will be rejected by the
    /// transport layer.
    pub write_fence: WriteFence,
    /// Millisecond timestamp when the lease expires.
    pub expiration_deadline_ms: u64,
}

impl PoolLeaseToken {
    /// Create a new pool lease token from the given lease and fence.
    pub fn new(
        node_id: u64,
        pool_guid: [u8; 16],
        epoch: EpochId,
        lease_id: u64,
        slot: u64,
        write_fence: WriteFence,
        expiration_deadline_ms: u64,
    ) -> Self {
        Self {
            node_id,
            pool_guid,
            epoch,
            lease_id,
            slot,
            write_fence,
            expiration_deadline_ms,
        }
    }

    /// Returns true if the token has valid non-zero identifying fields.
    ///
    /// A token with `node_id == 0` or `epoch == EpochId(0)` is considered
    /// uninitialized/invalid and should be refused by consumers.
    pub fn is_valid(&self) -> bool {
        self.node_id > 0 && self.epoch.0 > 0 && self.lease_id > 0
    }

    /// Check if the token has expired at the given `now_ms`.
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expiration_deadline_ms
    }

    /// Verify that the token authorizes access to the given pool GUID.
    pub fn authorizes_pool(&self, pool_guid: &[u8; 16]) -> bool {
        self.pool_guid == *pool_guid
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_token_passes_is_valid() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(1),
            100,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        assert!(token.is_valid());
    }

    #[test]
    fn zero_node_id_is_invalid() {
        let token = PoolLeaseToken::new(
            0,
            [0xAB; 16],
            EpochId(1),
            100,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        assert!(!token.is_valid());
    }

    #[test]
    fn zero_epoch_is_invalid() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(0),
            100,
            0,
            WriteFence::new(EpochId(0), 3),
            30_000,
        );
        assert!(!token.is_valid());
    }

    #[test]
    fn zero_lease_id_is_invalid() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(1),
            0,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        assert!(!token.is_valid());
    }

    #[test]
    fn authorizes_pool_matches_guid() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(1),
            100,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        assert!(token.authorizes_pool(&[0xAB; 16]));
        assert!(!token.authorizes_pool(&[0xCD; 16]));
    }

    #[test]
    fn expiration_check() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(1),
            100,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        assert!(!token.is_expired_at(0));
        assert!(!token.is_expired_at(29_999));
        assert!(token.is_expired_at(30_000));
        assert!(token.is_expired_at(50_000));
    }

    #[test]
    fn token_serialization_roundtrip() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(7),
            999,
            3,
            WriteFence::new(EpochId(7), 5),
            120_000,
        );
        let json = serde_json::to_string(&token).unwrap();
        let restored: PoolLeaseToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
    }

    #[test]
    fn token_clone_preserves_fields() {
        let token = PoolLeaseToken::new(
            42,
            [0xAB; 16],
            EpochId(1),
            100,
            0,
            WriteFence::new(EpochId(1), 3),
            30_000,
        );
        let cloned = token.clone();
        assert_eq!(token, cloned);
    }
}
