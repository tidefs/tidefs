// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId, ReceiptId};

// ---------------------------------------------------------------------------
// Lease class
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeaseClass {
    Exclusive,
    Shared,
    Staging,
}

impl LeaseClass {
    pub const fn is_exclusive(self) -> bool {
        matches!(self, Self::Exclusive)
    }
    pub const fn allows_concurrent_holders(self) -> bool {
        matches!(self, Self::Shared)
    }
}

// ---------------------------------------------------------------------------
// Lease domain — extended for sharded lease hierarchy (design doc #1663 §3.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseDomain {
    EpochTransition {
        epoch_id: EpochId,
    },
    ChunkRange {
        replica_set_id: u64,
        start_chunk: u64,
        end_chunk: u64,
    },
    Snapshot {
        snapshot_id: u64,
    },
    MembershipReconfig {
        config_id: u64,
    },
    Transfer {
        receipt_id: ReceiptId,
    },
    /// Tier 1: directory subtree lease (design doc #1663 §3.1)
    Subtree {
        dataset_id: u64,
        prefix: String,
    },
    /// Tier 2: per-inode lease token (design doc #1663 §3.1)
    Inode {
        dataset_id: u64,
        ino: u64,
    },
    /// Tier 3: byte-range record lock (design doc #1663 §3.1)
    ByteRange {
        dataset_id: u64,
        ino: u64,
        start: u64,
        end: u64,
    },
}

// ---------------------------------------------------------------------------
// Lock service types (design docs #1663 §3-5 / #1248 §4-5)
// ---------------------------------------------------------------------------

/// Hierarchical level for the three-tier sharded lease model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeaseLevel {
    Subtree,
    Inode,
    ByteRange,
}

/// POSIX advisory record lock type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RangeLockType {
    /// F_RDLCK: shared read lock, compatible with other READ locks.
    Read,
    /// F_WRLCK: exclusive write lock, conflicts with any lock on overlapping range.
    Write,
}

/// Lock acquisition status returned by the lock service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LockStatus {
    Granted,
    DeniedConflict,
    DeniedFenced,
    DeniedQuota,
    DeniedNotLeader,
    Queued,
}

/// Identity of a POSIX record lock owner (design spec #1248 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockOwner {
    pub node_id: MemberId,
    pub pid: u32,
    pub owner_key: u64,
}

impl LockOwner {
    pub const fn new(node_id: MemberId, pid: u32, owner_key: u64) -> Self {
        Self {
            node_id,
            pid,
            owner_key,
        }
    }
}

// ---------------------------------------------------------------------------
// Lease lifecycle
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeaseLifecycle {
    Requested,
    Granted,
    Renewing,
    Fenced,
    Released,
    Expired,
    Revoked,
}

impl LeaseLifecycle {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Fenced | Self::Released | Self::Expired | Self::Revoked
        )
    }
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Granted | Self::Renewing)
    }
}

// ---------------------------------------------------------------------------
// Lease grant
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease_id: u64,
    pub lease_class: LeaseClass,
    pub domain: LeaseDomain,
    pub holder_id: MemberId,
    pub dataset_mount_id: u64,
    pub lifecycle: LeaseLifecycle,
    pub granted_at_millis: u64,
    pub term_millis: u64,
    pub expires_at_millis: u64,
    pub renew_by_millis: u64,
    pub grace_period_millis: u64,
    pub epoch: EpochId,
    pub mount_identity: DatasetMountIdentity,
    pub version: u64,
    pub witness_set_id: u64,
    pub witness_confirmations: usize,
    pub witness_total: usize,
}

impl LeaseGrant {
    pub fn request(
        lease_id: u64,
        lease_class: LeaseClass,
        domain: LeaseDomain,
        holder_id: MemberId,
        dataset_mount_id: u64,
        term_millis: u64,
        granted_at_millis: u64,
        epoch: EpochId,
        mount_identity: DatasetMountIdentity,
        witness_set_id: u64,
        witness_confirmations: usize,
        witness_total: usize,
    ) -> Self {
        let expires_at = granted_at_millis.saturating_add(term_millis);
        let renew_by = expires_at.saturating_sub(term_millis / 4);
        let grace_period = term_millis / 8;
        LeaseGrant {
            lease_id,
            lease_class,
            domain,
            holder_id,
            dataset_mount_id,
            lifecycle: LeaseLifecycle::Granted,
            granted_at_millis,
            term_millis,
            expires_at_millis: expires_at,
            renew_by_millis: renew_by,
            grace_period_millis: grace_period,
            epoch,
            mount_identity,
            version: 1,
            witness_set_id,
            witness_confirmations,
            witness_total,
        }
    }

    pub fn is_expired(&self, now_millis: u64) -> bool {
        now_millis
            >= self
                .expires_at_millis
                .saturating_add(self.grace_period_millis)
    }

    pub fn should_renew(&self, now_millis: u64) -> bool {
        now_millis >= self.renew_by_millis && !self.lifecycle.is_terminal()
    }

    pub fn is_stale(&self, now_millis: u64) -> bool {
        let stale_threshold = self
            .expires_at_millis
            .saturating_add(self.grace_period_millis)
            .saturating_add(self.term_millis);
        now_millis >= stale_threshold
    }

    pub fn fence(&mut self) -> Result<(), LeaseError> {
        if self.lifecycle.is_terminal() {
            return Err(LeaseError::AlreadyTerminal {
                lease_id: self.lease_id,
                state: self.lifecycle,
            });
        }
        self.lifecycle = LeaseLifecycle::Fenced;
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), LeaseError> {
        if self.lifecycle.is_terminal() {
            return Err(LeaseError::AlreadyTerminal {
                lease_id: self.lease_id,
                state: self.lifecycle,
            });
        }
        self.lifecycle = LeaseLifecycle::Released;
        Ok(())
    }

    pub fn renew(&mut self, now_millis: u64) -> Result<(), LeaseError> {
        if self.lifecycle.is_terminal() {
            return Err(LeaseError::AlreadyTerminal {
                lease_id: self.lease_id,
                state: self.lifecycle,
            });
        }
        if self.is_expired(now_millis) {
            return Err(LeaseError::Expired {
                lease_id: self.lease_id,
            });
        }
        self.granted_at_millis = now_millis;
        self.expires_at_millis = now_millis.saturating_add(self.term_millis);
        self.renew_by_millis = self.expires_at_millis.saturating_sub(self.term_millis / 4);
        self.version = self.version.saturating_add(1);
        self.lifecycle = LeaseLifecycle::Renewing;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lease receipt
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReceipt {
    pub lease_id: u64,
    pub version: u64,
    pub action: LeaseAction,
    pub verified: bool,
    pub epoch: EpochId,
    pub verified_at_millis: u64,
    pub receipt_digest: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeaseAction {
    Grant,
    Renew,
    Release,
    Fence,
    Revoke,
}

// ---------------------------------------------------------------------------
// Lease errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("lease {lease_id} not found")]
    NotFound { lease_id: u64 },
    #[error("lease {lease_id} already exists")]
    Duplicate { lease_id: u64 },
    #[error("lease {lease_id} already in terminal state {state:?}")]
    AlreadyTerminal {
        lease_id: u64,
        state: LeaseLifecycle,
    },
    #[error("lease {lease_id} has expired")]
    Expired { lease_id: u64 },
    #[error("insufficient witness confirmations: {confirmations} of {total}")]
    InsufficientWitnesses { confirmations: usize, total: usize },
    #[error("holder {holder_id} does not match lease holder {lease_holder_id}")]
    HolderMismatch {
        holder_id: u64,
        lease_holder_id: u64,
    },
    #[error(
        "mount identity mismatch: lease mount {lease_mount:?} != current mount {current_mount:?}"
    )]
    MountIdentityMismatch {
        lease_mount: DatasetMountIdentity,
        current_mount: DatasetMountIdentity,
    },
    #[error("lease {lease_id} is not in epoch {lease_epoch:?}, current is {current_epoch:?}")]
    EpochMismatch {
        lease_id: u64,
        lease_epoch: EpochId,
        current_epoch: EpochId,
    },
    #[error("lease {lease_id} fenced: further mutations rejected")]
    Fenced { lease_id: u64 },
}

// ---------------------------------------------------------------------------
// Pending lock request (design spec §3.5)
// ---------------------------------------------------------------------------

/// A pending blocking lock request enqueued in the LockTable's per-inode FIFO.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingLockRequest {
    pub request_id: u64,
    pub owner: LockOwner,
    pub domain: LeaseDomain,
    pub lease_class: LeaseClass,
    pub enqueued_at_millis: u64,
    pub timeout_millis: u64,
    pub callback_node_id: MemberId,
    pub callback_opaque: u64,
}

impl PendingLockRequest {
    pub fn is_timed_out(&self, now_millis: u64) -> bool {
        now_millis >= self.enqueued_at_millis.saturating_add(self.timeout_millis)
    }
}

// ---------------------------------------------------------------------------
// Raft state machine commands (design spec §5.3)
// ---------------------------------------------------------------------------

/// Commands proposed to the embedded Raft state machine for lock state replication.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RaftCommand {
    Grant {
        grant: LeaseGrant,
    },
    Renew {
        lease_id: u64,
        new_expires_at_millis: u64,
        version: u64,
    },
    Release {
        lease_id: u64,
    },
    Break {
        lease_id: u64,
    },
    Upgrade {
        lease_id: u64,
    },
    Downgrade {
        lease_id: u64,
    },
    Snapshot {
        grants: Vec<LeaseGrant>,
        last_applied: u64,
    },
}

// ---------------------------------------------------------------------------
// Lock service wire protocol / method ID definitions (implementation spec #1248 §5.1)
// ---------------------------------------------------------------------------

/// Lock service wire protocol method identifiers (service_id=0x0A, 18 methods).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum LockMethod {
    Acquire = 0x00,
    AcquireAck = 0x01,
    Renew = 0x02,
    RenewAck = 0x03,
    Release = 0x04,
    ReleaseAck = 0x05,
    Recall = 0x06,
    RecallAck = 0x07,
    Break = 0x08,
    BreakAck = 0x09,
    Getlk = 0x0A,
    GetlkAck = 0x0B,
    Setlk = 0x0C,
    Setlkw = 0x0D,
    SetlkAck = 0x0E,
    LockGrantEvent = 0x0F,
    RecallAll = 0x10,
    RecallAllAck = 0x11,
    Unmount = 0x12,
    UnmountAck = 0x13,
}

impl LockMethod {
    pub const SERVICE_ID: u8 = 0x0A;

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Acquire),
            0x01 => Some(Self::AcquireAck),
            0x02 => Some(Self::Renew),
            0x03 => Some(Self::RenewAck),
            0x04 => Some(Self::Release),
            0x05 => Some(Self::ReleaseAck),
            0x06 => Some(Self::Recall),
            0x07 => Some(Self::RecallAck),
            0x08 => Some(Self::Break),
            0x09 => Some(Self::BreakAck),
            0x0A => Some(Self::Getlk),
            0x0B => Some(Self::GetlkAck),
            0x0C => Some(Self::Setlk),
            0x0D => Some(Self::Setlkw),
            0x0E => Some(Self::SetlkAck),
            0x0F => Some(Self::LockGrantEvent),
            0x10 => Some(Self::RecallAll),
            0x11 => Some(Self::RecallAllAck),
            _ => None,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// LeaseDomain helpers (design spec §2.3, §5.2)
// ---------------------------------------------------------------------------

impl LeaseDomain {
    /// Return the tier level for this lease domain.
    pub fn tier(&self) -> LeaseLevel {
        match self {
            Self::Subtree { .. } => LeaseLevel::Subtree,
            Self::Inode { .. } => LeaseLevel::Inode,
            Self::ByteRange { .. } => LeaseLevel::ByteRange,
            _ => LeaseLevel::Inode,
        }
    }

    /// Extract dataset_id if present.
    pub fn dataset_id(&self) -> Option<u64> {
        match self {
            Self::Subtree { dataset_id, .. }
            | Self::Inode { dataset_id, .. }
            | Self::ByteRange { dataset_id, .. } => Some(*dataset_id),
            _ => None,
        }
    }

    /// Extract inode number if present.
    pub fn ino(&self) -> Option<u64> {
        match self {
            Self::Inode { ino, .. } | Self::ByteRange { ino, .. } => Some(*ino),
            _ => None,
        }
    }

    /// Check whether this domain covers (is an ancestor of) another domain.
    /// A subtree lease covering `/a/b/` covers an inode lease on the same
    /// dataset; an inode lease covers byte-range locks on that inode.
    pub fn covers(&self, other: &LeaseDomain) -> bool {
        match (self, other) {
            (
                Self::Subtree {
                    dataset_id: d1,
                    prefix: p1,
                },
                Self::Subtree {
                    dataset_id: d2,
                    prefix: p2,
                },
            ) => d1 == d2 && subtree_prefix_is_descendant(p1, p2),
            (Self::Subtree { dataset_id: d1, .. }, Self::Inode { dataset_id: d2, .. }) => d1 == d2,
            (Self::Subtree { dataset_id: d1, .. }, Self::ByteRange { dataset_id: d2, .. }) => {
                d1 == d2
            }
            (
                Self::Inode {
                    dataset_id: d1,
                    ino: i1,
                },
                Self::Inode {
                    dataset_id: d2,
                    ino: i2,
                },
            ) => d1 == d2 && i1 == i2,
            (
                Self::Inode {
                    dataset_id: d1,
                    ino: i1,
                },
                Self::ByteRange {
                    dataset_id: d2,
                    ino: i2,
                    ..
                },
            ) => d1 == d2 && i1 == i2,
            (
                Self::ByteRange {
                    dataset_id: d1,
                    ino: i1,
                    start: s1,
                    end: e1,
                },
                Self::ByteRange {
                    dataset_id: d2,
                    ino: i2,
                    start: s2,
                    end: e2,
                },
            ) => d1 == d2 && i1 == i2 && *s1 <= *s2 && *e1 >= *e2,
            _ => false,
        }
    }
}

/// Check if `descendant` prefix is a child subtree of `ancestor` prefix.
/// Both must be canonicalized with trailing `/`.
/// Root `"/"` covers everything.
pub fn subtree_prefix_is_descendant(ancestor: &str, descendant: &str) -> bool {
    if ancestor == "/" {
        return true;
    }
    descendant.starts_with(ancestor)
}

/// Check if two subtree prefixes overlap (one covers the other).
pub fn subtree_overlap(a: &str, b: &str) -> bool {
    subtree_prefix_is_descendant(a, b) || subtree_prefix_is_descendant(b, a)
}
