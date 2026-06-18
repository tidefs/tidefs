// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write-fence mechanism preventing split ownership in the multi-node write path.
//!
//! When a node acquires the single-writer lease, the [`FenceAuthority`] generates
//! a new [`WriteFence`] token with a strictly-increasing generation counter.
//! Every write submitted to the transport layer carries its sender's current
//! fence token. The transport-side [`WriteGate`] (in `tidefs-transport`) compares
//! the write's fence against the active authoritative fence and rejects writes
//! carrying a stale (older) fence.
//!
//! ## Architecture
//!
//! - [`WriteFence`]: an opaque, ordered token pairing an epoch with a monotonic
//!   generation counter. Earlier fences are strictly less than later ones.
//! - [`FenceAuthority`]: held by the cluster lease runtime. Issues a new
//!   `WriteFence` on single-writer lease acquisition.
//! - [`FenceValidator`]: compares an inbound write's fence against the currently
//!   active fence. Returns `Ok(())` when the write's fence matches the active
//!   fence (i.e. was issued by the current lease holder), or
//!   `Err(StaleFence)` when the write carries an older fence from a previous
//!   lease holder.
//!
//! ## Integration
//!
//! The [`FenceAuthority`] is wired into
//! [`ClusterLeaseRuntime`](crate::runtime::ClusterLeaseRuntime):
//! when `handle_incoming` processes an `AcquireAck` and the state machine
//! transitions to `Held`, the runtime calls `FenceAuthority::issue_fence()`
//! and stores the result as the active fence. The transport layer then
//! consults the active fence via [`WriteGate`] before dispatching writes
//! to the storage layer.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tidefs_membership_epoch::EpochId;

/// An opaque, ordered fence token issued by the lease authority when a node
/// acquires the single-writer lease.
///
/// Comparison is lexicographic on (`epoch`, `generation`). An earlier epoch
/// is strictly less than a later epoch. Within the same epoch, a smaller
/// generation is less than a larger generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFence {
    pub epoch: EpochId,
    pub generation: u64,
}

impl WriteFence {
    pub fn new(epoch: EpochId, generation: u64) -> Self {
        Self { epoch, generation }
    }

    pub fn is_later_than(&self, other: &WriteFence) -> bool {
        self > other
    }

    pub fn is_stale_against(&self, other: &WriteFence) -> bool {
        self < other
    }
}

impl PartialOrd for WriteFence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WriteFence {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .0
            .cmp(&other.epoch.0)
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

impl std::fmt::Display for WriteFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WriteFence(e{:?}.g{})", self.epoch, self.generation)
    }
}

/// Error returned when a write carries a fence token older than the
/// currently active fence.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("stale write fence: write carries {write_fence}, active is {active_fence}")]
pub struct StaleFence {
    pub write_fence: WriteFence,
    pub active_fence: WriteFence,
}

impl StaleFence {
    pub fn new(write_fence: WriteFence, active_fence: WriteFence) -> Self {
        Self {
            write_fence,
            active_fence,
        }
    }
}

/// Generates and tracks the active write fence.
///
/// Held by the [`ClusterLeaseRuntime`](crate::runtime::ClusterLeaseRuntime).
/// Each call to [`issue_fence`](FenceAuthority::issue_fence) produces a
/// strictly-greater [`WriteFence`] token than the previous one.
#[derive(Clone, Debug)]
pub struct FenceAuthority {
    active: Arc<std::sync::RwLock<Option<WriteFence>>>,
    next_gen: Arc<AtomicU64>,
}

impl FenceAuthority {
    pub fn new() -> Self {
        Self {
            active: Arc::new(std::sync::RwLock::new(None)),
            next_gen: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn issue_fence(&self, epoch: EpochId) -> WriteFence {
        let generation = self.next_gen.fetch_add(1, AtomicOrdering::Relaxed);
        let fence = WriteFence::new(epoch, generation);
        let mut active = self.active.write().expect("lock poisoned");
        *active = Some(fence);
        fence
    }

    pub fn active_fence(&self) -> Option<WriteFence> {
        *self.active.read().expect("lock poisoned")
    }

    pub fn validator(&self) -> FenceValidator {
        FenceValidator {
            active: Arc::clone(&self.active),
        }
    }

    pub fn clear(&self) {
        let mut active = self.active.write().expect("lock poisoned");
        *active = None;
    }
}

impl Default for FenceAuthority {
    fn default() -> Self {
        Self::new()
    }
}

/// A shareable read-only view of the active write fence, used by the
/// transport layer to validate write requests before dispatching them
/// to the storage layer.
#[derive(Clone, Debug)]
pub struct FenceValidator {
    active: Arc<std::sync::RwLock<Option<WriteFence>>>,
}

impl FenceValidator {
    pub fn validate(&self, write_fence: WriteFence) -> Result<(), StaleFence> {
        let active = self.active.read().expect("lock poisoned");
        match *active {
            None => Err(StaleFence::new(write_fence, WriteFence::new(EpochId(0), 0))),
            Some(active_fence) => {
                if write_fence == active_fence {
                    Ok(())
                } else {
                    Err(StaleFence::new(write_fence, active_fence))
                }
            }
        }
    }

    pub fn active_fence(&self) -> Option<WriteFence> {
        *self.active.read().expect("lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(id: u64) -> EpochId {
        EpochId(id)
    }

    #[test]
    fn fence_ordering_within_epoch() {
        let f1 = WriteFence::new(epoch(1), 1);
        let f2 = WriteFence::new(epoch(1), 2);
        let f3 = WriteFence::new(epoch(1), 3);
        assert!(f1 < f2);
        assert!(f2 < f3);
        assert!(f1 < f3);
        assert!((f2 >= f1));
    }

    #[test]
    fn fence_ordering_across_epochs() {
        let f1 = WriteFence::new(epoch(1), 100);
        let f2 = WriteFence::new(epoch(2), 1);
        assert!(f1 < f2);
    }

    #[test]
    fn fence_equality() {
        let f1 = WriteFence::new(epoch(1), 5);
        let f2 = WriteFence::new(epoch(1), 5);
        assert_eq!(f1, f2);
    }

    #[test]
    fn is_stale_against() {
        let old = WriteFence::new(epoch(1), 1);
        let new = WriteFence::new(epoch(1), 2);
        assert!(old.is_stale_against(&new));
        assert!(!new.is_stale_against(&old));
    }

    #[test]
    fn serialize_deserialize() {
        let fence = WriteFence::new(epoch(3), 42);
        let json = serde_json::to_string(&fence).unwrap();
        let restored: WriteFence = serde_json::from_str(&json).unwrap();
        assert_eq!(fence, restored);
    }

    #[test]
    fn authority_starts_with_no_active_fence() {
        let auth = FenceAuthority::new();
        assert!(auth.active_fence().is_none());
    }

    #[test]
    fn issue_fence_returns_increasing_tokens() {
        let auth = FenceAuthority::new();
        let f1 = auth.issue_fence(epoch(1));
        let f2 = auth.issue_fence(epoch(1));
        let f3 = auth.issue_fence(epoch(2));
        assert_eq!(f1.generation, 1);
        assert_eq!(f2.generation, 2);
        assert_eq!(f3.generation, 3);
        assert!(f1 < f2);
        assert!(f2 < f3);
    }

    #[test]
    fn active_fence_tracks_latest() {
        let auth = FenceAuthority::new();
        let f1 = auth.issue_fence(epoch(1));
        assert_eq!(auth.active_fence(), Some(f1));
        let f2 = auth.issue_fence(epoch(2));
        assert_eq!(auth.active_fence(), Some(f2));
    }

    #[test]
    fn clear_removes_active_fence() {
        let auth = FenceAuthority::new();
        auth.issue_fence(epoch(1));
        assert!(auth.active_fence().is_some());
        auth.clear();
        assert!(auth.active_fence().is_none());
    }

    #[test]
    fn validator_accepts_active_fence() {
        let auth = FenceAuthority::new();
        let fence = auth.issue_fence(epoch(1));
        let validator = auth.validator();
        assert!(validator.validate(fence).is_ok());
    }

    #[test]
    fn validator_rejects_stale_fence() {
        let auth = FenceAuthority::new();
        let old_fence = auth.issue_fence(epoch(1));
        let _new_fence = auth.issue_fence(epoch(1));
        let validator = auth.validator();
        let result = validator.validate(old_fence);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.write_fence, old_fence);
    }

    #[test]
    fn validator_rejects_when_no_active_fence() {
        let auth = FenceAuthority::new();
        let validator = auth.validator();
        let fence = WriteFence::new(epoch(1), 1);
        assert!(validator.validate(fence).is_err());
    }

    #[test]
    fn validator_sees_active_fence_updates() {
        let auth = FenceAuthority::new();
        let validator = auth.validator();
        let f1 = auth.issue_fence(epoch(1));
        assert_eq!(validator.active_fence(), Some(f1));
        let f2 = auth.issue_fence(epoch(1));
        assert_eq!(validator.active_fence(), Some(f2));
        assert!(validator.validate(f1).is_err());
        assert!(validator.validate(f2).is_ok());
    }

    #[test]
    fn validator_clone_shares_state() {
        let auth = FenceAuthority::new();
        let v1 = auth.validator();
        let v2 = auth.validator();
        let fence = auth.issue_fence(epoch(1));
        assert_eq!(v1.active_fence(), Some(fence));
        assert_eq!(v2.active_fence(), Some(fence));
    }
}
