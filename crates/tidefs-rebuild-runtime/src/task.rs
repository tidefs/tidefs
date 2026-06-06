//! BackfillTask: a single data-movement work item scoped to one
//! replica placement (source → target), carrying priority, retry
//! budget, and a creation deadline so the scheduler can age out
//! stale tasks.

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{
    ObjectDigest, PlacementReceiptRef, ReplicaMovementClass, ReplicatedSubjectId,
};

/// Maximum retry attempts before a task is permanently failed.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// A single backfill data-movement task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackfillTask {
    /// Object to replicate.
    pub subject_ref: ReplicatedSubjectId,
    /// Source placement receipt that authorizes the bytes being moved.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Source member that holds a healthy copy.
    pub source_member: MemberId,
    /// Target member to receive the replica.
    pub target_member: MemberId,
    /// Movement class (rebuild, backfill, rebalance).
    pub movement_class: ReplicaMovementClass,
    /// Expected BLAKE3 digest of the payload.
    pub payload_digest: ObjectDigest,
    /// Payload size in bytes.
    pub payload_len: u64,
    /// Monotonic creation timestamp (nanoseconds since some epoch).
    pub created_at_ns: u64,
    /// Deadline after which the task is considered stale.
    pub deadline_ns: u64,
    /// Maximum number of retries before failing permanently.
    pub max_retries: u32,
    /// Retry count consumed so far.
    pub retries_consumed: u32,
}

/// Inputs for creating a [`BackfillTask`] with the default retry budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackfillTaskInit {
    pub subject_ref: ReplicatedSubjectId,
    pub placement_receipt_ref: PlacementReceiptRef,
    pub source_member: MemberId,
    pub target_member: MemberId,
    pub movement_class: ReplicaMovementClass,
    pub payload_digest: ObjectDigest,
    pub payload_len: u64,
    pub created_at_ns: u64,
    pub deadline_ns: u64,
}

impl BackfillTask {
    /// Create a new backfill task with default retry budget.
    #[must_use]
    pub fn new(init: BackfillTaskInit) -> Self {
        Self {
            subject_ref: init.subject_ref,
            placement_receipt_ref: init.placement_receipt_ref,
            source_member: init.source_member,
            target_member: init.target_member,
            movement_class: init.movement_class,
            payload_digest: init.payload_digest,
            payload_len: init.payload_len,
            created_at_ns: init.created_at_ns,
            deadline_ns: init.deadline_ns,
            max_retries: DEFAULT_MAX_RETRIES,
            retries_consumed: 0,
        }
    }

    /// Create a task with a custom retry budget.
    #[must_use]
    pub fn with_retry_budget(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Whether the task has any remaining retry budget.
    #[must_use]
    pub fn can_retry(&self) -> bool {
        self.retries_consumed < self.max_retries
    }

    /// Consume one retry attempt. Returns `true` if a retry was available.
    pub fn consume_retry(&mut self) -> bool {
        if self.can_retry() {
            self.retries_consumed += 1;
            true
        } else {
            false
        }
    }

    /// Whether the task has exceeded its deadline.
    #[must_use]
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.deadline_ns
    }

    /// Canonical deduplication key: (subject, target_member).
    #[must_use]
    pub fn dedup_key(&self) -> (ReplicatedSubjectId, MemberId) {
        (self.subject_ref, self.target_member)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> BackfillTask {
        BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(1),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(1),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(0xABCD),
            payload_len: 4096,
            created_at_ns: 1000,
            deadline_ns: 5000,
        })
    }

    #[test]
    fn retry_budget_exhaustion() {
        let mut t = task().with_retry_budget(2);
        assert!(t.can_retry());
        assert!(t.consume_retry());
        assert_eq!(t.retries_consumed, 1);
        assert!(t.can_retry());
        assert!(t.consume_retry());
        assert_eq!(t.retries_consumed, 2);
        assert!(!t.can_retry());
        assert!(!t.consume_retry());
    }

    #[test]
    fn deadline_expiry() {
        let t = task();
        assert!(!t.is_expired(4000));
        assert!(t.is_expired(5000));
        assert!(t.is_expired(6000));
    }

    #[test]
    fn dedup_key_uniqueness() {
        let a = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(1),
            target_member: MemberId::new(2),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: ObjectDigest::new(0x99),
            payload_len: 1024,
            created_at_ns: 0,
            deadline_ns: 100,
        });
        let b = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(99),
            target_member: MemberId::new(2),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: ObjectDigest::new(0x99),
            payload_len: 1024,
            created_at_ns: 0,
            deadline_ns: 100,
        });
        // Same (subject, target) -> same dedup key even if source differs
        assert_eq!(a.dedup_key(), b.dedup_key());

        let c = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(1),
            target_member: MemberId::new(3),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: ObjectDigest::new(0x99),
            payload_len: 1024,
            created_at_ns: 0,
            deadline_ns: 100,
        });
        assert_ne!(a.dedup_key(), c.dedup_key());
    }

    #[test]
    fn default_max_retries_is_3() {
        let t = task();
        assert_eq!(t.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(t.retries_consumed, 0);
    }
}
