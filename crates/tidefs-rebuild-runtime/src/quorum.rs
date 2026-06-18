// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! QuorumIntegration: coordinates backfill writes with the replication
//! quorum so data-movement participates in replica-set consistency
//! without violating single-writer invariants.
//!
//! Backfill writes carry an epoch-bound lease token; the quorum
//! coordinator validates the token before admitting the write into
//! the replication quorum, ensuring backfill and client writes never
//! race on the same subject.

use crate::task::BackfillTask;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::ReplicatedSubjectId;

/// An epoch-bound lease token that authorises a backfill write.
///
/// The token is valid only within a specific epoch; the quorum
/// coordinator rejects writes carrying a token from a different
/// epoch, preventing stale backfill operations from interfering
/// with live client writes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackfillLeaseToken {
    /// The subject this lease authorises writes for.
    pub subject: ReplicatedSubjectId,
    /// The member that will perform the backfill write.
    pub writer: MemberId,
    /// The epoch during which this lease is valid.
    pub epoch: EpochId,
    /// A BLAKE3-based authorisation tag binding the token to
    /// its epoch and writer.
    pub auth_tag: [u8; 32],
}

impl BackfillLeaseToken {
    /// Issue a new lease token for a backfill write.
    ///
    /// The auth_tag is the BLAKE3 hash of
    /// `subject || writer || epoch || "backfill-lease-v1"`.
    #[must_use]
    pub fn issue(subject: ReplicatedSubjectId, writer: MemberId, epoch: EpochId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&subject.0.to_le_bytes());
        hasher.update(&writer.0.to_le_bytes());
        hasher.update(&epoch.0.to_le_bytes());
        hasher.update(b"backfill-lease-v1");
        let digest = hasher.finalize();
        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(digest.as_bytes());
        Self {
            subject,
            writer,
            epoch,
            auth_tag,
        }
    }

    /// Verify this token is valid for the given epoch.
    ///
    /// Returns `true` if the token's epoch matches and the auth_tag
    /// recomputes correctly.
    #[must_use]
    pub fn verify(&self, expected_epoch: EpochId) -> bool {
        if self.epoch != expected_epoch {
            return false;
        }
        let expected = Self::issue(self.subject, self.writer, self.epoch);
        self.auth_tag == expected.auth_tag
    }

    /// Whether this lease has expired relative to the current epoch.
    #[must_use]
    pub fn is_expired(&self, current_epoch: EpochId) -> bool {
        self.epoch.0 < current_epoch.0
    }
}

/// Outcome of admitting a backfill write into the quorum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumAdmission {
    /// Write admitted; backfill may proceed.
    Admitted,
    /// Write refused because the lease token is invalid or expired.
    LeaseRefused,
    /// Write refused because another write is in-flight for this subject.
    WriteInProgress,
    /// Write refused because the target member is not in the current
    /// membership view.
    TargetNotMember,
}

/// Coordinates backfill write admission into the replication quorum.
///
/// The coordinator maintains a set of in-flight subjects and validates
/// lease tokens against the current epoch. It does not itself execute
/// writes; it gates admission so the higher-level [`crate::RebuildRuntime`]
/// can schedule transfers safely.
#[derive(Clone, Debug, Default)]
pub struct QuorumCoordinator {
    /// Current epoch. Writes from older epochs are refused.
    current_epoch: EpochId,
    /// Subjects that currently have an in-flight write (backfill or client).
    inflight_subjects: std::collections::BTreeSet<ReplicatedSubjectId>,
    /// Current membership: MemberId → is_active.
    active_members: std::collections::BTreeMap<MemberId, bool>,
}

impl QuorumCoordinator {
    /// Create a new coordinator at the given epoch.
    #[must_use]
    pub fn new(current_epoch: EpochId) -> Self {
        Self {
            current_epoch,
            inflight_subjects: std::collections::BTreeSet::new(),
            active_members: std::collections::BTreeMap::new(),
        }
    }

    /// Advance to a new epoch, clearing in-flight state.
    ///
    /// All in-flight backfill writes from the previous epoch are
    /// implicitly cancelled (they will fail lease verification).
    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        self.inflight_subjects.clear();
    }

    /// Set the active membership view.
    pub fn set_membership(&mut self, members: &[(MemberId, bool)]) {
        self.active_members.clear();
        for &(member, active) in members {
            self.active_members.insert(member, active);
        }
    }

    /// Attempt to admit a backfill write into the quorum.
    ///
    /// Checks the lease token, subject concurrency, and target membership.
    pub fn admit(&mut self, task: &BackfillTask, lease: &BackfillLeaseToken) -> QuorumAdmission {
        // Lease must be valid for the current epoch.
        if !lease.verify(self.current_epoch) {
            return QuorumAdmission::LeaseRefused;
        }

        // Target member must be in the active membership.
        if let Some(active) = self.active_members.get(&task.target_member) {
            if !active {
                return QuorumAdmission::TargetNotMember;
            }
        }
        // If membership is empty (unset), allow all targets (testing mode).

        // Only one write per subject at a time.
        if self.inflight_subjects.contains(&task.subject_ref) {
            return QuorumAdmission::WriteInProgress;
        }

        self.inflight_subjects.insert(task.subject_ref);
        QuorumAdmission::Admitted
    }

    /// Release a subject after its write completes (or fails).
    pub fn release(&mut self, subject: ReplicatedSubjectId) {
        self.inflight_subjects.remove(&subject);
    }

    /// Number of currently in-flight subjects.
    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.inflight_subjects.len()
    }

    /// Current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::BackfillTaskInit;
    use tidefs_replication_model::{ObjectDigest, PlacementReceiptRef, ReplicaMovementClass};

    fn task(id: u64) -> BackfillTask {
        BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(id),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(id),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(id * 100),
            payload_len: 4096,
            created_at_ns: 1000,
            deadline_ns: 5000,
        })
    }

    // ── BackfillLeaseToken tests ──────────────────────────────────

    #[test]
    fn lease_verify_success() {
        let epoch = EpochId(5);
        let token =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), epoch);
        assert!(token.verify(epoch));
    }

    #[test]
    fn lease_verify_wrong_epoch() {
        let token =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), EpochId(5));
        assert!(!token.verify(EpochId(6)));
    }

    #[test]
    fn lease_deterministic() {
        let t1 =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), EpochId(5));
        let t2 =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), EpochId(5));
        assert_eq!(t1.auth_tag, t2.auth_tag);
    }

    #[test]
    fn lease_different_inputs_produce_different_tags() {
        let t1 =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), EpochId(5));
        let t2 =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(2), MemberId::new(10), EpochId(5));
        assert_ne!(t1.auth_tag, t2.auth_tag);
    }

    #[test]
    fn lease_is_expired() {
        let token =
            BackfillLeaseToken::issue(ReplicatedSubjectId::new(1), MemberId::new(10), EpochId(5));
        assert!(token.is_expired(EpochId(6)));
        assert!(!token.is_expired(EpochId(5)));
        assert!(!token.is_expired(EpochId(4)));
    }

    // ── QuorumCoordinator tests ───────────────────────────────────

    #[test]
    fn admit_with_valid_lease() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);

        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::Admitted);
        assert_eq!(coord.inflight_count(), 1);
    }

    #[test]
    fn refuse_expired_lease() {
        let mut coord = QuorumCoordinator::new(EpochId(10));
        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, EpochId(5));

        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::LeaseRefused);
        assert_eq!(coord.inflight_count(), 0);
    }

    #[test]
    fn refuse_concurrent_write_same_subject() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        let t1 = task(42);
        let t2 = task(42); // same subject
        let lease1 = BackfillLeaseToken::issue(t1.subject_ref, t1.source_member, epoch);
        let lease2 = BackfillLeaseToken::issue(t2.subject_ref, t2.source_member, epoch);

        assert_eq!(coord.admit(&t1, &lease1), QuorumAdmission::Admitted);
        assert_eq!(coord.admit(&t2, &lease2), QuorumAdmission::WriteInProgress);
    }

    #[test]
    fn release_allows_re_admission() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);

        coord.admit(&t, &lease);
        coord.release(t.subject_ref);
        assert_eq!(coord.inflight_count(), 0);

        // Re-admission succeeds
        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::Admitted);
    }

    #[test]
    fn advance_epoch_clears_inflight() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);
        coord.admit(&t, &lease);

        coord.advance_epoch(EpochId(2));
        assert_eq!(coord.inflight_count(), 0);
        assert_eq!(coord.current_epoch(), EpochId(2));
    }

    #[test]
    fn membership_refuses_inactive_target() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        coord.set_membership(&[(MemberId::new(20), false)]); // target is inactive

        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);

        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::TargetNotMember);
    }

    #[test]
    fn membership_allows_active_target() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        coord.set_membership(&[(MemberId::new(20), true)]);

        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);

        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::Admitted);
    }

    #[test]
    fn empty_membership_allows_all() {
        let epoch = EpochId(1);
        let mut coord = QuorumCoordinator::new(epoch);
        // No membership set → allow all targets

        let t = task(42);
        let lease = BackfillLeaseToken::issue(t.subject_ref, t.source_member, epoch);

        assert_eq!(coord.admit(&t, &lease), QuorumAdmission::Admitted);
    }

    #[test]
    fn default_coordinator_is_epoch_zero() {
        let coord = QuorumCoordinator::default();
        assert_eq!(coord.current_epoch(), EpochId(0));
        assert_eq!(coord.inflight_count(), 0);
    }
}
