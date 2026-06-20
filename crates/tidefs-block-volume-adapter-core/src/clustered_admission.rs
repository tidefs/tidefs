// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clustered writable block-export admission gate.
//!
//! This module is a deterministic authority check over already-produced
//! membership, lease/authority, reserve, and receipt-continuity evidence. It
//! does not acquire leases, contact membership, or mutate ublk state.

use crate::{BlockVolumeId, BlockVolumeReceiptId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeClusteredAdmissionClass {
    Admitted,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeClusteredAdmissionRefusal {
    MissingProjectionIdentity,
    MissingMembership,
    StaleMembershipEpoch,
    MissingWriterAuthority,
    StaleWriterAuthority,
    MultipleWritableAuthorities,
    MissingReserveEscrow,
    StaleReserveEscrow,
    MissingReceiptContinuity,
    StaleReceiptContinuity,
}

impl BlockVolumeClusteredAdmissionRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingProjectionIdentity => "missing_projection_identity",
            Self::MissingMembership => "missing_membership",
            Self::StaleMembershipEpoch => "stale_membership_epoch",
            Self::MissingWriterAuthority => "missing_writer_authority",
            Self::StaleWriterAuthority => "stale_writer_authority",
            Self::MultipleWritableAuthorities => "multiple_writable_authorities",
            Self::MissingReserveEscrow => "missing_reserve_escrow",
            Self::StaleReserveEscrow => "stale_reserve_escrow",
            Self::MissingReceiptContinuity => "missing_receipt_continuity",
            Self::StaleReceiptContinuity => "stale_receipt_continuity",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeClusterWriterClass {
    SingleWritableAuthority,
    MultiWritableAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeClusterReserveEscrowStatus {
    Current,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusteredExportIdentityRecord {
    pub volume_id: BlockVolumeId,
    pub projection_root_ref: BlockVolumeReceiptId,
    pub export_instance_ref: BlockVolumeReceiptId,
    pub export_generation: u64,
}

impl BlockVolumeClusteredExportIdentityRecord {
    #[must_use]
    pub const fn is_present(self) -> bool {
        receipt_present(self.projection_root_ref)
            && receipt_present(self.export_instance_ref)
            && self.export_generation > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusterMembershipEpochRecord {
    pub membership_epoch: u64,
    pub membership_epoch_ref: BlockVolumeReceiptId,
    pub observed_at_millis: u64,
    pub valid_until_millis: u64,
}

impl BlockVolumeClusterMembershipEpochRecord {
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.membership_epoch > 0 && receipt_present(self.membership_epoch_ref)
    }

    #[must_use]
    pub const fn is_current_for(self, policy: BlockVolumeClusteredAdmissionPolicy) -> bool {
        self.is_present()
            && self.membership_epoch >= policy.minimum_membership_epoch
            && self.observed_at_millis <= policy.now_millis
            && policy.now_millis <= self.valid_until_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusterWriterAuthorityRecord {
    pub writer_authority_ref: BlockVolumeReceiptId,
    pub authority_domain_ref: BlockVolumeReceiptId,
    pub writer_member_ref: BlockVolumeReceiptId,
    pub lease_membership_epoch: u64,
    pub lease_expires_at_millis: u64,
    pub writer_class: BlockVolumeClusterWriterClass,
    pub active_writer_count: u16,
    pub fenced: bool,
}

impl BlockVolumeClusterWriterAuthorityRecord {
    #[must_use]
    pub const fn is_present(self) -> bool {
        receipt_present(self.writer_authority_ref)
            && receipt_present(self.authority_domain_ref)
            && receipt_present(self.writer_member_ref)
            && self.lease_membership_epoch > 0
            && self.active_writer_count > 0
    }

    #[must_use]
    pub const fn is_single_writer(self) -> bool {
        matches!(
            self.writer_class,
            BlockVolumeClusterWriterClass::SingleWritableAuthority
        ) && self.active_writer_count == 1
    }

    #[must_use]
    pub const fn is_current_for(
        self,
        membership: BlockVolumeClusterMembershipEpochRecord,
        policy: BlockVolumeClusteredAdmissionPolicy,
    ) -> bool {
        self.is_present()
            && !self.fenced
            && self.lease_membership_epoch == membership.membership_epoch
            && policy.now_millis < self.lease_expires_at_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusterReserveEscrowRecord {
    pub reserve_escrow_ref: BlockVolumeReceiptId,
    pub reserve_budget_ref: BlockVolumeReceiptId,
    pub reserve_membership_epoch: u64,
    pub status: BlockVolumeClusterReserveEscrowStatus,
}

impl BlockVolumeClusterReserveEscrowRecord {
    #[must_use]
    pub const fn is_present(self) -> bool {
        receipt_present(self.reserve_escrow_ref)
            && receipt_present(self.reserve_budget_ref)
            && self.reserve_membership_epoch > 0
    }

    #[must_use]
    pub const fn is_current_for(self, membership: BlockVolumeClusterMembershipEpochRecord) -> bool {
        self.is_present()
            && matches!(self.status, BlockVolumeClusterReserveEscrowStatus::Current)
            && self.reserve_membership_epoch == membership.membership_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusterReceiptContinuityRecord {
    pub last_flush_barrier_ref: BlockVolumeReceiptId,
    pub last_durability_receipt_ref: BlockVolumeReceiptId,
    pub continuity_membership_epoch: u64,
    pub contiguous: bool,
}

impl BlockVolumeClusterReceiptContinuityRecord {
    #[must_use]
    pub const fn is_present(self) -> bool {
        receipt_present(self.last_flush_barrier_ref)
            && receipt_present(self.last_durability_receipt_ref)
            && self.continuity_membership_epoch > 0
    }

    #[must_use]
    pub const fn is_current_for(self, membership: BlockVolumeClusterMembershipEpochRecord) -> bool {
        self.is_present()
            && self.contiguous
            && self.continuity_membership_epoch == membership.membership_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusteredAdmissionPolicy {
    pub now_millis: u64,
    pub minimum_membership_epoch: u64,
    pub require_single_writer: bool,
}

impl BlockVolumeClusteredAdmissionPolicy {
    #[must_use]
    pub const fn at_millis(now_millis: u64, minimum_membership_epoch: u64) -> Self {
        Self {
            now_millis,
            minimum_membership_epoch,
            require_single_writer: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusteredAdmissionInput {
    pub identity: BlockVolumeClusteredExportIdentityRecord,
    pub policy: BlockVolumeClusteredAdmissionPolicy,
    pub membership: Option<BlockVolumeClusterMembershipEpochRecord>,
    pub writer_authority: Option<BlockVolumeClusterWriterAuthorityRecord>,
    pub reserve_escrow: Option<BlockVolumeClusterReserveEscrowRecord>,
    pub receipt_continuity: Option<BlockVolumeClusterReceiptContinuityRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeClusteredExportAdmissionRecord {
    pub admission_id: BlockVolumeReceiptId,
    pub admission_class: BlockVolumeClusteredAdmissionClass,
    pub refusal_class: Option<BlockVolumeClusteredAdmissionRefusal>,
    pub identity: BlockVolumeClusteredExportIdentityRecord,
    pub membership: Option<BlockVolumeClusterMembershipEpochRecord>,
    pub writer_authority: Option<BlockVolumeClusterWriterAuthorityRecord>,
    pub reserve_escrow: Option<BlockVolumeClusterReserveEscrowRecord>,
    pub receipt_continuity: Option<BlockVolumeClusterReceiptContinuityRecord>,
}

#[must_use]
pub fn admit_clustered_block_export(
    input: BlockVolumeClusteredAdmissionInput,
) -> BlockVolumeClusteredExportAdmissionRecord {
    let refusal = classify_clustered_admission(input);
    BlockVolumeClusteredExportAdmissionRecord {
        admission_id: clustered_admission_id(input.identity),
        admission_class: if refusal.is_some() {
            BlockVolumeClusteredAdmissionClass::Refused
        } else {
            BlockVolumeClusteredAdmissionClass::Admitted
        },
        refusal_class: refusal,
        identity: input.identity,
        membership: input.membership,
        writer_authority: input.writer_authority,
        reserve_escrow: input.reserve_escrow,
        receipt_continuity: input.receipt_continuity,
    }
}

fn classify_clustered_admission(
    input: BlockVolumeClusteredAdmissionInput,
) -> Option<BlockVolumeClusteredAdmissionRefusal> {
    if !input.identity.is_present() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingProjectionIdentity);
    }

    let Some(membership) = input.membership else {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingMembership);
    };
    if !membership.is_present() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingMembership);
    }
    if !membership.is_current_for(input.policy) {
        return Some(BlockVolumeClusteredAdmissionRefusal::StaleMembershipEpoch);
    }

    let Some(writer_authority) = input.writer_authority else {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingWriterAuthority);
    };
    if !writer_authority.is_present() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingWriterAuthority);
    }
    if !writer_authority.is_current_for(membership, input.policy) {
        return Some(BlockVolumeClusteredAdmissionRefusal::StaleWriterAuthority);
    }
    if input.policy.require_single_writer && !writer_authority.is_single_writer() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MultipleWritableAuthorities);
    }

    let Some(reserve_escrow) = input.reserve_escrow else {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingReserveEscrow);
    };
    if !reserve_escrow.is_present() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingReserveEscrow);
    }
    if !reserve_escrow.is_current_for(membership) {
        return Some(BlockVolumeClusteredAdmissionRefusal::StaleReserveEscrow);
    }

    let Some(receipt_continuity) = input.receipt_continuity else {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingReceiptContinuity);
    };
    if !receipt_continuity.is_present() {
        return Some(BlockVolumeClusteredAdmissionRefusal::MissingReceiptContinuity);
    }
    if !receipt_continuity.is_current_for(membership) {
        return Some(BlockVolumeClusteredAdmissionRefusal::StaleReceiptContinuity);
    }

    None
}

const fn receipt_present(receipt: BlockVolumeReceiptId) -> bool {
    receipt.0 != 0
}

const fn clustered_admission_id(
    identity: BlockVolumeClusteredExportIdentityRecord,
) -> BlockVolumeReceiptId {
    BlockVolumeReceiptId(
        0x6210_0000_0000_0000
            ^ identity.volume_id.0
            ^ identity.projection_root_ref.0.rotate_left(7)
            ^ identity.export_instance_ref.0.rotate_left(17)
            ^ identity.export_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockVolumeExportLifecycleRuntime, BlockVolumeExportPhaseClass,
        BlockVolumeExportTransitionOutcomeClass, BlockVolumeGeometryRecord,
    };

    fn identity() -> BlockVolumeClusteredExportIdentityRecord {
        BlockVolumeClusteredExportIdentityRecord {
            volume_id: BlockVolumeId::new(621),
            projection_root_ref: BlockVolumeReceiptId(10),
            export_instance_ref: BlockVolumeReceiptId(11),
            export_generation: 1,
        }
    }

    fn membership() -> BlockVolumeClusterMembershipEpochRecord {
        BlockVolumeClusterMembershipEpochRecord {
            membership_epoch: 7,
            membership_epoch_ref: BlockVolumeReceiptId(20),
            observed_at_millis: 100,
            valid_until_millis: 200,
        }
    }

    fn writer_authority() -> BlockVolumeClusterWriterAuthorityRecord {
        BlockVolumeClusterWriterAuthorityRecord {
            writer_authority_ref: BlockVolumeReceiptId(30),
            authority_domain_ref: BlockVolumeReceiptId(31),
            writer_member_ref: BlockVolumeReceiptId(32),
            lease_membership_epoch: 7,
            lease_expires_at_millis: 190,
            writer_class: BlockVolumeClusterWriterClass::SingleWritableAuthority,
            active_writer_count: 1,
            fenced: false,
        }
    }

    fn reserve_escrow() -> BlockVolumeClusterReserveEscrowRecord {
        BlockVolumeClusterReserveEscrowRecord {
            reserve_escrow_ref: BlockVolumeReceiptId(40),
            reserve_budget_ref: BlockVolumeReceiptId(41),
            reserve_membership_epoch: 7,
            status: BlockVolumeClusterReserveEscrowStatus::Current,
        }
    }

    fn receipt_continuity() -> BlockVolumeClusterReceiptContinuityRecord {
        BlockVolumeClusterReceiptContinuityRecord {
            last_flush_barrier_ref: BlockVolumeReceiptId(50),
            last_durability_receipt_ref: BlockVolumeReceiptId(51),
            continuity_membership_epoch: 7,
            contiguous: true,
        }
    }

    fn coherent_input() -> BlockVolumeClusteredAdmissionInput {
        BlockVolumeClusteredAdmissionInput {
            identity: identity(),
            policy: BlockVolumeClusteredAdmissionPolicy::at_millis(150, 7),
            membership: Some(membership()),
            writer_authority: Some(writer_authority()),
            reserve_escrow: Some(reserve_escrow()),
            receipt_continuity: Some(receipt_continuity()),
        }
    }

    #[test]
    fn coherent_cluster_authority_inputs_admit_writable_export() {
        let record = admit_clustered_block_export(coherent_input());

        assert_eq!(
            record.admission_class,
            BlockVolumeClusteredAdmissionClass::Admitted
        );
        assert_eq!(record.refusal_class, None);
        assert_eq!(record.identity, identity());
        assert_eq!(record.membership, Some(membership()));
        assert_eq!(record.writer_authority, Some(writer_authority()));
        assert_eq!(record.reserve_escrow, Some(reserve_escrow()));
        assert_eq!(record.receipt_continuity, Some(receipt_continuity()));
    }

    #[test]
    fn stale_membership_epoch_refuses_clustered_export() {
        let mut input = coherent_input();
        input.membership = Some(BlockVolumeClusterMembershipEpochRecord {
            membership_epoch: 6,
            ..membership()
        });

        let record = admit_clustered_block_export(input);

        assert_eq!(
            record.admission_class,
            BlockVolumeClusteredAdmissionClass::Refused
        );
        assert_eq!(
            record.refusal_class,
            Some(BlockVolumeClusteredAdmissionRefusal::StaleMembershipEpoch)
        );
    }

    #[test]
    fn missing_writer_authority_refuses_clustered_export() {
        let mut input = coherent_input();
        input.writer_authority = None;

        let record = admit_clustered_block_export(input);

        assert_eq!(
            record.refusal_class,
            Some(BlockVolumeClusteredAdmissionRefusal::MissingWriterAuthority)
        );
    }

    #[test]
    fn missing_reserve_escrow_refuses_clustered_export() {
        let mut input = coherent_input();
        input.reserve_escrow = None;

        let record = admit_clustered_block_export(input);

        assert_eq!(
            record.refusal_class,
            Some(BlockVolumeClusteredAdmissionRefusal::MissingReserveEscrow)
        );
    }

    #[test]
    fn missing_receipt_continuity_refuses_clustered_export() {
        let mut input = coherent_input();
        input.receipt_continuity = None;

        let record = admit_clustered_block_export(input);

        assert_eq!(
            record.refusal_class,
            Some(BlockVolumeClusteredAdmissionRefusal::MissingReceiptContinuity)
        );
    }

    #[test]
    fn default_clustered_policy_refuses_multi_writer_authority() {
        let mut input = coherent_input();
        input.writer_authority = Some(BlockVolumeClusterWriterAuthorityRecord {
            writer_class: BlockVolumeClusterWriterClass::MultiWritableAuthority,
            active_writer_count: 2,
            ..writer_authority()
        });

        let record = admit_clustered_block_export(input);

        assert_eq!(
            record.refusal_class,
            Some(BlockVolumeClusteredAdmissionRefusal::MultipleWritableAuthorities)
        );
    }

    #[test]
    fn local_export_lifecycle_does_not_require_clustered_inputs() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(62), 4096, 16, 4);
        let mut lifecycle = BlockVolumeExportLifecycleRuntime::bootstrap(geometry, 2, 4, 4096)
            .expect("local lifecycle bootstrap");

        let admit = lifecycle.admit_export();
        let start = lifecycle.start_queues();

        assert_eq!(
            admit.outcome_class,
            BlockVolumeExportTransitionOutcomeClass::Completed
        );
        assert_eq!(
            start.outcome_class,
            BlockVolumeExportTransitionOutcomeClass::Completed
        );
        assert_eq!(
            lifecycle.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive
        );
    }
}
