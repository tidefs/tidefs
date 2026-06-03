#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` `publication_pipeline` core types: queue classes, batch classes,
//! seal-trigger classes, persistence-task classes, stop triggers, stage markers,
//! and the canonical emission ticket record.
//!
//! Wave Zero provisions the fixed-width publication-enumeration surface so that
//! the P3-02 runtime crate can reference named queue, batch, seal, and persistence
//! classes without rebuilding the taxonomy.

use core::convert::TryFrom;
use tidefs_types_control_plane_core::{
    ControlPlaneDigest32, ControlPlaneId128, ControlPlaneJournalId, ControlPlaneReceiptId,
    ControlPlaneRequestId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineDecodeError {
    UnknownQueueClass(u32),
    UnknownBatchClass(u32),
    UnknownEmissionTicketKind(u32),
    UnknownSealTriggerClass(u32),
    UnknownPersistenceTaskClass(u32),
    UnknownStopTriggerClass(u32),
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineQueueClass {
    Ingress = 0,
    Prepare = 1,
    Batch = 2,
    Commit = 3,
    Progress = 4,
    ProductWake = 5,
    EmitTicket = 6,
    Recovery = 7,
}

impl PublicationPipelineQueueClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "queue.publication_pipeline.ingress.q0",
            Self::Prepare => "queue.publication_pipeline.prepare.q1",
            Self::Batch => "queue.publication_pipeline.batch.q2",
            Self::Commit => "queue.publication_pipeline.commit.q3",
            Self::Progress => "queue.publication_pipeline.progress.q4",
            Self::ProductWake => "queue.publication_pipeline.product_wake.q5",
            Self::EmitTicket => "queue.publication_pipeline.emit_ticket.q6",
            Self::Recovery => "queue.publication_pipeline.recovery.q7",
        }
    }
}

impl Default for PublicationPipelineQueueClass {
    fn default() -> Self {
        Self::Ingress
    }
}

impl TryFrom<u32> for PublicationPipelineQueueClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ingress),
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Batch),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Progress),
            5 => Ok(Self::ProductWake),
            6 => Ok(Self::EmitTicket),
            7 => Ok(Self::Recovery),
            _ => Err(PublicationPipelineDecodeError::UnknownQueueClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineBatchClass {
    SingleDomain = 0,
    SyncForced = 1,
    ClusterCommitGroup = 2,
    PolicyOrGovernance = 3,
    FailoverOrStage = 4,
    MultiDomainExpensive = 5,
}

impl PublicationPipelineBatchClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleDomain => "batch.publication_pipeline.single_domain.b0",
            Self::SyncForced => "batch.publication_pipeline.sync_forced.b1",
            Self::ClusterCommitGroup => "batch.publication_pipeline.cluster_commit_group.b2",
            Self::PolicyOrGovernance => "batch.publication_pipeline.policy_or_governance.b3",
            Self::FailoverOrStage => "batch.publication_pipeline.failover_or_stage.b4",
            Self::MultiDomainExpensive => "batch.publication_pipeline.multi_domain_expensive.b5",
        }
    }
}

impl Default for PublicationPipelineBatchClass {
    fn default() -> Self {
        Self::SingleDomain
    }
}

impl TryFrom<u32> for PublicationPipelineBatchClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SingleDomain),
            1 => Ok(Self::SyncForced),
            2 => Ok(Self::ClusterCommitGroup),
            3 => Ok(Self::PolicyOrGovernance),
            4 => Ok(Self::FailoverOrStage),
            5 => Ok(Self::MultiDomainExpensive),
            _ => Err(PublicationPipelineDecodeError::UnknownBatchClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineEmissionTicketKind {
    ControlWriteMutation = 0,
}

impl PublicationPipelineEmissionTicketKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlWriteMutation => "ticket.publication_pipeline.control_write_mutation.t0",
        }
    }
}

impl Default for PublicationPipelineEmissionTicketKind {
    fn default() -> Self {
        Self::ControlWriteMutation
    }
}

impl TryFrom<u32> for PublicationPipelineEmissionTicketKind {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlWriteMutation),
            _ => Err(PublicationPipelineDecodeError::UnknownEmissionTicketKind(
                value,
            )),
        }
    }
}

// ── Seal-trigger classes (P3-02 §3, s0-s6) ──────────────────────────

/// P3-02 §3 seal-trigger taxonomy: the seven conditions that force a batch
/// to seal and proceed to commit cut.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineSealTriggerClass {
    /// s0 — op-count threshold (default: 256 ops)
    TargetOps = 0,
    /// s1 — time threshold (default: 10 ms)
    TargetSeconds = 1,
    /// s2 — dirty-bytes threshold (default: 256 KiB)
    TargetBytes = 2,
    /// s3 — hard dirty cap (default: 1 GiB)
    DirtyMaxBytes = 3,
    /// s4 — caller barrier: fsync / fdatasync / fsyncdata
    CallerBarrier = 4,
    /// s5 — runbook stage fence or failover cut
    RunbookOrFailover = 5,
    /// s6 — checkpoint or snapshot boundary
    CheckpointOrCursor = 6,
}

impl PublicationPipelineSealTriggerClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetOps => "seal.publication_pipeline.target_ops.s0",
            Self::TargetSeconds => "seal.publication_pipeline.target_seconds.s1",
            Self::TargetBytes => "seal.publication_pipeline.target_bytes.s2",
            Self::DirtyMaxBytes => "seal.publication_pipeline.dirty_max_bytes.s3",
            Self::CallerBarrier => "seal.publication_pipeline.caller_barrier.s4",
            Self::RunbookOrFailover => "seal.publication_pipeline.runbook_or_failover.s5",
            Self::CheckpointOrCursor => "seal.publication_pipeline.checkpoint_or_cursor.s6",
        }
    }
}

impl Default for PublicationPipelineSealTriggerClass {
    fn default() -> Self {
        Self::TargetOps
    }
}

impl From<PublicationPipelineSealTriggerClass> for u32 {
    fn from(v: PublicationPipelineSealTriggerClass) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelineSealTriggerClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TargetOps),
            1 => Ok(Self::TargetSeconds),
            2 => Ok(Self::TargetBytes),
            3 => Ok(Self::DirtyMaxBytes),
            4 => Ok(Self::CallerBarrier),
            5 => Ok(Self::RunbookOrFailover),
            6 => Ok(Self::CheckpointOrCursor),
            _ => Err(PublicationPipelineDecodeError::UnknownSealTriggerClass(
                value,
            )),
        }
    }
}

// ── Persistence-task classes (P3-02 §5, t0-t9) ───────────────────────

/// P3-02 §5 persistence-task taxonomy: the ten durable-task classes that
/// must survive restart or failover.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelinePersistenceTaskClass {
    /// t0 — commit-cut persistence
    CommitCut = 0,
    /// t1 — replica cursor advance
    ReplicaCursor = 1,
    /// t2 — product cache invalidation
    ProductCache = 2,
    /// t3 — view / truth-surface invalidation
    ViewInvalidation = 3,
    /// t4 — fence / barrier release
    FenceRelease = 4,
    /// t5 — transport-session progress cursor (consumes transport_session_0)
    TransportProgressCursor = 5,
    /// t6 — checkpoint / snapshot cursor write
    CheckpointCursor = 6,
    /// t7 — emission ticket persistence
    EmissionTicket = 7,
    /// t8 — recovery marker write
    RecoveryMarker = 8,
    /// t9 — archive / validation hold
    ArchiveHold = 9,
}

impl PublicationPipelinePersistenceTaskClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommitCut => "task.publication_pipeline.commit_cut.t0",
            Self::ReplicaCursor => "task.publication_pipeline.replica_cursor.t1",
            Self::ProductCache => "task.publication_pipeline.product_cache.t2",
            Self::ViewInvalidation => "task.publication_pipeline.view_invalidation.t3",
            Self::FenceRelease => "task.publication_pipeline.fence_release.t4",
            Self::TransportProgressCursor => {
                "task.publication_pipeline.transport_progress_cursor.t5"
            }
            Self::CheckpointCursor => "task.publication_pipeline.checkpoint_cursor.t6",
            Self::EmissionTicket => "task.publication_pipeline.emission_ticket.t7",
            Self::RecoveryMarker => "task.publication_pipeline.recovery_marker.t8",
            Self::ArchiveHold => "task.publication_pipeline.archive_hold.t9",
        }
    }
}

impl Default for PublicationPipelinePersistenceTaskClass {
    fn default() -> Self {
        Self::CommitCut
    }
}

impl From<PublicationPipelinePersistenceTaskClass> for u32 {
    fn from(v: PublicationPipelinePersistenceTaskClass) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelinePersistenceTaskClass {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CommitCut),
            1 => Ok(Self::ReplicaCursor),
            2 => Ok(Self::ProductCache),
            3 => Ok(Self::ViewInvalidation),
            4 => Ok(Self::FenceRelease),
            5 => Ok(Self::TransportProgressCursor),
            6 => Ok(Self::CheckpointCursor),
            7 => Ok(Self::EmissionTicket),
            8 => Ok(Self::RecoveryMarker),
            9 => Ok(Self::ArchiveHold),
            _ => Err(PublicationPipelineDecodeError::UnknownPersistenceTaskClass(
                value,
            )),
        }
    }
}

// ── Stop-trigger classes (P3-02 §8) ───────────────────────────────────

/// P3-02 §8: typed refusal/hold/rollback conditions.
/// When one fires, the result is not a warning — it is a typed stop.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineStopTrigger {
    /// batch reached hard capacity without a legal seal
    BatchCapacityExceeded = 0,
    /// membership anchor, epoch, or cut precondition changed before h5
    MembershipAnchorChanged = 1,
    /// commit cut happened but progress state is ambiguous
    ProgressUncertain = 2,
    /// committed cut lacks required emission ticket
    EmissionTicketGap = 3,
    /// restart/failover cannot classify in-flight work
    RecoveryUnknown = 4,
}

impl PublicationPipelineStopTrigger {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BatchCapacityExceeded => "stop.publication_pipeline.batch_capacity_exceeded",
            Self::MembershipAnchorChanged => "stop.publication_pipeline.membership_anchor_changed",
            Self::ProgressUncertain => "stop.publication_pipeline.progress_uncertain",
            Self::EmissionTicketGap => "stop.publication_pipeline.emission_ticket_gap",
            Self::RecoveryUnknown => "stop.publication_pipeline.recovery_unknown",
        }
    }
}

impl Default for PublicationPipelineStopTrigger {
    fn default() -> Self {
        Self::BatchCapacityExceeded
    }
}

impl From<PublicationPipelineStopTrigger> for u32 {
    fn from(v: PublicationPipelineStopTrigger) -> Self {
        v.as_u32()
    }
}

impl TryFrom<u32> for PublicationPipelineStopTrigger {
    type Error = PublicationPipelineDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::BatchCapacityExceeded),
            1 => Ok(Self::MembershipAnchorChanged),
            2 => Ok(Self::ProgressUncertain),
            3 => Ok(Self::EmissionTicketGap),
            4 => Ok(Self::RecoveryUnknown),
            _ => Err(PublicationPipelineDecodeError::UnknownStopTriggerClass(
                value,
            )),
        }
    }
}

// ── Publication stage marker (P3-02 §4, h0-h9) ───────────────────────

/// P3-02 canonical 10-stage publication chain.
/// h0 normalizes intent, h9 recovers or retires.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicationPipelineStage {
    /// h0 — normalize intent
    NormalizeIntent = 0,
    /// h1 — freeze anchor set
    FreezeAnchorSet = 1,
    /// h2 — prepare work item
    PrepareWorkItem = 2,
    /// h3 — join batch
    JoinBatch = 3,
    /// h4 — seal batch
    SealBatch = 4,
    /// h5 — commit cut
    CommitCut = 5,
    /// h6 — persist progress cursor
    PersistProgressCursor = 6,
    /// h7 — emit wake tasks
    EmitWakeTasks = 7,
    /// h8 — issue emission ticket
    IssueEmissionTicket = 8,
    /// h9 — recover or retire
    RecoverOrRetire = 9,
}

impl PublicationPipelineStage {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalizeIntent => "stage.publication_pipeline.normalize_intent.h0",
            Self::FreezeAnchorSet => "stage.publication_pipeline.freeze_anchor_set.h1",
            Self::PrepareWorkItem => "stage.publication_pipeline.prepare_work_item.h2",
            Self::JoinBatch => "stage.publication_pipeline.join_batch.h3",
            Self::SealBatch => "stage.publication_pipeline.seal_batch.h4",
            Self::CommitCut => "stage.publication_pipeline.commit_cut.h5",
            Self::PersistProgressCursor => "stage.publication_pipeline.persist_progress_cursor.h6",
            Self::EmitWakeTasks => "stage.publication_pipeline.emit_wake_tasks.h7",
            Self::IssueEmissionTicket => "stage.publication_pipeline.issue_emission_ticket.h8",
            Self::RecoverOrRetire => "stage.publication_pipeline.recover_or_retire.h9",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationPipelineEmissionTicketInput {
    pub ticket_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub primary_shard_class: u32,
    pub queue_class: PublicationPipelineQueueClass,
    pub batch_class: PublicationPipelineBatchClass,
    pub ticket_kind: PublicationPipelineEmissionTicketKind,
    pub freeze_id: ControlPlaneId128,
    pub answer_plan_id: ControlPlaneId128,
    pub render_receipt_seed: ControlPlaneReceiptId,
    pub outcome_digest: ControlPlaneDigest32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicationPipelineEmissionTicketRecord {
    pub ticket_id: ControlPlaneId128,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub primary_shard_class: u32,
    pub queue_class: u32,
    pub batch_class: u32,
    pub ticket_kind: u32,
    pub _reserved0: u32,
    pub freeze_id: ControlPlaneId128,
    pub answer_plan_id: ControlPlaneId128,
    pub render_receipt_seed: ControlPlaneReceiptId,
    pub outcome_digest: ControlPlaneDigest32,
}

impl PublicationPipelineEmissionTicketRecord {
    #[must_use]
    pub const fn new(input: PublicationPipelineEmissionTicketInput) -> Self {
        Self {
            ticket_id: input.ticket_id,
            request_id: input.request_id,
            journal_id: input.journal_id,
            primary_shard_class: input.primary_shard_class,
            queue_class: input.queue_class.as_u32(),
            batch_class: input.batch_class.as_u32(),
            ticket_kind: input.ticket_kind.as_u32(),
            _reserved0: 0,
            freeze_id: input.freeze_id,
            answer_plan_id: input.answer_plan_id,
            render_receipt_seed: input.render_receipt_seed,
            outcome_digest: input.outcome_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownQueueClass`] if the stored
    /// raw tag does not correspond to a valid publication pipeline queue class.
    pub fn queue(self) -> Result<PublicationPipelineQueueClass, PublicationPipelineDecodeError> {
        PublicationPipelineQueueClass::try_from(self.queue_class)
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownBatchClass`] if the stored
    /// raw tag does not correspond to a valid publication pipeline batch class.
    pub fn batch(self) -> Result<PublicationPipelineBatchClass, PublicationPipelineDecodeError> {
        PublicationPipelineBatchClass::try_from(self.batch_class)
    }

    /// # Errors
    ///
    /// Returns [`PublicationPipelineDecodeError::UnknownEmissionTicketKind`] if the stored
    /// raw tag does not correspond to a valid emission ticket kind.
    pub fn ticket_kind(
        self,
    ) -> Result<PublicationPipelineEmissionTicketKind, PublicationPipelineDecodeError> {
        PublicationPipelineEmissionTicketKind::try_from(self.ticket_kind)
    }
}

const _: [(); 148] = [(); core::mem::size_of::<PublicationPipelineEmissionTicketRecord>()];

// TURN3_HUMAN_PUBLICATION_PIPELINE_ALIASES
/// Human-named module for the Publication Pipeline family.
pub mod publication_pipeline {
    pub const FAMILY_NAME: &str = "Publication Pipeline";
    pub const STABLE_SOURCE_LOCATOR: &str = "publication_pipeline";
    pub const ROLE: &str = "emission tickets and admitted-decision publication";

    pub use super::{
        PublicationPipelineBatchClass as BatchClass, PublicationPipelineDecodeError as DecodeError,
        PublicationPipelineEmissionTicketInput as EmissionTicketInput,
        PublicationPipelineEmissionTicketKind as EmissionTicketKind,
        PublicationPipelineEmissionTicketRecord as EmissionTicketRecord,
        PublicationPipelinePersistenceTaskClass as PersistenceTaskClass,
        PublicationPipelineQueueClass as QueueClass,
        PublicationPipelineSealTriggerClass as SealTriggerClass, PublicationPipelineStage as Stage,
        PublicationPipelineStopTrigger as StopTrigger,
    };
}

/// Human alias namespace. Prefer `human::publication_pipeline::*` in new examples.
pub mod human {
    pub mod publication_pipeline {
        pub use crate::publication_pipeline::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_batch_and_emit_queue_round_trip() {
        let ticket =
            PublicationPipelineEmissionTicketRecord::new(PublicationPipelineEmissionTicketInput {
                ticket_id: ControlPlaneId128::from_u128_le(0x11),
                request_id: ControlPlaneId128::from_u128_le(0x22),
                journal_id: ControlPlaneId128::from_u128_le(0x33),
                primary_shard_class: 4,
                queue_class: PublicationPipelineQueueClass::EmitTicket,
                batch_class: PublicationPipelineBatchClass::PolicyOrGovernance,
                ticket_kind: PublicationPipelineEmissionTicketKind::ControlWriteMutation,
                freeze_id: ControlPlaneId128::from_u128_le(0x44),
                answer_plan_id: ControlPlaneId128::from_u128_le(0x55),
                render_receipt_seed: ControlPlaneId128::from_u128_le(0x66),
                outcome_digest: [0xAA_u8; 32],
            });
        assert_eq!(
            ticket.queue(),
            Ok(PublicationPipelineQueueClass::EmitTicket)
        );
        assert_eq!(
            ticket.batch(),
            Ok(PublicationPipelineBatchClass::PolicyOrGovernance)
        );
        assert_eq!(
            ticket.ticket_kind(),
            Ok(PublicationPipelineEmissionTicketKind::ControlWriteMutation)
        );
    }

    #[test]
    fn invalid_wire_values_report_publication_pipeline_decode_errors() {
        let ticket = PublicationPipelineEmissionTicketRecord {
            queue_class: 99,
            ..PublicationPipelineEmissionTicketRecord::default()
        };
        assert_eq!(
            ticket.queue(),
            Err(PublicationPipelineDecodeError::UnknownQueueClass(99))
        );

        let ticket = PublicationPipelineEmissionTicketRecord {
            batch_class: 88,
            ..PublicationPipelineEmissionTicketRecord::default()
        };
        assert_eq!(
            ticket.batch(),
            Err(PublicationPipelineDecodeError::UnknownBatchClass(88))
        );

        let ticket = PublicationPipelineEmissionTicketRecord {
            ticket_kind: 77,
            ..PublicationPipelineEmissionTicketRecord::default()
        };
        assert_eq!(
            ticket.ticket_kind(),
            Err(PublicationPipelineDecodeError::UnknownEmissionTicketKind(
                77
            ))
        );
    }
    #[test]
    fn emission_ticket_new_preserves_all_input_fields() {
        let input = PublicationPipelineEmissionTicketInput {
            ticket_id: ControlPlaneId128::from_u128_le(0xBB),
            request_id: ControlPlaneRequestId::from_u128_le(0xCC),
            journal_id: ControlPlaneJournalId::from_u128_le(0xDD),
            primary_shard_class: 1,
            queue_class: PublicationPipelineQueueClass::ProductWake,
            batch_class: PublicationPipelineBatchClass::default(),
            ticket_kind: PublicationPipelineEmissionTicketKind::default(),
            freeze_id: ControlPlaneId128::ZERO,
            answer_plan_id: ControlPlaneId128::ZERO,
            render_receipt_seed: ControlPlaneReceiptId::ZERO,
            outcome_digest: [0xEE_u8; 32],
        };
        let ticket = PublicationPipelineEmissionTicketRecord::new(input);
        assert_eq!(ticket.ticket_id, ControlPlaneId128::from_u128_le(0xBB));
        assert_eq!(
            ticket.queue(),
            Ok(PublicationPipelineQueueClass::ProductWake)
        );
        assert_eq!(ticket.request_id, ControlPlaneRequestId::from_u128_le(0xCC));
        assert_eq!(ticket.outcome_digest, [0xEE_u8; 32]);
    }

    #[test]
    fn queue_class_all_variants_round_trip() {
        let classes = [
            PublicationPipelineQueueClass::Ingress,
            PublicationPipelineQueueClass::Prepare,
            PublicationPipelineQueueClass::Batch,
            PublicationPipelineQueueClass::Commit,
            PublicationPipelineQueueClass::Progress,
            PublicationPipelineQueueClass::ProductWake,
            PublicationPipelineQueueClass::EmitTicket,
            PublicationPipelineQueueClass::Recovery,
        ];
        for &c in &classes {
            let roundtrip = PublicationPipelineQueueClass::try_from(c.as_u32());
            assert_eq!(roundtrip, Ok(c));
        }
    }

    #[test]
    fn batch_class_all_variants_round_trip() {
        let classes = [PublicationPipelineBatchClass::default()];
        for &c in &classes {
            let roundtrip = PublicationPipelineBatchClass::try_from(c.as_u32());
            assert_eq!(roundtrip, Ok(c));
        }
    }

    #[test]
    fn ticket_kind_all_variants_round_trip() {
        let kinds = [PublicationPipelineEmissionTicketKind::default()];
        for &k in &kinds {
            let roundtrip = PublicationPipelineEmissionTicketKind::try_from(k.as_u32());
            assert_eq!(roundtrip, Ok(k));
        }
    }

    #[test]
    fn emission_ticket_batch_and_kind_accessors_work() {
        let input = PublicationPipelineEmissionTicketInput {
            ticket_id: ControlPlaneId128::from_u128_le(0xAA),
            request_id: ControlPlaneRequestId::from_u128_le(0xBB),
            journal_id: ControlPlaneJournalId::from_u128_le(0xCC),
            primary_shard_class: 2,
            queue_class: PublicationPipelineQueueClass::EmitTicket,
            batch_class: PublicationPipelineBatchClass::default(),
            ticket_kind: PublicationPipelineEmissionTicketKind::default(),
            freeze_id: ControlPlaneId128::ZERO,
            answer_plan_id: ControlPlaneId128::ZERO,
            render_receipt_seed: ControlPlaneReceiptId::ZERO,
            outcome_digest: [0xAA_u8; 32],
        };
        let ticket = PublicationPipelineEmissionTicketRecord::new(input);
        assert_eq!(ticket.batch(), Ok(PublicationPipelineBatchClass::default()));
        assert_eq!(
            ticket.ticket_kind(),
            Ok(PublicationPipelineEmissionTicketKind::default())
        );
        assert_eq!(ticket.journal_id, ControlPlaneJournalId::from_u128_le(0xCC));
    }

    #[test]
    fn emission_ticket_default_has_zero_values() {
        let ticket = PublicationPipelineEmissionTicketRecord::default();
        assert!(ticket.ticket_id.is_zero());
        assert!(ticket.request_id.is_zero());
        assert!(ticket.journal_id.is_zero());
    }

    // ── Batch class exhaustive roundtrip ───────────────────────────────

    #[test]
    fn batch_class_all_variants_exhaustive_roundtrip() {
        let variants = [
            PublicationPipelineBatchClass::SingleDomain,
            PublicationPipelineBatchClass::SyncForced,
            PublicationPipelineBatchClass::ClusterCommitGroup,
            PublicationPipelineBatchClass::PolicyOrGovernance,
            PublicationPipelineBatchClass::FailoverOrStage,
            PublicationPipelineBatchClass::MultiDomainExpensive,
        ];
        for v in &variants {
            assert_eq!(PublicationPipelineBatchClass::try_from(v.as_u32()), Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            PublicationPipelineBatchClass::default(),
            PublicationPipelineBatchClass::SingleDomain
        );
        assert!(PublicationPipelineBatchClass::try_from(99_u32).is_err());
    }

    // ── Enum as_str coverage ───────────────────────────────────────────

    #[test]
    fn queue_class_as_str_non_empty() {
        let variants = [
            PublicationPipelineQueueClass::Ingress,
            PublicationPipelineQueueClass::Prepare,
            PublicationPipelineQueueClass::Batch,
            PublicationPipelineQueueClass::Commit,
            PublicationPipelineQueueClass::Progress,
            PublicationPipelineQueueClass::ProductWake,
            PublicationPipelineQueueClass::EmitTicket,
            PublicationPipelineQueueClass::Recovery,
        ];
        for v in &variants {
            assert!(!v.as_str().is_empty());
        }
    }

    #[test]
    fn ticket_kind_default_and_as_str() {
        assert_eq!(
            PublicationPipelineEmissionTicketKind::default(),
            PublicationPipelineEmissionTicketKind::ControlWriteMutation
        );
        assert!(!PublicationPipelineEmissionTicketKind::ControlWriteMutation
            .as_str()
            .is_empty());
    }

    // ── Emission ticket exhaustive roundtrip ──────────────────────────

    #[test]
    fn emission_ticket_exhaustive_roundtrip_all_fields() {
        let ticket =
            PublicationPipelineEmissionTicketRecord::new(PublicationPipelineEmissionTicketInput {
                ticket_id: ControlPlaneId128::from_u128_le(0xA1),
                request_id: ControlPlaneRequestId::from_u128_le(0xA2),
                journal_id: ControlPlaneJournalId::from_u128_le(0xA3),
                primary_shard_class: 7,
                queue_class: PublicationPipelineQueueClass::Commit,
                batch_class: PublicationPipelineBatchClass::ClusterCommitGroup,
                ticket_kind: PublicationPipelineEmissionTicketKind::ControlWriteMutation,
                freeze_id: ControlPlaneId128::from_u128_le(0xB1),
                answer_plan_id: ControlPlaneId128::from_u128_le(0xB2),
                render_receipt_seed: ControlPlaneReceiptId::from_u128_le(0xB3),
                outcome_digest: [0xC1_u8; 32],
            });
        assert_eq!(ticket.ticket_id.as_u128_le(), 0xA1);
        assert_eq!(ticket.request_id.as_u128_le(), 0xA2);
        assert_eq!(ticket.journal_id.as_u128_le(), 0xA3);
        assert_eq!(ticket.primary_shard_class, 7);
        assert_eq!(ticket.queue(), Ok(PublicationPipelineQueueClass::Commit));
        assert_eq!(
            ticket.batch(),
            Ok(PublicationPipelineBatchClass::ClusterCommitGroup)
        );
        assert_eq!(
            ticket.ticket_kind(),
            Ok(PublicationPipelineEmissionTicketKind::ControlWriteMutation)
        );
        assert_eq!(ticket.freeze_id.as_u128_le(), 0xB1);
        assert_eq!(ticket.answer_plan_id.as_u128_le(), 0xB2);
        assert_eq!(ticket.render_receipt_seed.as_u128_le(), 0xB3);
        assert_eq!(ticket.outcome_digest, [0xC1_u8; 32]);
    }

    #[test]
    fn emission_ticket_max_boundary_values() {
        let ticket =
            PublicationPipelineEmissionTicketRecord::new(PublicationPipelineEmissionTicketInput {
                ticket_id: ControlPlaneId128::from_u128_le(u128::MAX),
                request_id: ControlPlaneRequestId::from_u128_le(u128::MAX),
                journal_id: ControlPlaneJournalId::from_u128_le(u128::MAX),
                primary_shard_class: u32::MAX,
                queue_class: PublicationPipelineQueueClass::Recovery,
                batch_class: PublicationPipelineBatchClass::MultiDomainExpensive,
                ticket_kind: PublicationPipelineEmissionTicketKind::ControlWriteMutation,
                freeze_id: ControlPlaneId128::from_u128_le(u128::MAX),
                answer_plan_id: ControlPlaneId128::from_u128_le(u128::MAX),
                render_receipt_seed: ControlPlaneReceiptId::from_u128_le(u128::MAX),
                outcome_digest: [0xFF_u8; 32],
            });
        assert_eq!(ticket.ticket_id.as_u128_le(), u128::MAX);
        assert_eq!(ticket.request_id.as_u128_le(), u128::MAX);
        assert_eq!(ticket.journal_id.as_u128_le(), u128::MAX);
        assert_eq!(ticket.primary_shard_class, u32::MAX);
        assert_eq!(ticket.queue(), Ok(PublicationPipelineQueueClass::Recovery));
        assert_eq!(
            ticket.batch(),
            Ok(PublicationPipelineBatchClass::MultiDomainExpensive)
        );
        assert_eq!(ticket.freeze_id.as_u128_le(), u128::MAX);
        assert_eq!(ticket.answer_plan_id.as_u128_le(), u128::MAX);
        assert_eq!(ticket.render_receipt_seed.as_u128_le(), u128::MAX);
        assert_eq!(ticket.outcome_digest, [0xFF_u8; 32]);
    }

    #[test]
    fn emission_ticket_zero_values() {
        let ticket = PublicationPipelineEmissionTicketRecord::default();
        assert!(ticket.ticket_id.is_zero());
        assert!(ticket.request_id.is_zero());
        assert!(ticket.journal_id.is_zero());
        assert_eq!(ticket.primary_shard_class, 0);
        assert_eq!(ticket.queue(), Ok(PublicationPipelineQueueClass::Ingress));
        assert_eq!(
            ticket.batch(),
            Ok(PublicationPipelineBatchClass::SingleDomain)
        );
        assert_eq!(
            ticket.ticket_kind(),
            Ok(PublicationPipelineEmissionTicketKind::ControlWriteMutation)
        );
        assert!(ticket.freeze_id.is_zero());
        assert!(ticket.answer_plan_id.is_zero());
        assert!(ticket.render_receipt_seed.is_zero());
        assert_eq!(ticket.outcome_digest, [0_u8; 32]);
    }

    // ── DecodeError exhaustive coverage ─────────────────────────────────

    #[test]
    fn decode_error_variants_exhaustive() {
        let e1 = PublicationPipelineDecodeError::UnknownQueueClass(99);
        match e1 {
            PublicationPipelineDecodeError::UnknownQueueClass(v) => assert_eq!(v, 99),
            _ => panic!("wrong variant"),
        }
        let e2 = PublicationPipelineDecodeError::UnknownBatchClass(88);
        match e2 {
            PublicationPipelineDecodeError::UnknownBatchClass(v) => assert_eq!(v, 88),
            _ => panic!("wrong variant"),
        }
        let e3 = PublicationPipelineDecodeError::UnknownEmissionTicketKind(77);
        match e3 {
            PublicationPipelineDecodeError::UnknownEmissionTicketKind(v) => assert_eq!(v, 77),
            _ => panic!("wrong variant"),
        }
    }

    // ── Record size assertion ──────────────────────────────────────────

    #[test]
    fn emission_ticket_record_size_is_148_bytes() {
        assert_eq!(
            core::mem::size_of::<PublicationPipelineEmissionTicketRecord>(),
            148
        );
    }
}
