// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` `posix_filesystem_adapter` wake-receipt core types.
//!
//! The adapter family keeps the POSIX surface unchanged while providing typed
//! family-local receipts proving whether a committed publication produced a
//! view wake or whether a refusal left the product surface unchanged.

use core::convert::TryFrom;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PosixFilesystemAdapterId128(pub [u8; 16]);

impl PosixFilesystemAdapterId128 {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn from_u128_le(value: u128) -> Self {
        Self(value.to_le_bytes())
    }

    #[must_use]
    pub const fn as_u128_le(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

pub type PosixFilesystemAdapterRequestId = PosixFilesystemAdapterId128;
pub type PosixFilesystemAdapterJournalId = PosixFilesystemAdapterId128;
pub type PosixFilesystemAdapterReceiptId = PosixFilesystemAdapterId128;
pub type PosixFilesystemAdapterDigest32 = [u8; 32];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
    pub witness_join_id: PosixFilesystemAdapterId128,
    pub policy_witness_id: PosixFilesystemAdapterId128,
    pub budget_witness_id: PosixFilesystemAdapterId128,
    pub recipe_witness_id: PosixFilesystemAdapterId128,
    pub witness_join_digest: PosixFilesystemAdapterDigest32,
}

impl PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
    pub const ZERO: Self = Self {
        witness_join_id: PosixFilesystemAdapterId128::ZERO,
        policy_witness_id: PosixFilesystemAdapterId128::ZERO,
        budget_witness_id: PosixFilesystemAdapterId128::ZERO,
        recipe_witness_id: PosixFilesystemAdapterId128::ZERO,
        witness_join_digest: [0_u8; 32],
    };

    #[must_use]
    pub const fn new(
        witness_join_id: PosixFilesystemAdapterId128,
        policy_witness_id: PosixFilesystemAdapterId128,
        budget_witness_id: PosixFilesystemAdapterId128,
        recipe_witness_id: PosixFilesystemAdapterId128,
        witness_join_digest: PosixFilesystemAdapterDigest32,
    ) -> Self {
        Self {
            witness_join_id,
            policy_witness_id,
            budget_witness_id,
            recipe_witness_id,
            witness_join_digest,
        }
    }

    #[must_use]
    pub const fn has_join(&self) -> bool {
        !self.witness_join_id.is_zero()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterDecodeError {
    UnknownWakeClass(u32),
    UnknownVisibilityClass(u32),
    UnknownSurfaceValidationClass(u32),
    UnknownValidationStatus(u32),
    UnknownRequestClass(u32),
    UnknownReplyClass(u32),
    UnknownShardKeyPolicy(u32),
    UnknownExecClass(u32),
    UnknownThreadSetClass(u32),
    UnknownPhaseClass(u32),
    UnknownRestartVerdictClass(u32),
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterWakeClass {
    NamespaceProjection = 0,
    MetadataProjection = 1,
    DataProjection = 2,
    DurabilityBarrier = 3,
    RefusalProjection = 4,
}

impl PosixFilesystemAdapterWakeClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NamespaceProjection => {
                "receipt.posix_filesystem_adapter.wake.namespace_projection.w0"
            }
            Self::MetadataProjection => {
                "receipt.posix_filesystem_adapter.wake.metadata_projection.w1"
            }
            Self::DataProjection => "receipt.posix_filesystem_adapter.wake.data_projection.w2",
            Self::DurabilityBarrier => {
                "receipt.posix_filesystem_adapter.wake.durability_barrier.w3"
            }
            Self::RefusalProjection => {
                "receipt.posix_filesystem_adapter.wake.refusal_projection.w4"
            }
        }
    }
}

impl Default for PosixFilesystemAdapterWakeClass {
    fn default() -> Self {
        Self::NamespaceProjection
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterWakeClass {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NamespaceProjection),
            1 => Ok(Self::MetadataProjection),
            2 => Ok(Self::DataProjection),
            3 => Ok(Self::DurabilityBarrier),
            4 => Ok(Self::RefusalProjection),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownWakeClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterVisibilityClass {
    CommittedVisible = 0,
    DeferredOrBuffered = 1,
    NoMutationVisible = 2,
}

impl PosixFilesystemAdapterVisibilityClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommittedVisible => "visibility.posix_filesystem_adapter.committed_visible.v0",
            Self::DeferredOrBuffered => {
                "visibility.posix_filesystem_adapter.deferred_or_buffered.v1"
            }
            Self::NoMutationVisible => "visibility.posix_filesystem_adapter.no_mutation_visible.v2",
        }
    }
}

impl Default for PosixFilesystemAdapterVisibilityClass {
    fn default() -> Self {
        Self::CommittedVisible
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterVisibilityClass {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CommittedVisible),
            1 => Ok(Self::DeferredOrBuffered),
            2 => Ok(Self::NoMutationVisible),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownVisibilityClass(
                value,
            )),
        }
    }
}

pub const FUSE_MOUNT_SURFACE_VALIDATION_SPEC: &str = "publishing checklist item PC-004A FUSE mount surface validation map: the current userspace FUSE implementation must name implementation-tracked non-release operations, recorded smoke or scoreboard validation, explicit unsupported boundaries, and remaining parent PC-004 non-closing validation without claiming POSIX-complete correctness";
pub const FUSE_MOUNT_SURFACE_VALIDATION_POLICY_VERSION: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterSurfaceValidationClass {
    MountLifecycle = 0,
    NamespaceTraversal = 1,
    FileDataIo = 2,
    DurabilityBarrier = 3,
    SessionHandleSemantics = 4,
    CapacityAccounting = 5,
    UnsupportedBoundary = 6,
    ExternalSuiteCoverage = 7,
    FutureFullGate = 8,
}

impl PosixFilesystemAdapterSurfaceValidationClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MountLifecycle => "surface.posix_filesystem_adapter.fuse.mount_lifecycle.e0",
            Self::NamespaceTraversal => {
                "surface.posix_filesystem_adapter.fuse.namespace_traversal.e1"
            }
            Self::FileDataIo => "surface.posix_filesystem_adapter.fuse.file_data_io.e2",
            Self::DurabilityBarrier => {
                "surface.posix_filesystem_adapter.fuse.durability_barrier.e3"
            }
            Self::SessionHandleSemantics => {
                "surface.posix_filesystem_adapter.fuse.session_handle_semantics.e4"
            }
            Self::CapacityAccounting => {
                "surface.posix_filesystem_adapter.fuse.capacity_accounting.e5"
            }
            Self::UnsupportedBoundary => {
                "surface.posix_filesystem_adapter.fuse.unsupported_boundary.e6"
            }
            Self::ExternalSuiteCoverage => {
                "surface.posix_filesystem_adapter.fuse.external_suite_coverage.e7"
            }
            Self::FutureFullGate => "surface.posix_filesystem_adapter.fuse.future_full_gate.e8",
        }
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterSurfaceValidationClass {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MountLifecycle),
            1 => Ok(Self::NamespaceTraversal),
            2 => Ok(Self::FileDataIo),
            3 => Ok(Self::DurabilityBarrier),
            4 => Ok(Self::SessionHandleSemantics),
            5 => Ok(Self::CapacityAccounting),
            6 => Ok(Self::UnsupportedBoundary),
            7 => Ok(Self::ExternalSuiteCoverage),
            8 => Ok(Self::FutureFullGate),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownSurfaceValidationClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterValidationStatus {
    SourceBound = 0,
    ExecutedSmoke = 1,
    RecordedScoreboard = 2,
    ExplicitSkip = 3,
    DeferredNonClosing = 4,
}

impl PosixFilesystemAdapterValidationStatus {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBound => "validation.posix_filesystem_adapter.source_bound.s0",
            Self::ExecutedSmoke => "validation.posix_filesystem_adapter.executed_smoke.s1",
            Self::RecordedScoreboard => {
                "validation.posix_filesystem_adapter.recorded_scoreboard.s2"
            }
            Self::ExplicitSkip => "validation.posix_filesystem_adapter.explicit_skip.s3",
            Self::DeferredNonClosing => {
                "validation.posix_filesystem_adapter.deferred_non_closing.s4"
            }
        }
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterValidationStatus {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SourceBound),
            1 => Ok(Self::ExecutedSmoke),
            2 => Ok(Self::RecordedScoreboard),
            3 => Ok(Self::ExplicitSkip),
            4 => Ok(Self::DeferredNonClosing),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownValidationStatus(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixFilesystemAdapterSurfaceValidationCase {
    pub stable_id: &'static str,
    pub validation_class: PosixFilesystemAdapterSurfaceValidationClass,
    pub status: PosixFilesystemAdapterValidationStatus,
    pub current_surface: &'static str,
    pub validation_output: &'static str,
    pub parent_gate_boundary: &'static str,
    pub closes_parent_publishing_checklist_item: bool,
}

pub const FUSE_MOUNT_SURFACE_VALIDATION_CASES: &[PosixFilesystemAdapterSurfaceValidationCase] = &[
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_0.mount_lifecycle",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::MountLifecycle,
        status: PosixFilesystemAdapterValidationStatus::ExecutedSmoke,
        current_surface: "foreground mount command, smoke-mount command, and QEMU /dev/fuse smoke path",
        validation_output: "docs/FUSE_MOUNT.md plus qemu-smoke and validation logs",
        parent_gate_boundary: "does not prove long-running, multi-client, unmount-race, or broad xfstests mount lifecycle correctness",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_1.namespace_traversal",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::NamespaceTraversal,
        status: PosixFilesystemAdapterValidationStatus::SourceBound,
        current_surface: "lookup, getattr, opendir, readdir, releasedir, mkdir, rmdir-empty, symlink, and readlink",
        validation_output: "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_FUSE userspace implementation.rs source markers and check-fuse-mount-path",
        parent_gate_boundary: "does not prove full path encoding, ACL, xattr, hard error, or all core VFS namespace behavior",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_2.file_data_io",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
        status: PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
        current_surface: "create, open, release, read, write, truncate, live FUSE smoke, and fio lane",
        validation_output: "docs/POSIX_SCOREBOARD_OW107.md and scoreboard logs",
        parent_gate_boundary: "does not prove mmap-heavy correctness, complete direct I/O semantics, or a broad external-suite pass",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_3.durability_barrier",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::DurabilityBarrier,
        status: PosixFilesystemAdapterValidationStatus::SourceBound,
        current_surface: "file fsync and directory fsync route through committed root-slot publication and backing sync failure maps to EIO",
        validation_output: "docs/POSIX_SEMANTICS_OW106.md and check-posix-semantics",
        parent_gate_boundary: "does not prove all Linux writeback, mmap, O_SYNC, O_DSYNC, or crash-powercut FUSE combinations",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_4.session_handle_semantics",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::SessionHandleSemantics,
        status: PosixFilesystemAdapterValidationStatus::ExecutedSmoke,
        current_surface: "unlink-while-open and rename-over-open-target regular-file handles retain session-local content until final release",
        validation_output: "docs/POSIX_SEMANTICS_OW106.md plus live FUSE smoke and targeted xfstests generic/035 validation",
        parent_gate_boundary: "does not persist orphan inodes or prove complete Linux file-handle lifetime behavior",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_5.capacity_accounting",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::CapacityAccounting,
        status: PosixFilesystemAdapterValidationStatus::SourceBound,
        current_surface: "statfs reports allocator truth and fallocate mode zero zero-extends through allocator admission",
        validation_output: "docs/FUSE_MOUNT.md, docs/LOCAL_STORAGE_ALLOCATOR_OW102.md, and check-local-storage-allocator",
        parent_gate_boundary: "does not prove production block-volume free-space semantics or unsupported fallocate modes",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_6.unsupported_boundaries",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::UnsupportedBoundary,
        status: PosixFilesystemAdapterValidationStatus::ExplicitSkip,
        current_surface: "xattrs return EOPNOTSUPP, unsupported fallocate flags return EOPNOTSUPP, and non-UTF-8 path names are rejected",
        validation_output: "docs/FUSE_MOUNT.md and FUSE userspace implementation POSIX subset boundaries",
        parent_gate_boundary: "unsupported rows are explicit non-closing validation for full PC-004 correctness",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_7.external_suite_coverage",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::ExternalSuiteCoverage,
        status: PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
        current_surface: "scoreboard records pass, fail, and skip rows, including targeted real xfstests generic/035 when configured",
        validation_output: "docs/POSIX_SCOREBOARD_OW107.md and /root/ai/tmp/tidefs-validation/20260428-issue56-integration-generic035-hardening/",
        parent_gate_boundary: "targeted generic/035 validation and explicit skips are not broad xfstests-grade coverage",
        closes_parent_publishing_checklist_item: false,
    },
    PosixFilesystemAdapterSurfaceValidationCase {
        stable_id: "fuse_surface_8.future_full_gate",
        validation_class: PosixFilesystemAdapterSurfaceValidationClass::FutureFullGate,
        status: PosixFilesystemAdapterValidationStatus::DeferredNonClosing,
        current_surface: "parent PC-004 still requires xfstests-grade breadth, mmap-heavy correctness, and no missing core VFS behavior skips",
        validation_output: "none for full parent gate in this surface",
        parent_gate_boundary: "this validation surface map keeps parent PC-004 open",
        closes_parent_publishing_checklist_item: false,
    },
];

#[must_use]
pub const fn fuse_mount_surface_validation_cases(
) -> &'static [PosixFilesystemAdapterSurfaceValidationCase] {
    FUSE_MOUNT_SURFACE_VALIDATION_CASES
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(feature = "wake-receipt")]
pub struct PosixFilesystemAdapterProductWakeReceiptRecord {
    pub wake_receipt_id: PosixFilesystemAdapterReceiptId,
    pub request_id: PosixFilesystemAdapterRequestId,
    pub journal_id: PosixFilesystemAdapterJournalId,
    pub response_registry_receipt_id: PosixFilesystemAdapterReceiptId,
    pub publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128,
    pub wake_class: u32,
    pub visibility_class: u32,
    pub _reserved0: u64,
    pub answer_digest: PosixFilesystemAdapterDigest32,
    pub artifact_locator_digest: PosixFilesystemAdapterDigest32,
    pub witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
}

/// Named input shape for `PosixFilesystemAdapterProductWakeReceiptRecord::new`.
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "wake-receipt")]
pub struct PosixFilesystemAdapterProductWakeReceiptDraft {
    pub wake_receipt_id: PosixFilesystemAdapterReceiptId,
    pub request_id: PosixFilesystemAdapterRequestId,
    pub journal_id: PosixFilesystemAdapterJournalId,
    pub response_registry_receipt_id: PosixFilesystemAdapterReceiptId,
    pub publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128,
    pub wake_class: PosixFilesystemAdapterWakeClass,
    pub visibility_class: PosixFilesystemAdapterVisibilityClass,
    pub answer_digest: PosixFilesystemAdapterDigest32,
    pub artifact_locator_digest: PosixFilesystemAdapterDigest32,
    pub witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
}

#[cfg(feature = "wake-receipt")]
impl PosixFilesystemAdapterProductWakeReceiptRecord {
    #[must_use]
    pub const fn new(draft: PosixFilesystemAdapterProductWakeReceiptDraft) -> Self {
        let PosixFilesystemAdapterProductWakeReceiptDraft {
            wake_receipt_id,
            request_id,
            journal_id,
            response_registry_receipt_id,
            publication_pipeline_ticket_id_or_zero,
            wake_class,
            visibility_class,
            answer_digest,
            artifact_locator_digest,
            witness_refs,
        } = draft;
        Self {
            wake_receipt_id,
            request_id,
            journal_id,
            response_registry_receipt_id,
            publication_pipeline_ticket_id_or_zero,
            wake_class: wake_class.as_u32(),
            visibility_class: visibility_class.as_u32(),
            _reserved0: 0,
            answer_digest,
            artifact_locator_digest,
            witness_refs,
        }
    }

    /// # Errors
    ///
    /// Returns [`PosixFilesystemAdapterDecodeError::UnknownWakeClass`] if the stored
    /// raw tag does not correspond to a valid posix filesystem adapter wake class.
    pub fn wake_class(
        self,
    ) -> Result<PosixFilesystemAdapterWakeClass, PosixFilesystemAdapterDecodeError> {
        PosixFilesystemAdapterWakeClass::try_from(self.wake_class)
    }

    /// # Errors
    ///
    /// Returns [`PosixFilesystemAdapterDecodeError::UnknownVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid posix filesystem adapter visibility class.
    pub fn visibility(
        self,
    ) -> Result<PosixFilesystemAdapterVisibilityClass, PosixFilesystemAdapterDecodeError> {
        PosixFilesystemAdapterVisibilityClass::try_from(self.visibility_class)
    }

    #[must_use]
    pub const fn has_publication_pipeline_ticket(&self) -> bool {
        !self.publication_pipeline_ticket_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_witness_join(&self) -> bool {
        self.witness_refs.has_join()
    }
}

#[cfg(feature = "wake-receipt")]
const _: [(); 256] = [(); core::mem::size_of::<PosixFilesystemAdapterProductWakeReceiptRecord>()];
const _: [(); 16] = [(); core::mem::size_of::<PosixFilesystemAdapterId128>()];
const _: [(); 96] =
    [(); core::mem::size_of::<PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs>()];

// TURN3_HUMAN_POSIX_FILESYSTEM_ADAPTER_ALIASES
/// Human-named module for the POSIX Filesystem Adapter family.
pub mod posix_filesystem_adapter {
    pub const FAMILY_NAME: &str = "POSIX Filesystem Adapter";
    pub const STABLE_SOURCE_LOCATOR: &str = "posix_filesystem_adapter";
    pub const ROLE: &str = "POSIX/VFS projection path for future FUSE and kernel adapters";

    pub use super::{
        fuse_mount_surface_validation_cases, PosixFilesystemAdapterDecodeError as DecodeError,
        PosixFilesystemAdapterSurfaceValidationCase as SurfaceValidationCase,
        PosixFilesystemAdapterSurfaceValidationClass as SurfaceValidationClass,
        PosixFilesystemAdapterValidationStatus as ValidationStatus,
        PosixFilesystemAdapterVisibilityClass as VisibilityClass,
        PosixFilesystemAdapterWakeClass as WakeClass, FUSE_MOUNT_SURFACE_VALIDATION_CASES,
        FUSE_MOUNT_SURFACE_VALIDATION_POLICY_VERSION, FUSE_MOUNT_SURFACE_VALIDATION_SPEC,
    };

    #[cfg(feature = "wake-receipt")]
    pub use super::PosixFilesystemAdapterProductWakeReceiptRecord as ProductWakeReceiptRecord;
}

/// Human alias namespace. Prefer `human::posix_filesystem_adapter::*` in new examples.
pub mod human {
    pub mod posix_filesystem_adapter {
        pub use crate::posix_filesystem_adapter::*;
    }
}

/// P5-02 FUSE request class (canonical 8-class queue topology) ABI.
///
/// Wire encoding: `u32` LE.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterRequestClass {
    ControlUrgent = 0,
    MetaRead = 1,
    NamespaceMut = 2,
    DirStream = 3,
    FileRead = 4,
    FileWriteback = 5,
    LockWait = 6,
    Maintenance = 7,
}

impl PosixFilesystemAdapterRequestClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlUrgent => "queue_class_0.control_urgent",
            Self::MetaRead => "queue_class_1.meta_read",
            Self::NamespaceMut => "queue_class_2.namespace_mut",
            Self::DirStream => "queue_class_3.dir_stream",
            Self::FileRead => "queue_class_4.file_read",
            Self::FileWriteback => "queue_class_5.file_writeback",
            Self::LockWait => "queue_class_6.lock_wait",
            Self::Maintenance => "queue_class_7.maintenance",
        }
    }

    #[must_use]
    pub const fn control_urgent_only(self) -> bool {
        matches!(self, Self::ControlUrgent)
    }

    #[must_use]
    pub const fn may_block_on_lock_waits(self) -> bool {
        matches!(self, Self::LockWait)
    }
}

impl Default for PosixFilesystemAdapterRequestClass {
    fn default() -> Self {
        Self::MetaRead
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterRequestClass {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlUrgent),
            1 => Ok(Self::MetaRead),
            2 => Ok(Self::NamespaceMut),
            3 => Ok(Self::DirStream),
            4 => Ok(Self::FileRead),
            5 => Ok(Self::FileWriteback),
            6 => Ok(Self::LockWait),
            7 => Ok(Self::Maintenance),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownRequestClass(
                value,
            )),
        }
    }
}

/// P5-02 reply class (canonical 2-class commit topology) ABI.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterReplyClass {
    SmallReply = 0,
    BulkReply = 1,
}

impl PosixFilesystemAdapterReplyClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SmallReply => "reply_class_0.small_reply",
            Self::BulkReply => "reply_class_1.bulk_reply",
        }
    }
}

impl Default for PosixFilesystemAdapterReplyClass {
    fn default() -> Self {
        Self::SmallReply
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterReplyClass {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SmallReply),
            1 => Ok(Self::BulkReply),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownReplyClass(value)),
        }
    }
}

/// P5-02 canonical shard-key policy (7 families).
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterShardKeyPolicy {
    Session = 0,
    ParentDir = 1,
    DualParentPair = 2,
    ObjectRead = 3,
    ObjectWrite = 4,
    DirHandle = 5,
    LockScope = 6,
}

impl PosixFilesystemAdapterShardKeyPolicy {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "secret_key_policy_0.session",
            Self::ParentDir => "secret_key_policy_1.parent_dir",
            Self::DualParentPair => "secret_key_policy_2.dual_parent_pair",
            Self::ObjectRead => "secret_key_policy_3.object_read",
            Self::ObjectWrite => "secret_key_policy_4.object_write",
            Self::DirHandle => "secret_key_policy_5.dir_handle",
            Self::LockScope => "secret_key_policy_6.lock_scope",
        }
    }
}

impl Default for PosixFilesystemAdapterShardKeyPolicy {
    fn default() -> Self {
        Self::Session
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterShardKeyPolicy {
    type Error = PosixFilesystemAdapterDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Session),
            1 => Ok(Self::ParentDir),
            2 => Ok(Self::DualParentPair),
            3 => Ok(Self::ObjectRead),
            4 => Ok(Self::ObjectWrite),
            5 => Ok(Self::DirHandle),
            6 => Ok(Self::LockScope),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownShardKeyPolicy(
                value,
            )),
        }
    }
}

/// P5-02 backpressure state record.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterBackpressureStateRecord {
    pub inflight_request_count: u64,
    pub inflight_request_bytes: u64,
    pub reply_bytes_inflight: u64,
    pub dirty_window_bytes: u64,
    pub bulk_read_reply_bytes: u64,
    pub lock_wait_count: u32,
    pub maintenance_backlog: u64,
    pub _reserved: [u32; 3],
}

/// P5-02 interrupt token — maps an INTERRUPT wire request to a cancel-pending marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterInterruptTokenRecord {
    pub unique_fuse_request: u64,
    pub cancel_requested: bool,
    pub _reserved: [u32; 2],
}

/// P5-02 forget batch mirror — tiny queue payload for BATCH_FORGET.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterForgetBatchMirrorRecord {
    pub forget_count: u32,
    pub first_inode: u64,
    pub batch_length: u32,
    pub _reserved: [u32; 1],
}

/// P5-02 request context mirror — frozen projection for a single FUSE request.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterRequestContextMirrorRecord {
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub opcode: u32,
    pub request_class: u32,
    pub shard_key_policy: u32,
    pub shard_key: u64,
    pub _reserved: [u32; 1],
}

/// P5-02 reply commit record — payload for reply commit lanes.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterReplyCommitRecord {
    pub unique: u64,
    pub reply_class: u32,
    pub error_or_zero: i32,
    pub payload_len: u32,
    pub _reserved: [u32; 2],
}

/// Front-end write staging request produced by FUSE ingress classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterWriteStagingRequest {
    pub unique: u64,
    pub inode: u64,
    pub fh: u64,
    pub offset: u64,
    pub length: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub _reserved: [u32; 2],
}

impl PosixFilesystemAdapterWriteStagingRequest {
    #[must_use]
    pub const fn end_offset(self) -> Option<u64> {
        self.offset.checked_add(self.length as u64)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }
}

/// Outcome returned after the IO worker copies write payload into staging.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterWriteStagingOutcome {
    pub unique: u64,
    pub inode: u64,
    pub offset: u64,
    pub length: u32,
    pub buffer_handle: u64,
    pub content_hash64: u64,
    pub write_flags: u32,
    pub _reserved: [u32; 1],
}

impl PosixFilesystemAdapterWriteStagingOutcome {
    #[must_use]
    pub const fn end_offset(self) -> Option<u64> {
        self.offset.checked_add(self.length as u64)
    }
}

/// Dirty-extent work item submitted to the scheduler for later writeback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterDirtyExtentWorkItem {
    pub work_item_id: u64,
    pub unique: u64,
    pub inode: u64,
    pub offset: u64,
    pub length: u32,
    pub buffer_handle: u64,
    pub content_hash64: u64,
    pub write_flags: u32,
    pub _reserved: [u32; 1],
}

impl PosixFilesystemAdapterDirtyExtentWorkItem {
    #[must_use]
    pub const fn from_staging_outcome(
        work_item_id: u64,
        outcome: PosixFilesystemAdapterWriteStagingOutcome,
    ) -> Self {
        Self {
            work_item_id,
            unique: outcome.unique,
            inode: outcome.inode,
            offset: outcome.offset,
            length: outcome.length,
            buffer_handle: outcome.buffer_handle,
            content_hash64: outcome.content_hash64,
            write_flags: outcome.write_flags,
            _reserved: [0_u32; 1],
        }
    }
}

/// P5-02 session runtime record — long-lived session topology.
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterSessionRuntimeRecord {
    pub session_id: u64,
    pub phase: u32,
    pub ingress_reader_count: u32,
    pub urgent_control_worker_count: u32,
    pub meta_worker_count: u32,
    pub namespace_mut_worker_count: u32,
    pub dir_stream_worker_count: u32,
    pub file_read_worker_count: u32,
    pub file_writeback_worker_count: u32,
    pub lock_wait_worker_count: u32,
    pub maintenance_worker_count: u32,
    pub small_reply_committer_count: u32,
    pub bulk_reply_committer_count: u32,
    pub _reserved: [u32; 2],
}

/// P5-02 session phase discriminator.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixFilesystemAdapterSessionPhase {
    Bootstrap = 0,
    SteadyState = 1,
    Draining = 2,
    Terminal = 3,
}

impl PosixFilesystemAdapterSessionPhase {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// P5-02 ingress frame ownership marker (memory_domain_3).
#[derive(Clone, Copy, Debug, Default)]
pub struct PosixFilesystemAdapterFuseIngressFrame {
    pub frame_id: u64,
    pub payload_len: u32,
    pub _reserved: [u32; 1],
}

/// P5-02 worker-pool sizing configuration (policy defaults, not hard ABI).
#[derive(Clone, Copy, Debug)]
pub struct PosixFilesystemAdapterWorkerPoolSizingRecord {
    pub ingress_readers: u32,
    pub meta_workers: u32,
    pub namespace_mut_workers: u32,
    pub dir_stream_workers: u32,
    pub file_read_workers: u32,
    pub file_writeback_workers: u32,
    pub lock_wait_workers: u32,
    pub maintenance_workers: u32,
    pub small_reply_committers: u32,
    pub bulk_reply_committers: u32,
    pub urgent_control_workers: u32,
}

impl Default for PosixFilesystemAdapterWorkerPoolSizingRecord {
    fn default() -> Self {
        Self {
            ingress_readers: 1,
            meta_workers: 2,
            namespace_mut_workers: 2,
            dir_stream_workers: 1,
            file_read_workers: 2,
            file_writeback_workers: 2,
            lock_wait_workers: 1,
            maintenance_workers: 1,
            small_reply_committers: 1,
            bulk_reply_committers: 1,
            urgent_control_workers: 1,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POSIX / FUSE operation flag constants
// ═══════════════════════════════════════════════════════════════════════════
//
// These constants are the canonical source of truth for flag values shared
// across the tidefs-posix-filesystem-adapter-* crate family. They were
// previously duplicated in fusewire, capacity, workers-io, workers-ns, and
// the adapter daemon. Centralising them here prevents accidental divergence
// and reduces merge-conflict surface.

/// Linux `fallocate(2)` mode flags as carried by `FUSE_FALLOCATE`.
pub mod fallocate_flags {
    /// Keep file size unchanged (deallocation / hole punching).
    pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    /// Punch hole: deallocate the range.
    pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    /// Collapse range: remove data without leaving a hole.
    pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
    /// Zero range: zero-fill without changing file size.
    pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
    /// Insert range: shift data forward, creating a hole.
    pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
    /// Unshare range: break CoW links for the range.
    pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;
}

/// Linux `lseek(2)` whence values as carried by `FUSE_LSEEK`.
pub mod lseek_whence {
    pub const SEEK_SET: u32 = 0;
    pub const SEEK_CUR: u32 = 1;
    pub const SEEK_END: u32 = 2;
    pub const SEEK_DATA: u32 = 3;
    pub const SEEK_HOLE: u32 = 4;
}

/// Linux `renameat2(2)` flags as carried by `FUSE_RENAME`.
pub mod rename_flags {
    /// Fail if the destination exists (`renameat2` only).
    pub const RENAME_NOREPLACE: u32 = 0x01;
    /// Atomically exchange source and destination.
    pub const RENAME_EXCHANGE: u32 = 0x02;
}

/// Fixed block size used by the sparse-file I/O worker primitive.
pub const SPARSE_IO_BLOCK_SIZE: u64 = 4096;
#[cfg(all(test, feature = "wake-receipt"))]
mod tests {
    use super::*;

    #[test]
    fn refusal_projection_keeps_zero_ticket() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::new(
            PosixFilesystemAdapterProductWakeReceiptDraft {
                wake_receipt_id: PosixFilesystemAdapterId128::from_u128_le(0x11),
                request_id: PosixFilesystemAdapterId128::from_u128_le(0x22),
                journal_id: PosixFilesystemAdapterId128::from_u128_le(0x33),
                response_registry_receipt_id: PosixFilesystemAdapterId128::from_u128_le(0x44),
                publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::ZERO,
                wake_class: PosixFilesystemAdapterWakeClass::RefusalProjection,
                visibility_class: PosixFilesystemAdapterVisibilityClass::NoMutationVisible,
                answer_digest: [0xAA_u8; 32],
                artifact_locator_digest: [0xBB_u8; 32],
                witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                    PosixFilesystemAdapterId128::from_u128_le(0x55),
                    PosixFilesystemAdapterId128::from_u128_le(0x66),
                    PosixFilesystemAdapterId128::from_u128_le(0x77),
                    PosixFilesystemAdapterId128::from_u128_le(0x88),
                    [0xCC_u8; 32],
                ),
            },
        );
        assert_eq!(
            record.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::RefusalProjection)
        );
        assert_eq!(
            record.visibility(),
            Ok(PosixFilesystemAdapterVisibilityClass::NoMutationVisible)
        );
        assert!(!record.has_publication_pipeline_ticket());
        assert!(record.has_witness_join());
    }

    #[test]
    fn invalid_product_wake_wire_values_report_decode_errors() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord {
            wake_class: 99,
            ..PosixFilesystemAdapterProductWakeReceiptRecord::default()
        };
        assert_eq!(
            record.wake_class(),
            Err(PosixFilesystemAdapterDecodeError::UnknownWakeClass(99))
        );

        let record = PosixFilesystemAdapterProductWakeReceiptRecord {
            visibility_class: 88,
            ..PosixFilesystemAdapterProductWakeReceiptRecord::default()
        };
        assert_eq!(
            record.visibility(),
            Err(PosixFilesystemAdapterDecodeError::UnknownVisibilityClass(
                88
            ))
        );
    }

    #[test]
    fn fuse_surface_validation_map_keeps_parent_gate_open() {
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_SPEC.contains("PC-004A"));
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_SPEC.contains("non-closing validation"));
        assert_eq!(
            fuse_mount_surface_validation_cases(),
            FUSE_MOUNT_SURFACE_VALIDATION_CASES
        );
        assert_eq!(FUSE_MOUNT_SURFACE_VALIDATION_CASES.len(), 9);
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_CASES
            .iter()
            .all(|case| !case.closes_parent_publishing_checklist_item));
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_CASES.iter().any(|case| {
            case.validation_class == PosixFilesystemAdapterSurfaceValidationClass::FutureFullGate
                && case.status == PosixFilesystemAdapterValidationStatus::DeferredNonClosing
                && case.current_surface.contains("mmap-heavy correctness")
        }));
    }

    #[test]
    fn fuse_surface_validation_map_names_current_validation_and_skips() {
        let classes = [
            PosixFilesystemAdapterSurfaceValidationClass::MountLifecycle,
            PosixFilesystemAdapterSurfaceValidationClass::NamespaceTraversal,
            PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
            PosixFilesystemAdapterSurfaceValidationClass::DurabilityBarrier,
            PosixFilesystemAdapterSurfaceValidationClass::SessionHandleSemantics,
            PosixFilesystemAdapterSurfaceValidationClass::CapacityAccounting,
            PosixFilesystemAdapterSurfaceValidationClass::UnsupportedBoundary,
            PosixFilesystemAdapterSurfaceValidationClass::ExternalSuiteCoverage,
            PosixFilesystemAdapterSurfaceValidationClass::FutureFullGate,
        ];
        for (idx, class) in classes.into_iter().enumerate() {
            assert_eq!(
                PosixFilesystemAdapterSurfaceValidationClass::try_from(idx as u32),
                Ok(class)
            );
            assert!(class.as_str().contains("posix_filesystem_adapter"));
        }
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_CASES.iter().any(|case| {
            case.status == PosixFilesystemAdapterValidationStatus::RecordedScoreboard
                && case.validation_output.contains("generic035")
        }));
        assert!(FUSE_MOUNT_SURFACE_VALIDATION_CASES.iter().any(|case| {
            case.status == PosixFilesystemAdapterValidationStatus::ExplicitSkip
                && case.current_surface.contains("EOPNOTSUPP")
        }));
    }
    #[test]
    fn product_wake_receipt_new_preserves_draft_fields() {
        let draft = PosixFilesystemAdapterProductWakeReceiptDraft {
            wake_receipt_id: PosixFilesystemAdapterReceiptId::from_u128_le(0xA10),
            request_id: PosixFilesystemAdapterRequestId::from_u128_le(0xA11),
            journal_id: PosixFilesystemAdapterJournalId::from_u128_le(0xA12),
            response_registry_receipt_id: PosixFilesystemAdapterReceiptId::from_u128_le(0xA13),
            publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::ZERO,
            wake_class: PosixFilesystemAdapterWakeClass::NamespaceProjection,
            visibility_class: PosixFilesystemAdapterVisibilityClass::CommittedVisible,
            answer_digest: [0xFE_u8; 32],
            artifact_locator_digest: [0xFD_u8; 32],
            witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
        };
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::new(draft);
        assert_eq!(
            record.wake_receipt_id,
            PosixFilesystemAdapterReceiptId::from_u128_le(0xA10)
        );
        assert_eq!(
            record.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::NamespaceProjection)
        );
        assert_eq!(record.answer_digest, [0xFE_u8; 32]);
        assert!(!record.has_witness_join());
    }

    #[test]
    fn all_wake_classes_round_trip() {
        let classes = [
            PosixFilesystemAdapterWakeClass::NamespaceProjection,
            PosixFilesystemAdapterWakeClass::MetadataProjection,
            PosixFilesystemAdapterWakeClass::DataProjection,
            PosixFilesystemAdapterWakeClass::DurabilityBarrier,
            PosixFilesystemAdapterWakeClass::RefusalProjection,
        ];
        for c in classes {
            assert_eq!(PosixFilesystemAdapterWakeClass::try_from(c.as_u32()), Ok(c));
        }
    }

    #[test]
    fn all_visibility_classes_round_trip() {
        let classes = [
            PosixFilesystemAdapterVisibilityClass::CommittedVisible,
            PosixFilesystemAdapterVisibilityClass::DeferredOrBuffered,
            PosixFilesystemAdapterVisibilityClass::NoMutationVisible,
        ];
        for c in classes {
            assert_eq!(
                PosixFilesystemAdapterVisibilityClass::try_from(c.as_u32()),
                Ok(c)
            );
        }
    }

    #[test]
    fn all_surface_validation_classes_round_trip() {
        let classes = [
            PosixFilesystemAdapterSurfaceValidationClass::MountLifecycle,
            PosixFilesystemAdapterSurfaceValidationClass::NamespaceTraversal,
            PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
            PosixFilesystemAdapterSurfaceValidationClass::DurabilityBarrier,
            PosixFilesystemAdapterSurfaceValidationClass::SessionHandleSemantics,
            PosixFilesystemAdapterSurfaceValidationClass::CapacityAccounting,
            PosixFilesystemAdapterSurfaceValidationClass::UnsupportedBoundary,
            PosixFilesystemAdapterSurfaceValidationClass::ExternalSuiteCoverage,
            PosixFilesystemAdapterSurfaceValidationClass::FutureFullGate,
        ];
        for (idx, c) in classes.iter().enumerate() {
            assert_eq!(
                PosixFilesystemAdapterSurfaceValidationClass::try_from(idx as u32),
                Ok(*c)
            );
        }
    }

    #[test]
    fn all_validation_statuses_round_trip() {
        let statuses = [
            PosixFilesystemAdapterValidationStatus::SourceBound,
            PosixFilesystemAdapterValidationStatus::ExecutedSmoke,
            PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
            PosixFilesystemAdapterValidationStatus::ExplicitSkip,
            PosixFilesystemAdapterValidationStatus::DeferredNonClosing,
        ];
        for s in statuses {
            assert_eq!(
                PosixFilesystemAdapterValidationStatus::try_from(s.as_u32()),
                Ok(s)
            );
        }
    }

    #[test]
    fn validation_case_struct_fields() {
        let case = PosixFilesystemAdapterSurfaceValidationCase {
            stable_id: "test-surface-id",
            validation_class: PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
            status: PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
            current_surface: "TideFS/fuse/read",
            validation_output: "generic001/generic002",
            parent_gate_boundary: "full-fuse-FUSE userspace implementation",
            closes_parent_publishing_checklist_item: false,
        };
        assert_eq!(case.stable_id, "test-surface-id");
        assert_eq!(
            case.validation_class,
            PosixFilesystemAdapterSurfaceValidationClass::FileDataIo
        );
        assert_eq!(
            case.status,
            PosixFilesystemAdapterValidationStatus::RecordedScoreboard
        );
        assert_eq!(case.current_surface, "TideFS/fuse/read");
        assert_eq!(case.validation_output, "generic001/generic002");
        assert_eq!(
            case.parent_gate_boundary,
            "full-fuse-FUSE userspace implementation"
        );
        assert!(!case.closes_parent_publishing_checklist_item);
    }

    #[test]
    fn product_wake_receipt_default_has_zero_ids() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::default();
        assert_eq!(record.wake_receipt_id, PosixFilesystemAdapterId128::ZERO);
        assert_eq!(record.request_id, PosixFilesystemAdapterId128::ZERO);
        assert_eq!(record.journal_id, PosixFilesystemAdapterId128::ZERO);
        assert_eq!(
            record.response_registry_receipt_id,
            PosixFilesystemAdapterId128::ZERO
        );
        assert_eq!(
            record.publication_pipeline_ticket_id_or_zero,
            PosixFilesystemAdapterId128::ZERO
        );
        assert!(!record.has_publication_pipeline_ticket());
    }

    #[test]
    fn decode_error_equality() {
        let e1 = PosixFilesystemAdapterDecodeError::UnknownWakeClass(99);
        let e2 = PosixFilesystemAdapterDecodeError::UnknownWakeClass(99);
        let e3 = PosixFilesystemAdapterDecodeError::UnknownVisibilityClass(88);
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn default_record_has_valid_zero_variant_fields() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::default();
        assert_eq!(
            record.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::NamespaceProjection)
        );
        assert_eq!(
            record.visibility(),
            Ok(PosixFilesystemAdapterVisibilityClass::CommittedVisible)
        );
    }
    #[test]
    fn wake_receipt_with_non_zero_ticket_has_it() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::new(
            PosixFilesystemAdapterProductWakeReceiptDraft {
                wake_receipt_id: PosixFilesystemAdapterId128::ZERO,
                request_id: PosixFilesystemAdapterId128::ZERO,
                journal_id: PosixFilesystemAdapterId128::ZERO,
                response_registry_receipt_id: PosixFilesystemAdapterId128::ZERO,
                publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::from_u128_le(
                    1,
                ),
                wake_class: PosixFilesystemAdapterWakeClass::NamespaceProjection,
                visibility_class: PosixFilesystemAdapterVisibilityClass::CommittedVisible,
                answer_digest: [0_u8; 32],
                artifact_locator_digest: [0_u8; 32],
                witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
            },
        );
        assert!(record.has_publication_pipeline_ticket());
    }
}
