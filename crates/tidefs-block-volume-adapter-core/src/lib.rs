// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Deterministic block-volume adapter core model for OW-301A.
//!
//! This crate models the byte-level contract that a later userspace block
//! export must preserve: geometry bounds, exact reads and writes, flush barrier
//! receipts, discard/zero visibility, and explicit refusals. It is not a ublk
//! daemon, not a Linux block device, and not fio or guest-filesystem validation.

use tidefs_block_allocator::DeviceTopology;

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::Path;

// Linux fallocate(2) mode flags for hole-punching discard.
// These mirror the kernel FALLOC_FL_* constants from <linux/falloc.h>.
pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;

pub const BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A: &str =
    "OW-301A block-volume adapter core model covers read/write/flush/discard gates";
pub const BLOCK_VOLUME_QUEUE_ADMISSION_GATE_OW_301B: &str =
    "OW-301B block-volume queue admission model covers queue/shard/backpressure/fence gates";
pub const BLOCK_VOLUME_DISPATCH_EXECUTION_GATE_OW_301C: &str =
    "OW-301C block-volume dispatch execution model covers admitted request execution gates";
pub const BLOCK_VOLUME_EXPORT_LIFECYCLE_GATE_OW_301D: &str =
    "OW-301D block-volume export lifecycle model covers quiesce/fence/resume gates";
pub const BLOCK_VOLUME_CACHE_COHERENCY_GATE_OW_301E: &str =
    "OW-301E block-volume cache coherency model covers cache/barrier/guard gates";
pub const BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F: &str =
    "OW-301F block-volume resize/fence transition model covers capacity target, drain, and geometry publication gates";
pub const BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N: &str =
    "OW-301N block-volume file-backed image surface binds block-volume image requests to durable userspace backing files without live ublk";

pub mod boundary;
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockVolumeId(pub u64);

impl BlockVolumeId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockVolumeReceiptId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeRequestClass {
    Read,
    Write,
    Flush,
    Discard,
    WriteZeroes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeCompletionClass {
    Completed,
    RefusedOutOfBounds,
    RefusedMisalignedRange,
    RefusedDiscardUnsupported,
    RefusedBackpressure,
    RefusedExportFenced,
    RefusedUnadmittedContext,
    RefusedPayloadMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeFlushBarrierClass {
    NotRequired,
    Satisfied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRangeRecord {
    pub start_block: usize,
    pub block_count: usize,
}

impl BlockRangeRecord {
    #[must_use]
    pub const fn new(start_block: usize, block_count: usize) -> Self {
        Self {
            start_block,
            block_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockVolumeGeometryRecord {
    pub volume_id: BlockVolumeId,
    pub block_size_bytes: usize,
    pub block_count: usize,
    pub discard_granularity_blocks: usize,
    /// Logical sector size in bytes (e.g., 512, 4096).
    pub logical_sector_size: u64,
    /// Physical sector size in bytes (e.g., 4096, 8192).
    pub physical_sector_size: u64,
    /// Optimal I/O size in bytes reported by the device.
    pub optimal_io_size: u64,
    /// Byte offset to first aligned sector.
    pub alignment_offset: u64,
    /// Minimum I/O size in bytes.
    pub min_io_size: u64,
}

impl BlockVolumeGeometryRecord {
    #[must_use]
    pub const fn new(
        volume_id: BlockVolumeId,
        block_size_bytes: usize,
        block_count: usize,
        discard_granularity_blocks: usize,
    ) -> Self {
        Self {
            volume_id,
            block_size_bytes,
            block_count,
            discard_granularity_blocks,
            logical_sector_size: 512,
            physical_sector_size: 512,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        }
    }

    /// Create a geometry record with explicit device topology.
    #[must_use]
    pub const fn with_topology(
        volume_id: BlockVolumeId,
        block_size_bytes: usize,
        block_count: usize,
        discard_granularity_blocks: usize,
        topology: DeviceTopology,
    ) -> Self {
        Self {
            volume_id,
            block_size_bytes,
            block_count,
            discard_granularity_blocks,
            logical_sector_size: topology.logical_sector_size,
            physical_sector_size: topology.physical_sector_size,
            optimal_io_size: topology.optimal_io_size,
            alignment_offset: topology.alignment_offset,
            min_io_size: topology.min_io_size,
        }
    }

    #[must_use]
    pub const fn capacity_bytes(self) -> Option<usize> {
        self.block_size_bytes.checked_mul(self.block_count)
    }

    #[must_use]
    pub const fn admits_discard(self) -> bool {
        self.discard_granularity_blocks > 0
    }

    /// Convert this geometry record into a [`DeviceTopology`] suitable
    /// for registration with the block allocator.
    #[must_use]
    pub const fn to_device_topology(self) -> DeviceTopology {
        DeviceTopology {
            logical_sector_size: self.logical_sector_size,
            physical_sector_size: self.physical_sector_size,
            optimal_io_size: self.optimal_io_size,
            alignment_offset: self.alignment_offset,
            min_io_size: self.min_io_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeDirtyRangeEpochRecord {
    pub epoch_id: BlockVolumeReceiptId,
    pub range: BlockRangeRecord,
    pub dirty_bytes: usize,
    pub sealed_for_flush: bool,
    pub invalidated_by_discard: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeFlushBarrierRecord {
    pub barrier_id: BlockVolumeReceiptId,
    pub barrier_class: BlockVolumeFlushBarrierClass,
    pub covered_epoch_ids: Vec<BlockVolumeReceiptId>,
    pub durability_receipt_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeDiscardIntentRecord {
    pub intent_id: BlockVolumeReceiptId,
    pub range: BlockRangeRecord,
    pub invalidated_epoch_ids: Vec<BlockVolumeReceiptId>,
    pub zeroes_visible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeRequestPlan {
    pub request_class: BlockVolumeRequestClass,
    pub completion_class: BlockVolumeCompletionClass,
    pub range: Option<BlockRangeRecord>,
    pub payload_len: usize,
    pub dirty_epoch_ref: Option<BlockVolumeReceiptId>,
    pub flush_barrier_ref: Option<BlockVolumeReceiptId>,
    pub discard_intent_ref: Option<BlockVolumeReceiptId>,
    pub completion_receipt_ref: BlockVolumeReceiptId,
}

#[must_use]
pub fn plan_read_write_request_bounds(
    geometry: BlockVolumeGeometryRecord,
    request_class: BlockVolumeRequestClass,
    byte_offset: usize,
    byte_len: usize,
) -> BlockVolumeRequestPlan {
    match request_class {
        BlockVolumeRequestClass::Read | BlockVolumeRequestClass::Write => {}
        _ => {
            return read_write_bounds_refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedUnadmittedContext,
                None,
                byte_len,
            );
        }
    }

    let block_size = geometry.block_size_bytes;
    if block_size == 0 || byte_offset % block_size != 0 || byte_len % block_size != 0 {
        return read_write_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange,
            None,
            byte_len,
        );
    }

    if byte_len == 0 {
        return match geometry.capacity_bytes() {
            Some(capacity_bytes) if byte_offset <= capacity_bytes => {
                read_write_bounds_completed_plan(geometry, request_class, None, 0)
            }
            _ => read_write_bounds_refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                None,
                0,
            ),
        };
    }

    let range = BlockRangeRecord::new(byte_offset / block_size, byte_len / block_size);
    if block_range_bytes(geometry, range).is_none() {
        return read_write_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds,
            Some(range),
            byte_len,
        );
    }

    read_write_bounds_completed_plan(geometry, request_class, Some(range), byte_len)
}

#[must_use]
pub fn plan_discard_request_bounds(
    geometry: BlockVolumeGeometryRecord,
    request_class: BlockVolumeRequestClass,
    byte_offset: usize,
    byte_len: usize,
) -> BlockVolumeRequestPlan {
    match request_class {
        BlockVolumeRequestClass::Discard | BlockVolumeRequestClass::WriteZeroes => {}
        _ => {
            return discard_bounds_refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedUnadmittedContext,
                None,
            );
        }
    }

    let block_size = geometry.block_size_bytes;
    if block_size == 0 || byte_offset % block_size != 0 || byte_len % block_size != 0 {
        return discard_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange,
            None,
        );
    }

    if byte_len == 0 {
        return match geometry.capacity_bytes() {
            Some(capacity_bytes) if byte_offset <= capacity_bytes => {
                discard_bounds_completed_plan(geometry, request_class, None)
            }
            _ => discard_bounds_refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                None,
            ),
        };
    }

    let range = BlockRangeRecord::new(byte_offset / block_size, byte_len / block_size);
    if block_range_bytes(geometry, range).is_none() {
        return discard_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds,
            Some(range),
        );
    }

    if request_class == BlockVolumeRequestClass::Discard && !geometry.admits_discard() {
        return discard_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedDiscardUnsupported,
            Some(range),
        );
    }

    if request_class == BlockVolumeRequestClass::Discard
        && !range_aligned_to_granularity(range, geometry.discard_granularity_blocks)
    {
        return discard_bounds_refusal_plan(
            request_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange,
            Some(range),
        );
    }

    discard_bounds_completed_plan(geometry, request_class, Some(range))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeDurabilityClass {
    None,
    FlushRequired,
    FuaRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeQueueClass {
    ReadFast,
    OrderedMutation,
    Barrier,
    ZeroDiscard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeQueueOrderingScopeClass {
    Independent,
    OverlapSerialized,
    GlobalBarrier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeQueueBlockingClass {
    NonBlocking,
    MayBlockForMutation,
    MustDrainBeforeCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeQueuePhaseClass {
    Open,
    Fenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeQueueAdmissionClass {
    Admitted,
    RefusedBackpressure,
    RefusedExportFenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueuePolicyRecord {
    pub policy_id: BlockVolumeReceiptId,
    pub max_inflight_requests: usize,
    pub max_inflight_bytes: usize,
    pub shard_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueueClassRecord {
    pub queue_class_id: BlockVolumeReceiptId,
    pub queue_class: BlockVolumeQueueClass,
    pub ordering_scope_class: BlockVolumeQueueOrderingScopeClass,
    pub blocking_class: BlockVolumeQueueBlockingClass,
    pub default_worker_floor: usize,
    pub burst_worker_ceiling: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueueSetRecord {
    pub queue_set_id: BlockVolumeReceiptId,
    pub queue_index: usize,
    pub shard_count: usize,
    pub block_count: usize,
    pub shard_span_blocks: usize,
    pub queue_phase_class: BlockVolumeQueuePhaseClass,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueueShardRecord {
    pub queue_shard_id: BlockVolumeReceiptId,
    pub queue_set_ref: BlockVolumeReceiptId,
    pub shard_index: usize,
    pub covered_range: BlockRangeRecord,
    pub ordered_ranges: Vec<BlockRangeRecord>,
    pub inflight_context_ids: Vec<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeSubmissionContextMirrorRecord {
    pub submission_context_id: BlockVolumeReceiptId,
    pub request_class: BlockVolumeRequestClass,
    pub queue_class: BlockVolumeQueueClass,
    pub queue_shard_refs: Vec<BlockVolumeReceiptId>,
    pub range: Option<BlockRangeRecord>,
    pub payload_len: usize,
    pub exactness_class: BlockVolumeCompletionClass,
    pub durability_class: BlockVolumeDurabilityClass,
    pub anchor_snapshot_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueueBackpressureStateRecord {
    pub backpressure_state_id: BlockVolumeReceiptId,
    pub queue_set_ref: BlockVolumeReceiptId,
    pub max_inflight_requests: usize,
    pub max_inflight_bytes: usize,
    pub inflight_requests: usize,
    pub inflight_bytes: usize,
    pub open_flush_epochs: usize,
    pub issue_receipt_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeExportFenceMirrorRecord {
    pub export_fence_id: BlockVolumeReceiptId,
    pub queue_set_ref: BlockVolumeReceiptId,
    pub queue_phase_class: BlockVolumeQueuePhaseClass,
    pub affected_queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub issue_receipt_ref: Option<BlockVolumeReceiptId>,
    pub close_receipt_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdmissionDecisionRecord {
    pub admission_class: BlockVolumeQueueAdmissionClass,
    pub submission_context_ref: BlockVolumeReceiptId,
    pub queue_shard_refs: Vec<BlockVolumeReceiptId>,
    pub completion_class: BlockVolumeCompletionClass,
    pub issue_receipt_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeFlushEpochRecord {
    pub flush_epoch_id: BlockVolumeReceiptId,
    pub covered_submission_context_refs: Vec<BlockVolumeReceiptId>,
    pub durability_class: BlockVolumeDurabilityClass,
    pub sealed: bool,
    pub completion_token_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeCompletionCommitMirrorRecord {
    pub completion_commit_id: BlockVolumeReceiptId,
    pub submission_context_ref: BlockVolumeReceiptId,
    pub queue_set_ref: BlockVolumeReceiptId,
    pub result_class: BlockVolumeCompletionClass,
    pub byte_count: usize,
    pub linux_status_code: i32,
    pub completion_receipt_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeDispatchClass {
    Executed,
    RefusedUnadmittedContext,
    RefusedPayloadMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeDispatchExecutionRecord {
    pub dispatch_id: BlockVolumeReceiptId,
    pub dispatch_class: BlockVolumeDispatchClass,
    pub submission_context_ref: BlockVolumeReceiptId,
    pub request_class: BlockVolumeRequestClass,
    pub range: Option<BlockRangeRecord>,
    pub request_plan: BlockVolumeRequestPlan,
    pub read_payload_len: usize,
    pub completion_commit_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeExportPhaseClass {
    Bootstrap,
    ExportAdmitted,
    QueuesLive,
    QuiesceTransition,
    Fenced,
    Resumed,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeExportTransitionClass {
    AdmitExport,
    StartQueues,
    ResizeQuiesce,
    RevokeQuiesce,
    FailoverQuiesce,
    FenceAfterDrain,
    ResumeAfterFence,
    StopAfterDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeInflightTransitionClass {
    CommitOk,
    ReplayRequired,
    AbortRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeExportTransitionOutcomeClass {
    Completed,
    RefusedInvalidPhase,
    RefusedDrainIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeExportRuntimeRecord {
    pub export_runtime_id: BlockVolumeReceiptId,
    pub volume_id: BlockVolumeId,
    pub export_phase_class: BlockVolumeExportPhaseClass,
    pub queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub authority_anchor_ref: BlockVolumeReceiptId,
    pub fence_epoch_ref: BlockVolumeReceiptId,
    pub lifecycle_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeInflightTransitionClassificationRecord {
    pub submission_context_ref: BlockVolumeReceiptId,
    pub request_class: BlockVolumeRequestClass,
    pub classification: BlockVolumeInflightTransitionClass,
    pub range: Option<BlockRangeRecord>,
    pub queue_shard_refs: Vec<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeExportLifecycleTransitionRecord {
    pub transition_id: BlockVolumeReceiptId,
    pub transition_class: BlockVolumeExportTransitionClass,
    pub from_phase_class: BlockVolumeExportPhaseClass,
    pub to_phase_class: BlockVolumeExportPhaseClass,
    pub outcome_class: BlockVolumeExportTransitionOutcomeClass,
    pub affected_queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub inflight_classifications: Vec<BlockVolumeInflightTransitionClassificationRecord>,
    pub issue_receipt_ref: BlockVolumeReceiptId,
    pub close_receipt_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeCacheResidencyClass {
    Absent,
    CleanHot,
    CleanPrefetch,
    DirtyOpen,
    DirtySealed,
    FlushBarrierPending,
    DiscardZeroTransition,
    DirectOverlapGuard,
    FrozenTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeCacheTransitionClass {
    ReadCacheFill,
    DirtyWrite,
    FlushBarrier,
    FuaTicket,
    DiscardInvalidation,
    WriteZeroesInvalidation,
    DirectOverlapGuard,
    CacheLoss,
    FailoverFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeDirectOverlapGuardClass {
    Open,
    BlockedDirtyDrain,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeReadCacheWindowRecord {
    pub cache_window_id: BlockVolumeReceiptId,
    pub range: BlockRangeRecord,
    pub residency_class: BlockVolumeCacheResidencyClass,
    pub anchor_snapshot_ref: BlockVolumeReceiptId,
    pub cached_bytes: usize,
    pub invalidated_by_mutation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeCacheDirtyEpochRecord {
    pub cache_epoch_id: BlockVolumeReceiptId,
    pub range: BlockRangeRecord,
    pub dirty_bytes: usize,
    pub sealed_for_barrier: bool,
    pub write_order_fence_ref: BlockVolumeReceiptId,
    pub invalidated_cache_window_refs: Vec<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeCacheFlushBarrierRecord {
    pub cache_barrier_id: BlockVolumeReceiptId,
    pub covered_cache_epoch_refs: Vec<BlockVolumeReceiptId>,
    pub required_durability_class: BlockVolumeDurabilityClass,
    pub satisfied: bool,
    pub fua_ticket_ref: Option<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeFuaCompletionTicketRecord {
    pub fua_ticket_id: BlockVolumeReceiptId,
    pub barrier_ref: BlockVolumeReceiptId,
    pub durability_class: BlockVolumeDurabilityClass,
    pub completion_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeDirectOverlapGuardRecord {
    pub direct_guard_id: BlockVolumeReceiptId,
    pub range: BlockRangeRecord,
    pub guard_class: BlockVolumeDirectOverlapGuardClass,
    pub blocked_epoch_refs: Vec<BlockVolumeReceiptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeCacheCoherencyTransitionRecord {
    pub transition_id: BlockVolumeReceiptId,
    pub transition_class: BlockVolumeCacheTransitionClass,
    pub range: Option<BlockRangeRecord>,
    pub affected_cache_window_refs: Vec<BlockVolumeReceiptId>,
    pub affected_epoch_refs: Vec<BlockVolumeReceiptId>,
    pub receipt_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeResizeDirectionClass {
    Grow,
    Shrink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeResizeTransitionClass {
    Prepare,
    Commit,
    Refuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeResizeTransitionOutcomeClass {
    Prepared,
    Committed,
    RefusedNotFenced,
    RefusedDrainIncomplete,
    RefusedInvalidCapacity,
    RefusedNoAuthority,
    RefusedMissingPrepare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeCapacityTargetPublicationClass {
    NotPublished,
    PublishedForCommit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeResizeTransitionRecord {
    pub transition_id: BlockVolumeReceiptId,
    pub transition_class: BlockVolumeResizeTransitionClass,
    pub outcome_class: BlockVolumeResizeTransitionOutcomeClass,
    pub direction_class: Option<BlockVolumeResizeDirectionClass>,
    pub from_geometry: BlockVolumeGeometryRecord,
    pub target_geometry: BlockVolumeGeometryRecord,
    pub post_resize_geometry: Option<BlockVolumeGeometryRecord>,
    pub affected_tail_range: Option<BlockRangeRecord>,
    pub zero_visible_range: Option<BlockRangeRecord>,
    pub capacity_target_publication_class: BlockVolumeCapacityTargetPublicationClass,
    pub requires_drain: bool,
    pub overlapping_inflight_context_refs: Vec<BlockVolumeReceiptId>,
    pub overlapping_dirty_epoch_refs: Vec<BlockVolumeReceiptId>,
    pub overlapping_guard_refs: Vec<BlockVolumeReceiptId>,
    pub authority_anchor_ref: BlockVolumeReceiptId,
    pub issue_receipt_ref: BlockVolumeReceiptId,
    pub close_receipt_ref: Option<BlockVolumeReceiptId>,
}

/// Aggregate resize timing and geometry statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockVolumeResizeStats {
    /// Geometry before the resize transition.
    pub from_block_count: usize,
    /// Geometry after the resize transition.
    pub to_block_count: usize,
    /// Block size (bytes), unchanged by resize.
    pub block_size_bytes: usize,
    /// Direction of the resize.
    pub direction: Option<BlockVolumeResizeDirectionClass>,
    /// Duration of the quiesce phase (µs).
    pub quiesce_time_us: u64,
    /// Duration of the fence/drain phase (µs).
    pub fence_time_us: u64,
    /// Duration of the commit/geometry-update phase (µs).
    pub commit_time_us: u64,
}

impl BlockVolumeResizeStats {
    /// Total resize wall-clock time in microseconds.
    #[must_use]
    pub fn total_time_us(&self) -> u64 {
        self.quiesce_time_us
            .saturating_add(self.fence_time_us)
            .saturating_add(self.commit_time_us)
    }

    /// Expand or shrink as a signed block delta.
    #[must_use]
    pub fn block_delta(&self) -> i64 {
        let from = self.from_block_count as i64;
        let to = self.to_block_count as i64;
        to - from
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeQueueRuntime {
    pub volume_id: BlockVolumeId,
    pub queue_policy: BlockVolumeQueuePolicyRecord,
    pub queue_set: BlockVolumeQueueSetRecord,
    pub queue_classes: Vec<BlockVolumeQueueClassRecord>,
    pub shards: Vec<BlockVolumeQueueShardRecord>,
    pub backpressure: BlockVolumeQueueBackpressureStateRecord,
    pub export_fence: BlockVolumeExportFenceMirrorRecord,
    pub inflight_contexts: Vec<BlockVolumeSubmissionContextMirrorRecord>,
    pub flush_epochs: Vec<BlockVolumeFlushEpochRecord>,
    pub completion_commits: Vec<BlockVolumeCompletionCommitMirrorRecord>,
    pub dispatch_records: Vec<BlockVolumeDispatchExecutionRecord>,
    next_context_counter: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeExportLifecycleRuntime {
    pub export_runtime: BlockVolumeExportRuntimeRecord,
    pub queue_runtime: BlockVolumeQueueRuntime,
    pub transition_records: Vec<BlockVolumeExportLifecycleTransitionRecord>,
    next_lifecycle_counter: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeCacheCoherencyRuntime {
    pub volume_id: BlockVolumeId,
    pub read_cache_windows: Vec<BlockVolumeReadCacheWindowRecord>,
    pub dirty_epochs: Vec<BlockVolumeCacheDirtyEpochRecord>,
    pub flush_barriers: Vec<BlockVolumeCacheFlushBarrierRecord>,
    pub fua_tickets: Vec<BlockVolumeFuaCompletionTicketRecord>,
    pub direct_guards: Vec<BlockVolumeDirectOverlapGuardRecord>,
    pub transition_records: Vec<BlockVolumeCacheCoherencyTransitionRecord>,
    next_cache_counter: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeResizeFenceRuntime {
    pub current_geometry: BlockVolumeGeometryRecord,
    pub lifecycle_runtime: BlockVolumeExportLifecycleRuntime,
    pub cache_runtime: BlockVolumeCacheCoherencyRuntime,
    pub resize_records: Vec<BlockVolumeResizeTransitionRecord>,
    next_resize_counter: u64,
}

#[derive(Default)]
struct ResizeTransitionBlockers {
    inflight_context_refs: Vec<BlockVolumeReceiptId>,
    dirty_epoch_refs: Vec<BlockVolumeReceiptId>,
    guard_refs: Vec<BlockVolumeReceiptId>,
}

impl ResizeTransitionBlockers {
    fn is_empty(&self) -> bool {
        self.inflight_context_refs.is_empty()
            && self.dirty_epoch_refs.is_empty()
            && self.guard_refs.is_empty()
    }
}

struct ResizeTransitionDraft {
    transition_class: BlockVolumeResizeTransitionClass,
    outcome_class: BlockVolumeResizeTransitionOutcomeClass,
    direction_class: Option<BlockVolumeResizeDirectionClass>,
    from_geometry: BlockVolumeGeometryRecord,
    target_geometry: BlockVolumeGeometryRecord,
    post_resize_geometry: Option<BlockVolumeGeometryRecord>,
    affected_tail_range: Option<BlockRangeRecord>,
    zero_visible_range: Option<BlockRangeRecord>,
    requires_drain: bool,
    blockers: ResizeTransitionBlockers,
    authority_anchor_ref: BlockVolumeReceiptId,
}

// ---------------------------------------------------------------------------
// P6-03: Export transition state machines (5 canonical state machines)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterExportTransitionState {
    Steady,
    AdmissionFreeze,
    ResizePrepare,
    ResizeCommit,
    FailoverHandoff,
    RevokeStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterAdmissionGateState {
    Open,
    Narrowed,
    Closed,
    Reopened,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterInflightDispositionState {
    Observed,
    Frozen,
    Committed,
    ReplayRequired,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterResizeTransitionState {
    Planned,
    FenceOpen,
    Drained,
    GeometryCommit,
    Resumed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterFailoverHandoffState {
    IntentOpen,
    EscrowStaged,
    QuorumMet,
    FenceOpen,
    Drained,
    CutoverCommit,
    Resumed,
    Aborted,
}

// ---------------------------------------------------------------------------
// P6-03: Fence class enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeAdapterFenceClass {
    SoftGate,
    QuiesceGate,
    ResizeGate,
    FailoverGate,
    RevokeGate,
    RepairGate,
}

// ---------------------------------------------------------------------------
// P6-03: Supporting record types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterInflightDispositionRecord {
    pub submission_context_ref: BlockVolumeReceiptId,
    pub disposition: BlockVolumeAdapterInflightDispositionState,
    pub classification: BlockVolumeInflightTransitionClass,
    pub request_class: BlockVolumeRequestClass,
    pub range: Option<BlockRangeRecord>,
    pub epoch_ref: BlockVolumeReceiptId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterReplayCursorRecord {
    pub cursor_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub cursor_position: u64,
    pub cursor_epoch: u64,
    pub fence_epoch_ref: BlockVolumeReceiptId,
    pub authoritative: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterTransitionReceiptRecord {
    pub receipt_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub transition_class: BlockVolumeExportTransitionClass,
    pub outcome_class: BlockVolumeExportTransitionOutcomeClass,
    pub from_state: BlockVolumeAdapterExportTransitionState,
    pub to_state: BlockVolumeAdapterExportTransitionState,
    pub fence_epoch_ref: BlockVolumeReceiptId,
    pub is_durable: bool,
}
// ---------------------------------------------------------------------------
// P6-03: Canonical runtime/schema record types (spec §4)
// ---------------------------------------------------------------------------

/// One active or historical fence epoch over an export with class, scope,
/// previous/new authority anchors, and queue frontier refs (runtime mirror / receipt-linked).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportFenceEpochRecord {
    pub fence_epoch_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub fence_class: BlockVolumeAdapterFenceClass,
    pub fence_generation: u64,
    pub previous_authority_anchor_ref: Option<BlockVolumeReceiptId>,
    pub new_authority_anchor_ref: Option<BlockVolumeReceiptId>,
    pub queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub is_open: bool,
    pub is_durable: bool,
    pub issue_receipt_ref: BlockVolumeReceiptId,
    pub close_receipt_ref: Option<BlockVolumeReceiptId>,
}

/// Current admission state for conflicting/non-conflicting request classes during
/// a transition (runtime mirror).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportAdmissionGateRecord {
    pub gate_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub gate_state: BlockVolumeAdapterAdmissionGateState,
    pub queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Canonical transition intent for resize/failover/revoke/repair gate with
/// issuer, target state, and linked authority refs (authoritative declaration / runtime-linked).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportTransitionIntentRecord {
    pub intent_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub transition_class: BlockVolumeExportTransitionClass,
    pub target_state: BlockVolumeAdapterExportTransitionState,
    pub fence_class: Option<BlockVolumeAdapterFenceClass>,
    pub authority_anchor_ref: BlockVolumeReceiptId,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Frozen preconditions, target geometry, required drains, and continuity checks
/// for one resize event (authoritative declaration / runtime-linked).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportResizePlanRecord {
    pub plan_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub direction_class: BlockVolumeResizeDirectionClass,
    pub from_geometry: BlockVolumeGeometryRecord,
    pub target_geometry: BlockVolumeGeometryRecord,
    pub affected_tail_range: Option<BlockRangeRecord>,
    pub requires_drain: bool,
    pub continuity_check_satisfied: bool,
    pub authority_anchor_ref: BlockVolumeReceiptId,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Handoff target, reserve-escrow refs, witness-quorum refs, replay policy,
/// and successor export target (authoritative declaration).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportFailoverIntentRecord {
    pub intent_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub successor_export_target_ref: BlockVolumeReceiptId,
    pub escrow_receipt_ref: Option<BlockVolumeReceiptId>,
    pub witness_quorum_refs: Vec<BlockVolumeReceiptId>,
    pub quorum_threshold: u32,
    pub quorum_satisfied: bool,
    pub replay_policy_ref: BlockVolumeReceiptId,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Durable proof that a fence epoch satisfied its drain conditions and no
/// conflicting inflight work remains unclassified (authoritative receipt).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterFenceQuiesceReceipt {
    pub receipt_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub fence_epoch_ref: BlockVolumeReceiptId,
    pub fence_class: BlockVolumeAdapterFenceClass,
    pub drain_complete: bool,
    pub inflight_classified_count: usize,
    pub unclassified_count: usize,
    pub is_durable: bool,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Durable proof that geometry/size change completed, was published, and
/// resumed under a fresh epoch (authoritative receipt).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterResizeCommitReceipt {
    pub receipt_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub from_geometry: BlockVolumeGeometryRecord,
    pub to_geometry: BlockVolumeGeometryRecord,
    pub resize_direction: BlockVolumeResizeDirectionClass,
    pub new_epoch_ref: BlockVolumeReceiptId,
    pub is_durable: bool,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

/// Durable proof that authority moved, replay cursor became current, and
/// previous runtime lost service rights (authoritative receipt).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterFailoverCutoverReceipt {
    pub receipt_id: BlockVolumeReceiptId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub previous_runtime_ref: BlockVolumeReceiptId,
    pub successor_runtime_ref: BlockVolumeReceiptId,
    pub replay_cursor_ref: BlockVolumeReceiptId,
    pub escrow_receipt_ref: Option<BlockVolumeReceiptId>,
    pub is_durable: bool,
    pub issue_receipt_ref: BlockVolumeReceiptId,
}

// ---------------------------------------------------------------------------
// P6-03: 10 canonical export transition runtime components
// ---------------------------------------------------------------------------

/// Orchestrates the full export transition lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterExportTransitionSupervisor {
    pub volume_id: BlockVolumeId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub current_state: BlockVolumeAdapterExportTransitionState,
    pub transition_generation: u64,
    pub fence_epoch_refs: Vec<BlockVolumeReceiptId>,
    pub transition_receipt_refs: Vec<BlockVolumeReceiptId>,
    pub transition_records: Vec<BlockVolumeExportLifecycleTransitionRecord>,
    next_supervisor_counter: u64,
}

/// Manages admission gate state (open/narrowed/closed/reopened/retired).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterAdmissionGateCoordinator {
    pub gate_state: BlockVolumeAdapterAdmissionGateState,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub admission_decision_records: Vec<BlockVolumeAdmissionDecisionRecord>,
    next_gate_counter: u64,
}

/// Creates and closes fence epochs for resize/failover/revoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterFenceEpochCoordinator {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub active_fence_class: Option<BlockVolumeAdapterFenceClass>,
    pub fence_epoch_ref: BlockVolumeReceiptId,
    pub fence_generation: u64,
    pub fence_records: Vec<BlockVolumeExportFenceMirrorRecord>,
    pub queue_set_refs: Vec<BlockVolumeReceiptId>,
    pub is_open: bool,
    next_fence_counter: u64,
}

/// Classifies inflight requests into commit/replay/abort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterInflightClassifier {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub classifications: Vec<BlockVolumeInflightTransitionClassificationRecord>,
    pub disposition_records: Vec<BlockVolumeAdapterInflightDispositionRecord>,
    next_classifier_counter: u64,
}

/// Freeze preconditions, target geometry, drains, continuity checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterResizePlanner {
    pub volume_id: BlockVolumeId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub resize_state: BlockVolumeAdapterResizeTransitionState,
    pub current_geometry: BlockVolumeGeometryRecord,
    pub target_geometry: Option<BlockVolumeGeometryRecord>,
    pub resize_records: Vec<BlockVolumeResizeTransitionRecord>,
    next_planner_counter: u64,
}

/// Emits authoritative replay cursors after failover/restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterReplayCursorWriter {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub cursor_records: Vec<BlockVolumeAdapterReplayCursorRecord>,
    pub last_cursor_position: u64,
    pub last_cursor_epoch: u64,
    next_cursor_counter: u64,
}

/// Reserve escrow, witness quorum, handoff commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterFailoverHandoffCoordinator {
    pub volume_id: BlockVolumeId,
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub handoff_state: BlockVolumeAdapterFailoverHandoffState,
    pub escrow_receipt_ref: Option<BlockVolumeReceiptId>,
    pub witness_count: u32,
    pub quorum_threshold: u32,
    pub handoff_generation: u64,
    pub transition_records: Vec<BlockVolumeExportLifecycleTransitionRecord>,
    next_handoff_counter: u64,
}

/// Controlled stop, revoke, tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterRevokeStopCoordinator {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub is_tombstoned: bool,
    pub revoke_receipt_ref: Option<BlockVolumeReceiptId>,
    pub stop_transition_records: Vec<BlockVolumeExportLifecycleTransitionRecord>,
    pub fence_receipt_ref: Option<BlockVolumeReceiptId>,
    next_revoke_counter: u64,
}

/// Drain dirty epochs, barriers, direct guards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterQueueDrainCoordinator {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub drained_dirty_epoch_refs: Vec<BlockVolumeReceiptId>,
    pub drained_barrier_refs: Vec<BlockVolumeReceiptId>,
    pub drained_guard_refs: Vec<BlockVolumeReceiptId>,
    pub drain_complete: bool,
    next_drain_counter: u64,
}

/// Durable transition receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeAdapterTransitionReceiptEmitter {
    pub export_runtime_ref: BlockVolumeReceiptId,
    pub receipt_records: Vec<BlockVolumeAdapterTransitionReceiptRecord>,
    pub is_durable: bool,
    next_emitter_counter: u64,
}

impl BlockVolumeQueueRuntime {
    #[must_use]
    pub fn open(
        geometry: BlockVolumeGeometryRecord,
        shard_count: usize,
        max_inflight_requests: usize,
        max_inflight_bytes: usize,
    ) -> Option<Self> {
        if shard_count == 0
            || geometry.block_count == 0
            || max_inflight_requests == 0
            || max_inflight_bytes == 0
        {
            return None;
        }
        let shard_span_blocks = geometry.block_count.div_ceil(shard_count);
        let queue_set_id = receipt_for_volume(geometry.volume_id, 1, 0x301B);
        let queue_policy = BlockVolumeQueuePolicyRecord {
            policy_id: receipt_for_volume(geometry.volume_id, 2, 0x301B),
            max_inflight_requests,
            max_inflight_bytes,
            shard_count,
        };
        let queue_set = BlockVolumeQueueSetRecord {
            queue_set_id,
            queue_index: 0,
            shard_count,
            block_count: geometry.block_count,
            shard_span_blocks,
            queue_phase_class: BlockVolumeQueuePhaseClass::Open,
        };
        let shards = (0..shard_count)
            .map(|idx| {
                let start_block = idx * shard_span_blocks;
                let end_block = ((idx + 1) * shard_span_blocks).min(geometry.block_count);
                BlockVolumeQueueShardRecord {
                    queue_shard_id: receipt_for_volume(geometry.volume_id, idx as u64 + 1, 0x5A11),
                    queue_set_ref: queue_set_id,
                    shard_index: idx,
                    covered_range: BlockRangeRecord::new(start_block, end_block - start_block),
                    ordered_ranges: Vec::new(),
                    inflight_context_ids: Vec::new(),
                }
            })
            .collect();
        let backpressure = BlockVolumeQueueBackpressureStateRecord {
            backpressure_state_id: receipt_for_volume(geometry.volume_id, 3, 0x301B),
            queue_set_ref: queue_set_id,
            max_inflight_requests,
            max_inflight_bytes,
            inflight_requests: 0,
            inflight_bytes: 0,
            open_flush_epochs: 0,
            issue_receipt_ref: None,
        };
        let export_fence = BlockVolumeExportFenceMirrorRecord {
            export_fence_id: receipt_for_volume(geometry.volume_id, 4, 0x301B),
            queue_set_ref: queue_set_id,
            queue_phase_class: BlockVolumeQueuePhaseClass::Open,
            affected_queue_set_refs: Vec::new(),
            issue_receipt_ref: None,
            close_receipt_ref: None,
        };

        Some(Self {
            volume_id: geometry.volume_id,
            queue_policy,
            queue_set,
            queue_classes: vec![
                queue_class_record(geometry.volume_id, BlockVolumeQueueClass::ReadFast),
                queue_class_record(geometry.volume_id, BlockVolumeQueueClass::OrderedMutation),
                queue_class_record(geometry.volume_id, BlockVolumeQueueClass::Barrier),
                queue_class_record(geometry.volume_id, BlockVolumeQueueClass::ZeroDiscard),
            ],
            shards,
            backpressure,
            export_fence,
            inflight_contexts: Vec::new(),
            flush_epochs: Vec::new(),
            completion_commits: Vec::new(),
            dispatch_records: Vec::new(),
            next_context_counter: 10,
        })
    }

    #[must_use]
    pub fn classify_request(
        &self,
        request_class: BlockVolumeRequestClass,
        durability_class: BlockVolumeDurabilityClass,
    ) -> BlockVolumeQueueClassRecord {
        let queue_class = match request_class {
            BlockVolumeRequestClass::Read => BlockVolumeQueueClass::ReadFast,
            BlockVolumeRequestClass::Write => BlockVolumeQueueClass::OrderedMutation,
            BlockVolumeRequestClass::Flush => BlockVolumeQueueClass::Barrier,
            BlockVolumeRequestClass::Discard | BlockVolumeRequestClass::WriteZeroes => {
                BlockVolumeQueueClass::ZeroDiscard
            }
        };
        let mut record = queue_class_record(self.volume_id, queue_class);
        if durability_class == BlockVolumeDurabilityClass::FuaRequired
            && request_class == BlockVolumeRequestClass::Write
        {
            record.blocking_class = BlockVolumeQueueBlockingClass::MustDrainBeforeCompletion;
        }
        record
    }

    pub fn build_submission_context(
        &mut self,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
        durability_class: BlockVolumeDurabilityClass,
    ) -> Option<BlockVolumeSubmissionContextMirrorRecord> {
        if request_class != BlockVolumeRequestClass::Flush && range.is_none() {
            return None;
        }
        let queue_class = self
            .classify_request(request_class, durability_class)
            .queue_class;
        let queue_shard_refs = if request_class == BlockVolumeRequestClass::Flush {
            self.shards
                .iter()
                .map(|shard| shard.queue_shard_id)
                .collect()
        } else {
            self.queue_shard_refs_for_range(range?)?
        };
        let submission_context_id = self.next_context_receipt(0xC011);
        Some(BlockVolumeSubmissionContextMirrorRecord {
            submission_context_id,
            request_class,
            queue_class,
            queue_shard_refs,
            range,
            payload_len,
            exactness_class: BlockVolumeCompletionClass::Completed,
            durability_class,
            anchor_snapshot_ref: self.next_context_receipt(0xAACC),
        })
    }

    pub fn admit_submission_context(
        &mut self,
        context: BlockVolumeSubmissionContextMirrorRecord,
    ) -> BlockVolumeAdmissionDecisionRecord {
        if self.export_fence.queue_phase_class == BlockVolumeQueuePhaseClass::Fenced {
            return BlockVolumeAdmissionDecisionRecord {
                admission_class: BlockVolumeQueueAdmissionClass::RefusedExportFenced,
                submission_context_ref: context.submission_context_id,
                queue_shard_refs: context.queue_shard_refs,
                completion_class: BlockVolumeCompletionClass::RefusedExportFenced,
                issue_receipt_ref: self.export_fence.issue_receipt_ref,
            };
        }
        if self.backpressure.inflight_requests + 1 > self.backpressure.max_inflight_requests
            || self.backpressure.inflight_bytes + context.payload_len
                > self.backpressure.max_inflight_bytes
        {
            return BlockVolumeAdmissionDecisionRecord {
                admission_class: BlockVolumeQueueAdmissionClass::RefusedBackpressure,
                submission_context_ref: context.submission_context_id,
                queue_shard_refs: context.queue_shard_refs,
                completion_class: BlockVolumeCompletionClass::RefusedBackpressure,
                issue_receipt_ref: Some(self.next_context_receipt(0xBACC)),
            };
        }

        for shard_ref in &context.queue_shard_refs {
            if let Some(shard) = self
                .shards
                .iter_mut()
                .find(|shard| shard.queue_shard_id == *shard_ref)
            {
                shard
                    .inflight_context_ids
                    .push(context.submission_context_id);
                if context.queue_class != BlockVolumeQueueClass::ReadFast {
                    if let Some(range) = context.range {
                        shard.ordered_ranges.push(range);
                    }
                }
            }
        }
        self.backpressure.inflight_requests += 1;
        self.backpressure.inflight_bytes += context.payload_len;
        self.inflight_contexts.push(context.clone());

        BlockVolumeAdmissionDecisionRecord {
            admission_class: BlockVolumeQueueAdmissionClass::Admitted,
            submission_context_ref: context.submission_context_id,
            queue_shard_refs: context.queue_shard_refs,
            completion_class: BlockVolumeCompletionClass::Completed,
            issue_receipt_ref: None,
        }
    }

    pub fn open_export_fence(&mut self) -> BlockVolumeExportFenceMirrorRecord {
        let issue_receipt_ref = self.next_context_receipt(0xF3CE);
        self.queue_set.queue_phase_class = BlockVolumeQueuePhaseClass::Fenced;
        self.export_fence.queue_phase_class = BlockVolumeQueuePhaseClass::Fenced;
        self.export_fence.affected_queue_set_refs = vec![self.queue_set.queue_set_id];
        self.export_fence.issue_receipt_ref = Some(issue_receipt_ref);
        self.export_fence.clone()
    }

    pub fn seal_flush_epoch(
        &mut self,
        durability_class: BlockVolumeDurabilityClass,
    ) -> BlockVolumeFlushEpochRecord {
        let covered_submission_context_refs: Vec<BlockVolumeReceiptId> = self
            .inflight_contexts
            .iter()
            .filter(|context| {
                context.request_class != BlockVolumeRequestClass::Read
                    && context.request_class != BlockVolumeRequestClass::Flush
            })
            .map(|context| context.submission_context_id)
            .collect();
        let record = BlockVolumeFlushEpochRecord {
            flush_epoch_id: self.next_context_receipt(0xF10E),
            covered_submission_context_refs,
            durability_class,
            sealed: true,
            completion_token_ref: self.next_context_receipt(0xF10F),
        };
        self.backpressure.open_flush_epochs += 1;
        self.flush_epochs.push(record.clone());
        record
    }

    pub fn complete_submission_context(
        &mut self,
        submission_context_id: BlockVolumeReceiptId,
        result_class: BlockVolumeCompletionClass,
        byte_count: usize,
    ) -> Option<BlockVolumeCompletionCommitMirrorRecord> {
        let position = self
            .inflight_contexts
            .iter()
            .position(|context| context.submission_context_id == submission_context_id)?;
        let context = self.inflight_contexts.remove(position);
        for shard_ref in &context.queue_shard_refs {
            if let Some(shard) = self
                .shards
                .iter_mut()
                .find(|shard| shard.queue_shard_id == *shard_ref)
            {
                remove_one(
                    &mut shard.inflight_context_ids,
                    context.submission_context_id,
                );
                if let Some(range) = context.range {
                    remove_one(&mut shard.ordered_ranges, range);
                }
            }
        }
        self.backpressure.inflight_requests = self.backpressure.inflight_requests.saturating_sub(1);
        self.backpressure.inflight_bytes = self
            .backpressure
            .inflight_bytes
            .saturating_sub(context.payload_len);
        if context.request_class == BlockVolumeRequestClass::Flush {
            self.backpressure.open_flush_epochs =
                self.backpressure.open_flush_epochs.saturating_sub(1);
        }

        let record = BlockVolumeCompletionCommitMirrorRecord {
            completion_commit_id: self.next_context_receipt(0xC0DE),
            submission_context_ref: submission_context_id,
            queue_set_ref: self.queue_set.queue_set_id,
            result_class,
            byte_count,
            linux_status_code: linux_status_code_for_completion(result_class),
            completion_receipt_ref: self.next_context_receipt(0xC0DF),
        };
        self.completion_commits.push(record.clone());
        Some(record)
    }

    pub fn dispatch_submission_context(
        &mut self,
        image: &mut BlockVolumeImage,
        submission_context_id: BlockVolumeReceiptId,
        write_payload: Option<&[u8]>,
    ) -> (BlockVolumeDispatchExecutionRecord, Option<Vec<u8>>) {
        let Some(context) = self
            .inflight_contexts
            .iter()
            .find(|context| context.submission_context_id == submission_context_id)
            .cloned()
        else {
            let record = self.refused_dispatch_record(
                submission_context_id,
                BlockVolumeRequestClass::Read,
                None,
                BlockVolumeCompletionClass::RefusedUnadmittedContext,
                BlockVolumeDispatchClass::RefusedUnadmittedContext,
                0,
            );
            self.dispatch_records.push(record.clone());
            return (record, None);
        };

        let (plan, read_payload) = match context.request_class {
            BlockVolumeRequestClass::Read => match context.range {
                Some(range) => image.read_blocks(range),
                None => missing_range_dispatch_refusal(
                    image,
                    context.request_class,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                    0,
                ),
            },
            BlockVolumeRequestClass::Write => {
                let payload = write_payload.unwrap_or(&[]);
                match context.range {
                    Some(range) => {
                        let expected_range_bytes = range
                            .block_count
                            .checked_mul(image.geometry.block_size_bytes)
                            .unwrap_or(usize::MAX);
                        if payload.len() != context.payload_len
                            || payload.len() != expected_range_bytes
                        {
                            (
                                image.refusal_plan(
                                    BlockVolumeRequestClass::Write,
                                    BlockVolumeCompletionClass::RefusedPayloadMismatch,
                                    context.range,
                                    payload.len(),
                                ),
                                None,
                            )
                        } else {
                            image
                                .write_blocks(range.start_block, payload)
                                .without_read_payload()
                        }
                    }
                    None => missing_range_dispatch_refusal(
                        image,
                        context.request_class,
                        BlockVolumeCompletionClass::RefusedPayloadMismatch,
                        payload.len(),
                    ),
                }
            }
            BlockVolumeRequestClass::Flush => {
                let flush_epoch = self.seal_flush_epoch(context.durability_class);
                let mut plan = image.flush();
                plan.flush_barrier_ref =
                    plan.flush_barrier_ref.or(Some(flush_epoch.flush_epoch_id));
                (plan, None)
            }
            BlockVolumeRequestClass::Discard => match context.range {
                Some(range) => image.discard_blocks(range).without_read_payload(),
                None => missing_range_dispatch_refusal(
                    image,
                    context.request_class,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                    0,
                ),
            },
            BlockVolumeRequestClass::WriteZeroes => match context.range {
                Some(range) => image.write_zeroes(range).without_read_payload(),
                None => missing_range_dispatch_refusal(
                    image,
                    context.request_class,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                    0,
                ),
            },
        };

        let completion = self.complete_submission_context(
            context.submission_context_id,
            plan.completion_class,
            if plan.completion_class == BlockVolumeCompletionClass::Completed {
                plan.payload_len
            } else {
                0
            },
        );
        let dispatch_class = if plan.completion_class == BlockVolumeCompletionClass::Completed {
            BlockVolumeDispatchClass::Executed
        } else if plan.completion_class == BlockVolumeCompletionClass::RefusedPayloadMismatch {
            BlockVolumeDispatchClass::RefusedPayloadMismatch
        } else {
            BlockVolumeDispatchClass::Executed
        };
        let record = BlockVolumeDispatchExecutionRecord {
            dispatch_id: self.next_context_receipt(0xD15C),
            dispatch_class,
            submission_context_ref: context.submission_context_id,
            request_class: context.request_class,
            range: context.range,
            read_payload_len: read_payload.as_ref().map_or(0, Vec::len),
            request_plan: plan,
            completion_commit_ref: completion.map(|record| record.completion_commit_id),
        };
        self.dispatch_records.push(record.clone());
        (record, read_payload)
    }

    fn queue_shard_refs_for_range(
        &self,
        range: BlockRangeRecord,
    ) -> Option<Vec<BlockVolumeReceiptId>> {
        if range.block_count == 0 {
            return None;
        }
        let end_block = range.start_block.checked_add(range.block_count)?;
        if end_block > self.queue_set.block_count {
            return None;
        }
        let first = range.start_block / self.queue_set.shard_span_blocks;
        let last = (end_block - 1) / self.queue_set.shard_span_blocks;
        let refs = (first..=last)
            .filter_map(|idx| self.shards.get(idx).map(|shard| shard.queue_shard_id))
            .collect::<Vec<_>>();
        if refs.is_empty() {
            None
        } else {
            Some(refs)
        }
    }

    fn publish_geometry(&mut self, geometry: BlockVolumeGeometryRecord) -> bool {
        if geometry.block_count == 0 || self.queue_set.shard_count == 0 {
            return false;
        }
        let shard_span_blocks = geometry.block_count.div_ceil(self.queue_set.shard_count);
        self.queue_set.block_count = geometry.block_count;
        self.queue_set.shard_span_blocks = shard_span_blocks;
        for (idx, shard) in self.shards.iter_mut().enumerate() {
            let start_block = idx * shard_span_blocks;
            let end_block = ((idx + 1) * shard_span_blocks).min(geometry.block_count);
            shard.covered_range =
                BlockRangeRecord::new(start_block, end_block.saturating_sub(start_block));
        }
        true
    }

    fn next_context_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(self.volume_id, self.next_context_counter, salt);
        self.next_context_counter = self.next_context_counter.wrapping_add(1);
        receipt
    }

    fn refused_dispatch_record(
        &mut self,
        submission_context_id: BlockVolumeReceiptId,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        completion_class: BlockVolumeCompletionClass,
        dispatch_class: BlockVolumeDispatchClass,
        payload_len: usize,
    ) -> BlockVolumeDispatchExecutionRecord {
        BlockVolumeDispatchExecutionRecord {
            dispatch_id: self.next_context_receipt(0xD15F),
            dispatch_class,
            submission_context_ref: submission_context_id,
            request_class,
            range,
            request_plan: BlockVolumeRequestPlan {
                request_class,
                completion_class,
                range,
                payload_len,
                dirty_epoch_ref: None,
                flush_barrier_ref: None,
                discard_intent_ref: None,
                completion_receipt_ref: BlockVolumeReceiptId::default(),
            },
            read_payload_len: 0,
            completion_commit_ref: None,
        }
    }
}

fn missing_range_dispatch_refusal(
    image: &BlockVolumeImage,
    request_class: BlockVolumeRequestClass,
    completion_class: BlockVolumeCompletionClass,
    payload_len: usize,
) -> (BlockVolumeRequestPlan, Option<Vec<u8>>) {
    (
        image.refusal_plan(request_class, completion_class, None, payload_len),
        None,
    )
}

impl BlockVolumeExportLifecycleRuntime {
    #[must_use]
    pub fn bootstrap(
        geometry: BlockVolumeGeometryRecord,
        shard_count: usize,
        max_inflight_requests: usize,
        max_inflight_bytes: usize,
    ) -> Option<Self> {
        let mut queue_runtime = BlockVolumeQueueRuntime::open(
            geometry,
            shard_count,
            max_inflight_requests,
            max_inflight_bytes,
        )?;
        queue_runtime.queue_set.queue_phase_class = BlockVolumeQueuePhaseClass::Fenced;
        queue_runtime.export_fence.queue_phase_class = BlockVolumeQueuePhaseClass::Fenced;
        queue_runtime.export_fence.affected_queue_set_refs =
            vec![queue_runtime.queue_set.queue_set_id];
        queue_runtime.export_fence.issue_receipt_ref =
            Some(receipt_for_volume(geometry.volume_id, 4, 0x301D));

        Some(Self {
            export_runtime: BlockVolumeExportRuntimeRecord {
                export_runtime_id: receipt_for_volume(geometry.volume_id, 1, 0x301D),
                volume_id: geometry.volume_id,
                export_phase_class: BlockVolumeExportPhaseClass::Bootstrap,
                queue_set_refs: vec![queue_runtime.queue_set.queue_set_id],
                authority_anchor_ref: receipt_for_volume(geometry.volume_id, 2, 0x301D),
                fence_epoch_ref: receipt_for_volume(geometry.volume_id, 3, 0x301D),
                lifecycle_generation: 0,
            },
            queue_runtime,
            transition_records: Vec::new(),
            next_lifecycle_counter: 10,
        })
    }

    pub fn build_submission_context(
        &mut self,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
        durability_class: BlockVolumeDurabilityClass,
    ) -> Option<BlockVolumeSubmissionContextMirrorRecord> {
        self.queue_runtime.build_submission_context(
            request_class,
            range,
            payload_len,
            durability_class,
        )
    }

    pub fn admit_submission_context(
        &mut self,
        context: BlockVolumeSubmissionContextMirrorRecord,
    ) -> BlockVolumeAdmissionDecisionRecord {
        if !matches!(
            self.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive | BlockVolumeExportPhaseClass::Resumed
        ) {
            return BlockVolumeAdmissionDecisionRecord {
                admission_class: BlockVolumeQueueAdmissionClass::RefusedExportFenced,
                submission_context_ref: context.submission_context_id,
                queue_shard_refs: context.queue_shard_refs,
                completion_class: BlockVolumeCompletionClass::RefusedExportFenced,
                issue_receipt_ref: self.queue_runtime.export_fence.issue_receipt_ref,
            };
        }
        self.queue_runtime.admit_submission_context(context)
    }

    pub fn complete_submission_context(
        &mut self,
        submission_context_id: BlockVolumeReceiptId,
        result_class: BlockVolumeCompletionClass,
        byte_count: usize,
    ) -> Option<BlockVolumeCompletionCommitMirrorRecord> {
        self.queue_runtime.complete_submission_context(
            submission_context_id,
            result_class,
            byte_count,
        )
    }

    pub fn admit_export(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.export_runtime.export_phase_class != BlockVolumeExportPhaseClass::Bootstrap {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::AdmitExport,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::ExportAdmitted;
        self.export_runtime.lifecycle_generation += 1;
        self.record_lifecycle_transition(
            BlockVolumeExportTransitionClass::AdmitExport,
            BlockVolumeExportPhaseClass::Bootstrap,
            BlockVolumeExportPhaseClass::ExportAdmitted,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            Vec::new(),
            true,
        )
    }

    pub fn start_queues(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if !matches!(
            self.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::ExportAdmitted
        ) {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::StartQueues,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        let from_phase = self.export_runtime.export_phase_class;
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::QueuesLive;
        self.export_runtime.lifecycle_generation += 1;
        self.set_queue_phase(BlockVolumeQueuePhaseClass::Open);
        self.record_lifecycle_transition(
            BlockVolumeExportTransitionClass::StartQueues,
            from_phase,
            BlockVolumeExportPhaseClass::QueuesLive,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            Vec::new(),
            true,
        )
    }

    pub fn begin_quiesce(
        &mut self,
        transition_class: BlockVolumeExportTransitionClass,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        if !matches!(
            transition_class,
            BlockVolumeExportTransitionClass::ResizeQuiesce
                | BlockVolumeExportTransitionClass::RevokeQuiesce
                | BlockVolumeExportTransitionClass::FailoverQuiesce
        ) || !matches!(
            self.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive | BlockVolumeExportPhaseClass::Resumed
        ) {
            return self.record_lifecycle_transition(
                transition_class,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        let from_phase = self.export_runtime.export_phase_class;
        let classifications = self.classify_inflight_for_transition();
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::QuiesceTransition;
        self.export_runtime.lifecycle_generation += 1;
        self.set_queue_phase(BlockVolumeQueuePhaseClass::Fenced);
        self.queue_runtime.export_fence.issue_receipt_ref =
            Some(self.next_lifecycle_receipt(0xF3CE));

        self.record_lifecycle_transition(
            transition_class,
            from_phase,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            classifications,
            false,
        )
    }

    pub fn fence_after_drain(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.export_runtime.export_phase_class != BlockVolumeExportPhaseClass::QuiesceTransition
        {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::FenceAfterDrain,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        if !self.queue_runtime.inflight_contexts.is_empty() {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::FenceAfterDrain,
                BlockVolumeExportPhaseClass::QuiesceTransition,
                BlockVolumeExportPhaseClass::QuiesceTransition,
                BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete,
                self.classify_inflight_for_transition(),
                false,
            );
        }
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::Fenced;
        self.export_runtime.lifecycle_generation += 1;
        self.set_queue_phase(BlockVolumeQueuePhaseClass::Fenced);
        self.record_lifecycle_transition(
            BlockVolumeExportTransitionClass::FenceAfterDrain,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportPhaseClass::Fenced,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            Vec::new(),
            true,
        )
    }

    pub fn resume_after_fence(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.export_runtime.export_phase_class != BlockVolumeExportPhaseClass::Fenced {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::ResumeAfterFence,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        let from_phase = self.export_runtime.export_phase_class;
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::Resumed;
        self.export_runtime.lifecycle_generation += 1;
        self.export_runtime.fence_epoch_ref = self.next_lifecycle_receipt(0xF35A);
        self.set_queue_phase(BlockVolumeQueuePhaseClass::Open);
        self.record_lifecycle_transition(
            BlockVolumeExportTransitionClass::ResumeAfterFence,
            from_phase,
            BlockVolumeExportPhaseClass::Resumed,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            Vec::new(),
            true,
        )
    }

    pub fn stop_after_drain(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if !matches!(
            self.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Fenced | BlockVolumeExportPhaseClass::QuiesceTransition
        ) {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::StopAfterDrain,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
                Vec::new(),
                false,
            );
        }
        if !self.queue_runtime.inflight_contexts.is_empty() {
            return self.record_lifecycle_transition(
                BlockVolumeExportTransitionClass::StopAfterDrain,
                self.export_runtime.export_phase_class,
                self.export_runtime.export_phase_class,
                BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete,
                self.classify_inflight_for_transition(),
                false,
            );
        }
        let from_phase = self.export_runtime.export_phase_class;
        self.export_runtime.export_phase_class = BlockVolumeExportPhaseClass::Stopped;
        self.export_runtime.lifecycle_generation += 1;
        self.set_queue_phase(BlockVolumeQueuePhaseClass::Fenced);
        self.record_lifecycle_transition(
            BlockVolumeExportTransitionClass::StopAfterDrain,
            from_phase,
            BlockVolumeExportPhaseClass::Stopped,
            BlockVolumeExportTransitionOutcomeClass::Completed,
            Vec::new(),
            true,
        )
    }

    fn classify_inflight_for_transition(
        &self,
    ) -> Vec<BlockVolumeInflightTransitionClassificationRecord> {
        self.queue_runtime
            .inflight_contexts
            .iter()
            .map(|context| {
                let classification = match context.request_class {
                    BlockVolumeRequestClass::Read => BlockVolumeInflightTransitionClass::CommitOk,
                    BlockVolumeRequestClass::Write
                    | BlockVolumeRequestClass::Discard
                    | BlockVolumeRequestClass::WriteZeroes => {
                        BlockVolumeInflightTransitionClass::ReplayRequired
                    }
                    BlockVolumeRequestClass::Flush => {
                        BlockVolumeInflightTransitionClass::AbortRequired
                    }
                };
                BlockVolumeInflightTransitionClassificationRecord {
                    submission_context_ref: context.submission_context_id,
                    request_class: context.request_class,
                    classification,
                    range: context.range,
                    queue_shard_refs: context.queue_shard_refs.clone(),
                }
            })
            .collect()
    }

    fn record_lifecycle_transition(
        &mut self,
        transition_class: BlockVolumeExportTransitionClass,
        from_phase_class: BlockVolumeExportPhaseClass,
        to_phase_class: BlockVolumeExportPhaseClass,
        outcome_class: BlockVolumeExportTransitionOutcomeClass,
        inflight_classifications: Vec<BlockVolumeInflightTransitionClassificationRecord>,
        include_close_receipt: bool,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_lifecycle_receipt(0x7A15),
            transition_class,
            from_phase_class,
            to_phase_class,
            outcome_class,
            affected_queue_set_refs: self.export_runtime.queue_set_refs.clone(),
            inflight_classifications,
            issue_receipt_ref: self.next_lifecycle_receipt(0x155E),
            close_receipt_ref: include_close_receipt.then(|| self.next_lifecycle_receipt(0xC105)),
        };
        if include_close_receipt {
            self.queue_runtime.export_fence.close_receipt_ref = record.close_receipt_ref;
        }
        self.transition_records.push(record.clone());
        record
    }

    fn set_queue_phase(&mut self, queue_phase_class: BlockVolumeQueuePhaseClass) {
        self.queue_runtime.queue_set.queue_phase_class = queue_phase_class;
        self.queue_runtime.export_fence.queue_phase_class = queue_phase_class;
        if queue_phase_class == BlockVolumeQueuePhaseClass::Fenced {
            self.queue_runtime.export_fence.affected_queue_set_refs =
                self.export_runtime.queue_set_refs.clone();
        } else {
            self.queue_runtime
                .export_fence
                .affected_queue_set_refs
                .clear();
            self.queue_runtime.export_fence.issue_receipt_ref = None;
        }
    }

    fn next_lifecycle_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(
            self.export_runtime.volume_id,
            self.next_lifecycle_counter,
            salt,
        );
        self.next_lifecycle_counter = self.next_lifecycle_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeCacheCoherencyRuntime {
    #[must_use]
    pub const fn open(volume_id: BlockVolumeId) -> Self {
        Self {
            volume_id,
            read_cache_windows: Vec::new(),
            dirty_epochs: Vec::new(),
            flush_barriers: Vec::new(),
            fua_tickets: Vec::new(),
            direct_guards: Vec::new(),
            transition_records: Vec::new(),
            next_cache_counter: 1,
        }
    }

    pub fn fill_read_cache_window(
        &mut self,
        range: BlockRangeRecord,
        cached_bytes: usize,
        prefetch: bool,
    ) -> Option<BlockVolumeReadCacheWindowRecord> {
        if range.block_count == 0 || cached_bytes == 0 {
            return None;
        }
        let residency_class = if prefetch {
            BlockVolumeCacheResidencyClass::CleanPrefetch
        } else {
            BlockVolumeCacheResidencyClass::CleanHot
        };
        let record = BlockVolumeReadCacheWindowRecord {
            cache_window_id: self.next_cache_receipt(0xCA10),
            range,
            residency_class,
            anchor_snapshot_ref: self.next_cache_receipt(0xAACC),
            cached_bytes,
            invalidated_by_mutation: false,
        };
        self.read_cache_windows.push(record.clone());
        self.record_cache_transition(
            BlockVolumeCacheTransitionClass::ReadCacheFill,
            Some(range),
            vec![record.cache_window_id],
            Vec::new(),
        );
        Some(record)
    }

    #[must_use]
    pub fn read_cache_hit(
        &self,
        range: BlockRangeRecord,
    ) -> Option<BlockVolumeReadCacheWindowRecord> {
        self.read_cache_windows
            .iter()
            .find(|window| {
                !window.invalidated_by_mutation
                    && matches!(
                        window.residency_class,
                        BlockVolumeCacheResidencyClass::CleanHot
                            | BlockVolumeCacheResidencyClass::CleanPrefetch
                    )
                    && block_range_contains(window.range, range)
            })
            .cloned()
    }

    pub fn open_dirty_epoch(
        &mut self,
        range: BlockRangeRecord,
        dirty_bytes: usize,
    ) -> Option<BlockVolumeCacheDirtyEpochRecord> {
        if range.block_count == 0 || dirty_bytes == 0 {
            return None;
        }
        let invalidated_cache_window_refs = self.invalidate_overlapping_cache_windows(range);
        let record = BlockVolumeCacheDirtyEpochRecord {
            cache_epoch_id: self.next_cache_receipt(0xD147),
            range,
            dirty_bytes,
            sealed_for_barrier: false,
            write_order_fence_ref: self.next_cache_receipt(0xF3C3),
            invalidated_cache_window_refs: invalidated_cache_window_refs.clone(),
        };
        self.dirty_epochs.push(record.clone());
        self.record_cache_transition(
            BlockVolumeCacheTransitionClass::DirtyWrite,
            Some(range),
            invalidated_cache_window_refs,
            vec![record.cache_epoch_id],
        );
        Some(record)
    }

    pub fn seal_flush_barrier(
        &mut self,
        required_durability_class: BlockVolumeDurabilityClass,
    ) -> BlockVolumeCacheFlushBarrierRecord {
        let covered_cache_epoch_refs: Vec<BlockVolumeReceiptId> = self
            .dirty_epochs
            .iter()
            .filter(|epoch| !epoch.sealed_for_barrier)
            .map(|epoch| epoch.cache_epoch_id)
            .collect();

        for epoch in &mut self.dirty_epochs {
            if covered_cache_epoch_refs.contains(&epoch.cache_epoch_id) {
                epoch.sealed_for_barrier = true;
            }
        }

        let cache_barrier_id = self.next_cache_receipt(0xB411);
        let fua_ticket_ref = if required_durability_class == BlockVolumeDurabilityClass::FuaRequired
        {
            let ticket = BlockVolumeFuaCompletionTicketRecord {
                fua_ticket_id: self.next_cache_receipt(0xF0A),
                barrier_ref: cache_barrier_id,
                durability_class: required_durability_class,
                completion_allowed: true,
            };
            let ticket_ref = ticket.fua_ticket_id;
            self.fua_tickets.push(ticket);
            self.record_cache_transition(
                BlockVolumeCacheTransitionClass::FuaTicket,
                None,
                Vec::new(),
                covered_cache_epoch_refs.clone(),
            );
            Some(ticket_ref)
        } else {
            None
        };

        let record = BlockVolumeCacheFlushBarrierRecord {
            cache_barrier_id,
            covered_cache_epoch_refs: covered_cache_epoch_refs.clone(),
            required_durability_class,
            satisfied: true,
            fua_ticket_ref,
        };
        self.flush_barriers.push(record.clone());
        self.record_cache_transition(
            BlockVolumeCacheTransitionClass::FlushBarrier,
            None,
            Vec::new(),
            covered_cache_epoch_refs,
        );
        record
    }

    pub fn issue_discard_or_zero_invalidation(
        &mut self,
        request_class: BlockVolumeRequestClass,
        range: BlockRangeRecord,
    ) -> Option<BlockVolumeCacheCoherencyTransitionRecord> {
        let transition_class = match request_class {
            BlockVolumeRequestClass::Discard => {
                BlockVolumeCacheTransitionClass::DiscardInvalidation
            }
            BlockVolumeRequestClass::WriteZeroes => {
                BlockVolumeCacheTransitionClass::WriteZeroesInvalidation
            }
            _ => return None,
        };
        if range.block_count == 0 {
            return None;
        }
        let affected_cache_window_refs = self.invalidate_overlapping_cache_windows(range);
        let affected_epoch_refs: Vec<BlockVolumeReceiptId> = self
            .dirty_epochs
            .iter()
            .filter(|epoch| block_ranges_overlap(epoch.range, range))
            .map(|epoch| epoch.cache_epoch_id)
            .collect();
        Some(self.record_cache_transition(
            transition_class,
            Some(range),
            affected_cache_window_refs,
            affected_epoch_refs,
        ))
    }

    pub fn open_direct_overlap_guard(
        &mut self,
        range: BlockRangeRecord,
    ) -> Option<BlockVolumeDirectOverlapGuardRecord> {
        if range.block_count == 0 {
            return None;
        }
        let blocked_epoch_refs = self.unsealed_overlapping_epoch_refs(range);
        let guard_class = if blocked_epoch_refs.is_empty() {
            BlockVolumeDirectOverlapGuardClass::Open
        } else {
            BlockVolumeDirectOverlapGuardClass::BlockedDirtyDrain
        };
        let record = BlockVolumeDirectOverlapGuardRecord {
            direct_guard_id: self.next_cache_receipt(0xD1EC),
            range,
            guard_class,
            blocked_epoch_refs: blocked_epoch_refs.clone(),
        };
        self.direct_guards.push(record.clone());
        self.record_cache_transition(
            BlockVolumeCacheTransitionClass::DirectOverlapGuard,
            Some(range),
            Vec::new(),
            blocked_epoch_refs,
        );
        Some(record)
    }

    pub fn resolve_direct_overlap_guard(
        &mut self,
        direct_guard_id: BlockVolumeReceiptId,
    ) -> Option<BlockVolumeDirectOverlapGuardRecord> {
        let position = self
            .direct_guards
            .iter()
            .position(|guard| guard.direct_guard_id == direct_guard_id)?;
        let range = self.direct_guards[position].range;
        let blocked_epoch_refs = self.unsealed_overlapping_epoch_refs(range);
        self.direct_guards[position].blocked_epoch_refs = blocked_epoch_refs;
        self.direct_guards[position].guard_class =
            if self.direct_guards[position].blocked_epoch_refs.is_empty() {
                BlockVolumeDirectOverlapGuardClass::Open
            } else {
                BlockVolumeDirectOverlapGuardClass::BlockedDirtyDrain
            };
        Some(self.direct_guards[position].clone())
    }

    pub fn drop_clean_cache_windows(&mut self) -> BlockVolumeCacheCoherencyTransitionRecord {
        let affected_cache_window_refs = self
            .read_cache_windows
            .iter()
            .filter(|window| !window.invalidated_by_mutation)
            .map(|window| window.cache_window_id)
            .collect::<Vec<_>>();
        for window in &mut self.read_cache_windows {
            window.invalidated_by_mutation = true;
            window.residency_class = BlockVolumeCacheResidencyClass::Absent;
        }
        self.record_cache_transition(
            BlockVolumeCacheTransitionClass::CacheLoss,
            None,
            affected_cache_window_refs,
            Vec::new(),
        )
    }

    fn invalidate_overlapping_cache_windows(
        &mut self,
        range: BlockRangeRecord,
    ) -> Vec<BlockVolumeReceiptId> {
        let mut invalidated = Vec::new();
        for window in &mut self.read_cache_windows {
            if !window.invalidated_by_mutation && block_ranges_overlap(window.range, range) {
                window.invalidated_by_mutation = true;
                window.residency_class = BlockVolumeCacheResidencyClass::Absent;
                invalidated.push(window.cache_window_id);
            }
        }
        invalidated
    }

    fn unsealed_overlapping_epoch_refs(
        &self,
        range: BlockRangeRecord,
    ) -> Vec<BlockVolumeReceiptId> {
        self.dirty_epochs
            .iter()
            .filter(|epoch| !epoch.sealed_for_barrier && block_ranges_overlap(epoch.range, range))
            .map(|epoch| epoch.cache_epoch_id)
            .collect()
    }

    fn record_cache_transition(
        &mut self,
        transition_class: BlockVolumeCacheTransitionClass,
        range: Option<BlockRangeRecord>,
        affected_cache_window_refs: Vec<BlockVolumeReceiptId>,
        affected_epoch_refs: Vec<BlockVolumeReceiptId>,
    ) -> BlockVolumeCacheCoherencyTransitionRecord {
        let record = BlockVolumeCacheCoherencyTransitionRecord {
            transition_id: self.next_cache_receipt(0x7A15),
            transition_class,
            range,
            affected_cache_window_refs,
            affected_epoch_refs,
            receipt_ref: self.next_cache_receipt(0xC0FE),
        };
        self.transition_records.push(record.clone());
        record
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 7: reconcile after discard or resize
    // ------------------------------------------------------------------

    /// Reconcile cached ranges (clean windows, dirty epochs, direct guards)
    /// that overlap with the affected range after a discard or resize operation.
    ///
    /// Overlapping clean/prefetch/dirty ranges must be reloaded, invalidated,
    /// or reclassified rather than left with stale range state.
    pub fn reconcile_cached_ranges_after_discard_or_resize(
        &mut self,
        affected_range: BlockRangeRecord,
        transition_class: BlockVolumeCacheTransitionClass,
    ) -> BlockVolumeCacheCoherencyTransitionRecord {
        let mut invalidated_window_refs = Vec::new();
        let mut reconciled_epoch_refs = Vec::new();

        // Invalidate overlapping clean read-cache windows
        for window in &mut self.read_cache_windows {
            if !window.invalidated_by_mutation
                && block_ranges_overlap(window.range, affected_range)
                && matches!(
                    window.residency_class,
                    BlockVolumeCacheResidencyClass::CleanHot
                        | BlockVolumeCacheResidencyClass::CleanPrefetch
                )
            {
                window.invalidated_by_mutation = true;
                window.residency_class = BlockVolumeCacheResidencyClass::Absent;
                invalidated_window_refs.push(window.cache_window_id);
            }
        }

        // Reconcile overlapping dirty epochs: seal if unsealed
        for epoch in &mut self.dirty_epochs {
            if block_ranges_overlap(epoch.range, affected_range) && !epoch.sealed_for_barrier {
                epoch.sealed_for_barrier = true;
                reconciled_epoch_refs.push(epoch.cache_epoch_id);
            }
        }

        // Resolve any direct-overlap guards that span into the affected range
        for guard in &mut self.direct_guards {
            if block_ranges_overlap(guard.range, affected_range)
                && guard.guard_class != BlockVolumeDirectOverlapGuardClass::Resolved
            {
                guard.guard_class = BlockVolumeDirectOverlapGuardClass::Resolved;
            }
        }

        let record = BlockVolumeCacheCoherencyTransitionRecord {
            transition_id: self.next_cache_receipt(0x4EC1),
            transition_class,
            range: Some(affected_range),
            affected_cache_window_refs: invalidated_window_refs,
            affected_epoch_refs: reconciled_epoch_refs,
            receipt_ref: self.next_cache_receipt(0x4EC2),
        };
        self.transition_records.push(record.clone());
        record
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 8: evict/invalidate under fence
    // ------------------------------------------------------------------

    /// Evict or invalidate cached ranges under a transition fence
    /// (resize, failover, or export revoke).
    ///
    /// Dirty epochs are sealed for barrier; clean/prefetch windows are
    /// invalidated; direct guards are resolved. Dirty ranges are NOT
    /// drained — that requires drain_dirty_ranges_for_failover_or_cutover.
    pub fn evict_or_invalidate_cache_under_fence(
        &mut self,
        fence_range: BlockRangeRecord,
        fence_class: BlockVolumeCacheTransitionClass,
    ) -> BlockVolumeCacheCoherencyTransitionRecord {
        let mut invalidated_window_refs = Vec::new();
        let mut fenced_epoch_refs = Vec::new();

        // Invalidate all clean/prefetch read-cache windows overlapping the fence
        for window in &mut self.read_cache_windows {
            if !window.invalidated_by_mutation && block_ranges_overlap(window.range, fence_range) {
                window.invalidated_by_mutation = true;
                window.residency_class = BlockVolumeCacheResidencyClass::FrozenTransition;
                invalidated_window_refs.push(window.cache_window_id);
            }
        }

        // Freeze dirty epochs by sealing them
        for epoch in &mut self.dirty_epochs {
            if block_ranges_overlap(epoch.range, fence_range) && !epoch.sealed_for_barrier {
                epoch.sealed_for_barrier = true;
                fenced_epoch_refs.push(epoch.cache_epoch_id);
            }
        }

        // Resolve direct guards under fence
        for guard in &mut self.direct_guards {
            if block_ranges_overlap(guard.range, fence_range)
                && guard.guard_class != BlockVolumeDirectOverlapGuardClass::Resolved
            {
                guard.guard_class = BlockVolumeDirectOverlapGuardClass::Resolved;
            }
        }

        let record = BlockVolumeCacheCoherencyTransitionRecord {
            transition_id: self.next_cache_receipt(0x5E1C),
            transition_class: fence_class,
            range: Some(fence_range),
            affected_cache_window_refs: invalidated_window_refs,
            affected_epoch_refs: fenced_epoch_refs,
            receipt_ref: self.next_cache_receipt(0x5E2C),
        };
        self.transition_records.push(record.clone());
        record
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 9: render completion from barrier state
    // ------------------------------------------------------------------

    /// Render a `BlockVolumeCompletionClass` from a barrier record's state.
    ///
    /// Completions must derive from explicit barrier state (`satisfied` or
    /// `failed`) rather than from queue-idle folklore.
    pub fn render_completion_from_barrier_state(
        &self,
        barrier_id: BlockVolumeReceiptId,
        request_class: BlockVolumeRequestClass,
    ) -> BlockVolumeCompletionClass {
        let barrier = self
            .flush_barriers
            .iter()
            .find(|b| b.cache_barrier_id == barrier_id);

        match barrier {
            None => {
                // Without an explicit barrier record we cannot claim
                // durability above the weakest completion class.
                match request_class {
                    BlockVolumeRequestClass::Write
                    | BlockVolumeRequestClass::Read
                    | BlockVolumeRequestClass::Flush
                    | BlockVolumeRequestClass::Discard
                    | BlockVolumeRequestClass::WriteZeroes => {
                        BlockVolumeCompletionClass::RefusedExportFenced
                    }
                }
            }
            Some(barrier) => {
                if !barrier.satisfied {
                    BlockVolumeCompletionClass::RefusedUnadmittedContext
                } else {
                    match barrier.required_durability_class {
                        BlockVolumeDurabilityClass::None => BlockVolumeCompletionClass::Completed,
                        BlockVolumeDurabilityClass::FlushRequired => {
                            let all_sealed = barrier.covered_cache_epoch_refs.iter().all(|id| {
                                self.dirty_epochs
                                    .iter()
                                    .any(|e| e.cache_epoch_id == *id && e.sealed_for_barrier)
                            });
                            if all_sealed {
                                BlockVolumeCompletionClass::Completed
                            } else {
                                BlockVolumeCompletionClass::RefusedExportFenced
                            }
                        }
                        BlockVolumeDurabilityClass::FuaRequired => {
                            let fua_ok = barrier.fua_ticket_ref.is_some()
                                && barrier.covered_cache_epoch_refs.iter().all(|id| {
                                    self.dirty_epochs
                                        .iter()
                                        .any(|e| e.cache_epoch_id == *id && e.sealed_for_barrier)
                                });
                            if fua_ok {
                                BlockVolumeCompletionClass::Completed
                            } else {
                                BlockVolumeCompletionClass::RefusedExportFenced
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 10: drain dirty ranges for failover/cutover
    // ------------------------------------------------------------------

    /// Drain all cached dirty ranges before authority handoff or export revoke.
    ///
    /// All dirty range epochs are sealed and either committed under the old
    /// epoch or reclassified for replay. Returns a drain barrier and a
    /// transition record summarising drained epochs.
    pub fn drain_dirty_ranges_for_failover_or_cutover(
        &mut self,
    ) -> (
        BlockVolumeCacheFlushBarrierRecord,
        BlockVolumeCacheCoherencyTransitionRecord,
    ) {
        // Seal every dirty epoch that is not yet sealed
        let drained_epoch_refs: Vec<BlockVolumeReceiptId> = self
            .dirty_epochs
            .iter_mut()
            .filter(|epoch| !epoch.sealed_for_barrier)
            .map(|epoch| {
                epoch.sealed_for_barrier = true;
                epoch.cache_epoch_id
            })
            .collect();

        // Create a drain barrier covering all drained epochs
        let drain_barrier = BlockVolumeCacheFlushBarrierRecord {
            cache_barrier_id: self.next_cache_receipt(0xD4A1),
            covered_cache_epoch_refs: drained_epoch_refs.clone(),
            required_durability_class: BlockVolumeDurabilityClass::FuaRequired,
            satisfied: true,
            fua_ticket_ref: Some(self.next_cache_receipt(0xD4F0)),
        };
        self.flush_barriers.push(drain_barrier.clone());

        // Record the drain as a transition
        let transition = self.record_cache_transition(
            BlockVolumeCacheTransitionClass::FailoverFence,
            None,
            Vec::new(),
            drained_epoch_refs,
        );

        (drain_barrier, transition)
    }

    fn next_cache_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(self.volume_id, self.next_cache_counter, salt);
        self.next_cache_counter = self.next_cache_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeResizeFenceRuntime {
    #[must_use]
    pub fn open(
        geometry: BlockVolumeGeometryRecord,
        shard_count: usize,
        max_inflight_requests: usize,
        max_inflight_bytes: usize,
    ) -> Option<Self> {
        let lifecycle_runtime = BlockVolumeExportLifecycleRuntime::bootstrap(
            geometry,
            shard_count,
            max_inflight_requests,
            max_inflight_bytes,
        )?;
        Some(Self {
            current_geometry: geometry,
            lifecycle_runtime,
            cache_runtime: BlockVolumeCacheCoherencyRuntime::open(geometry.volume_id),
            resize_records: Vec::new(),
            next_resize_counter: 1,
        })
    }

    pub fn prepare_resize(
        &mut self,
        target_block_count: usize,
        authority_anchor_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeResizeTransitionRecord {
        let from_geometry = self.current_geometry;
        let target_geometry = BlockVolumeGeometryRecord {
            block_count: target_block_count,
            ..from_geometry
        };
        let direction_class = resize_direction(from_geometry.block_count, target_block_count);
        let affected_tail_range = direction_class.and_then(|direction| {
            resize_tail_range(from_geometry.block_count, target_block_count, direction)
        });
        let zero_visible_range = match direction_class {
            Some(BlockVolumeResizeDirectionClass::Grow) => affected_tail_range,
            _ => None,
        };
        let requires_drain = direction_class.is_some();
        let blockers = affected_tail_range
            .map(|range| self.overlapping_resize_blockers(range))
            .unwrap_or_default();

        let outcome_class =
            if authority_anchor_ref != self.lifecycle_runtime.export_runtime.authority_anchor_ref {
                BlockVolumeResizeTransitionOutcomeClass::RefusedNoAuthority
            } else if target_block_count == 0 || target_block_count == from_geometry.block_count {
                BlockVolumeResizeTransitionOutcomeClass::RefusedInvalidCapacity
            } else if self.lifecycle_runtime.export_runtime.export_phase_class
                != BlockVolumeExportPhaseClass::Fenced
            {
                BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced
            } else if !blockers.is_empty() {
                BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete
            } else {
                BlockVolumeResizeTransitionOutcomeClass::Prepared
            };

        let transition_class = if outcome_class == BlockVolumeResizeTransitionOutcomeClass::Prepared
        {
            BlockVolumeResizeTransitionClass::Prepare
        } else {
            BlockVolumeResizeTransitionClass::Refuse
        };

        self.record_resize_transition(ResizeTransitionDraft {
            transition_class,
            outcome_class,
            direction_class,
            from_geometry,
            target_geometry,
            post_resize_geometry: None,
            affected_tail_range,
            zero_visible_range,
            requires_drain,
            blockers,
            authority_anchor_ref,
        })
    }

    pub fn commit_resize(
        &mut self,
        prepare_transition_id: BlockVolumeReceiptId,
    ) -> BlockVolumeResizeTransitionRecord {
        let Some(prepared) = self
            .resize_records
            .iter()
            .find(|record| {
                record.transition_id == prepare_transition_id
                    && record.transition_class == BlockVolumeResizeTransitionClass::Prepare
                    && record.outcome_class == BlockVolumeResizeTransitionOutcomeClass::Prepared
            })
            .cloned()
        else {
            return self.record_resize_transition(ResizeTransitionDraft {
                transition_class: BlockVolumeResizeTransitionClass::Refuse,
                outcome_class: BlockVolumeResizeTransitionOutcomeClass::RefusedMissingPrepare,
                direction_class: None,
                from_geometry: self.current_geometry,
                target_geometry: self.current_geometry,
                post_resize_geometry: None,
                affected_tail_range: None,
                zero_visible_range: None,
                requires_drain: false,
                blockers: ResizeTransitionBlockers::default(),
                authority_anchor_ref: self.lifecycle_runtime.export_runtime.authority_anchor_ref,
            });
        };

        let blockers = prepared
            .affected_tail_range
            .map(|range| self.overlapping_resize_blockers(range))
            .unwrap_or_default();
        if self.lifecycle_runtime.export_runtime.export_phase_class
            != BlockVolumeExportPhaseClass::Fenced
        {
            return self.record_resize_transition(ResizeTransitionDraft {
                transition_class: BlockVolumeResizeTransitionClass::Refuse,
                outcome_class: BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced,
                direction_class: prepared.direction_class,
                from_geometry: self.current_geometry,
                target_geometry: prepared.target_geometry,
                post_resize_geometry: None,
                affected_tail_range: prepared.affected_tail_range,
                zero_visible_range: prepared.zero_visible_range,
                requires_drain: prepared.requires_drain,
                blockers,
                authority_anchor_ref: prepared.authority_anchor_ref,
            });
        }
        if !blockers.is_empty() {
            return self.record_resize_transition(ResizeTransitionDraft {
                transition_class: BlockVolumeResizeTransitionClass::Refuse,
                outcome_class: BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete,
                direction_class: prepared.direction_class,
                from_geometry: self.current_geometry,
                target_geometry: prepared.target_geometry,
                post_resize_geometry: None,
                affected_tail_range: prepared.affected_tail_range,
                zero_visible_range: prepared.zero_visible_range,
                requires_drain: prepared.requires_drain,
                blockers,
                authority_anchor_ref: prepared.authority_anchor_ref,
            });
        }

        self.current_geometry = prepared.target_geometry;
        self.lifecycle_runtime
            .queue_runtime
            .publish_geometry(prepared.target_geometry);
        self.record_resize_transition(ResizeTransitionDraft {
            transition_class: BlockVolumeResizeTransitionClass::Commit,
            outcome_class: BlockVolumeResizeTransitionOutcomeClass::Committed,
            direction_class: prepared.direction_class,
            from_geometry: prepared.from_geometry,
            target_geometry: prepared.target_geometry,
            post_resize_geometry: Some(prepared.target_geometry),
            affected_tail_range: prepared.affected_tail_range,
            zero_visible_range: prepared.zero_visible_range,
            requires_drain: prepared.requires_drain,
            blockers: ResizeTransitionBlockers::default(),
            authority_anchor_ref: prepared.authority_anchor_ref,
        })
    }

    fn overlapping_resize_blockers(
        &self,
        affected_tail_range: BlockRangeRecord,
    ) -> ResizeTransitionBlockers {
        let inflight_context_refs = self
            .lifecycle_runtime
            .queue_runtime
            .inflight_contexts
            .iter()
            .filter(|context| {
                context
                    .range
                    .is_some_and(|range| block_ranges_overlap(range, affected_tail_range))
            })
            .map(|context| context.submission_context_id)
            .collect();
        let dirty_epoch_refs = self
            .cache_runtime
            .dirty_epochs
            .iter()
            .filter(|epoch| {
                !epoch.sealed_for_barrier && block_ranges_overlap(epoch.range, affected_tail_range)
            })
            .map(|epoch| epoch.cache_epoch_id)
            .collect();
        let guard_refs = self
            .cache_runtime
            .direct_guards
            .iter()
            .filter(|guard| block_ranges_overlap(guard.range, affected_tail_range))
            .map(|guard| guard.direct_guard_id)
            .collect();
        ResizeTransitionBlockers {
            inflight_context_refs,
            dirty_epoch_refs,
            guard_refs,
        }
    }

    fn record_resize_transition(
        &mut self,
        draft: ResizeTransitionDraft,
    ) -> BlockVolumeResizeTransitionRecord {
        let capacity_target_publication_class = match draft.outcome_class {
            BlockVolumeResizeTransitionOutcomeClass::Prepared
            | BlockVolumeResizeTransitionOutcomeClass::Committed => {
                BlockVolumeCapacityTargetPublicationClass::PublishedForCommit
            }
            _ => BlockVolumeCapacityTargetPublicationClass::NotPublished,
        };
        let close_receipt_ref = (draft.outcome_class
            != BlockVolumeResizeTransitionOutcomeClass::Prepared)
            .then(|| self.next_resize_receipt(0xC105));
        let record = BlockVolumeResizeTransitionRecord {
            transition_id: self.next_resize_receipt(0x7A15),
            transition_class: draft.transition_class,
            outcome_class: draft.outcome_class,
            direction_class: draft.direction_class,
            from_geometry: draft.from_geometry,
            target_geometry: draft.target_geometry,
            post_resize_geometry: draft.post_resize_geometry,
            affected_tail_range: draft.affected_tail_range,
            zero_visible_range: draft.zero_visible_range,
            capacity_target_publication_class,
            requires_drain: draft.requires_drain,
            overlapping_inflight_context_refs: draft.blockers.inflight_context_refs,
            overlapping_dirty_epoch_refs: draft.blockers.dirty_epoch_refs,
            overlapping_guard_refs: draft.blockers.guard_refs,
            authority_anchor_ref: draft.authority_anchor_ref,
            issue_receipt_ref: self.next_resize_receipt(0x155E),
            close_receipt_ref,
        };
        self.resize_records.push(record.clone());
        record
    }

    fn next_resize_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(
            self.current_geometry.volume_id,
            self.next_resize_counter,
            salt,
        );
        self.next_resize_counter = self.next_resize_counter.wrapping_add(1);
        receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockVolumeImage {
    pub geometry: BlockVolumeGeometryRecord,
    pub bytes: Vec<u8>,
    pub dirty_epochs: Vec<BlockVolumeDirtyRangeEpochRecord>,
    pub flush_barriers: Vec<BlockVolumeFlushBarrierRecord>,
    pub discard_intents: Vec<BlockVolumeDiscardIntentRecord>,
    next_receipt_counter: u64,
}

impl BlockVolumeAdapterExportTransitionSupervisor {
    #[must_use]
    pub fn open(volume_id: BlockVolumeId, export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            volume_id,
            export_runtime_ref,
            current_state: BlockVolumeAdapterExportTransitionState::Steady,
            transition_generation: 0,
            fence_epoch_refs: Vec::new(),
            transition_receipt_refs: Vec::new(),
            transition_records: Vec::new(),
            next_supervisor_counter: 1,
        }
    }

    /// Begin a resize transition: steady → admission_freeze.
    pub fn begin_resize_transition(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::Steady {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::ResizeQuiesce,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::AdmissionFreeze;
        self.transition_generation += 1;
        self.record_transition(
            BlockVolumeExportTransitionClass::ResizeQuiesce,
            BlockVolumeExportPhaseClass::QueuesLive,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        )
    }

    /// Finalize resize prepare: admission_freeze → resize_prepare.
    pub fn finalize_resize_prepare(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::AdmissionFreeze {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::FenceAfterDrain,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::ResizePrepare;
        self.record_transition(
            BlockVolumeExportTransitionClass::FenceAfterDrain,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportPhaseClass::Fenced,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        )
    }

    /// Commit resize and resume: resize_prepare → resize_commit → steady.
    pub fn commit_resize_and_resume(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::ResizePrepare {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::ResumeAfterFence,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::ResizeCommit;
        let record = self.record_transition(
            BlockVolumeExportTransitionClass::ResumeAfterFence,
            BlockVolumeExportPhaseClass::Fenced,
            BlockVolumeExportPhaseClass::Resumed,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        );
        self.current_state = BlockVolumeAdapterExportTransitionState::Steady;
        record
    }

    /// Begin failover handoff: steady → failover_handoff.
    pub fn begin_failover_transition(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::Steady {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::FailoverQuiesce,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::FailoverHandoff;
        self.transition_generation += 1;
        self.record_transition(
            BlockVolumeExportTransitionClass::FailoverQuiesce,
            BlockVolumeExportPhaseClass::QueuesLive,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        )
    }

    /// Complete failover: failover_handoff → steady.
    pub fn complete_failover(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::FailoverHandoff {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::ResumeAfterFence,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::Steady;
        self.record_transition(
            BlockVolumeExportTransitionClass::ResumeAfterFence,
            BlockVolumeExportPhaseClass::QuiesceTransition,
            BlockVolumeExportPhaseClass::Resumed,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        )
    }

    /// Begin revoke/stop: steady → revoke_stop.
    pub fn begin_revoke_transition(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.current_state != BlockVolumeAdapterExportTransitionState::Steady {
            return self.refused_transition(
                BlockVolumeExportTransitionClass::RevokeQuiesce,
                BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            );
        }
        self.current_state = BlockVolumeAdapterExportTransitionState::RevokeStop;
        self.transition_generation += 1;
        self.record_transition(
            BlockVolumeExportTransitionClass::RevokeQuiesce,
            BlockVolumeExportPhaseClass::QueuesLive,
            BlockVolumeExportPhaseClass::Stopped,
            BlockVolumeExportTransitionOutcomeClass::Completed,
        )
    }

    /// Abort the current transition back to steady.
    pub fn abort_transition(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        let record = self.record_transition(
            BlockVolumeExportTransitionClass::FenceAfterDrain,
            self.current_export_phase(),
            self.current_export_phase(),
            BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete,
        );
        self.current_state = BlockVolumeAdapterExportTransitionState::Steady;
        record
    }

    fn current_export_phase(&self) -> BlockVolumeExportPhaseClass {
        match self.current_state {
            BlockVolumeAdapterExportTransitionState::Steady => BlockVolumeExportPhaseClass::Resumed,
            BlockVolumeAdapterExportTransitionState::AdmissionFreeze
            | BlockVolumeAdapterExportTransitionState::ResizePrepare
            | BlockVolumeAdapterExportTransitionState::FailoverHandoff => {
                BlockVolumeExportPhaseClass::QuiesceTransition
            }
            BlockVolumeAdapterExportTransitionState::ResizeCommit => {
                BlockVolumeExportPhaseClass::Fenced
            }
            BlockVolumeAdapterExportTransitionState::RevokeStop => {
                BlockVolumeExportPhaseClass::Stopped
            }
        }
    }

    fn record_transition(
        &mut self,
        transition_class: BlockVolumeExportTransitionClass,
        from_phase_class: BlockVolumeExportPhaseClass,
        to_phase_class: BlockVolumeExportPhaseClass,
        outcome_class: BlockVolumeExportTransitionOutcomeClass,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_supervisor_receipt(0x7A15),
            transition_class,
            from_phase_class,
            to_phase_class,
            outcome_class,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_supervisor_receipt(0x155E),
            close_receipt_ref: Some(self.next_supervisor_receipt(0xC105)),
        };
        self.transition_receipt_refs.push(record.transition_id);
        self.transition_records.push(record.clone());
        record
    }

    fn refused_transition(
        &mut self,
        transition_class: BlockVolumeExportTransitionClass,
        outcome_class: BlockVolumeExportTransitionOutcomeClass,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        let phase = self.current_export_phase();
        self.record_transition(transition_class, phase, phase, outcome_class)
    }

    fn next_supervisor_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(self.volume_id, self.next_supervisor_counter, salt);
        self.next_supervisor_counter = self.next_supervisor_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeAdapterAdmissionGateCoordinator {
    #[must_use]
    pub fn open(
        export_runtime_ref: BlockVolumeReceiptId,
        queue_set_refs: Vec<BlockVolumeReceiptId>,
    ) -> Self {
        Self {
            gate_state: BlockVolumeAdapterAdmissionGateState::Open,
            export_runtime_ref,
            queue_set_refs,
            admission_decision_records: Vec::new(),
            next_gate_counter: 1,
        }
    }

    /// Narrow the admission gate (soft fencing).
    pub fn narrow_gate(&mut self) {
        if self.gate_state == BlockVolumeAdapterAdmissionGateState::Open {
            self.gate_state = BlockVolumeAdapterAdmissionGateState::Narrowed;
        }
    }

    /// Close the admission gate (full fencing).
    pub fn close_gate(&mut self) {
        if matches!(
            self.gate_state,
            BlockVolumeAdapterAdmissionGateState::Open
                | BlockVolumeAdapterAdmissionGateState::Narrowed
        ) {
            self.gate_state = BlockVolumeAdapterAdmissionGateState::Closed;
        }
    }

    /// Reopen the admission gate after fencing.
    pub fn reopen_gate(&mut self) {
        if matches!(
            self.gate_state,
            BlockVolumeAdapterAdmissionGateState::Closed
                | BlockVolumeAdapterAdmissionGateState::Narrowed
        ) {
            self.gate_state = BlockVolumeAdapterAdmissionGateState::Reopened;
        }
    }

    /// Retire the admission gate permanently.
    pub fn retire_gate(&mut self) {
        self.gate_state = BlockVolumeAdapterAdmissionGateState::Retired;
    }

    /// Check whether new conflicting requests can be admitted.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(
            self.gate_state,
            BlockVolumeAdapterAdmissionGateState::Open
                | BlockVolumeAdapterAdmissionGateState::Reopened
        )
    }

    /// Record an admission decision.
    pub fn record_decision(&mut self, decision: BlockVolumeAdmissionDecisionRecord) {
        self.admission_decision_records.push(decision);
    }
}

impl BlockVolumeAdapterFenceEpochCoordinator {
    #[must_use]
    pub fn open(
        export_runtime_ref: BlockVolumeReceiptId,
        queue_set_refs: Vec<BlockVolumeReceiptId>,
    ) -> Self {
        Self {
            export_runtime_ref,
            active_fence_class: None,
            fence_epoch_ref: receipt_for_volume(
                BlockVolumeId::new(0),
                export_runtime_ref.0,
                0x03FD,
            ),
            fence_generation: 0,
            fence_records: Vec::new(),
            queue_set_refs,
            is_open: false,
            next_fence_counter: 1,
        }
    }

    /// Open a new fence epoch of the given fence class.
    pub fn open_fence_epoch(
        &mut self,
        fence_class: BlockVolumeAdapterFenceClass,
    ) -> BlockVolumeExportFenceMirrorRecord {
        if self.is_open {
            return self.make_fence_record(false);
        }
        self.is_open = true;
        self.active_fence_class = Some(fence_class);
        self.fence_generation += 1;
        let record = BlockVolumeExportFenceMirrorRecord {
            export_fence_id: self.next_fence_receipt(0x03FD),
            queue_set_ref: self.export_runtime_ref,
            queue_phase_class: BlockVolumeQueuePhaseClass::Fenced,
            affected_queue_set_refs: self.queue_set_refs.clone(),
            issue_receipt_ref: Some(self.next_fence_receipt(0x155E)),
            close_receipt_ref: None,
        };
        self.fence_records.push(record.clone());
        record
    }

    /// Close the active fence epoch.
    pub fn close_fence_epoch(&mut self) -> BlockVolumeExportFenceMirrorRecord {
        if !self.is_open {
            return self.make_fence_record(false);
        }
        self.is_open = false;
        let close_receipt = self.next_fence_receipt(0xC105);
        let record = BlockVolumeExportFenceMirrorRecord {
            export_fence_id: self.next_fence_receipt(0x03FD),
            queue_set_ref: self.export_runtime_ref,
            queue_phase_class: BlockVolumeQueuePhaseClass::Open,
            affected_queue_set_refs: Vec::new(),
            issue_receipt_ref: None,
            close_receipt_ref: Some(close_receipt),
        };
        self.active_fence_class = None;
        self.fence_records.push(record.clone());
        record
    }

    fn make_fence_record(&mut self, _is_valid: bool) -> BlockVolumeExportFenceMirrorRecord {
        BlockVolumeExportFenceMirrorRecord {
            export_fence_id: self.next_fence_receipt(0x03FD),
            queue_set_ref: self.export_runtime_ref,
            queue_phase_class: if self.is_open {
                BlockVolumeQueuePhaseClass::Fenced
            } else {
                BlockVolumeQueuePhaseClass::Open
            },
            affected_queue_set_refs: self.queue_set_refs.clone(),
            issue_receipt_ref: None,
            close_receipt_ref: None,
        }
    }

    fn next_fence_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(
            BlockVolumeId::new(0),
            self.fence_generation
                .wrapping_mul(100)
                .wrapping_add(self.next_fence_counter),
            salt,
        );
        self.next_fence_counter = self.next_fence_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeAdapterInflightClassifier {
    #[must_use]
    pub fn open(export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            export_runtime_ref,
            classifications: Vec::new(),
            disposition_records: Vec::new(),
            next_classifier_counter: 1,
        }
    }

    /// Classify a single inflight request.
    pub fn classify_request(
        &mut self,
        submission_context_ref: BlockVolumeReceiptId,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        epoch_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeAdapterInflightDispositionRecord {
        let classification = match request_class {
            BlockVolumeRequestClass::Read => BlockVolumeInflightTransitionClass::CommitOk,
            BlockVolumeRequestClass::Write
            | BlockVolumeRequestClass::Discard
            | BlockVolumeRequestClass::WriteZeroes => {
                BlockVolumeInflightTransitionClass::ReplayRequired
            }
            BlockVolumeRequestClass::Flush => BlockVolumeInflightTransitionClass::AbortRequired,
        };
        let disposition = match classification {
            BlockVolumeInflightTransitionClass::CommitOk => {
                BlockVolumeAdapterInflightDispositionState::Committed
            }
            BlockVolumeInflightTransitionClass::ReplayRequired => {
                BlockVolumeAdapterInflightDispositionState::ReplayRequired
            }
            BlockVolumeInflightTransitionClass::AbortRequired => {
                BlockVolumeAdapterInflightDispositionState::Aborted
            }
        };
        let record = BlockVolumeAdapterInflightDispositionRecord {
            submission_context_ref,
            disposition,
            classification,
            request_class,
            range,
            epoch_ref,
        };
        self.disposition_records.push(record.clone());
        self.classifications
            .push(BlockVolumeInflightTransitionClassificationRecord {
                submission_context_ref,
                request_class,
                classification,
                range,
                queue_shard_refs: Vec::new(),
            });
        record
    }

    /// Classify a batch of inflight contexts.
    pub fn classify_batch(
        &mut self,
        contexts: &[BlockVolumeInflightTransitionClassificationRecord],
        epoch_ref: BlockVolumeReceiptId,
    ) -> Vec<BlockVolumeAdapterInflightDispositionRecord> {
        let mut records = Vec::new();
        for ctx in contexts {
            let disposition = match ctx.classification {
                BlockVolumeInflightTransitionClass::CommitOk => {
                    BlockVolumeAdapterInflightDispositionState::Committed
                }
                BlockVolumeInflightTransitionClass::ReplayRequired => {
                    BlockVolumeAdapterInflightDispositionState::ReplayRequired
                }
                BlockVolumeInflightTransitionClass::AbortRequired => {
                    BlockVolumeAdapterInflightDispositionState::Aborted
                }
            };
            let record = BlockVolumeAdapterInflightDispositionRecord {
                submission_context_ref: ctx.submission_context_ref,
                disposition,
                classification: ctx.classification,
                request_class: ctx.request_class,
                range: ctx.range,
                epoch_ref,
            };
            self.disposition_records.push(record.clone());
            self.classifications.push(ctx.clone());
            records.push(record);
        }
        records
    }
}

impl BlockVolumeAdapterResizePlanner {
    #[must_use]
    pub fn open(
        volume_id: BlockVolumeId,
        export_runtime_ref: BlockVolumeReceiptId,
        current_geometry: BlockVolumeGeometryRecord,
    ) -> Self {
        Self {
            volume_id,
            export_runtime_ref,
            resize_state: BlockVolumeAdapterResizeTransitionState::Resumed,
            current_geometry,
            target_geometry: None,
            resize_records: Vec::new(),
            next_planner_counter: 1,
        }
    }

    /// Plan a resize: validate preconditions and set target geometry.
    pub fn plan_resize(
        &mut self,
        target_block_count: usize,
        _authority_anchor_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeResizeTransitionRecord {
        if target_block_count == 0 || target_block_count == self.current_geometry.block_count {
            return self.record_resize(
                BlockVolumeResizeTransitionClass::Refuse,
                BlockVolumeResizeTransitionOutcomeClass::RefusedInvalidCapacity,
                None,
                None,
                None,
            );
        }
        let target_geometry = BlockVolumeGeometryRecord {
            block_count: target_block_count,
            ..self.current_geometry
        };
        let direction_class =
            resize_direction(self.current_geometry.block_count, target_block_count);
        let affected_tail_range = direction_class.and_then(|direction| {
            resize_tail_range(
                self.current_geometry.block_count,
                target_block_count,
                direction,
            )
        });
        self.resize_state = BlockVolumeAdapterResizeTransitionState::Planned;
        self.target_geometry = Some(target_geometry);
        self.record_resize(
            BlockVolumeResizeTransitionClass::Prepare,
            BlockVolumeResizeTransitionOutcomeClass::Prepared,
            direction_class,
            affected_tail_range,
            Some(target_geometry),
        )
    }

    /// Open the resize fence.
    pub fn open_fence(&mut self) -> BlockVolumeResizeTransitionRecord {
        if self.resize_state != BlockVolumeAdapterResizeTransitionState::Planned {
            return self.record_resize(
                BlockVolumeResizeTransitionClass::Refuse,
                BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced,
                None,
                None,
                None,
            );
        }
        self.resize_state = BlockVolumeAdapterResizeTransitionState::FenceOpen;
        self.record_resize(
            BlockVolumeResizeTransitionClass::Prepare,
            BlockVolumeResizeTransitionOutcomeClass::Prepared,
            None,
            None,
            self.target_geometry,
        )
    }

    /// Mark resize as drained.
    pub fn mark_drained(&mut self) -> BlockVolumeResizeTransitionRecord {
        if self.resize_state != BlockVolumeAdapterResizeTransitionState::FenceOpen {
            return self.record_resize(
                BlockVolumeResizeTransitionClass::Refuse,
                BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete,
                None,
                None,
                None,
            );
        }
        self.resize_state = BlockVolumeAdapterResizeTransitionState::Drained;
        self.record_resize(
            BlockVolumeResizeTransitionClass::Prepare,
            BlockVolumeResizeTransitionOutcomeClass::Prepared,
            None,
            None,
            self.target_geometry,
        )
    }

    /// Commit the geometry change.
    pub fn commit_geometry(&mut self) -> BlockVolumeResizeTransitionRecord {
        if self.resize_state != BlockVolumeAdapterResizeTransitionState::Drained {
            return self.record_resize(
                BlockVolumeResizeTransitionClass::Refuse,
                BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced,
                None,
                None,
                None,
            );
        }
        if let Some(target) = self.target_geometry {
            self.current_geometry = target;
        }
        self.resize_state = BlockVolumeAdapterResizeTransitionState::GeometryCommit;
        let post_geometry = self.target_geometry;
        let record = self.record_resize(
            BlockVolumeResizeTransitionClass::Commit,
            BlockVolumeResizeTransitionOutcomeClass::Committed,
            None,
            None,
            post_geometry,
        );
        self.resize_state = BlockVolumeAdapterResizeTransitionState::Resumed;
        self.target_geometry = None;
        record
    }

    /// Abort the resize.
    pub fn abort_resize(&mut self) -> BlockVolumeResizeTransitionRecord {
        let record = self.record_resize(
            BlockVolumeResizeTransitionClass::Refuse,
            BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete,
            None,
            None,
            None,
        );
        self.resize_state = BlockVolumeAdapterResizeTransitionState::Aborted;
        self.target_geometry = None;
        record
    }

    fn record_resize(
        &mut self,
        transition_class: BlockVolumeResizeTransitionClass,
        outcome_class: BlockVolumeResizeTransitionOutcomeClass,
        direction_class: Option<BlockVolumeResizeDirectionClass>,
        affected_tail_range: Option<BlockRangeRecord>,
        post_resize_geometry: Option<BlockVolumeGeometryRecord>,
    ) -> BlockVolumeResizeTransitionRecord {
        let capacity_target_publication_class = match outcome_class {
            BlockVolumeResizeTransitionOutcomeClass::Prepared
            | BlockVolumeResizeTransitionOutcomeClass::Committed => {
                BlockVolumeCapacityTargetPublicationClass::PublishedForCommit
            }
            _ => BlockVolumeCapacityTargetPublicationClass::NotPublished,
        };
        let close_receipt_ref = (outcome_class
            != BlockVolumeResizeTransitionOutcomeClass::Prepared)
            .then(|| self.next_planner_receipt(0xC105));
        let record = BlockVolumeResizeTransitionRecord {
            transition_id: self.next_planner_receipt(0x7A15),
            transition_class,
            outcome_class,
            direction_class,
            from_geometry: self.current_geometry,
            target_geometry: self.target_geometry.unwrap_or(self.current_geometry),
            post_resize_geometry,
            affected_tail_range,
            zero_visible_range: direction_class.and_then(|d| match d {
                BlockVolumeResizeDirectionClass::Grow => affected_tail_range,
                _ => None,
            }),
            capacity_target_publication_class,
            requires_drain: direction_class.is_some(),
            overlapping_inflight_context_refs: Vec::new(),
            overlapping_dirty_epoch_refs: Vec::new(),
            overlapping_guard_refs: Vec::new(),
            authority_anchor_ref: receipt_for_volume(self.volume_id, 2, 0x301D),
            issue_receipt_ref: self.next_planner_receipt(0x155E),
            close_receipt_ref,
        };
        self.resize_records.push(record.clone());
        record
    }

    fn next_planner_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(self.volume_id, self.next_planner_counter, salt);
        self.next_planner_counter = self.next_planner_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeAdapterReplayCursorWriter {
    #[must_use]
    pub fn open(export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            export_runtime_ref,
            cursor_records: Vec::new(),
            last_cursor_position: 0,
            last_cursor_epoch: 0,
            next_cursor_counter: 1,
        }
    }

    /// Emit an authoritative replay cursor after failover/restart.
    pub fn emit_replay_cursor(
        &mut self,
        cursor_position: u64,
        cursor_epoch: u64,
        fence_epoch_ref: BlockVolumeReceiptId,
        authoritative: bool,
    ) -> BlockVolumeAdapterReplayCursorRecord {
        let cursor_id = receipt_for_volume(BlockVolumeId::new(0), self.next_cursor_counter, 0x52EC);
        self.next_cursor_counter = self.next_cursor_counter.wrapping_add(1);
        let record = BlockVolumeAdapterReplayCursorRecord {
            cursor_id,
            export_runtime_ref: self.export_runtime_ref,
            cursor_position,
            cursor_epoch,
            fence_epoch_ref,
            authoritative,
        };
        self.last_cursor_position = cursor_position;
        self.last_cursor_epoch = cursor_epoch;
        self.cursor_records.push(record.clone());
        record
    }
}

impl BlockVolumeAdapterFailoverHandoffCoordinator {
    #[must_use]
    pub fn open(
        volume_id: BlockVolumeId,
        export_runtime_ref: BlockVolumeReceiptId,
        quorum_threshold: u32,
    ) -> Self {
        Self {
            volume_id,
            export_runtime_ref,
            handoff_state: BlockVolumeAdapterFailoverHandoffState::Resumed,
            escrow_receipt_ref: None,
            witness_count: 0,
            quorum_threshold,
            handoff_generation: 0,
            transition_records: Vec::new(),
            next_handoff_counter: 1,
        }
    }

    /// Open failover intent.
    pub fn open_failover_intent(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.handoff_state != BlockVolumeAdapterFailoverHandoffState::Resumed {
            return self.refused_handoff();
        }
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::IntentOpen;
        self.handoff_generation += 1;
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_handoff_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::FailoverQuiesce,
            from_phase_class: BlockVolumeExportPhaseClass::Resumed,
            to_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_handoff_receipt(0x155E),
            close_receipt_ref: None,
        };
        self.transition_records.push(record.clone());
        record
    }

    /// Stage reserve escrow.
    pub fn stage_escrow(&mut self, escrow_receipt_ref: BlockVolumeReceiptId) {
        if self.handoff_state == BlockVolumeAdapterFailoverHandoffState::IntentOpen {
            self.handoff_state = BlockVolumeAdapterFailoverHandoffState::EscrowStaged;
            self.escrow_receipt_ref = Some(escrow_receipt_ref);
        }
    }

    /// Add a witness and check quorum.
    pub fn add_witness(&mut self) -> bool {
        if self.handoff_state == BlockVolumeAdapterFailoverHandoffState::EscrowStaged {
            self.witness_count += 1;
            if self.witness_count >= self.quorum_threshold {
                self.handoff_state = BlockVolumeAdapterFailoverHandoffState::QuorumMet;
                return true;
            }
        }
        false
    }

    /// Open fence for cutover.
    pub fn open_cutover_fence(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.handoff_state != BlockVolumeAdapterFailoverHandoffState::QuorumMet {
            return self.refused_handoff();
        }
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::FenceOpen;
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_handoff_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::FenceAfterDrain,
            from_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            to_phase_class: BlockVolumeExportPhaseClass::Fenced,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_handoff_receipt(0x155E),
            close_receipt_ref: None,
        };
        self.transition_records.push(record.clone());
        record
    }

    /// Mark drained state.
    pub fn mark_drained(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.handoff_state != BlockVolumeAdapterFailoverHandoffState::FenceOpen {
            return self.refused_handoff();
        }
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::Drained;
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_handoff_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::FenceAfterDrain,
            from_phase_class: BlockVolumeExportPhaseClass::Fenced,
            to_phase_class: BlockVolumeExportPhaseClass::Fenced,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_handoff_receipt(0x155E),
            close_receipt_ref: None,
        };
        self.transition_records.push(record.clone());
        record
    }

    /// Commit the cutover and resume.
    pub fn commit_cutover(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        if self.handoff_state != BlockVolumeAdapterFailoverHandoffState::Drained {
            return self.refused_handoff();
        }
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::CutoverCommit;
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_handoff_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::ResumeAfterFence,
            from_phase_class: BlockVolumeExportPhaseClass::Fenced,
            to_phase_class: BlockVolumeExportPhaseClass::Resumed,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_handoff_receipt(0x155E),
            close_receipt_ref: Some(self.next_handoff_receipt(0xC105)),
        };
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::Resumed;
        self.transition_records.push(record.clone());
        record
    }

    /// Abort the failover/handoff.
    pub fn abort_handoff(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_handoff_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::FailoverQuiesce,
            from_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            to_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_handoff_receipt(0x155E),
            close_receipt_ref: Some(self.next_handoff_receipt(0xC105)),
        };
        self.handoff_state = BlockVolumeAdapterFailoverHandoffState::Aborted;
        self.transition_records.push(record.clone());
        record
    }

    fn refused_handoff(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        BlockVolumeExportLifecycleTransitionRecord {
            transition_id: receipt_for_volume(self.volume_id, self.next_handoff_counter, 0x7A15),
            transition_class: BlockVolumeExportTransitionClass::FailoverQuiesce,
            from_phase_class: BlockVolumeExportPhaseClass::Resumed,
            to_phase_class: BlockVolumeExportPhaseClass::Resumed,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: receipt_for_volume(
                self.volume_id,
                self.next_handoff_counter,
                0x155E,
            ),
            close_receipt_ref: None,
        }
    }

    fn next_handoff_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(self.volume_id, self.next_handoff_counter, salt);
        self.next_handoff_counter = self.next_handoff_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeAdapterRevokeStopCoordinator {
    #[must_use]
    pub fn open(export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            export_runtime_ref,
            is_tombstoned: false,
            revoke_receipt_ref: None,
            stop_transition_records: Vec::new(),
            fence_receipt_ref: None,
            next_revoke_counter: 1,
        }
    }

    /// Begin controlled stop with fence.
    pub fn begin_stop(
        &mut self,
        fence_receipt_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        self.fence_receipt_ref = Some(fence_receipt_ref);
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_revoke_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::StopAfterDrain,
            from_phase_class: BlockVolumeExportPhaseClass::QueuesLive,
            to_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_revoke_receipt(0x155E),
            close_receipt_ref: None,
        };
        self.stop_transition_records.push(record.clone());
        record
    }

    /// Complete the stop transition.
    pub fn complete_stop(&mut self) -> BlockVolumeExportLifecycleTransitionRecord {
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_revoke_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::StopAfterDrain,
            from_phase_class: BlockVolumeExportPhaseClass::QuiesceTransition,
            to_phase_class: BlockVolumeExportPhaseClass::Stopped,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_revoke_receipt(0x155E),
            close_receipt_ref: Some(self.next_revoke_receipt(0xC105)),
        };
        self.stop_transition_records.push(record.clone());
        record
    }

    /// Revoke the export and tombstone runtime mirrors.
    pub fn revoke_and_tombstone(
        &mut self,
        revoke_receipt_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeExportLifecycleTransitionRecord {
        self.revoke_receipt_ref = Some(revoke_receipt_ref);
        self.is_tombstoned = true;
        let record = BlockVolumeExportLifecycleTransitionRecord {
            transition_id: self.next_revoke_receipt(0x7A15),
            transition_class: BlockVolumeExportTransitionClass::RevokeQuiesce,
            from_phase_class: BlockVolumeExportPhaseClass::Stopped,
            to_phase_class: BlockVolumeExportPhaseClass::Stopped,
            outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
            affected_queue_set_refs: Vec::new(),
            inflight_classifications: Vec::new(),
            issue_receipt_ref: self.next_revoke_receipt(0x155E),
            close_receipt_ref: Some(self.next_revoke_receipt(0xC105)),
        };
        self.stop_transition_records.push(record.clone());
        record
    }

    fn next_revoke_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(BlockVolumeId::new(0), self.next_revoke_counter, salt);
        self.next_revoke_counter = self.next_revoke_counter.wrapping_add(1);
        receipt
    }
}

impl BlockVolumeAdapterQueueDrainCoordinator {
    #[must_use]
    pub fn open(export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            export_runtime_ref,
            drained_dirty_epoch_refs: Vec::new(),
            drained_barrier_refs: Vec::new(),
            drained_guard_refs: Vec::new(),
            drain_complete: false,
            next_drain_counter: 1,
        }
    }

    /// Record a drained dirty epoch.
    pub fn drain_dirty_epoch(&mut self, epoch_ref: BlockVolumeReceiptId) {
        self.drained_dirty_epoch_refs.push(epoch_ref);
    }

    /// Record a drained barrier.
    pub fn drain_barrier(&mut self, barrier_ref: BlockVolumeReceiptId) {
        self.drained_barrier_refs.push(barrier_ref);
    }

    /// Record a drained direct guard.
    pub fn drain_guard(&mut self, guard_ref: BlockVolumeReceiptId) {
        self.drained_guard_refs.push(guard_ref);
    }

    /// Mark the drain as complete.
    pub fn mark_drain_complete(&mut self) {
        self.drain_complete = true;
    }

    /// Check whether all required drains are satisfied.
    #[must_use]
    pub fn is_drain_complete(&self) -> bool {
        self.drain_complete
    }
}

impl BlockVolumeAdapterTransitionReceiptEmitter {
    #[must_use]
    pub fn open(export_runtime_ref: BlockVolumeReceiptId) -> Self {
        Self {
            export_runtime_ref,
            receipt_records: Vec::new(),
            is_durable: false,
            next_emitter_counter: 1,
        }
    }

    /// Emit a durable transition receipt.
    pub fn emit_transition_receipt(
        &mut self,
        transition_class: BlockVolumeExportTransitionClass,
        outcome_class: BlockVolumeExportTransitionOutcomeClass,
        from_state: BlockVolumeAdapterExportTransitionState,
        to_state: BlockVolumeAdapterExportTransitionState,
        fence_epoch_ref: BlockVolumeReceiptId,
    ) -> BlockVolumeAdapterTransitionReceiptRecord {
        self.is_durable = true;
        let record = BlockVolumeAdapterTransitionReceiptRecord {
            receipt_id: self.next_emitter_receipt(0x52EC),
            export_runtime_ref: self.export_runtime_ref,
            transition_class,
            outcome_class,
            from_state,
            to_state,
            fence_epoch_ref,
            is_durable: true,
        };
        self.receipt_records.push(record.clone());
        record
    }

    fn next_emitter_receipt(&mut self, salt: u64) -> BlockVolumeReceiptId {
        let receipt = receipt_for_volume(BlockVolumeId::new(0), self.next_emitter_counter, salt);
        self.next_emitter_counter = self.next_emitter_counter.wrapping_add(1);
        receipt
    }
}

// ---------------------------------------------------------------------------
// P6-03: 10 canonical export transition algorithm families (spec §9)
// ---------------------------------------------------------------------------

/// Open a new fence epoch over an export for resize/failover/revoke.
#[must_use]
pub fn open_block_volume_adapter_export_fence_epoch(
    export_runtime_ref: BlockVolumeReceiptId,
    fence_class: BlockVolumeAdapterFenceClass,
    queue_set_refs: &[BlockVolumeReceiptId],
    fence_generation: u64,
) -> BlockVolumeAdapterExportFenceEpochRecord {
    let fence_epoch_id = receipt_for_volume(
        BlockVolumeId::new(0),
        export_runtime_ref.0.wrapping_add(fence_generation),
        0x03FD,
    );
    BlockVolumeAdapterExportFenceEpochRecord {
        fence_epoch_id,
        export_runtime_ref,
        fence_class,
        fence_generation,
        previous_authority_anchor_ref: None,
        new_authority_anchor_ref: None,
        queue_set_refs: queue_set_refs.to_vec(),
        is_open: true,
        is_durable: false,
        issue_receipt_ref: receipt_for_volume(
            BlockVolumeId::new(0),
            export_runtime_ref.0.wrapping_add(fence_generation),
            0x155E,
        ),
        close_receipt_ref: None,
    }
}

/// Freeze the admission gate, returning the current gate snapshot.
#[must_use]
pub fn freeze_block_volume_adapter_export_admission_gate(
    export_runtime_ref: BlockVolumeReceiptId,
    gate_state: BlockVolumeAdapterAdmissionGateState,
    queue_set_refs: &[BlockVolumeReceiptId],
) -> BlockVolumeAdapterExportAdmissionGateRecord {
    BlockVolumeAdapterExportAdmissionGateRecord {
        gate_id: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0x6A13),
        export_runtime_ref,
        gate_state,
        queue_set_refs: queue_set_refs.to_vec(),
        issue_receipt_ref: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0x155E),
    }
}

/// Classify a single inflight request into commit, replay, or abort.
#[must_use]
pub fn classify_block_volume_adapter_inflight_request_for_commit_replay_abort(
    request_class: BlockVolumeRequestClass,
    submission_context_ref: BlockVolumeReceiptId,
    range: Option<BlockRangeRecord>,
    epoch_ref: BlockVolumeReceiptId,
) -> BlockVolumeAdapterInflightDispositionRecord {
    let classification = match request_class {
        BlockVolumeRequestClass::Read => BlockVolumeInflightTransitionClass::CommitOk,
        BlockVolumeRequestClass::Write
        | BlockVolumeRequestClass::Discard
        | BlockVolumeRequestClass::WriteZeroes => {
            BlockVolumeInflightTransitionClass::ReplayRequired
        }
        BlockVolumeRequestClass::Flush => BlockVolumeInflightTransitionClass::AbortRequired,
    };
    let disposition = match classification {
        BlockVolumeInflightTransitionClass::CommitOk => {
            BlockVolumeAdapterInflightDispositionState::Committed
        }
        BlockVolumeInflightTransitionClass::ReplayRequired => {
            BlockVolumeAdapterInflightDispositionState::ReplayRequired
        }
        BlockVolumeInflightTransitionClass::AbortRequired => {
            BlockVolumeAdapterInflightDispositionState::Aborted
        }
    };
    BlockVolumeAdapterInflightDispositionRecord {
        submission_context_ref,
        disposition,
        classification,
        request_class,
        range,
        epoch_ref,
    }
}

/// Seal a resize plan with frozen preconditions.
#[must_use]
pub fn seal_block_volume_adapter_export_resize_plan(
    export_runtime_ref: BlockVolumeReceiptId,
    direction_class: BlockVolumeResizeDirectionClass,
    from_geometry: BlockVolumeGeometryRecord,
    target_geometry: BlockVolumeGeometryRecord,
    affected_tail_range: Option<BlockRangeRecord>,
    requires_drain: bool,
    authority_anchor_ref: BlockVolumeReceiptId,
) -> BlockVolumeAdapterExportResizePlanRecord {
    BlockVolumeAdapterExportResizePlanRecord {
        plan_id: receipt_for_volume(from_geometry.volume_id, export_runtime_ref.0, 0x7A15),
        export_runtime_ref,
        direction_class,
        from_geometry,
        target_geometry,
        affected_tail_range,
        requires_drain,
        continuity_check_satisfied: true,
        authority_anchor_ref,
        issue_receipt_ref: receipt_for_volume(
            from_geometry.volume_id,
            export_runtime_ref.0,
            0x155E,
        ),
    }
}

/// Quiesce queue sets under an active export fence epoch.
#[must_use]
pub fn quiesce_block_volume_adapter_queue_sets_under_export_fence(
    fence_epoch: &BlockVolumeAdapterExportFenceEpochRecord,
    drain_inflight_count: usize,
    unclassified_count: usize,
) -> BlockVolumeAdapterFenceQuiesceReceipt {
    let drain_complete = unclassified_count == 0;
    BlockVolumeAdapterFenceQuiesceReceipt {
        receipt_id: receipt_for_volume(BlockVolumeId::new(0), fence_epoch.fence_epoch_id.0, 0xC145),
        export_runtime_ref: fence_epoch.export_runtime_ref,
        fence_epoch_ref: fence_epoch.fence_epoch_id,
        fence_class: fence_epoch.fence_class,
        drain_complete,
        inflight_classified_count: drain_inflight_count,
        unclassified_count,
        is_durable: drain_complete,
        issue_receipt_ref: receipt_for_volume(
            BlockVolumeId::new(0),
            fence_epoch.fence_epoch_id.0,
            0x155E,
        ),
    }
}

/// Commit a resize and resume export service under a fresh epoch.
#[must_use]
pub fn commit_block_volume_adapter_resize_and_resume_export(
    export_runtime_ref: BlockVolumeReceiptId,
    from_geometry: BlockVolumeGeometryRecord,
    to_geometry: BlockVolumeGeometryRecord,
    resize_direction: BlockVolumeResizeDirectionClass,
    new_epoch_ref: BlockVolumeReceiptId,
) -> BlockVolumeAdapterResizeCommitReceipt {
    BlockVolumeAdapterResizeCommitReceipt {
        receipt_id: receipt_for_volume(from_geometry.volume_id, new_epoch_ref.0, 0xC026),
        export_runtime_ref,
        from_geometry,
        to_geometry,
        resize_direction,
        new_epoch_ref,
        is_durable: true,
        issue_receipt_ref: receipt_for_volume(from_geometry.volume_id, new_epoch_ref.0, 0x155E),
    }
}

/// Stage a failover or handoff transition with escrow and quorum refs.
#[must_use]
pub fn stage_block_volume_adapter_failover_or_handoff_transition(
    export_runtime_ref: BlockVolumeReceiptId,
    successor_export_target_ref: BlockVolumeReceiptId,
    escrow_receipt_ref: Option<BlockVolumeReceiptId>,
    witness_quorum_refs: &[BlockVolumeReceiptId],
    quorum_threshold: u32,
    replay_policy_ref: BlockVolumeReceiptId,
) -> BlockVolumeAdapterExportFailoverIntentRecord {
    let quorum_satisfied = (witness_quorum_refs.len() as u32) >= quorum_threshold;
    BlockVolumeAdapterExportFailoverIntentRecord {
        intent_id: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0xF410),
        export_runtime_ref,
        successor_export_target_ref,
        escrow_receipt_ref,
        witness_quorum_refs: witness_quorum_refs.to_vec(),
        quorum_threshold,
        quorum_satisfied,
        replay_policy_ref,
        issue_receipt_ref: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0x155E),
    }
}

/// Emit an authoritative replay cursor after a transition.
#[must_use]
pub fn emit_block_volume_adapter_replay_cursor_after_transition(
    export_runtime_ref: BlockVolumeReceiptId,
    cursor_position: u64,
    cursor_epoch: u64,
    fence_epoch_ref: BlockVolumeReceiptId,
    authoritative: bool,
) -> BlockVolumeAdapterReplayCursorRecord {
    BlockVolumeAdapterReplayCursorRecord {
        cursor_id: receipt_for_volume(
            BlockVolumeId::new(0),
            export_runtime_ref.0.wrapping_add(cursor_epoch),
            0x52EC,
        ),
        export_runtime_ref,
        cursor_position,
        cursor_epoch,
        fence_epoch_ref,
        authoritative,
    }
}

/// Revoke an export and tombstone its runtime mirrors.
#[must_use]
pub fn revoke_block_volume_adapter_export_and_tombstone_runtime(
    export_runtime_ref: BlockVolumeReceiptId,
    _revoke_receipt_ref: BlockVolumeReceiptId,
    fence_epoch_ref: BlockVolumeReceiptId,
) -> BlockVolumeAdapterTransitionReceiptRecord {
    BlockVolumeAdapterTransitionReceiptRecord {
        receipt_id: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0x7E10),
        export_runtime_ref,
        transition_class: BlockVolumeExportTransitionClass::RevokeQuiesce,
        outcome_class: BlockVolumeExportTransitionOutcomeClass::Completed,
        from_state: BlockVolumeAdapterExportTransitionState::RevokeStop,
        to_state: BlockVolumeAdapterExportTransitionState::RevokeStop,
        fence_epoch_ref,
        is_durable: true,
    }
}

/// Resume export service after fence or failover.
#[must_use]
pub fn resume_block_volume_adapter_export_after_fence_or_failover(
    export_runtime_ref: BlockVolumeReceiptId,
    fence_epoch_ref: BlockVolumeReceiptId,
    succeeded: bool,
) -> BlockVolumeAdapterTransitionReceiptRecord {
    let (outcome_class, from_state, to_state) = if succeeded {
        (
            BlockVolumeExportTransitionOutcomeClass::Completed,
            BlockVolumeAdapterExportTransitionState::Steady,
            BlockVolumeAdapterExportTransitionState::Steady,
        )
    } else {
        (
            BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete,
            BlockVolumeAdapterExportTransitionState::AdmissionFreeze,
            BlockVolumeAdapterExportTransitionState::Steady,
        )
    };
    BlockVolumeAdapterTransitionReceiptRecord {
        receipt_id: receipt_for_volume(BlockVolumeId::new(0), export_runtime_ref.0, 0x7E51),
        export_runtime_ref,
        transition_class: BlockVolumeExportTransitionClass::ResumeAfterFence,
        outcome_class,
        from_state,
        to_state,
        fence_epoch_ref,
        is_durable: succeeded,
    }
}
impl BlockVolumeImage {
    #[must_use]
    pub fn open_zeroed(geometry: BlockVolumeGeometryRecord) -> Option<Self> {
        if geometry.block_size_bytes == 0 || geometry.block_count == 0 {
            return None;
        }
        let capacity = geometry.capacity_bytes()?;
        Some(Self {
            geometry,
            bytes: vec![0; capacity],
            dirty_epochs: Vec::new(),
            flush_barriers: Vec::new(),
            discard_intents: Vec::new(),
            next_receipt_counter: 1,
        })
    }

    /// Resize backing byte vector to new geometry.
    /// Grow extends with zeros; shrink truncates.
    /// Returns `None` if capacity overflows.
    pub fn resize_to(&mut self, new_geometry: BlockVolumeGeometryRecord) -> Option<()> {
        let new_cap = new_geometry.capacity_bytes()?;
        self.bytes.resize(new_cap, 0);
        self.geometry = new_geometry;
        Some(())
    }

    #[must_use]
    pub fn read_blocks(
        &self,
        range: BlockRangeRecord,
    ) -> (BlockVolumeRequestPlan, Option<Vec<u8>>) {
        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return (
                self.refusal_plan(
                    BlockVolumeRequestClass::Read,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                    Some(range),
                    0,
                ),
                None,
            );
        };
        let payload = self.bytes[byte_range].to_vec();
        (
            self.completed_plan(BlockVolumeRequestClass::Read, Some(range), payload.len()),
            Some(payload),
        )
    }

    pub fn write_blocks(&mut self, start_block: usize, payload: &[u8]) -> BlockVolumeRequestPlan {
        if payload.is_empty() || payload.len() % self.geometry.block_size_bytes != 0 {
            return self.refusal_plan(
                BlockVolumeRequestClass::Write,
                BlockVolumeCompletionClass::RefusedMisalignedRange,
                None,
                payload.len(),
            );
        }
        let range =
            BlockRangeRecord::new(start_block, payload.len() / self.geometry.block_size_bytes);
        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return self.refusal_plan(
                BlockVolumeRequestClass::Write,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                Some(range),
                payload.len(),
            );
        };

        self.bytes[byte_range].copy_from_slice(payload);
        let dirty_epoch_ref = self.record_dirty_epoch(range, payload.len());
        let mut plan =
            self.completed_plan(BlockVolumeRequestClass::Write, Some(range), payload.len());
        plan.dirty_epoch_ref = Some(dirty_epoch_ref);
        plan
    }

    pub fn flush(&mut self) -> BlockVolumeRequestPlan {
        let covered_epoch_ids: Vec<BlockVolumeReceiptId> = self
            .dirty_epochs
            .iter()
            .filter(|epoch| !epoch.sealed_for_flush && !epoch.invalidated_by_discard)
            .map(|epoch| epoch.epoch_id)
            .collect();
        if covered_epoch_ids.is_empty() {
            return self.completed_plan(BlockVolumeRequestClass::Flush, None, 0);
        }

        for epoch in &mut self.dirty_epochs {
            if covered_epoch_ids.contains(&epoch.epoch_id) {
                epoch.sealed_for_flush = true;
            }
        }
        let barrier_id = self.next_receipt();
        let durability_receipt_ref = self.receipt_for(covered_epoch_ids.len() as u64, 0xF1A5);
        self.flush_barriers.push(BlockVolumeFlushBarrierRecord {
            barrier_id,
            barrier_class: BlockVolumeFlushBarrierClass::Satisfied,
            covered_epoch_ids,
            durability_receipt_ref,
        });

        let mut plan = self.completed_plan(BlockVolumeRequestClass::Flush, None, 0);
        plan.flush_barrier_ref = Some(barrier_id);
        plan
    }

    pub fn discard_blocks(&mut self, range: BlockRangeRecord) -> BlockVolumeRequestPlan {
        self.zero_or_discard_blocks(BlockVolumeRequestClass::Discard, range, true)
    }

    pub fn write_zeroes(&mut self, range: BlockRangeRecord) -> BlockVolumeRequestPlan {
        self.zero_or_discard_blocks(BlockVolumeRequestClass::WriteZeroes, range, false)
    }

    fn zero_or_discard_blocks(
        &mut self,
        request_class: BlockVolumeRequestClass,
        range: BlockRangeRecord,
        require_discard_granularity: bool,
    ) -> BlockVolumeRequestPlan {
        if require_discard_granularity && !self.geometry.admits_discard() {
            return BlockVolumeRequestPlan {
                request_class,
                completion_class: BlockVolumeCompletionClass::RefusedDiscardUnsupported,
                range: Some(range),
                payload_len: 0,
                dirty_epoch_ref: None,
                flush_barrier_ref: None,
                discard_intent_ref: None,
                completion_receipt_ref: BlockVolumeReceiptId::default(),
            };
        }
        if range.block_count == 0
            || (require_discard_granularity
                && !range_aligned_to_granularity(range, self.geometry.discard_granularity_blocks))
        {
            return BlockVolumeRequestPlan {
                request_class,
                completion_class: BlockVolumeCompletionClass::RefusedMisalignedRange,
                range: Some(range),
                payload_len: 0,
                dirty_epoch_ref: None,
                flush_barrier_ref: None,
                discard_intent_ref: None,
                completion_receipt_ref: BlockVolumeReceiptId::default(),
            };
        }

        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return self.refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                Some(range),
                0,
            );
        };

        for byte in &mut self.bytes[byte_range.clone()] {
            *byte = 0;
        }
        let invalidated_epoch_ids = self.invalidate_overlapping_dirty_epochs(range);
        let intent_id = self.next_receipt();
        self.discard_intents.push(BlockVolumeDiscardIntentRecord {
            intent_id,
            range,
            invalidated_epoch_ids,
            zeroes_visible: true,
        });
        let dirty_epoch_ref = self.record_dirty_epoch(range, byte_range.len());

        let mut plan = self.completed_plan(request_class, Some(range), 0);
        plan.dirty_epoch_ref = Some(dirty_epoch_ref);
        plan.discard_intent_ref = Some(intent_id);
        plan
    }

    fn record_dirty_epoch(
        &mut self,
        range: BlockRangeRecord,
        dirty_bytes: usize,
    ) -> BlockVolumeReceiptId {
        let epoch_id = self.next_receipt();
        self.dirty_epochs.push(BlockVolumeDirtyRangeEpochRecord {
            epoch_id,
            range,
            dirty_bytes,
            sealed_for_flush: false,
            invalidated_by_discard: false,
        });
        epoch_id
    }

    fn invalidate_overlapping_dirty_epochs(
        &mut self,
        range: BlockRangeRecord,
    ) -> Vec<BlockVolumeReceiptId> {
        let mut invalidated = Vec::new();
        for epoch in &mut self.dirty_epochs {
            if !epoch.sealed_for_flush
                && !epoch.invalidated_by_discard
                && block_ranges_overlap(epoch.range, range)
            {
                epoch.invalidated_by_discard = true;
                invalidated.push(epoch.epoch_id);
            }
        }
        invalidated
    }

    const fn completed_plan(
        &self,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
    ) -> BlockVolumeRequestPlan {
        BlockVolumeRequestPlan {
            request_class,
            completion_class: BlockVolumeCompletionClass::Completed,
            range,
            payload_len,
            dirty_epoch_ref: None,
            flush_barrier_ref: None,
            discard_intent_ref: None,
            completion_receipt_ref: self.receipt_for(payload_len as u64, request_class as u64),
        }
    }

    fn refusal_plan(
        &self,
        request_class: BlockVolumeRequestClass,
        completion_class: BlockVolumeCompletionClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
    ) -> BlockVolumeRequestPlan {
        BlockVolumeRequestPlan {
            request_class,
            completion_class,
            range,
            payload_len,
            dirty_epoch_ref: None,
            flush_barrier_ref: None,
            discard_intent_ref: None,
            completion_receipt_ref: BlockVolumeReceiptId::default(),
        }
    }

    fn next_receipt(&mut self) -> BlockVolumeReceiptId {
        let receipt = self.receipt_for(self.next_receipt_counter, 0x301A);
        self.next_receipt_counter = self.next_receipt_counter.wrapping_add(1);
        receipt
    }

    const fn receipt_for(&self, left: u64, salt: u64) -> BlockVolumeReceiptId {
        receipt_for_volume(self.geometry.volume_id, left, salt)
    }

    /// Whether this image reports discard/TRIM support via its geometry.
    ///
    /// Returns `true` when `discard_granularity_blocks > 0`, indicating
    /// the geometry was configured for discard operations.
    #[must_use]
    pub fn supports_discard(&self) -> bool {
        self.geometry.admits_discard()
    }
}

#[derive(Debug)]
pub enum BlockVolumeFileImageError {
    InvalidGeometry,
    CapacityTooLarge,
    BackingLengthMismatch {
        expected_bytes: u64,
        actual_bytes: u64,
    },
    Io(io::Error),
}

impl fmt::Display for BlockVolumeFileImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeometry => write!(f, "invalid block-volume geometry"),
            Self::CapacityTooLarge => write!(f, "block-volume capacity is too large"),
            Self::BackingLengthMismatch {
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "backing media length mismatch: expected {expected_bytes} bytes, found {actual_bytes} bytes"
            ),
            Self::Io(err) => write!(f, "backing media I/O failed: {err}"),
        }
    }
}

impl Error for BlockVolumeFileImageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidGeometry | Self::CapacityTooLarge | Self::BackingLengthMismatch { .. } => {
                None
            }
        }
    }
}

impl From<io::Error> for BlockVolumeFileImageError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug)]
pub struct BlockVolumeFileImage {
    pub geometry: BlockVolumeGeometryRecord,
    file: File,
    pub dirty_epochs: Vec<BlockVolumeDirtyRangeEpochRecord>,
    pub flush_barriers: Vec<BlockVolumeFlushBarrierRecord>,
    pub discard_intents: Vec<BlockVolumeDiscardIntentRecord>,
    next_receipt_counter: u64,
}

impl BlockVolumeFileImage {
    /// Return the raw file descriptor of the backing file for io_uring
    /// or other low-level I/O dispatch.
    #[must_use]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.file.as_raw_fd()
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::InvalidGeometry`] if the geometry record is invalid,
    /// [`BlockVolumeFileImageError::CapacityTooLarge`] if the computed capacity overflows `u64`,
    /// or [`BlockVolumeFileImageError::Io`] if the backing file cannot be created or truncated.
    pub fn create_zeroed(
        path: impl AsRef<Path>,
        geometry: BlockVolumeGeometryRecord,
    ) -> Result<Self, BlockVolumeFileImageError> {
        let capacity_bytes = file_image_capacity_bytes(geometry)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(capacity_bytes)?;
        Ok(Self::new(file, geometry))
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::InvalidGeometry`] if the geometry record is invalid,
    /// [`BlockVolumeFileImageError::CapacityTooLarge`] if the computed capacity overflows `u64`,
    /// [`BlockVolumeFileImageError::BackingLengthMismatch`] if the existing file length
    /// differs from the expected capacity, or [`BlockVolumeFileImageError::Io`] if
    /// the backing file cannot be opened or queried.
    pub fn reopen_existing(
        path: impl AsRef<Path>,
        geometry: BlockVolumeGeometryRecord,
    ) -> Result<Self, BlockVolumeFileImageError> {
        let expected_bytes = file_image_capacity_bytes(geometry)?;
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let actual_bytes = existing_backing_capacity_bytes(path, &file)?;
        if actual_bytes != expected_bytes {
            return Err(BlockVolumeFileImageError::BackingLengthMismatch {
                expected_bytes,
                actual_bytes,
            });
        }
        Ok(Self::new(file, geometry))
    }

    /// Reopen an existing backing file in read-only mode.
    ///
    /// Opens the file with read-only permissions; write/flush/discard
    /// operations will be rejected at the OS level. Suitable for
    /// read-only ublk export and snapshot-backed devices.
    pub fn reopen_read_only(
        path: impl AsRef<Path>,
        geometry: BlockVolumeGeometryRecord,
    ) -> Result<Self, BlockVolumeFileImageError> {
        let expected_bytes = file_image_capacity_bytes(geometry)?;
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(false).open(path)?;
        let actual_bytes = existing_backing_capacity_bytes(path, &file)?;
        if actual_bytes != expected_bytes {
            return Err(BlockVolumeFileImageError::BackingLengthMismatch {
                expected_bytes,
                actual_bytes,
            });
        }
        Ok(Self::new(file, geometry))
    }

    /// Resize the backing file to match `new_geometry`.
    ///
    /// Grow extends the file with zeros; shrink truncates the tail.
    /// Geometry is updated immediately so subsequent reads/writes see
    /// the new bounds.  No dirty-epoch or flush-barrier state is
    /// carried across the resize — callers must drain/fence first.
    ///
    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::InvalidGeometry`] if the
    /// geometry record is invalid,
    /// [`BlockVolumeFileImageError::CapacityTooLarge`] if the computed
    /// capacity overflows `u64`,
    /// or [`BlockVolumeFileImageError::Io`] if the backing file
    /// `set_len` fails.
    pub fn resize_to(
        &mut self,
        new_geometry: BlockVolumeGeometryRecord,
    ) -> Result<(), BlockVolumeFileImageError> {
        let new_cap = file_image_capacity_bytes(new_geometry)?;
        self.file
            .set_len(new_cap)
            .map_err(BlockVolumeFileImageError::Io)?;
        self.geometry = new_geometry;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::CapacityTooLarge`] if the block range start offset
    /// overflows `u64`, or [`BlockVolumeFileImageError::Io`] if the backing file read fails.
    pub fn read_blocks(
        &self,
        range: BlockRangeRecord,
    ) -> Result<(BlockVolumeRequestPlan, Option<Vec<u8>>), BlockVolumeFileImageError> {
        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return Ok((
                self.refusal_plan(
                    BlockVolumeRequestClass::Read,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                    Some(range),
                    0,
                ),
                None,
            ));
        };

        let mut payload = vec![0; byte_range.len()];
        self.file
            .read_exact_at(&mut payload, offset_u64(byte_range.start)?)?;
        Ok((
            self.completed_plan(BlockVolumeRequestClass::Read, Some(range), payload.len()),
            Some(payload),
        ))
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::CapacityTooLarge`] if the block range start offset
    /// overflows `u64`, or [`BlockVolumeFileImageError::Io`] if the backing file write fails.
    pub fn write_blocks(
        &mut self,
        start_block: usize,
        payload: &[u8],
    ) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        if payload.is_empty() || payload.len() % self.geometry.block_size_bytes != 0 {
            return Ok(self.refusal_plan(
                BlockVolumeRequestClass::Write,
                BlockVolumeCompletionClass::RefusedMisalignedRange,
                None,
                payload.len(),
            ));
        }
        let range =
            BlockRangeRecord::new(start_block, payload.len() / self.geometry.block_size_bytes);
        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return Ok(self.refusal_plan(
                BlockVolumeRequestClass::Write,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                Some(range),
                payload.len(),
            ));
        };

        self.file
            .write_all_at(payload, offset_u64(byte_range.start)?)?;
        let dirty_epoch_ref = self.record_dirty_epoch(range, payload.len());
        let mut plan =
            self.completed_plan(BlockVolumeRequestClass::Write, Some(range), payload.len());
        plan.dirty_epoch_ref = Some(dirty_epoch_ref);
        Ok(plan)
    }

    /// Write blocks with Force Unit Access-style durability.
    ///
    /// Completed writes are synced with `sync_data` before returning, then
    /// recorded as an already-satisfied durability barrier. Refused writes use
    /// the same admission checks as [`Self::write_blocks`] and do not sync or
    /// create durability receipts.
    ///
    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::CapacityTooLarge`] if the block range start offset
    /// overflows `u64`, or [`BlockVolumeFileImageError::Io`] if the backing file write or sync fails.
    pub fn write_blocks_fua(
        &mut self,
        start_block: usize,
        payload: &[u8],
    ) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        let mut plan = self.write_blocks(start_block, payload)?;
        if plan.completion_class != BlockVolumeCompletionClass::Completed {
            return Ok(plan);
        }

        self.file.sync_data()?;
        let Some(epoch_id) = plan.dirty_epoch_ref else {
            return Ok(plan);
        };
        for epoch in &mut self.dirty_epochs {
            if epoch.epoch_id == epoch_id {
                epoch.sealed_for_flush = true;
                break;
            }
        }

        let barrier_id = self.next_receipt();
        let durability_receipt_ref = self.receipt_for(epoch_id.0, 0xF0A5);
        self.flush_barriers.push(BlockVolumeFlushBarrierRecord {
            barrier_id,
            barrier_class: BlockVolumeFlushBarrierClass::Satisfied,
            covered_epoch_ids: vec![epoch_id],
            durability_receipt_ref,
        });
        plan.flush_barrier_ref = Some(barrier_id);
        Ok(plan)
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::Io`] if `sync_all` on the backing file fails.
    pub fn flush(&mut self) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        self.file.sync_all()?;
        let covered_epoch_ids: Vec<BlockVolumeReceiptId> = self
            .dirty_epochs
            .iter()
            .filter(|epoch| !epoch.sealed_for_flush && !epoch.invalidated_by_discard)
            .map(|epoch| epoch.epoch_id)
            .collect();
        if covered_epoch_ids.is_empty() {
            return Ok(self.completed_plan(BlockVolumeRequestClass::Flush, None, 0));
        }

        for epoch in &mut self.dirty_epochs {
            if covered_epoch_ids.contains(&epoch.epoch_id) {
                epoch.sealed_for_flush = true;
            }
        }
        let barrier_id = self.next_receipt();
        let durability_receipt_ref = self.receipt_for(covered_epoch_ids.len() as u64, 0xF1A5);
        self.flush_barriers.push(BlockVolumeFlushBarrierRecord {
            barrier_id,
            barrier_class: BlockVolumeFlushBarrierClass::Satisfied,
            covered_epoch_ids,
            durability_receipt_ref,
        });

        let mut plan = self.completed_plan(BlockVolumeRequestClass::Flush, None, 0);
        plan.flush_barrier_ref = Some(barrier_id);
        Ok(plan)
    }

    /// Whether the backing file supports hole-punching discard.
    ///
    /// Returns `true` when the geometry was configured with a non-zero
    /// `discard_granularity_blocks`. Actual hole-punching via `fallocate(2)`
    /// or `BLKDISCARD` ioctl is performed by the block-volume adapter daemon;
    /// this model implementation zero-fills the range.
    #[must_use]
    pub fn supports_discard(&self) -> bool {
        self.geometry.admits_discard()
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::CapacityTooLarge`] if the block range start offset
    /// overflows `u64`, or [`BlockVolumeFileImageError::Io`] if the backing file write fails.
    pub fn discard_blocks(
        &mut self,
        range: BlockRangeRecord,
    ) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        self.zero_or_discard_blocks(BlockVolumeRequestClass::Discard, range, true)
    }
    /// Issue a TRIM/DISCARD to the backing file in the given byte range.
    ///
    /// Punches a hole in the backing file via `fallocate(FALLOC_FL_PUNCH_HOLE)`,
    /// deallocating the underlying storage for the specified range. Falls back
    /// to zero-fill when `fallocate(2)` is unavailable (e.g. in CI containers
    /// without util-linux, or on non-Linux platforms).
    ///
    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::Io`] if the backing file hole-punch
    /// or zero-fill fallback fails.
    pub fn trim_range(&self, offset: u64, length: u64) -> Result<(), BlockVolumeFileImageError> {
        self.punch_hole_at(offset, length as usize)
    }

    /// # Errors
    ///
    /// Returns [`BlockVolumeFileImageError::CapacityTooLarge`] if the block range start offset
    /// overflows `u64`, or [`BlockVolumeFileImageError::Io`] if the backing file write fails.
    pub fn write_zeroes(
        &mut self,
        range: BlockRangeRecord,
    ) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        self.zero_or_discard_blocks(BlockVolumeRequestClass::WriteZeroes, range, false)
    }

    const fn new(file: File, geometry: BlockVolumeGeometryRecord) -> Self {
        Self {
            geometry,
            file,
            dirty_epochs: Vec::new(),
            flush_barriers: Vec::new(),
            discard_intents: Vec::new(),
            next_receipt_counter: 1,
        }
    }

    fn zero_or_discard_blocks(
        &mut self,
        request_class: BlockVolumeRequestClass,
        range: BlockRangeRecord,
        require_discard_granularity: bool,
    ) -> Result<BlockVolumeRequestPlan, BlockVolumeFileImageError> {
        if require_discard_granularity && !self.geometry.admits_discard() {
            return Ok(BlockVolumeRequestPlan {
                request_class,
                completion_class: BlockVolumeCompletionClass::RefusedDiscardUnsupported,
                range: Some(range),
                payload_len: 0,
                dirty_epoch_ref: None,
                flush_barrier_ref: None,
                discard_intent_ref: None,
                completion_receipt_ref: BlockVolumeReceiptId::default(),
            });
        }
        if range.block_count == 0
            || (require_discard_granularity
                && !range_aligned_to_granularity(range, self.geometry.discard_granularity_blocks))
        {
            return Ok(BlockVolumeRequestPlan {
                request_class,
                completion_class: BlockVolumeCompletionClass::RefusedMisalignedRange,
                range: Some(range),
                payload_len: 0,
                dirty_epoch_ref: None,
                flush_barrier_ref: None,
                discard_intent_ref: None,
                completion_receipt_ref: BlockVolumeReceiptId::default(),
            });
        }

        let Some(byte_range) = block_range_bytes(self.geometry, range) else {
            return Ok(self.refusal_plan(
                request_class,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
                Some(range),
                0,
            ));
        };

        match request_class {
            BlockVolumeRequestClass::Discard => {
                self.punch_hole_at(offset_u64(byte_range.start)?, byte_range.len())?
            }
            _ => self.write_zeroes_at(offset_u64(byte_range.start)?, byte_range.len())?,
        }
        let invalidated_epoch_ids = self.invalidate_overlapping_dirty_epochs(range);
        let intent_id = self.next_receipt();
        self.discard_intents.push(BlockVolumeDiscardIntentRecord {
            intent_id,
            range,
            invalidated_epoch_ids,
            zeroes_visible: true,
        });
        let dirty_epoch_ref = self.record_dirty_epoch(range, byte_range.len());

        let mut plan = self.completed_plan(request_class, Some(range), 0);
        plan.dirty_epoch_ref = Some(dirty_epoch_ref);
        plan.discard_intent_ref = Some(intent_id);
        Ok(plan)
    }

    fn write_zeroes_at(
        &self,
        mut offset: u64,
        mut len: usize,
    ) -> Result<(), BlockVolumeFileImageError> {
        const ZERO_CHUNK: [u8; 4096] = [0; 4096];
        while len > 0 {
            let chunk_len = len.min(ZERO_CHUNK.len());
            self.file.write_all_at(&ZERO_CHUNK[..chunk_len], offset)?;
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or(BlockVolumeFileImageError::CapacityTooLarge)?;
            len -= chunk_len;
        }
        Ok(())
    }

    /// Punch a hole in the backing file for discard operations.
    ///
    /// In this model implementation, delegates to [`Self::write_zeroes_at`] because
    /// the core crate forbids `unsafe` (required for the `libc::fallocate` FFI
    /// call). Production discard goes through the ublk control runtime which
    /// issues real `BLKDISCARD` ioctls or `fallocate` hole-punching.
    /// Punch a hole in the backing file for discard operations.
    ///
    /// Uses `fallocate(1)` with `--punch-hole` on Linux to actually
    /// deallocate blocks in the backing file. Falls back to zero-fill
    /// if the `fallocate` command is unavailable or fails.
    fn punch_hole_at(&self, offset: u64, len: usize) -> Result<(), BlockVolumeFileImageError> {
        // Use the fallocate(1) utility to punch a hole. This is safe
        // Rust and works on Linux with util-linux installed. Falls back
        // to zero-fill when fallocate is unavailable (e.g. in CI
        // containers without util-linux, or non-Linux platforms).
        use std::os::unix::io::AsRawFd;
        let fd_path = format!("/proc/self/fd/{}", self.file.as_raw_fd());
        match std::process::Command::new("fallocate")
            .args([
                "-p",
                "-o",
                &offset.to_string(),
                "-l",
                &len.to_string(),
                &fd_path,
            ])
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            _ => {
                // fallocate unavailable or failed; fall back to zero-fill.
                // Review debt TFR-012: replace with direct fallocate(2)
                // via nix or libc when the safety lint policy permits.
                self.write_zeroes_at(offset, len)
            }
        }
    }
    fn record_dirty_epoch(
        &mut self,
        range: BlockRangeRecord,
        dirty_bytes: usize,
    ) -> BlockVolumeReceiptId {
        let epoch_id = self.next_receipt();
        self.dirty_epochs.push(BlockVolumeDirtyRangeEpochRecord {
            epoch_id,
            range,
            dirty_bytes,
            sealed_for_flush: false,
            invalidated_by_discard: false,
        });
        epoch_id
    }

    fn invalidate_overlapping_dirty_epochs(
        &mut self,
        range: BlockRangeRecord,
    ) -> Vec<BlockVolumeReceiptId> {
        let mut invalidated = Vec::new();
        for epoch in &mut self.dirty_epochs {
            if !epoch.sealed_for_flush
                && !epoch.invalidated_by_discard
                && block_ranges_overlap(epoch.range, range)
            {
                epoch.invalidated_by_discard = true;
                invalidated.push(epoch.epoch_id);
            }
        }
        invalidated
    }

    const fn completed_plan(
        &self,
        request_class: BlockVolumeRequestClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
    ) -> BlockVolumeRequestPlan {
        BlockVolumeRequestPlan {
            request_class,
            completion_class: BlockVolumeCompletionClass::Completed,
            range,
            payload_len,
            dirty_epoch_ref: None,
            flush_barrier_ref: None,
            discard_intent_ref: None,
            completion_receipt_ref: self.receipt_for(payload_len as u64, request_class as u64),
        }
    }

    fn refusal_plan(
        &self,
        request_class: BlockVolumeRequestClass,
        completion_class: BlockVolumeCompletionClass,
        range: Option<BlockRangeRecord>,
        payload_len: usize,
    ) -> BlockVolumeRequestPlan {
        BlockVolumeRequestPlan {
            request_class,
            completion_class,
            range,
            payload_len,
            dirty_epoch_ref: None,
            flush_barrier_ref: None,
            discard_intent_ref: None,
            completion_receipt_ref: BlockVolumeReceiptId::default(),
        }
    }

    fn next_receipt(&mut self) -> BlockVolumeReceiptId {
        let receipt = self.receipt_for(self.next_receipt_counter, 0x301E);
        self.next_receipt_counter = self.next_receipt_counter.wrapping_add(1);
        receipt
    }

    const fn receipt_for(&self, left: u64, salt: u64) -> BlockVolumeReceiptId {
        receipt_for_volume(self.geometry.volume_id, left, salt)
    }
}

const fn queue_class_record(
    volume_id: BlockVolumeId,
    queue_class: BlockVolumeQueueClass,
) -> BlockVolumeQueueClassRecord {
    let (ordering_scope_class, blocking_class, worker_floor, worker_ceiling, salt) =
        match queue_class {
            BlockVolumeQueueClass::ReadFast => (
                BlockVolumeQueueOrderingScopeClass::Independent,
                BlockVolumeQueueBlockingClass::NonBlocking,
                1,
                4,
                0x1001,
            ),
            BlockVolumeQueueClass::OrderedMutation => (
                BlockVolumeQueueOrderingScopeClass::OverlapSerialized,
                BlockVolumeQueueBlockingClass::MayBlockForMutation,
                1,
                2,
                0x1002,
            ),
            BlockVolumeQueueClass::Barrier => (
                BlockVolumeQueueOrderingScopeClass::GlobalBarrier,
                BlockVolumeQueueBlockingClass::MustDrainBeforeCompletion,
                1,
                1,
                0x1003,
            ),
            BlockVolumeQueueClass::ZeroDiscard => (
                BlockVolumeQueueOrderingScopeClass::OverlapSerialized,
                BlockVolumeQueueBlockingClass::MayBlockForMutation,
                1,
                2,
                0x1004,
            ),
        };
    BlockVolumeQueueClassRecord {
        queue_class_id: receipt_for_volume(volume_id, queue_class as u64 + 1, salt),
        queue_class,
        ordering_scope_class,
        blocking_class,
        default_worker_floor: worker_floor,
        burst_worker_ceiling: worker_ceiling,
    }
}

const fn linux_status_code_for_completion(result_class: BlockVolumeCompletionClass) -> i32 {
    match result_class {
        BlockVolumeCompletionClass::Completed => 0,
        BlockVolumeCompletionClass::RefusedBackpressure => 11,
        BlockVolumeCompletionClass::RefusedOutOfBounds
        | BlockVolumeCompletionClass::RefusedMisalignedRange
        | BlockVolumeCompletionClass::RefusedDiscardUnsupported
        | BlockVolumeCompletionClass::RefusedPayloadMismatch => 22,
        BlockVolumeCompletionClass::RefusedUnadmittedContext => 2,
        BlockVolumeCompletionClass::RefusedExportFenced => 108,
    }
}

trait BlockVolumeRequestPlanExt {
    fn without_read_payload(self) -> (BlockVolumeRequestPlan, Option<Vec<u8>>);
}

impl BlockVolumeRequestPlanExt for BlockVolumeRequestPlan {
    fn without_read_payload(self) -> (BlockVolumeRequestPlan, Option<Vec<u8>>) {
        (self, None)
    }
}
// ---------------------------------------------------------------------------
// P6-04: Block device handle with lifecycle state gating and byte-level I/O dispatch
// ---------------------------------------------------------------------------

/// Lifecycle state for a block device handle.
///
/// Reads and writes are only admitted in [`BlockDeviceLifecycleState::Active`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockDeviceLifecycleState {
    /// Device is offline -- no I/O admitted.
    Offline,
    /// Device is opening -- transitions to [`Active`](Self::Active) when the
    /// backing store and control-plane handshake complete.
    Opening,
    /// Device is active -- reads and writes are admitted.
    Active,
    /// Device is closing -- no new I/O admitted; drain in progress.
    Closing,
    /// Device has reached a terminal offline state after drain completion.
    OfflineTerminal,
}

/// Trait abstracting the backing byte store that a [`BlockDeviceHandle`]
/// dispatches reads and writes against.
pub trait BlockDeviceBacking {
    /// Total capacity of the backing store in bytes.
    fn capacity_bytes(&self) -> u64;

    /// Read up to `buf.len()` bytes starting at `offset`.
    ///
    /// Returns the number of bytes actually read. A return value less than
    /// `buf.len()` signals a short read (e.g. at end-of-device).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying store fails.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Write all of `data` starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying store fails.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;

    /// Flush all buffered writes to durable storage.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying store fails.
    fn flush(&mut self) -> io::Result<()>;
}

/// A byte-level block-device handle that gates I/O dispatch on lifecycle
/// state and translates raw byte offsets into backing-store operations.
///
/// `B` is the backing store type that implements [`BlockDeviceBacking`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockDeviceHandle<B: BlockDeviceBacking> {
    /// Current lifecycle state.
    pub state: BlockDeviceLifecycleState,
    /// Backing byte store.
    pub backing: B,
}

impl<B: BlockDeviceBacking> BlockDeviceHandle<B> {
    /// Create a new handle wrapping `backing`, starting in [`Offline`](BlockDeviceLifecycleState::Offline).
    #[must_use]
    pub fn new(backing: B) -> Self {
        Self {
            state: BlockDeviceLifecycleState::Offline,
            backing,
        }
    }

    /// Transition from `Offline` to `Opening`.
    ///
    /// Returns `Ok(())` when the transition succeeded, or the current state
    /// if it is not a valid source for this transition.
    pub fn begin_open(&mut self) -> Result<(), BlockDeviceLifecycleState> {
        match self.state {
            BlockDeviceLifecycleState::Offline => {
                self.state = BlockDeviceLifecycleState::Opening;
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Transition from `Opening` to `Active`.
    ///
    /// Returns `Ok(())` when the transition succeeded, or the current state
    /// if it is not a valid source for this transition.
    pub fn complete_open(&mut self) -> Result<(), BlockDeviceLifecycleState> {
        match self.state {
            BlockDeviceLifecycleState::Opening => {
                self.state = BlockDeviceLifecycleState::Active;
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Transition from `Active` to `Closing`.
    ///
    /// Returns `Ok(())` when the transition succeeded, or the current state
    /// if it is not a valid source for this transition.
    pub fn begin_close(&mut self) -> Result<(), BlockDeviceLifecycleState> {
        match self.state {
            BlockDeviceLifecycleState::Active => {
                self.state = BlockDeviceLifecycleState::Closing;
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Transition from `Closing` to `OfflineTerminal`.
    ///
    /// Returns `Ok(())` when the transition succeeded, or the current state
    /// if it is not a valid source for this transition.
    pub fn complete_close(&mut self) -> Result<(), BlockDeviceLifecycleState> {
        match self.state {
            BlockDeviceLifecycleState::Closing => {
                self.state = BlockDeviceLifecycleState::OfflineTerminal;
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Dispatch a read from the backing store at `offset`, copying up to
    /// `buf.len()` bytes into `buf`.
    ///
    /// Returns the number of bytes actually read. A return value less than
    /// `buf.len()` indicates a short read at end-of-device.
    ///
    /// # Errors
    ///
    /// Returns a [`BlockDeviceDispatchError`] if the device is not
    /// [`Active`](BlockDeviceLifecycleState::Active), or an I/O error from
    /// the backing store.
    pub fn dispatch_read(
        &self,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, BlockDeviceDispatchError> {
        self.check_active()?;

        let cap = self.backing.capacity_bytes();
        if offset >= cap {
            return Ok(0);
        }

        let max_readable = cap.saturating_sub(offset);
        let effective_len = (buf.len() as u64).min(max_readable) as usize;
        let read_buf = &mut buf[..effective_len];

        self.backing
            .read_at(offset, read_buf)
            .map_err(BlockDeviceDispatchError::Io)
    }

    /// Dispatch a write to the backing store at `offset` with `data`.
    ///
    /// # Errors
    ///
    /// Returns [`BlockDeviceDispatchError::OutOfBounds`] if `offset +
    /// data.len()` exceeds the backing store capacity.
    ///
    /// Returns [`BlockDeviceDispatchError::StateViolation`] if the device is
    /// not [`Active`](BlockDeviceLifecycleState::Active).
    ///
    /// Returns an I/O error from the backing store on failure.
    pub fn dispatch_write(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<(), BlockDeviceDispatchError> {
        self.check_active()?;

        let cap = self.backing.capacity_bytes();
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(BlockDeviceDispatchError::OutOfBounds)?;
        if end > cap {
            return Err(BlockDeviceDispatchError::OutOfBounds);
        }

        self.backing
            .write_at(offset, data)
            .map_err(BlockDeviceDispatchError::Io)
    }

    /// Flush all buffered writes to durable storage.
    ///
    /// # Errors
    ///
    /// Returns a [`BlockDeviceDispatchError`] if the device is not
    /// [`Active`](BlockDeviceLifecycleState::Active), or an I/O error from
    /// the backing store.
    pub fn dispatch_flush(&mut self) -> Result<(), BlockDeviceDispatchError> {
        self.check_active()?;
        self.backing.flush().map_err(BlockDeviceDispatchError::Io)
    }

    fn check_active(&self) -> Result<(), BlockDeviceDispatchError> {
        match self.state {
            BlockDeviceLifecycleState::Active => Ok(()),
            other => Err(BlockDeviceDispatchError::StateViolation(other)),
        }
    }
}

/// Errors returned by [`BlockDeviceHandle::dispatch_read`] and
/// [`BlockDeviceHandle::dispatch_write`].
#[derive(Debug)]
pub enum BlockDeviceDispatchError {
    /// The device lifecycle state does not permit I/O.
    StateViolation(BlockDeviceLifecycleState),
    /// The write would extend beyond the device capacity.
    OutOfBounds,
    /// An I/O error from the backing store.
    Io(io::Error),
}

impl fmt::Display for BlockDeviceDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateViolation(state) => {
                write!(f, "device not active: current state is {state:?}")
            }
            Self::OutOfBounds => write!(f, "write exceeds device capacity"),
            Self::Io(err) => write!(f, "backing store I/O error: {err}"),
        }
    }
}

impl Error for BlockDeviceDispatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::StateViolation(_) | Self::OutOfBounds => None,
        }
    }
}

impl From<io::Error> for BlockDeviceDispatchError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

// ---------------------------------------------------------------------------
// BlockDeviceBacking impl for BlockVolumeImage (in-memory)
// ---------------------------------------------------------------------------

impl BlockDeviceBacking for BlockVolumeImage {
    fn capacity_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        if off >= self.bytes.len() {
            return Ok(0);
        }
        let available = self.bytes.len() - off;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.bytes[off..off + n]);
        Ok(n)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let off = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let end = off
            .checked_add(data.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset + len overflow"))?;
        if end > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write exceeds capacity",
            ));
        }
        self.bytes[off..end].copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        // In-memory backing: no durable storage to flush.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlockDeviceBacking impl for BlockVolumeFileImage (file-backed)
// ---------------------------------------------------------------------------

impl BlockDeviceBacking for BlockVolumeFileImage {
    fn capacity_bytes(&self) -> u64 {
        let block_size = self.geometry.block_size_bytes as u64;
        let block_count = self.geometry.block_count as u64;
        block_size.saturating_mul(block_count)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file_ref().read_at(buf, offset)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.file_ref().write_all_at(data, offset)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_ref().sync_all()
    }
}

impl BlockVolumeFileImage {
    /// Obtain a reference to the private backing [`File`].
    fn file_ref(&self) -> &File {
        &self.file
    }
}

fn remove_one<T: Eq>(items: &mut Vec<T>, needle: T) {
    if let Some(position) = items.iter().position(|item| item == &needle) {
        items.remove(position);
    }
}

const fn receipt_for_volume(
    volume_id: BlockVolumeId,
    left: u64,
    salt: u64,
) -> BlockVolumeReceiptId {
    BlockVolumeReceiptId(
        volume_id.0.wrapping_mul(0x9E37_79B1_85EB_CA87)
            ^ left.rotate_left(13)
            ^ salt.wrapping_mul(0xC2B2_AE3D_27D4_EB4F),
    )
}

fn file_image_capacity_bytes(
    geometry: BlockVolumeGeometryRecord,
) -> Result<u64, BlockVolumeFileImageError> {
    if geometry.block_size_bytes == 0 || geometry.block_count == 0 {
        return Err(BlockVolumeFileImageError::InvalidGeometry);
    }
    let capacity = geometry
        .capacity_bytes()
        .ok_or(BlockVolumeFileImageError::CapacityTooLarge)?;
    u64::try_from(capacity).map_err(|_| BlockVolumeFileImageError::CapacityTooLarge)
}

fn existing_backing_capacity_bytes(
    path: &Path,
    file: &File,
) -> Result<u64, BlockVolumeFileImageError> {
    let metadata = file.metadata()?;
    if metadata.file_type().is_block_device() {
        return block_device_capacity_bytes(path, &metadata).map_err(BlockVolumeFileImageError::Io);
    }
    Ok(metadata.len())
}

#[cfg(target_os = "linux")]
fn block_device_capacity_bytes(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<u64, io::Error> {
    let major = linux_dev_major(metadata.rdev());
    let minor = linux_dev_minor(metadata.rdev());
    let size_path = Path::new("/sys/dev/block")
        .join(format!("{major}:{minor}"))
        .join("size");
    let sectors = std::fs::read_to_string(&size_path)
        .and_then(|raw| {
            raw.trim().parse::<u64>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse {}: {err}", size_path.display()),
                )
            })
        })
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("read block device capacity for {}: {err}", path.display()),
            )
        })?;
    sectors.checked_mul(512).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("block device capacity overflows u64 for {}", path.display()),
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn block_device_capacity_bytes(
    _path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<u64, io::Error> {
    Ok(metadata.len())
}

#[cfg(target_os = "linux")]
const fn linux_dev_major(dev: u64) -> u64 {
    ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fff)
}

#[cfg(target_os = "linux")]
const fn linux_dev_minor(dev: u64) -> u64 {
    (dev & 0x00ff) | ((dev >> 12) & !0x00ff)
}

fn offset_u64(offset: usize) -> Result<u64, BlockVolumeFileImageError> {
    u64::try_from(offset).map_err(|_| BlockVolumeFileImageError::CapacityTooLarge)
}

fn block_range_bytes(
    geometry: BlockVolumeGeometryRecord,
    range: BlockRangeRecord,
) -> Option<Range<usize>> {
    if range.block_count == 0 {
        return None;
    }
    let end_block = range.start_block.checked_add(range.block_count)?;
    if end_block > geometry.block_count {
        return None;
    }
    let start = range.start_block.checked_mul(geometry.block_size_bytes)?;
    let len = range.block_count.checked_mul(geometry.block_size_bytes)?;
    Some(start..start.checked_add(len)?)
}

const fn read_write_bounds_completed_plan(
    geometry: BlockVolumeGeometryRecord,
    request_class: BlockVolumeRequestClass,
    range: Option<BlockRangeRecord>,
    payload_len: usize,
) -> BlockVolumeRequestPlan {
    BlockVolumeRequestPlan {
        request_class,
        completion_class: BlockVolumeCompletionClass::Completed,
        range,
        payload_len,
        dirty_epoch_ref: None,
        flush_barrier_ref: None,
        discard_intent_ref: None,
        completion_receipt_ref: receipt_for_volume(
            geometry.volume_id,
            payload_len as u64,
            request_class as u64,
        ),
    }
}

const fn read_write_bounds_refusal_plan(
    request_class: BlockVolumeRequestClass,
    completion_class: BlockVolumeCompletionClass,
    range: Option<BlockRangeRecord>,
    byte_len: usize,
) -> BlockVolumeRequestPlan {
    let payload_len = match request_class {
        BlockVolumeRequestClass::Write => byte_len,
        _ => 0,
    };
    BlockVolumeRequestPlan {
        request_class,
        completion_class,
        range,
        payload_len,
        dirty_epoch_ref: None,
        flush_barrier_ref: None,
        discard_intent_ref: None,
        completion_receipt_ref: BlockVolumeReceiptId(0),
    }
}

const fn discard_bounds_completed_plan(
    geometry: BlockVolumeGeometryRecord,
    request_class: BlockVolumeRequestClass,
    range: Option<BlockRangeRecord>,
) -> BlockVolumeRequestPlan {
    BlockVolumeRequestPlan {
        request_class,
        completion_class: BlockVolumeCompletionClass::Completed,
        range,
        payload_len: 0,
        dirty_epoch_ref: None,
        flush_barrier_ref: None,
        discard_intent_ref: None,
        completion_receipt_ref: receipt_for_volume(geometry.volume_id, 0, request_class as u64),
    }
}

const fn discard_bounds_refusal_plan(
    request_class: BlockVolumeRequestClass,
    completion_class: BlockVolumeCompletionClass,
    range: Option<BlockRangeRecord>,
) -> BlockVolumeRequestPlan {
    BlockVolumeRequestPlan {
        request_class,
        completion_class,
        range,
        payload_len: 0,
        dirty_epoch_ref: None,
        flush_barrier_ref: None,
        discard_intent_ref: None,
        completion_receipt_ref: BlockVolumeReceiptId(0),
    }
}

const fn range_aligned_to_granularity(range: BlockRangeRecord, granularity_blocks: usize) -> bool {
    granularity_blocks > 0
        && range.start_block % granularity_blocks == 0
        && range.block_count % granularity_blocks == 0
}

const fn block_ranges_overlap(left: BlockRangeRecord, right: BlockRangeRecord) -> bool {
    let left_end = left.start_block.saturating_add(left.block_count);
    let right_end = right.start_block.saturating_add(right.block_count);
    left.start_block < right_end && right.start_block < left_end
}

const fn block_range_contains(outer: BlockRangeRecord, inner: BlockRangeRecord) -> bool {
    let outer_end = outer.start_block.saturating_add(outer.block_count);
    let inner_end = inner.start_block.saturating_add(inner.block_count);
    inner.block_count > 0 && outer.start_block <= inner.start_block && inner_end <= outer_end
}

const fn resize_direction(
    current_block_count: usize,
    target_block_count: usize,
) -> Option<BlockVolumeResizeDirectionClass> {
    if target_block_count > current_block_count {
        Some(BlockVolumeResizeDirectionClass::Grow)
    } else if target_block_count < current_block_count && target_block_count > 0 {
        Some(BlockVolumeResizeDirectionClass::Shrink)
    } else {
        None
    }
}

fn resize_tail_range(
    current_block_count: usize,
    target_block_count: usize,
    direction_class: BlockVolumeResizeDirectionClass,
) -> Option<BlockRangeRecord> {
    match direction_class {
        BlockVolumeResizeDirectionClass::Grow => Some(BlockRangeRecord::new(
            current_block_count,
            target_block_count.checked_sub(current_block_count)?,
        )),
        BlockVolumeResizeDirectionClass::Shrink => Some(BlockRangeRecord::new(
            target_block_count,
            current_block_count.checked_sub(target_block_count)?,
        )),
    }
}

// ── Volume trait ─────────────────────────────────────────────────────

/// Trait for block-volume backends that serve read, write, flush, discard,
/// and write-zeroes commands from a ublk target device.
///
/// Implementations forward I/O to the concrete storage layer (file image,
/// object store, etc.). The trait is purpose-built for the ublk IO command
/// handler and keeps the contract narrow: sector-aligned ranges, no scatter-
/// gather, and explicit completion classification.
pub trait Volume {
    /// Geometry of the block volume this backend serves.
    fn geometry(&self) -> BlockVolumeGeometryRecord;

    /// Read `count_or_zones` sectors starting at `start_sector` into `buf`.
    ///
    /// `buf.len()` must be at least `count_or_zones * sector_size`.
    /// Returns the number of bytes read. Unwritten regions return zeroes.
    fn read_sectors(
        &self,
        start_sector: u64,
        count_or_zones: u32,
        buf: &mut [u8],
    ) -> io::Result<usize>;

    /// Write `data` to `count_or_zones` sectors starting at `start_sector`.
    ///
    /// `data.len()` must equal `count_or_zones * sector_size`.
    fn write_sectors(
        &mut self,
        start_sector: u64,
        count_or_zones: u32,
        data: &[u8],
    ) -> io::Result<()>;

    /// Flush all pending writes to durable storage.
    ///
    /// For local-object-store backends this issues a sync that commits
    /// the current commit_group, drains the intent log, and persists the committed
    /// root.
    fn flush(&mut self) -> io::Result<()>;

    /// Discard `count_or_zones` sectors starting at `start_sector`.
    ///
    /// May be a no-op for backends that do not support hole-punching;
    /// returning `Ok(())` is a conservative safe default.
    fn discard_sectors(&mut self, start_sector: u64, count_or_zones: u32) -> io::Result<()>;

    /// Write zeroes to `count_or_zones` sectors starting at `start_sector`.
    fn write_zeroes_sectors(&mut self, start_sector: u64, count_or_zones: u32) -> io::Result<()>;
}

/// Gate label for the Volume trait surface.
pub const VOLUME_TRAIT_GATE_OW_301V: &str =
    "OW-301V Volume trait provides read/write/flush/discard/write-zeroes sector-level dispatch for ublk IO command serving";

/// Sector size used for all Volume trait operations (Linux standard).
pub const VOLUME_SECTOR_SIZE: u64 = 512;

/// Convert a sector count to a byte count using the standard sector size.
#[inline]
pub const fn sectors_to_bytes(sectors: u32) -> usize {
    (sectors as u64).saturating_mul(VOLUME_SECTOR_SIZE) as usize
}

/// Error returned when a Volume operation is refused due to invalid geometry
/// or out-of-bounds range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeError {
    OutOfBounds,
    UnsupportedOperation,
    IoError,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> BlockVolumeImage {
        BlockVolumeImage::open_zeroed(BlockVolumeGeometryRecord::new(
            BlockVolumeId::new(44),
            4,
            8,
            2,
        ))
        .expect("valid image")
    }

    struct FileImagePath {
        path: std::path::PathBuf,
    }

    impl FileImagePath {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "tidefs-block-volume-file-image-{name}-{}.img",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self { path }
        }
    }

    impl Drop for FileImagePath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    const fn file_geometry() -> BlockVolumeGeometryRecord {
        BlockVolumeGeometryRecord::new(BlockVolumeId::new(95), 4, 8, 2)
    }

    fn queue_runtime() -> BlockVolumeQueueRuntime {
        BlockVolumeQueueRuntime::open(
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(71), 4, 16, 2),
            4,
            4,
            32,
        )
        .expect("valid queue runtime")
    }

    fn dispatch_runtime() -> BlockVolumeQueueRuntime {
        BlockVolumeQueueRuntime::open(
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2),
            2,
            8,
            64,
        )
        .expect("valid dispatch runtime")
    }

    fn lifecycle_runtime() -> BlockVolumeExportLifecycleRuntime {
        BlockVolumeExportLifecycleRuntime::bootstrap(
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(80), 4, 16, 2),
            4,
            8,
            64,
        )
        .expect("valid lifecycle runtime")
    }

    const fn cache_runtime() -> BlockVolumeCacheCoherencyRuntime {
        BlockVolumeCacheCoherencyRuntime::open(BlockVolumeId::new(83))
    }

    fn resize_runtime() -> BlockVolumeResizeFenceRuntime {
        BlockVolumeResizeFenceRuntime::open(
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(87), 4, 16, 2),
            4,
            8,
            64,
        )
        .expect("valid resize runtime")
    }

    fn fenced_resize_runtime() -> BlockVolumeResizeFenceRuntime {
        let mut runtime = resize_runtime();
        runtime.lifecycle_runtime.admit_export();
        runtime.lifecycle_runtime.start_queues();
        runtime
            .lifecycle_runtime
            .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
        runtime.lifecycle_runtime.fence_after_drain();
        runtime
    }

    #[test]
    fn read_write_round_trips_exact_blocks() {
        let mut image = image();
        let payload = vec![0xAB; 8];

        let write = image.write_blocks(2, &payload);
        let (read, bytes) = image.read_blocks(BlockRangeRecord::new(2, 2));

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(write.dirty_epoch_ref.is_some());
        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(bytes.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn read_write_bounds_plan_maps_aligned_byte_ranges() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2);

        let read = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Read, 8, 12);
        let write = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Write, 4, 8);

        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(read.range, Some(BlockRangeRecord::new(2, 3)));
        assert_eq!(read.payload_len, 12);
        assert_ne!(read.completion_receipt_ref, BlockVolumeReceiptId::default());
        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(write.range, Some(BlockRangeRecord::new(1, 2)));
        assert_eq!(write.payload_len, 8);
    }

    #[test]
    fn read_write_bounds_plan_completes_zero_length_at_capacity_edge() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2);

        let read = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Read, 32, 0);
        let write = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Write, 32, 0);

        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(read.range, None);
        assert_eq!(read.payload_len, 0);
        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(write.range, None);
        assert_eq!(write.payload_len, 0);
    }

    #[test]
    fn read_write_bounds_plan_refuses_zero_length_past_capacity_or_overflow() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2);
        let overflowing = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), usize::MAX, 2, 0);

        let past_end =
            plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Read, 36, 0);
        let overflow =
            plan_read_write_request_bounds(overflowing, BlockVolumeRequestClass::Write, 0, 0);

        assert_eq!(
            past_end.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(past_end.range, None);
        assert_eq!(past_end.payload_len, 0);
        assert_eq!(
            past_end.completion_receipt_ref,
            BlockVolumeReceiptId::default()
        );
        assert_eq!(
            overflow.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(overflow.range, None);
        assert_eq!(overflow.payload_len, 0);
    }

    #[test]
    fn read_write_bounds_plan_refuses_misaligned_requests() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2);

        let read = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Read, 1, 4);
        let write = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Write, 4, 3);

        assert_eq!(
            read.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(read.range, None);
        assert_eq!(read.payload_len, 0);
        assert_eq!(read.completion_receipt_ref, BlockVolumeReceiptId::default());
        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(write.range, None);
        assert_eq!(write.payload_len, 3);
        assert_eq!(
            write.completion_receipt_ref,
            BlockVolumeReceiptId::default()
        );
    }

    #[test]
    fn read_write_bounds_plan_enforces_capacity_boundary() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), 4, 8, 2);

        let at_end = plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Read, 28, 4);
        let past_end =
            plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Write, 28, 8);

        assert_eq!(
            at_end.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(at_end.range, Some(BlockRangeRecord::new(7, 1)));
        assert_eq!(
            past_end.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(past_end.range, Some(BlockRangeRecord::new(7, 2)));
        assert_eq!(past_end.payload_len, 8);
    }

    #[test]
    fn read_write_bounds_plan_refuses_overflowing_byte_ranges() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(44), usize::MAX, 2, 0);

        let write = plan_read_write_request_bounds(
            geometry,
            BlockVolumeRequestClass::Write,
            usize::MAX,
            usize::MAX,
        );

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(write.range, Some(BlockRangeRecord::new(1, 1)));
        assert_eq!(write.payload_len, usize::MAX);
        assert_eq!(
            write.completion_receipt_ref,
            BlockVolumeReceiptId::default()
        );
    }

    #[test]
    fn discard_bounds_plan_maps_aligned_byte_ranges() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), 4, 16, 2);

        let discard =
            plan_discard_request_bounds(geometry, BlockVolumeRequestClass::Discard, 8, 16);
        let write_zeroes =
            plan_discard_request_bounds(geometry, BlockVolumeRequestClass::WriteZeroes, 4, 12);

        assert_eq!(
            discard.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(discard.range, Some(BlockRangeRecord::new(2, 4)));
        assert_eq!(discard.payload_len, 0);
        assert_ne!(
            discard.completion_receipt_ref,
            BlockVolumeReceiptId::default()
        );
        assert_eq!(
            write_zeroes.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(write_zeroes.range, Some(BlockRangeRecord::new(1, 3)));
    }

    #[test]
    fn discard_bounds_plan_completes_zero_length_at_capacity_edge() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), 4, 16, 2);

        let discard =
            plan_discard_request_bounds(geometry, BlockVolumeRequestClass::Discard, 64, 0);

        assert_eq!(
            discard.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(discard.range, None);
        assert_eq!(discard.payload_len, 0);
        assert_ne!(
            discard.completion_receipt_ref,
            BlockVolumeReceiptId::default()
        );
    }

    #[test]
    fn discard_bounds_plan_refuses_unsupported_or_misaligned_ranges() {
        let unsupported = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), 4, 16, 0);
        let aligned = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), 4, 16, 2);

        let no_discard =
            plan_discard_request_bounds(unsupported, BlockVolumeRequestClass::Discard, 8, 8);
        let byte_misaligned =
            plan_discard_request_bounds(aligned, BlockVolumeRequestClass::Discard, 2, 8);
        let granularity_misaligned =
            plan_discard_request_bounds(aligned, BlockVolumeRequestClass::Discard, 8, 12);

        assert_eq!(
            no_discard.completion_class,
            BlockVolumeCompletionClass::RefusedDiscardUnsupported
        );
        assert_eq!(no_discard.range, Some(BlockRangeRecord::new(2, 2)));
        assert_eq!(
            byte_misaligned.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(byte_misaligned.range, None);
        assert_eq!(
            granularity_misaligned.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(
            granularity_misaligned.range,
            Some(BlockRangeRecord::new(2, 3))
        );
    }

    #[test]
    fn discard_bounds_plan_enforces_capacity_and_overflow_boundary() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), 4, 16, 1);
        let overflowing = BlockVolumeGeometryRecord::new(BlockVolumeId::new(45), usize::MAX, 2, 1);

        let at_end = plan_discard_request_bounds(geometry, BlockVolumeRequestClass::Discard, 60, 4);
        let past_end =
            plan_discard_request_bounds(geometry, BlockVolumeRequestClass::Discard, 60, 8);
        let overflow = plan_discard_request_bounds(
            overflowing,
            BlockVolumeRequestClass::Discard,
            usize::MAX,
            usize::MAX,
        );
        let zero_len_overflow =
            plan_discard_request_bounds(overflowing, BlockVolumeRequestClass::Discard, 0, 0);

        assert_eq!(
            at_end.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(at_end.range, Some(BlockRangeRecord::new(15, 1)));
        assert_eq!(
            past_end.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(past_end.range, Some(BlockRangeRecord::new(15, 2)));
        assert_eq!(
            overflow.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(overflow.range, Some(BlockRangeRecord::new(1, 1)));
        assert_eq!(
            zero_len_overflow.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(zero_len_overflow.range, None);
    }

    #[test]
    fn flush_seals_dirty_epoch_and_records_barrier() {
        let mut image = image();
        let write = image.write_blocks(1, &[1, 2, 3, 4]);

        let flush = image.flush();

        assert_eq!(
            flush.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(flush.flush_barrier_ref.is_some());
        assert_eq!(image.flush_barriers.len(), 1);
        assert_eq!(
            image.flush_barriers[0].covered_epoch_ids,
            vec![write.dirty_epoch_ref.expect("dirty epoch")]
        );
        assert_eq!(
            image.flush_barriers[0].barrier_class,
            BlockVolumeFlushBarrierClass::Satisfied
        );
        assert!(image.dirty_epochs[0].sealed_for_flush);
    }

    #[test]
    fn discard_zeroes_range_and_invalidates_dirty_epoch() {
        let mut image = image();
        let write = image.write_blocks(0, &[9; 16]);

        let discard = image.discard_blocks(BlockRangeRecord::new(2, 2));
        let (_, bytes) = image.read_blocks(BlockRangeRecord::new(2, 2));

        assert_eq!(
            discard.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(bytes.as_deref(), Some([0; 8].as_slice()));
        assert_eq!(image.discard_intents.len(), 1);
        assert_eq!(
            image.discard_intents[0].invalidated_epoch_ids,
            vec![write.dirty_epoch_ref.expect("dirty epoch")]
        );
        assert!(image.discard_intents[0].zeroes_visible);
        assert!(image.dirty_epochs[0].invalidated_by_discard);
    }

    #[test]
    fn misaligned_write_is_refused_without_mutation() {
        let mut image = image();

        let write = image.write_blocks(1, &[1, 2, 3]);
        let (_, bytes) = image.read_blocks(BlockRangeRecord::new(1, 1));

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert!(write.dirty_epoch_ref.is_none());
        assert!(image.dirty_epochs.is_empty());
        assert_eq!(bytes.as_deref(), Some([0; 4].as_slice()));
    }

    #[test]
    fn out_of_bounds_read_is_refused() {
        let image = image();

        let (read, bytes) = image.read_blocks(BlockRangeRecord::new(7, 2));

        assert_eq!(
            read.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert!(bytes.is_none());
        assert_eq!(read.completion_receipt_ref, BlockVolumeReceiptId::default());
    }

    #[test]
    fn discard_alignment_is_enforced() {
        let mut image = image();

        let discard = image.discard_blocks(BlockRangeRecord::new(1, 1));

        assert_eq!(
            discard.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert!(image.discard_intents.is_empty());
    }

    #[test]
    fn file_backed_image_flush_reopen_round_trips_exact_blocks() {
        let path = FileImagePath::new("flush-reopen");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");
        let payload = vec![0xA5; 8];

        let write = image.write_blocks(2, &payload).expect("write file image");
        let flush = image.flush().expect("flush file image");
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(&path.path, geometry).expect("reopen image");
        let (read, bytes) = reopened
            .read_blocks(BlockRangeRecord::new(2, 2))
            .expect("read reopened image");

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(write.dirty_epoch_ref.is_some());
        assert_eq!(
            flush.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(flush.flush_barrier_ref.is_some());
        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(bytes.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn file_backed_image_fua_write_reopen_round_trips_without_explicit_flush() {
        let path = FileImagePath::new("fua-reopen");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");
        let payload = vec![0xF5; 8];

        let write = image
            .write_blocks_fua(2, &payload)
            .expect("write fua file image");
        let write_epoch = write.dirty_epoch_ref.expect("dirty epoch");
        let write_barrier = write.flush_barrier_ref.expect("fua barrier");

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(image.flush_barriers.len(), 1);
        assert_eq!(image.flush_barriers[0].barrier_id, write_barrier);
        assert_eq!(image.flush_barriers[0].covered_epoch_ids, vec![write_epoch]);
        assert!(image
            .dirty_epochs
            .iter()
            .any(|epoch| epoch.epoch_id == write_epoch && epoch.sealed_for_flush));
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(&path.path, geometry).expect("reopen image");
        let (read, bytes) = reopened
            .read_blocks(BlockRangeRecord::new(2, 2))
            .expect("read reopened image");

        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(bytes.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn file_backed_image_fua_write_makes_deferred_flush_clean() {
        let path = FileImagePath::new("fua-clean-flush");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");

        let write = image
            .write_blocks_fua(1, &[0x9B; 4])
            .expect("write fua file image");
        let flush = image.flush().expect("flush after fua");

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(write.flush_barrier_ref.is_some());
        assert_eq!(
            flush.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(flush.flush_barrier_ref.is_none());
        assert_eq!(image.flush_barriers.len(), 1);
    }

    #[test]
    fn file_backed_image_fua_refusal_does_not_record_durability_barrier() {
        let path = FileImagePath::new("fua-refusal");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");

        let write = image
            .write_blocks_fua(1, &[0xA1; 3])
            .expect("misaligned fua write");

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert!(write.dirty_epoch_ref.is_none());
        assert!(write.flush_barrier_ref.is_none());
        assert!(image.dirty_epochs.is_empty());
        assert!(image.flush_barriers.is_empty());
    }

    #[test]
    fn file_backed_image_discard_and_write_zeroes_are_zero_visible() {
        let path = FileImagePath::new("discard-zeroes");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");
        let payload = vec![0x7D; 16];

        image.write_blocks(0, &payload).expect("write file image");
        let discard = image
            .discard_blocks(BlockRangeRecord::new(0, 2))
            .expect("discard file image");
        let write_zeroes = image
            .write_zeroes(BlockRangeRecord::new(2, 2))
            .expect("write zeroes file image");
        let (read, bytes) = image
            .read_blocks(BlockRangeRecord::new(0, 4))
            .expect("read zeroed image");
        let expected_zeroes = vec![0; 16];

        assert_eq!(
            discard.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(
            write_zeroes.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(image.discard_intents.len(), 2);
        assert!(image
            .dirty_epochs
            .iter()
            .any(|epoch| epoch.invalidated_by_discard));
        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(bytes.as_deref(), Some(expected_zeroes.as_slice()));
    }

    #[test]
    fn file_backed_image_refuses_bad_ranges_without_backing_mutation() {
        let path = FileImagePath::new("refusal-no-mutation");
        let geometry = file_geometry();
        let mut image =
            BlockVolumeFileImage::create_zeroed(&path.path, geometry).expect("create image");

        let misaligned = image.write_blocks(1, &[1, 2, 3]).expect("misaligned write");
        let (out_of_bounds_read, missing_payload) = image
            .read_blocks(BlockRangeRecord::new(7, 2))
            .expect("out of bounds read");
        let (read, bytes) = image
            .read_blocks(BlockRangeRecord::new(0, 8))
            .expect("read whole image");
        let expected_zeroes = vec![0; 32];

        assert_eq!(
            misaligned.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(
            out_of_bounds_read.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert!(missing_payload.is_none());
        assert_eq!(read.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(bytes.as_deref(), Some(expected_zeroes.as_slice()));
    }

    #[test]
    fn file_backed_image_reopen_refuses_length_mismatch() {
        let path = FileImagePath::new("length-mismatch");
        let geometry = file_geometry();
        std::fs::write(&path.path, [0xEF; 3]).expect("write short image");

        let err = BlockVolumeFileImage::reopen_existing(&path.path, geometry)
            .expect_err("length mismatch");

        match err {
            BlockVolumeFileImageError::BackingLengthMismatch {
                expected_bytes,
                actual_bytes,
            } => {
                assert_eq!(expected_bytes, 32);
                assert_eq!(actual_bytes, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn file_backed_image_refuses_invalid_geometry() {
        let path = FileImagePath::new("invalid-geometry");
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(95), 0, 8, 2);

        let err = BlockVolumeFileImage::create_zeroed(&path.path, geometry)
            .expect_err("invalid geometry");

        assert!(matches!(err, BlockVolumeFileImageError::InvalidGeometry));
        assert!(!path.path.exists());
    }

    #[test]
    fn queue_classification_binds_read_and_write_to_expected_classes() {
        let runtime = queue_runtime();

        let read = runtime.classify_request(
            BlockVolumeRequestClass::Read,
            BlockVolumeDurabilityClass::None,
        );
        let write = runtime.classify_request(
            BlockVolumeRequestClass::Write,
            BlockVolumeDurabilityClass::FuaRequired,
        );
        let flush = runtime.classify_request(
            BlockVolumeRequestClass::Flush,
            BlockVolumeDurabilityClass::FlushRequired,
        );

        assert_eq!(read.queue_class, BlockVolumeQueueClass::ReadFast);
        assert_eq!(
            read.ordering_scope_class,
            BlockVolumeQueueOrderingScopeClass::Independent
        );
        assert_eq!(write.queue_class, BlockVolumeQueueClass::OrderedMutation);
        assert_eq!(
            write.blocking_class,
            BlockVolumeQueueBlockingClass::MustDrainBeforeCompletion
        );
        assert_eq!(flush.queue_class, BlockVolumeQueueClass::Barrier);
        assert_eq!(
            flush.ordering_scope_class,
            BlockVolumeQueueOrderingScopeClass::GlobalBarrier
        );
    }

    #[test]
    fn overlapping_mutations_share_a_queue_shard_for_serialization() {
        let mut runtime = queue_runtime();
        let left = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(3, 3)),
                12,
                BlockVolumeDurabilityClass::None,
            )
            .expect("left context");
        let right = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Discard,
                Some(BlockRangeRecord::new(5, 3)),
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("right context");

        let shared = left
            .queue_shard_refs
            .iter()
            .any(|left_ref| right.queue_shard_refs.contains(left_ref));
        let left_admit = runtime.admit_submission_context(left.clone());
        let right_admit = runtime.admit_submission_context(right.clone());

        assert!(shared);
        assert_eq!(
            left_admit.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert_eq!(
            right_admit.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let shared_shard_ref = left
            .queue_shard_refs
            .iter()
            .find(|left_ref| right.queue_shard_refs.contains(left_ref))
            .copied()
            .expect("shared shard ref");
        let shared_shard = runtime
            .shards
            .iter()
            .find(|shard| shard.queue_shard_id == shared_shard_ref)
            .expect("shared shard");
        assert!(shared_shard.ordered_ranges.contains(&left.range.unwrap()));
        assert!(shared_shard.ordered_ranges.contains(&right.range.unwrap()));
    }

    #[test]
    fn backpressure_refuses_without_mutating_inflight_state() {
        let mut runtime = BlockVolumeQueueRuntime::open(
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(72), 4, 8, 2),
            2,
            1,
            8,
        )
        .expect("valid queue runtime");
        let first = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(0, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("first context");
        let second = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(2, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("second context");

        let first_admit = runtime.admit_submission_context(first);
        let second_admit = runtime.admit_submission_context(second);

        assert_eq!(
            first_admit.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert_eq!(
            second_admit.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedBackpressure
        );
        assert_eq!(
            second_admit.completion_class,
            BlockVolumeCompletionClass::RefusedBackpressure
        );
        assert_eq!(runtime.backpressure.inflight_requests, 1);
        assert_eq!(runtime.inflight_contexts.len(), 1);
    }

    #[test]
    fn export_fence_refuses_new_admission_without_queue_state_mutation() {
        let mut runtime = queue_runtime();
        let fence = runtime.open_export_fence();
        let context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");

        let decision = runtime.admit_submission_context(context);

        assert_eq!(fence.queue_phase_class, BlockVolumeQueuePhaseClass::Fenced);
        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedExportFenced
        );
        assert_eq!(
            decision.completion_class,
            BlockVolumeCompletionClass::RefusedExportFenced
        );
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn flush_epoch_seals_mutating_submission_contexts() {
        let mut runtime = queue_runtime();
        let read = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let write = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(4, 2)),
                8,
                BlockVolumeDurabilityClass::FuaRequired,
            )
            .expect("write context");
        runtime.admit_submission_context(read);
        runtime.admit_submission_context(write.clone());

        let flush = runtime.seal_flush_epoch(BlockVolumeDurabilityClass::FuaRequired);

        assert_eq!(
            flush.durability_class,
            BlockVolumeDurabilityClass::FuaRequired
        );
        assert!(flush.sealed);
        assert_eq!(
            flush.covered_submission_context_refs,
            vec![write.submission_context_id]
        );
        assert_eq!(runtime.backpressure.open_flush_epochs, 1);
    }

    #[test]
    fn completion_commit_releases_backpressure_and_renders_linux_status() {
        let mut runtime = queue_runtime();
        let context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(8, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        runtime.admit_submission_context(context.clone());

        let completion = runtime
            .complete_submission_context(
                context.submission_context_id,
                BlockVolumeCompletionClass::Completed,
                8,
            )
            .expect("completion");

        assert_eq!(
            completion.submission_context_ref,
            context.submission_context_id
        );
        assert_eq!(completion.linux_status_code, 0);
        assert_eq!(completion.byte_count, 8);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime
            .shards
            .iter()
            .all(|shard| shard.inflight_context_ids.is_empty()));
    }

    #[test]
    fn dispatch_read_admitted_context_returns_payload_and_completion() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        image.write_blocks(2, &[7; 8]);
        let context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(2, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        runtime.admit_submission_context(context.clone());

        let (dispatch, payload) =
            runtime.dispatch_submission_context(&mut image, context.submission_context_id, None);

        assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(dispatch.read_payload_len, 8);
        assert_eq!(payload.as_deref(), Some([7; 8].as_slice()));
        assert!(dispatch.completion_commit_ref.is_some());
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn dispatch_write_admitted_context_mutates_exact_bytes_and_releases_queue() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let payload = [0xC7; 8];
        let context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(1, 2)),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        runtime.admit_submission_context(context.clone());

        let (dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            context.submission_context_id,
            Some(&payload),
        );
        let (_, bytes) = image.read_blocks(BlockRangeRecord::new(1, 2));

        assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(read_payload.is_none());
        assert_eq!(bytes.as_deref(), Some(payload.as_slice()));
        assert!(dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
    }

    #[test]
    fn synthetic_queue_sparse_read_returns_zeroes_without_dirty_state() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let range = BlockRangeRecord::new(3, 3);
        let payload_len = 12;
        let expected_zeroes = vec![0; payload_len];

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(range),
                payload_len,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let read_decision = runtime.admit_submission_context(read_context.clone());
        assert_eq!(
            read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.request_class, BlockVolumeRequestClass::Read);
        assert_eq!(read_dispatch.range, Some(range));
        assert_eq!(read_dispatch.read_payload_len, payload_len);
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(read_dispatch.request_plan.dirty_epoch_ref.is_none());
        assert!(read_dispatch.request_plan.flush_barrier_ref.is_none());
        assert!(read_dispatch.request_plan.discard_intent_ref.is_none());
        assert_eq!(read_payload.as_deref(), Some(expected_zeroes.as_slice()));
        assert!(read_dispatch.completion_commit_ref.is_some());

        assert!(image.dirty_epochs.is_empty());
        assert!(image.flush_barriers.is_empty());
        assert!(image.discard_intents.is_empty());
        assert_eq!(runtime.dispatch_records.len(), 1);
        assert_eq!(runtime.completion_commits.len(), 1);
        assert_eq!(runtime.completion_commits[0].byte_count, payload_len);
        assert_eq!(
            runtime.completion_commits[0].result_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(runtime.completion_commits[0].linux_status_code, 0);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_read_write_dispatch_loop_preserves_bytes_and_completions() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let range = BlockRangeRecord::new(1, 2);
        let payload = [0x5A; 8];

        let write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        let write_decision = runtime.admit_submission_context(write_context.clone());
        assert_eq!(
            write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        let (write_dispatch, write_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            write_context.submission_context_id,
            Some(&payload),
        );
        assert!(write_read_payload.is_none());
        assert_eq!(
            write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(write_dispatch.range, Some(range));
        assert_eq!(write_dispatch.request_plan.payload_len, payload.len());
        assert_eq!(
            write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(write_dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(write_dispatch.completion_commit_ref.is_some());

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let read_decision = runtime.admit_submission_context(read_context.clone());
        assert_eq!(
            read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );
        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.range, Some(range));
        assert_eq!(read_dispatch.read_payload_len, payload.len());
        assert_eq!(read_payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(read_dispatch.completion_commit_ref.is_some());

        assert_eq!(runtime.dispatch_records.len(), 2);
        assert_eq!(runtime.completion_commits.len(), 2);
        assert_eq!(runtime.completion_commits[0].byte_count, payload.len());
        assert_eq!(runtime.completion_commits[1].byte_count, payload.len());
        assert!(runtime.completion_commits.iter().all(|completion| {
            completion.result_class == BlockVolumeCompletionClass::Completed
        }));
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn ublk_bounds_synthetic_queue_refuses_out_of_range_read_write_without_mutation() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let edge_range = BlockRangeRecord::new(7, 1);
        let edge_payload = [0xE7; 4];

        let edge_write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(edge_range),
                edge_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("edge write context");
        let edge_write_decision = runtime.admit_submission_context(edge_write_context.clone());
        assert_eq!(
            edge_write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (edge_write_dispatch, edge_write_payload) = runtime.dispatch_submission_context(
            &mut image,
            edge_write_context.submission_context_id,
            Some(&edge_payload),
        );
        assert!(edge_write_payload.is_none());
        assert_eq!(
            edge_write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(
            edge_write_dispatch.request_plan.payload_len,
            edge_payload.len()
        );

        let (_, baseline_bytes) = image.read_blocks(BlockRangeRecord::new(0, 8));
        let baseline_bytes = baseline_bytes.expect("baseline bytes");
        let baseline_dirty_epochs = image.dirty_epochs.len();
        let tail_shard_ref = runtime.shards.last().expect("tail shard").queue_shard_id;
        let out_of_range = BlockRangeRecord::new(7, 2);
        let out_of_range_len = 8;

        let stale_read_context = BlockVolumeSubmissionContextMirrorRecord {
            submission_context_id: BlockVolumeReceiptId(0xB0_01),
            request_class: BlockVolumeRequestClass::Read,
            queue_class: BlockVolumeQueueClass::ReadFast,
            queue_shard_refs: vec![tail_shard_ref],
            range: Some(out_of_range),
            payload_len: out_of_range_len,
            exactness_class: BlockVolumeCompletionClass::Completed,
            durability_class: BlockVolumeDurabilityClass::None,
            anchor_snapshot_ref: BlockVolumeReceiptId(0xAA_B0_01),
        };
        let stale_read_decision = runtime.admit_submission_context(stale_read_context.clone());
        assert_eq!(
            stale_read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (stale_read_dispatch, stale_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            stale_read_context.submission_context_id,
            None,
        );
        assert!(stale_read_payload.is_none());
        assert_eq!(
            stale_read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(stale_read_dispatch.range, Some(out_of_range));
        assert_eq!(stale_read_dispatch.read_payload_len, 0);
        assert_eq!(
            stale_read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(stale_read_dispatch.request_plan.payload_len, 0);
        assert!(stale_read_dispatch.completion_commit_ref.is_some());
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("read completion")
                .result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("read completion")
                .byte_count,
            0
        );
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("read completion")
                .linux_status_code,
            22
        );
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));

        let refused_write_payload = [0xD4; 8];
        let stale_write_context = BlockVolumeSubmissionContextMirrorRecord {
            submission_context_id: BlockVolumeReceiptId(0xB0_02),
            request_class: BlockVolumeRequestClass::Write,
            queue_class: BlockVolumeQueueClass::OrderedMutation,
            queue_shard_refs: vec![tail_shard_ref],
            range: Some(out_of_range),
            payload_len: refused_write_payload.len(),
            exactness_class: BlockVolumeCompletionClass::Completed,
            durability_class: BlockVolumeDurabilityClass::None,
            anchor_snapshot_ref: BlockVolumeReceiptId(0xAA_B0_02),
        };
        let stale_write_decision = runtime.admit_submission_context(stale_write_context.clone());
        assert_eq!(
            stale_write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (stale_write_dispatch, stale_write_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            stale_write_context.submission_context_id,
            Some(&refused_write_payload),
        );
        assert!(stale_write_read_payload.is_none());
        assert_eq!(
            stale_write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(stale_write_dispatch.range, Some(out_of_range));
        assert_eq!(
            stale_write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(
            stale_write_dispatch.request_plan.payload_len,
            refused_write_payload.len()
        );
        assert!(stale_write_dispatch.completion_commit_ref.is_some());
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("write completion")
                .result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("write completion")
                .byte_count,
            0
        );
        assert_eq!(
            runtime
                .completion_commits
                .last()
                .expect("write completion")
                .linux_status_code,
            22
        );

        let (_, final_bytes) = image.read_blocks(BlockRangeRecord::new(0, 8));
        assert_eq!(final_bytes.as_deref(), Some(baseline_bytes.as_slice()));
        assert_eq!(image.dirty_epochs.len(), baseline_dirty_epochs);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_overwrite_dispatch_returns_latest_bytes_and_releases_queue() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let range = BlockRangeRecord::new(1, 2);
        let first_payload = [0x11; 8];
        let latest_payload = [0xC7; 8];

        let first_write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(range),
                first_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("first write context");
        let first_write_decision = runtime.admit_submission_context(first_write_context.clone());
        assert_eq!(
            first_write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (first_write_dispatch, first_write_payload) = runtime.dispatch_submission_context(
            &mut image,
            first_write_context.submission_context_id,
            Some(&first_payload),
        );
        assert!(first_write_payload.is_none());
        assert_eq!(
            first_write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(first_write_dispatch.range, Some(range));
        assert_eq!(
            first_write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(first_write_dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(first_write_dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());

        let overwrite_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(range),
                latest_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("overwrite context");
        let overwrite_decision = runtime.admit_submission_context(overwrite_context.clone());
        assert_eq!(
            overwrite_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (overwrite_dispatch, overwrite_payload) = runtime.dispatch_submission_context(
            &mut image,
            overwrite_context.submission_context_id,
            Some(&latest_payload),
        );
        assert!(overwrite_payload.is_none());
        assert_eq!(
            overwrite_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(overwrite_dispatch.range, Some(range));
        assert_eq!(
            overwrite_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(overwrite_dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(overwrite_dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(range),
                latest_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let read_decision = runtime.admit_submission_context(read_context.clone());
        assert_eq!(
            read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.range, Some(range));
        assert_eq!(read_dispatch.read_payload_len, latest_payload.len());
        assert_eq!(read_payload.as_deref(), Some(latest_payload.as_slice()));
        assert_ne!(read_payload.as_deref(), Some(first_payload.as_slice()));
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(read_dispatch.completion_commit_ref.is_some());

        assert_eq!(runtime.dispatch_records.len(), 3);
        assert_eq!(runtime.completion_commits.len(), 3);
        assert_eq!(
            runtime.completion_commits[0].byte_count,
            first_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[1].byte_count,
            latest_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[2].byte_count,
            latest_payload.len()
        );
        assert!(runtime.completion_commits.iter().all(|completion| {
            completion.result_class == BlockVolumeCompletionClass::Completed
        }));
        assert_eq!(image.dirty_epochs.len(), 2);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_partial_overwrite_preserves_untouched_bytes() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let full_range = BlockRangeRecord::new(1, 3);
        let overwrite_range = BlockRangeRecord::new(2, 1);
        let baseline_payload = [
            0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x51, 0x52, 0x53, 0x54,
        ];
        let overwrite_payload = [0xD1, 0xD2, 0xD3, 0xD4];
        let expected_payload = [
            0x31, 0x32, 0x33, 0x34, 0xD1, 0xD2, 0xD3, 0xD4, 0x51, 0x52, 0x53, 0x54,
        ];

        let baseline_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(full_range),
                baseline_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("baseline write context");
        let baseline_decision = runtime.admit_submission_context(baseline_context.clone());
        assert_eq!(
            baseline_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (baseline_dispatch, baseline_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            baseline_context.submission_context_id,
            Some(&baseline_payload),
        );
        assert!(baseline_read_payload.is_none());
        assert_eq!(
            baseline_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(baseline_dispatch.range, Some(full_range));
        assert_eq!(
            baseline_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(baseline_dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(baseline_dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());

        let overwrite_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(overwrite_range),
                overwrite_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("partial overwrite context");
        let overwrite_decision = runtime.admit_submission_context(overwrite_context.clone());
        assert_eq!(
            overwrite_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (overwrite_dispatch, overwrite_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            overwrite_context.submission_context_id,
            Some(&overwrite_payload),
        );
        assert!(overwrite_read_payload.is_none());
        assert_eq!(
            overwrite_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(overwrite_dispatch.range, Some(overwrite_range));
        assert_eq!(
            overwrite_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(overwrite_dispatch.request_plan.dirty_epoch_ref.is_some());
        assert!(overwrite_dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(full_range),
                expected_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let read_decision = runtime.admit_submission_context(read_context.clone());
        assert_eq!(
            read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.range, Some(full_range));
        assert_eq!(read_dispatch.read_payload_len, expected_payload.len());
        assert_eq!(read_payload.as_deref(), Some(expected_payload.as_slice()));
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[..4],
            &baseline_payload[..4]
        );
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[4..8],
            &overwrite_payload
        );
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[8..],
            &baseline_payload[8..]
        );
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(read_dispatch.completion_commit_ref.is_some());

        assert_eq!(runtime.dispatch_records.len(), 3);
        assert_eq!(runtime.completion_commits.len(), 3);
        assert_eq!(
            runtime.completion_commits[0].byte_count,
            baseline_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[1].byte_count,
            overwrite_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[2].byte_count,
            expected_payload.len()
        );
        assert!(runtime.completion_commits.iter().all(|completion| {
            completion.result_class == BlockVolumeCompletionClass::Completed
        }));
        assert_eq!(image.dirty_epochs.len(), 2);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_partial_overwrite_flush_seals_dirty_epochs_and_preserves_bytes() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let full_range = BlockRangeRecord::new(1, 3);
        let overwrite_range = BlockRangeRecord::new(2, 1);
        let baseline_payload = [
            0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44,
        ];
        let overwrite_payload = [0xE1, 0xE2, 0xE3, 0xE4];
        let expected_payload = [
            0x21, 0x22, 0x23, 0x24, 0xE1, 0xE2, 0xE3, 0xE4, 0x41, 0x42, 0x43, 0x44,
        ];

        let baseline_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(full_range),
                baseline_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("baseline write context");
        assert_eq!(
            runtime
                .admit_submission_context(baseline_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (baseline_dispatch, baseline_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            baseline_context.submission_context_id,
            Some(&baseline_payload),
        );
        assert!(baseline_read_payload.is_none());
        assert_eq!(
            baseline_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        let baseline_dirty_epoch = baseline_dispatch
            .request_plan
            .dirty_epoch_ref
            .expect("baseline dirty epoch");

        let overwrite_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(overwrite_range),
                overwrite_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("partial overwrite context");
        assert_eq!(
            runtime
                .admit_submission_context(overwrite_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (overwrite_dispatch, overwrite_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            overwrite_context.submission_context_id,
            Some(&overwrite_payload),
        );
        assert!(overwrite_read_payload.is_none());
        assert_eq!(
            overwrite_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        let overwrite_dirty_epoch = overwrite_dispatch
            .request_plan
            .dirty_epoch_ref
            .expect("overwrite dirty epoch");
        assert_ne!(baseline_dirty_epoch, overwrite_dirty_epoch);
        assert_eq!(image.dirty_epochs.len(), 2);
        assert_eq!(image.dirty_epochs[0].range, full_range);
        assert_eq!(image.dirty_epochs[1].range, overwrite_range);
        assert!(image
            .dirty_epochs
            .iter()
            .all(|epoch| !epoch.sealed_for_flush));
        assert_eq!(runtime.completion_commits.len(), 2);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());

        let flush_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush context");
        assert_eq!(
            runtime
                .admit_submission_context(flush_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert_eq!(runtime.backpressure.inflight_requests, 1);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.shards.iter().all(|shard| {
            shard
                .inflight_context_ids
                .contains(&flush_context.submission_context_id)
                && shard.ordered_ranges.is_empty()
        }));

        let (flush_dispatch, flush_payload) = runtime.dispatch_submission_context(
            &mut image,
            flush_context.submission_context_id,
            None,
        );
        let flush_barrier_ref = flush_dispatch
            .request_plan
            .flush_barrier_ref
            .expect("flush barrier");
        assert!(flush_payload.is_none());
        assert_eq!(
            flush_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(flush_dispatch.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(flush_dispatch.request_plan.payload_len, 0);
        assert_eq!(
            flush_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(image.flush_barriers.len(), 1);
        assert_eq!(image.flush_barriers[0].barrier_id, flush_barrier_ref);
        assert_eq!(
            image.flush_barriers[0].covered_epoch_ids,
            vec![baseline_dirty_epoch, overwrite_dirty_epoch]
        );
        assert!(image
            .dirty_epochs
            .iter()
            .all(|epoch| epoch.sealed_for_flush));
        assert_eq!(runtime.flush_epochs.len(), 1);
        assert_eq!(runtime.completion_commits.len(), 3);
        assert_eq!(
            runtime.completion_commits[0].byte_count,
            baseline_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[1].byte_count,
            overwrite_payload.len()
        );
        assert_eq!(runtime.completion_commits[2].byte_count, 0);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(full_range),
                expected_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        assert_eq!(
            runtime
                .admit_submission_context(read_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.range, Some(full_range));
        assert_eq!(read_dispatch.read_payload_len, expected_payload.len());
        assert_eq!(read_payload.as_deref(), Some(expected_payload.as_slice()));
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[..4],
            &baseline_payload[..4]
        );
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[4..8],
            &overwrite_payload
        );
        assert_eq!(
            &read_payload.as_deref().expect("read payload")[8..],
            &baseline_payload[8..]
        );
        assert_eq!(runtime.dispatch_records.len(), 4);
        assert_eq!(runtime.completion_commits.len(), 4);
        assert_eq!(
            runtime.completion_commits[3].byte_count,
            expected_payload.len()
        );
        assert!(runtime.completion_commits.iter().all(|completion| {
            completion.result_class == BlockVolumeCompletionClass::Completed
        }));
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_mixed_dispatch_preserves_ordered_read_visibility_and_completion_tags() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let full_range = BlockRangeRecord::new(0, 4);
        let tail_overwrite_range = BlockRangeRecord::new(3, 2);
        let late_read_range = BlockRangeRecord::new(2, 3);
        let baseline_payload = [
            0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x40, 0x41,
            0x42, 0x43,
        ];
        let tail_payload = [0xD0, 0xD1, 0xD2, 0xD3, 0xE0, 0xE1, 0xE2, 0xE3];
        let late_expected_payload = [
            0x30, 0x31, 0x32, 0x33, 0xD0, 0xD1, 0xD2, 0xD3, 0xE0, 0xE1, 0xE2, 0xE3,
        ];

        let first_write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(full_range),
                baseline_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("first write context");
        let early_read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(full_range),
                baseline_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("early read context");
        let tail_write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(tail_overwrite_range),
                tail_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("tail overwrite context");
        let late_read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(late_read_range),
                late_expected_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("late read context");

        for context in [
            first_write_context.clone(),
            early_read_context.clone(),
            tail_write_context.clone(),
            late_read_context.clone(),
        ] {
            assert_eq!(
                runtime.admit_submission_context(context).admission_class,
                BlockVolumeQueueAdmissionClass::Admitted
            );
        }
        assert_eq!(runtime.backpressure.inflight_requests, 4);
        assert_eq!(
            runtime.backpressure.inflight_bytes,
            baseline_payload.len()
                + baseline_payload.len()
                + tail_payload.len()
                + late_expected_payload.len()
        );

        let (first_dispatch, first_payload) = runtime.dispatch_submission_context(
            &mut image,
            first_write_context.submission_context_id,
            Some(&baseline_payload),
        );
        let (early_read_dispatch, early_payload) = runtime.dispatch_submission_context(
            &mut image,
            early_read_context.submission_context_id,
            None,
        );
        let (tail_dispatch, tail_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            tail_write_context.submission_context_id,
            Some(&tail_payload),
        );
        let (late_read_dispatch, late_payload) = runtime.dispatch_submission_context(
            &mut image,
            late_read_context.submission_context_id,
            None,
        );

        assert!(first_payload.is_none());
        assert!(tail_read_payload.is_none());
        assert_eq!(early_payload.as_deref(), Some(baseline_payload.as_slice()));
        assert_eq!(
            late_payload.as_deref(),
            Some(late_expected_payload.as_slice())
        );
        assert_eq!(
            &late_payload.as_deref().expect("late read payload")[..4],
            &baseline_payload[8..12]
        );
        assert_eq!(
            &late_payload.as_deref().expect("late read payload")[4..],
            &tail_payload
        );

        assert_eq!(runtime.dispatch_records.len(), 4);
        assert_eq!(runtime.completion_commits.len(), 4);
        assert_eq!(
            runtime
                .dispatch_records
                .iter()
                .map(|record| record.request_class)
                .collect::<Vec<_>>(),
            vec![
                BlockVolumeRequestClass::Write,
                BlockVolumeRequestClass::Read,
                BlockVolumeRequestClass::Write,
                BlockVolumeRequestClass::Read,
            ]
        );
        assert!(runtime
            .completion_commits
            .iter()
            .all(
                |completion| completion.result_class == BlockVolumeCompletionClass::Completed
                    && completion.linux_status_code == 0
                    && completion.completion_receipt_ref != BlockVolumeReceiptId::default()
            ));

        for (dispatch, completion) in [
            first_dispatch,
            early_read_dispatch,
            tail_dispatch,
            late_read_dispatch,
        ]
        .iter()
        .zip(runtime.completion_commits.iter())
        {
            assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
            assert_eq!(
                dispatch.request_plan.completion_class,
                BlockVolumeCompletionClass::Completed
            );
            assert_eq!(
                dispatch.completion_commit_ref,
                Some(completion.completion_commit_id)
            );
            assert_eq!(
                completion.submission_context_ref,
                dispatch.submission_context_ref
            );
        }
        assert_eq!(
            runtime.completion_commits[0].byte_count,
            baseline_payload.len()
        );
        assert_eq!(
            runtime.completion_commits[1].byte_count,
            baseline_payload.len()
        );
        assert_eq!(runtime.completion_commits[2].byte_count, tail_payload.len());
        assert_eq!(
            runtime.completion_commits[3].byte_count,
            late_expected_payload.len()
        );
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_write_flush_read_dispatch_preserves_bytes_and_releases_barrier_state() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let range = BlockRangeRecord::new(1, 2);
        let payload = [0xA6; 8];

        let write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        let write_decision = runtime.admit_submission_context(write_context.clone());
        assert_eq!(
            write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (write_dispatch, write_payload) = runtime.dispatch_submission_context(
            &mut image,
            write_context.submission_context_id,
            Some(&payload),
        );
        assert!(write_payload.is_none());
        assert_eq!(
            write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(
            write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );

        let flush_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush context");
        let flush_decision = runtime.admit_submission_context(flush_context.clone());
        assert_eq!(
            flush_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert_eq!(runtime.backpressure.inflight_requests, 1);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.shards.iter().all(|shard| {
            shard
                .inflight_context_ids
                .contains(&flush_context.submission_context_id)
                && shard.ordered_ranges.is_empty()
        }));

        let (flush_dispatch, flush_payload) = runtime.dispatch_submission_context(
            &mut image,
            flush_context.submission_context_id,
            None,
        );
        let flush_completion_ref = flush_dispatch
            .completion_commit_ref
            .expect("flush completion commit");
        let flush_barrier_ref = flush_dispatch
            .request_plan
            .flush_barrier_ref
            .expect("flush barrier");

        assert!(flush_payload.is_none());
        assert_eq!(
            flush_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(flush_dispatch.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(flush_dispatch.request_plan.payload_len, 0);
        assert_eq!(
            flush_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(image.flush_barriers.len(), 1);
        assert_eq!(image.flush_barriers[0].barrier_id, flush_barrier_ref);
        assert_eq!(image.flush_barriers[0].covered_epoch_ids.len(), 1);
        assert!(image
            .dirty_epochs
            .iter()
            .all(|epoch| epoch.sealed_for_flush));
        assert_eq!(runtime.flush_epochs.len(), 1);
        assert_eq!(runtime.completion_commits.len(), 2);
        assert_eq!(
            runtime.completion_commits[1].completion_commit_id,
            flush_completion_ref
        );
        assert_eq!(
            runtime.completion_commits[1].result_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(runtime.completion_commits[1].byte_count, 0);
        assert_eq!(runtime.completion_commits[1].linux_status_code, 0);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let read_decision = runtime.admit_submission_context(read_context.clone());
        assert_eq!(
            read_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.read_payload_len, payload.len());
        assert_eq!(read_payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(runtime.dispatch_records.len(), 3);
        assert_eq!(runtime.completion_commits.len(), 3);
        assert!(runtime
            .completion_commits
            .iter()
            .all(|completion| completion.result_class == BlockVolumeCompletionClass::Completed));
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn synthetic_queue_flush_readback_persistence_preserves_full_block_payload() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(144), 4096, 16, 4);
        let mut image = BlockVolumeImage::open_zeroed(geometry).expect("valid image");
        let mut runtime =
            BlockVolumeQueueRuntime::open(geometry, 4, 4, geometry.block_size_bytes * 4)
                .expect("valid dispatch runtime");
        let range = BlockRangeRecord::new(0, 1);
        let payload: Vec<u8> = (0..geometry.block_size_bytes)
            .map(|idx| ((idx * 31 + 7) % 251) as u8)
            .collect();

        let write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        assert_eq!(
            runtime
                .admit_submission_context(write_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (write_dispatch, write_payload) = runtime.dispatch_submission_context(
            &mut image,
            write_context.submission_context_id,
            Some(&payload),
        );
        assert!(write_payload.is_none());
        assert_eq!(
            write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(
            write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );

        let flush_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush context");
        assert_eq!(
            runtime
                .admit_submission_context(flush_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (flush_dispatch, flush_payload) = runtime.dispatch_submission_context(
            &mut image,
            flush_context.submission_context_id,
            None,
        );
        let flush_completion_ref = flush_dispatch
            .completion_commit_ref
            .expect("flush completion commit");
        let flush_completion = runtime
            .completion_commits
            .iter()
            .find(|commit| commit.completion_commit_id == flush_completion_ref)
            .expect("flush completion record");

        assert!(flush_payload.is_none());
        assert_eq!(
            flush_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(flush_dispatch.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(
            flush_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(flush_dispatch.request_plan.flush_barrier_ref.is_some());
        assert_eq!(
            flush_completion.result_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(flush_completion.linux_status_code, 0);
        assert_eq!(flush_completion.byte_count, 0);

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        assert_eq!(
            runtime
                .admit_submission_context(read_context.clone())
                .admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(read_dispatch.read_payload_len, payload.len());
        assert_eq!(read_payload.as_deref(), Some(payload.as_slice()));
        assert!(runtime
            .completion_commits
            .iter()
            .all(
                |completion| completion.result_class == BlockVolumeCompletionClass::Completed
                    && completion.linux_status_code == 0
            ));
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert_eq!(runtime.backpressure.open_flush_epochs, 0);
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn ublk_bounds_synthetic_queue_refuses_out_of_range_read_write_without_mutation_dynamic_geometry(
    ) {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let edge_range = BlockRangeRecord::new(image.geometry.block_count - 1, 1);
        let out_of_bounds_range = BlockRangeRecord::new(image.geometry.block_count - 1, 2);
        let edge_payload = [0x7A; 4];

        let edge_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(edge_range),
                edge_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("edge write context");
        runtime.admit_submission_context(edge_context.clone());
        let (edge_dispatch, edge_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            edge_context.submission_context_id,
            Some(&edge_payload),
        );
        let (_, edge_bytes) = image.read_blocks(edge_range);

        assert!(edge_read_payload.is_none());
        assert_eq!(
            edge_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(
            edge_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(edge_bytes.as_deref(), Some(edge_payload.as_slice()));

        let bytes_before_refusals = image.bytes.clone();
        let dirty_epochs_before_refusals = image.dirty_epochs.len();

        let mut read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(edge_range),
                edge_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        read_context.range = Some(out_of_bounds_range);
        read_context.payload_len = edge_payload.len() * 2;
        runtime.admit_submission_context(read_context.clone());

        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );
        let read_completion = runtime
            .completion_commits
            .last()
            .expect("read refusal completion");

        assert!(read_payload.is_none());
        assert_eq!(
            read_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(read_dispatch.range, Some(out_of_bounds_range));
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(read_dispatch.request_plan.range, Some(out_of_bounds_range));
        assert_eq!(read_dispatch.read_payload_len, 0);
        assert!(read_dispatch.completion_commit_ref.is_some());
        assert_eq!(
            read_completion.result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(read_completion.byte_count, 0);
        assert_eq!(read_completion.linux_status_code, 22);
        assert_eq!(image.bytes, bytes_before_refusals);
        assert_eq!(image.dirty_epochs.len(), dirty_epochs_before_refusals);

        let write_payload = [0xE5; 8];
        let mut write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(edge_range),
                edge_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        write_context.range = Some(out_of_bounds_range);
        write_context.payload_len = write_payload.len();
        runtime.admit_submission_context(write_context.clone());

        let (write_dispatch, write_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            write_context.submission_context_id,
            Some(&write_payload),
        );
        let write_completion = runtime
            .completion_commits
            .last()
            .expect("write refusal completion");

        assert!(write_read_payload.is_none());
        assert_eq!(
            write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(write_dispatch.range, Some(out_of_bounds_range));
        assert_eq!(
            write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(write_dispatch.request_plan.range, Some(out_of_bounds_range));
        assert_eq!(write_dispatch.request_plan.payload_len, write_payload.len());
        assert!(write_dispatch.completion_commit_ref.is_some());
        assert_eq!(
            write_completion.result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(write_completion.byte_count, 0);
        assert_eq!(write_completion.linux_status_code, 22);
        assert_eq!(image.bytes, bytes_before_refusals);
        assert_eq!(image.dirty_epochs.len(), dirty_epochs_before_refusals);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_zero_len_read_refuses_and_releases_queue_without_mutation() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let bytes_before = image.bytes.clone();
        let context = BlockVolumeSubmissionContextMirrorRecord {
            submission_context_id: BlockVolumeReceiptId(0x24_00_01),
            request_class: BlockVolumeRequestClass::Read,
            queue_class: BlockVolumeQueueClass::ReadFast,
            queue_shard_refs: Vec::new(),
            range: Some(BlockRangeRecord::new(0, 0)),
            payload_len: 0,
            exactness_class: BlockVolumeCompletionClass::Completed,
            durability_class: BlockVolumeDurabilityClass::None,
            anchor_snapshot_ref: BlockVolumeReceiptId(0x24_AA_01),
        };

        let decision = runtime.admit_submission_context(context.clone());
        let (dispatch, payload) =
            runtime.dispatch_submission_context(&mut image, context.submission_context_id, None);
        let completion = runtime
            .completion_commits
            .last()
            .expect("zero-len read completion");

        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert!(payload.is_none());
        assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
        assert_eq!(dispatch.range, Some(BlockRangeRecord::new(0, 0)));
        assert_eq!(dispatch.read_payload_len, 0);
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(
            completion.result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(completion.byte_count, 0);
        assert_eq!(completion.linux_status_code, 22);
        assert_eq!(image.bytes, bytes_before);
        assert!(image.dirty_epochs.is_empty());
        assert!(image.flush_barriers.is_empty());
        assert!(image.discard_intents.is_empty());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_zero_len_write_at_capacity_refuses_without_mutation() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let bytes_before = image.bytes.clone();
        let capacity_edge = BlockRangeRecord::new(image.geometry.block_count, 0);
        let context = BlockVolumeSubmissionContextMirrorRecord {
            submission_context_id: BlockVolumeReceiptId(0x24_00_02),
            request_class: BlockVolumeRequestClass::Write,
            queue_class: BlockVolumeQueueClass::OrderedMutation,
            queue_shard_refs: Vec::new(),
            range: Some(capacity_edge),
            payload_len: 0,
            exactness_class: BlockVolumeCompletionClass::Completed,
            durability_class: BlockVolumeDurabilityClass::None,
            anchor_snapshot_ref: BlockVolumeReceiptId(0x24_AA_02),
        };

        let decision = runtime.admit_submission_context(context.clone());
        let (dispatch, payload) = runtime.dispatch_submission_context(
            &mut image,
            context.submission_context_id,
            Some(&[]),
        );
        let completion = runtime
            .completion_commits
            .last()
            .expect("zero-len write completion");

        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        assert!(payload.is_none());
        assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
        assert_eq!(dispatch.range, Some(capacity_edge));
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(dispatch.request_plan.payload_len, 0);
        assert_eq!(
            completion.result_class,
            BlockVolumeCompletionClass::RefusedMisalignedRange
        );
        assert_eq!(completion.byte_count, 0);
        assert_eq!(completion.linux_status_code, 22);
        assert_eq!(image.bytes, bytes_before);
        assert!(image.dirty_epochs.is_empty());
        assert!(image.flush_barriers.is_empty());
        assert!(image.discard_intents.is_empty());
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn ublk_bounds_synthetic_queue_reads_last_block_at_capacity_edge() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let tail_range = BlockRangeRecord::new(image.geometry.block_count - 1, 1);
        let payload = [0x24, 0x91, 0xC0, 0xDE];

        let write_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(tail_range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("tail write context");
        runtime.admit_submission_context(write_context.clone());
        let (write_dispatch, write_payload) = runtime.dispatch_submission_context(
            &mut image,
            write_context.submission_context_id,
            Some(&payload),
        );

        let read_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(tail_range),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("tail read context");
        runtime.admit_submission_context(read_context.clone());
        let (read_dispatch, read_payload) = runtime.dispatch_submission_context(
            &mut image,
            read_context.submission_context_id,
            None,
        );

        assert!(write_payload.is_none());
        assert_eq!(
            write_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(read_dispatch.range, Some(tail_range));
        assert_eq!(read_dispatch.read_payload_len, payload.len());
        assert_eq!(read_payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            read_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(runtime.completion_commits.len(), 2);
        assert!(runtime.completion_commits.iter().all(|completion| {
            completion.result_class == BlockVolumeCompletionClass::Completed
        }));
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn synthetic_queue_refusal_drains_only_failed_context_and_preserves_next_request() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let tail_range = BlockRangeRecord::new(image.geometry.block_count - 1, 1);
        let out_of_bounds_range = BlockRangeRecord::new(image.geometry.block_count - 1, 2);
        let refused_payload = [0xEF; 8];
        let following_payload = [0x51; 4];

        let mut refused_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(tail_range),
                refused_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("refused write context");
        refused_context.range = Some(out_of_bounds_range);
        let following_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(tail_range),
                following_payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("following write context");
        runtime.admit_submission_context(refused_context.clone());
        runtime.admit_submission_context(following_context.clone());

        let (refused_dispatch, refused_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            refused_context.submission_context_id,
            Some(&refused_payload),
        );

        assert!(refused_read_payload.is_none());
        assert_eq!(
            refused_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(runtime.inflight_contexts.len(), 1);
        assert_eq!(
            runtime.inflight_contexts[0].submission_context_id,
            following_context.submission_context_id
        );
        assert!(runtime.shards.iter().any(|shard| shard
            .inflight_context_ids
            .contains(&following_context.submission_context_id)));
        assert_eq!(runtime.backpressure.inflight_requests, 1);
        assert_eq!(runtime.backpressure.inflight_bytes, following_payload.len());

        let (following_dispatch, following_read_payload) = runtime.dispatch_submission_context(
            &mut image,
            following_context.submission_context_id,
            Some(&following_payload),
        );
        let (_, tail_bytes) = image.read_blocks(tail_range);

        assert!(following_read_payload.is_none());
        assert_eq!(
            following_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(tail_bytes.as_deref(), Some(following_payload.as_slice()));
        assert_eq!(runtime.completion_commits.len(), 2);
        assert_eq!(
            runtime.completion_commits[0].result_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(
            runtime.completion_commits[1].result_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert_eq!(runtime.backpressure.inflight_bytes, 0);
        assert!(runtime.inflight_contexts.is_empty());
        assert!(runtime.shards.iter().all(|shard| {
            shard.inflight_context_ids.is_empty() && shard.ordered_ranges.is_empty()
        }));
    }

    #[test]
    fn dispatch_flush_context_seals_dirty_epochs_and_records_completion() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        image.write_blocks(0, &[9; 8]);
        let flush_context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush context");
        runtime.admit_submission_context(flush_context.clone());

        let (dispatch, payload) = runtime.dispatch_submission_context(
            &mut image,
            flush_context.submission_context_id,
            None,
        );

        assert!(payload.is_none());
        assert_eq!(dispatch.dispatch_class, BlockVolumeDispatchClass::Executed);
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(dispatch.request_plan.flush_barrier_ref.is_some());
        assert_eq!(image.flush_barriers.len(), 1);
        assert!(image
            .dirty_epochs
            .iter()
            .all(|epoch| epoch.sealed_for_flush));
        assert_eq!(runtime.flush_epochs.len(), 1);
        assert!(dispatch.completion_commit_ref.is_some());
    }

    #[test]
    fn dispatch_discard_and_write_zeroes_zero_visible_ranges() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        image.write_blocks(0, &[5; 16]);
        let discard = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Discard,
                Some(BlockRangeRecord::new(0, 2)),
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("discard context");
        let zeroes = runtime
            .build_submission_context(
                BlockVolumeRequestClass::WriteZeroes,
                Some(BlockRangeRecord::new(2, 2)),
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("write-zeroes context");
        runtime.admit_submission_context(discard.clone());
        runtime.admit_submission_context(zeroes.clone());

        let (discard_dispatch, _) =
            runtime.dispatch_submission_context(&mut image, discard.submission_context_id, None);
        let (zeroes_dispatch, _) =
            runtime.dispatch_submission_context(&mut image, zeroes.submission_context_id, None);
        let (_, bytes) = image.read_blocks(BlockRangeRecord::new(0, 4));

        assert_eq!(
            discard_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(
            zeroes_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(bytes.as_deref(), Some([0; 16].as_slice()));
        assert_eq!(image.discard_intents.len(), 2);
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn dispatch_refuses_unadmitted_context_without_completion_commit() {
        let mut image = image();
        let mut runtime = dispatch_runtime();

        let (dispatch, payload) =
            runtime.dispatch_submission_context(&mut image, BlockVolumeReceiptId(0xDEAD), None);

        assert!(payload.is_none());
        assert_eq!(
            dispatch.dispatch_class,
            BlockVolumeDispatchClass::RefusedUnadmittedContext
        );
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedUnadmittedContext
        );
        assert!(dispatch.completion_commit_ref.is_none());
        assert!(runtime.completion_commits.is_empty());
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn dispatch_payload_mismatch_refuses_and_releases_queue_without_mutation() {
        let mut image = image();
        let mut runtime = dispatch_runtime();
        let context = runtime
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(4, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        runtime.admit_submission_context(context.clone());

        let (dispatch, payload) = runtime.dispatch_submission_context(
            &mut image,
            context.submission_context_id,
            Some(&[1, 2, 3]),
        );
        let (_, bytes) = image.read_blocks(BlockRangeRecord::new(4, 2));

        assert!(payload.is_none());
        assert_eq!(
            dispatch.dispatch_class,
            BlockVolumeDispatchClass::RefusedPayloadMismatch
        );
        assert_eq!(
            dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::RefusedPayloadMismatch
        );
        assert_eq!(bytes.as_deref(), Some([0; 8].as_slice()));
        assert!(dispatch.completion_commit_ref.is_some());
        assert_eq!(runtime.completion_commits[0].byte_count, 0);
        assert_eq!(runtime.backpressure.inflight_requests, 0);
        assert!(runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn dispatch_missing_non_flush_range_refuses_and_releases_queue() {
        let cases = [
            (
                BlockVolumeRequestClass::Read,
                BlockVolumeQueueClass::ReadFast,
                0,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
            ),
            (
                BlockVolumeRequestClass::Write,
                BlockVolumeQueueClass::OrderedMutation,
                4,
                BlockVolumeCompletionClass::RefusedPayloadMismatch,
            ),
            (
                BlockVolumeRequestClass::Discard,
                BlockVolumeQueueClass::ZeroDiscard,
                0,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
            ),
            (
                BlockVolumeRequestClass::WriteZeroes,
                BlockVolumeQueueClass::ZeroDiscard,
                0,
                BlockVolumeCompletionClass::RefusedOutOfBounds,
            ),
        ];

        for (idx, (request_class, queue_class, payload_len, expected_completion)) in
            cases.into_iter().enumerate()
        {
            let mut image = image();
            let mut runtime = dispatch_runtime();
            let context = BlockVolumeSubmissionContextMirrorRecord {
                submission_context_id: BlockVolumeReceiptId(0xBAD0 + idx as u64),
                request_class,
                queue_class,
                queue_shard_refs: Vec::new(),
                range: None,
                payload_len,
                exactness_class: BlockVolumeCompletionClass::Completed,
                durability_class: BlockVolumeDurabilityClass::None,
                anchor_snapshot_ref: BlockVolumeReceiptId(0xAA00 + idx as u64),
            };
            let decision = runtime.admit_submission_context(context.clone());
            let payload = [0xAB; 4];
            let write_payload =
                (request_class == BlockVolumeRequestClass::Write).then_some(payload.as_slice());

            let (dispatch, read_payload) = runtime.dispatch_submission_context(
                &mut image,
                context.submission_context_id,
                write_payload,
            );

            assert_eq!(
                decision.admission_class,
                BlockVolumeQueueAdmissionClass::Admitted
            );
            assert!(read_payload.is_none());
            assert_eq!(dispatch.request_plan.completion_class, expected_completion);
            assert_eq!(dispatch.request_plan.range, None);
            assert!(dispatch.completion_commit_ref.is_some());
            assert_eq!(runtime.completion_commits.len(), 1);
            assert_eq!(
                runtime.completion_commits[0].result_class,
                expected_completion
            );
            assert_eq!(runtime.completion_commits[0].byte_count, 0);
            assert_eq!(runtime.backpressure.inflight_requests, 0);
            assert!(runtime.inflight_contexts.is_empty());
        }
    }

    #[test]
    fn export_lifecycle_bootstrap_admit_and_start_queues() {
        let mut lifecycle = lifecycle_runtime();
        let context = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");

        let refused = lifecycle.admit_submission_context(context.clone());
        let admit = lifecycle.admit_export();
        let start = lifecycle.start_queues();
        let admitted = lifecycle.admit_submission_context(context);

        assert_eq!(
            refused.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedExportFenced
        );
        assert_eq!(
            admit.to_phase_class,
            BlockVolumeExportPhaseClass::ExportAdmitted
        );
        assert_eq!(
            start.to_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive
        );
        assert_eq!(
            lifecycle.queue_runtime.queue_set.queue_phase_class,
            BlockVolumeQueuePhaseClass::Open
        );
        assert_eq!(
            admitted.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
    }

    #[test]
    fn export_lifecycle_refuses_data_before_live_and_after_stop() {
        let mut lifecycle = lifecycle_runtime();
        let early_context = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("early read context");

        let early = lifecycle.admit_submission_context(early_context);
        lifecycle.admit_export();
        lifecycle.start_queues();
        lifecycle.begin_quiesce(BlockVolumeExportTransitionClass::RevokeQuiesce);
        lifecycle.fence_after_drain();
        lifecycle.stop_after_drain();
        let late_context = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(1, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("late read context");
        let late = lifecycle.admit_submission_context(late_context);

        assert_eq!(
            early.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedExportFenced
        );
        assert_eq!(
            lifecycle.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Stopped
        );
        assert_eq!(
            late.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedExportFenced
        );
        assert!(lifecycle.queue_runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn quiesce_transition_closes_ingress_and_classifies_inflight() {
        let mut lifecycle = lifecycle_runtime();
        lifecycle.admit_export();
        lifecycle.start_queues();
        let read = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read context");
        let write = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(4, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        let flush = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush context");
        lifecycle.admit_submission_context(read);
        lifecycle.admit_submission_context(write);
        lifecycle.admit_submission_context(flush);

        let quiesce = lifecycle.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
        let new_read = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(2, 1)),
                4,
                BlockVolumeDurabilityClass::None,
            )
            .expect("new read context");
        let refused = lifecycle.admit_submission_context(new_read);

        assert_eq!(
            quiesce.to_phase_class,
            BlockVolumeExportPhaseClass::QuiesceTransition
        );
        assert_eq!(
            lifecycle.queue_runtime.queue_set.queue_phase_class,
            BlockVolumeQueuePhaseClass::Fenced
        );
        assert_eq!(quiesce.inflight_classifications.len(), 3);
        assert!(quiesce.inflight_classifications.iter().any(|record| {
            record.classification == BlockVolumeInflightTransitionClass::CommitOk
        }));
        assert!(quiesce.inflight_classifications.iter().any(|record| {
            record.classification == BlockVolumeInflightTransitionClass::ReplayRequired
        }));
        assert!(quiesce.inflight_classifications.iter().any(|record| {
            record.classification == BlockVolumeInflightTransitionClass::AbortRequired
        }));
        assert_eq!(
            refused.admission_class,
            BlockVolumeQueueAdmissionClass::RefusedExportFenced
        );
        assert_eq!(lifecycle.queue_runtime.inflight_contexts.len(), 3);
    }

    #[test]
    fn fence_completion_is_refused_until_quiesce_drain_finishes() {
        let mut lifecycle = lifecycle_runtime();
        lifecycle.admit_export();
        lifecycle.start_queues();
        let write = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(6, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        lifecycle.admit_submission_context(write.clone());
        lifecycle.begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);

        let blocked = lifecycle.fence_after_drain();
        lifecycle
            .complete_submission_context(
                write.submission_context_id,
                BlockVolumeCompletionClass::Completed,
                8,
            )
            .expect("completion");
        let fenced = lifecycle.fence_after_drain();

        assert_eq!(
            blocked.outcome_class,
            BlockVolumeExportTransitionOutcomeClass::RefusedDrainIncomplete
        );
        assert_eq!(
            fenced.outcome_class,
            BlockVolumeExportTransitionOutcomeClass::Completed
        );
        assert_eq!(
            lifecycle.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Fenced
        );
        assert!(lifecycle.queue_runtime.inflight_contexts.is_empty());
    }

    #[test]
    fn resume_after_fence_reopens_admission_under_new_fence_epoch() {
        let mut lifecycle = lifecycle_runtime();
        lifecycle.admit_export();
        lifecycle.start_queues();
        lifecycle.begin_quiesce(BlockVolumeExportTransitionClass::RevokeQuiesce);
        lifecycle.fence_after_drain();
        let old_fence_epoch = lifecycle.export_runtime.fence_epoch_ref;

        let resume = lifecycle.resume_after_fence();
        let context = lifecycle
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(8, 2)),
                8,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write context");
        let admitted = lifecycle.admit_submission_context(context);

        assert_eq!(resume.to_phase_class, BlockVolumeExportPhaseClass::Resumed);
        assert_ne!(lifecycle.export_runtime.fence_epoch_ref, old_fence_epoch);
        assert_eq!(
            lifecycle.queue_runtime.queue_set.queue_phase_class,
            BlockVolumeQueuePhaseClass::Open
        );
        assert_eq!(
            admitted.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
    }

    #[test]
    fn invalid_lifecycle_transition_is_recorded_without_state_mutation() {
        let mut lifecycle = lifecycle_runtime();

        let invalid = lifecycle.start_queues();

        assert_eq!(
            invalid.outcome_class,
            BlockVolumeExportTransitionOutcomeClass::RefusedInvalidPhase
        );
        assert_eq!(
            lifecycle.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Bootstrap
        );
        assert_eq!(
            lifecycle.queue_runtime.queue_set.queue_phase_class,
            BlockVolumeQueuePhaseClass::Fenced
        );
        assert_eq!(lifecycle.transition_records.len(), 1);
    }

    #[test]
    fn cache_hit_requires_live_anchor_bound_window() {
        let mut cache = cache_runtime();
        let range = BlockRangeRecord::new(2, 2);
        let window = cache
            .fill_read_cache_window(range, 8, false)
            .expect("cache window");

        let hit = cache
            .read_cache_hit(BlockRangeRecord::new(2, 1))
            .expect("cache hit");
        cache
            .open_dirty_epoch(BlockRangeRecord::new(3, 1), 4)
            .expect("dirty epoch");
        let miss_after_invalidation = cache.read_cache_hit(range);

        assert_eq!(hit.cache_window_id, window.cache_window_id);
        assert_eq!(
            hit.residency_class,
            BlockVolumeCacheResidencyClass::CleanHot
        );
        assert!(miss_after_invalidation.is_none());
        assert!(cache.read_cache_windows[0].invalidated_by_mutation);
    }

    #[test]
    fn dirty_epoch_creation_invalidates_overlapping_read_cache_window() {
        let mut cache = cache_runtime();
        let cold = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 2), 8, false)
            .expect("cold window");
        let survivor = cache
            .fill_read_cache_window(BlockRangeRecord::new(8, 2), 8, true)
            .expect("survivor window");

        let dirty = cache
            .open_dirty_epoch(BlockRangeRecord::new(1, 2), 8)
            .expect("dirty epoch");

        assert_eq!(
            dirty.invalidated_cache_window_refs,
            vec![cold.cache_window_id]
        );
        assert_eq!(
            cache
                .read_cache_hit(survivor.range)
                .expect("survivor hit")
                .cache_window_id,
            survivor.cache_window_id
        );
        assert_eq!(
            cache
                .transition_records
                .last()
                .expect("transition")
                .transition_class,
            BlockVolumeCacheTransitionClass::DirtyWrite
        );
    }

    #[test]
    fn flush_barrier_covers_dirty_epoch_and_creates_fua_ticket() {
        let mut cache = cache_runtime();
        let dirty = cache
            .open_dirty_epoch(BlockRangeRecord::new(4, 2), 8)
            .expect("dirty epoch");

        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FuaRequired);

        assert_eq!(barrier.covered_cache_epoch_refs, vec![dirty.cache_epoch_id]);
        assert_eq!(
            barrier.required_durability_class,
            BlockVolumeDurabilityClass::FuaRequired
        );
        assert!(barrier.satisfied);
        assert!(barrier.fua_ticket_ref.is_some());
        assert_eq!(cache.fua_tickets.len(), 1);
        assert!(cache.dirty_epochs[0].sealed_for_barrier);
        assert!(cache.fua_tickets[0].completion_allowed);
    }

    #[test]
    fn discard_and_write_zeroes_invalidate_cache_windows() {
        let mut cache = cache_runtime();
        let discard_window = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 2), 8, false)
            .expect("discard window");
        let zero_window = cache
            .fill_read_cache_window(BlockRangeRecord::new(4, 2), 8, false)
            .expect("zero window");

        let discard = cache
            .issue_discard_or_zero_invalidation(
                BlockVolumeRequestClass::Discard,
                BlockRangeRecord::new(1, 1),
            )
            .expect("discard invalidation");
        let zeroes = cache
            .issue_discard_or_zero_invalidation(
                BlockVolumeRequestClass::WriteZeroes,
                BlockRangeRecord::new(4, 2),
            )
            .expect("write zeroes invalidation");

        assert_eq!(
            discard.transition_class,
            BlockVolumeCacheTransitionClass::DiscardInvalidation
        );
        assert_eq!(
            zeroes.transition_class,
            BlockVolumeCacheTransitionClass::WriteZeroesInvalidation
        );
        assert_eq!(
            discard.affected_cache_window_refs,
            vec![discard_window.cache_window_id]
        );
        assert_eq!(
            zeroes.affected_cache_window_refs,
            vec![zero_window.cache_window_id]
        );
        assert!(cache.read_cache_hit(discard_window.range).is_none());
        assert!(cache.read_cache_hit(zero_window.range).is_none());
    }

    #[test]
    fn direct_overlap_guard_blocks_until_dirty_epoch_is_sealed() {
        let mut cache = cache_runtime();
        let dirty = cache
            .open_dirty_epoch(BlockRangeRecord::new(5, 2), 8)
            .expect("dirty epoch");

        let blocked = cache
            .open_direct_overlap_guard(BlockRangeRecord::new(6, 1))
            .expect("direct guard");
        cache.seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);
        let resolved = cache
            .resolve_direct_overlap_guard(blocked.direct_guard_id)
            .expect("resolved guard");

        assert_eq!(
            blocked.guard_class,
            BlockVolumeDirectOverlapGuardClass::BlockedDirtyDrain
        );
        assert_eq!(blocked.blocked_epoch_refs, vec![dirty.cache_epoch_id]);
        assert_eq!(
            resolved.guard_class,
            BlockVolumeDirectOverlapGuardClass::Open
        );
        assert!(resolved.blocked_epoch_refs.is_empty());
    }

    #[test]
    fn cache_loss_drops_clean_windows_without_removing_dirty_authority_records() {
        let mut cache = cache_runtime();
        cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 2), 8, false)
            .expect("cache window");
        let dirty = cache
            .open_dirty_epoch(BlockRangeRecord::new(8, 2), 8)
            .expect("dirty epoch");

        let loss = cache.drop_clean_cache_windows();
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);

        assert_eq!(
            loss.transition_class,
            BlockVolumeCacheTransitionClass::CacheLoss
        );
        assert!(cache
            .read_cache_windows
            .iter()
            .all(|window| window.invalidated_by_mutation));
        assert_eq!(cache.dirty_epochs.len(), 1);
        assert_eq!(barrier.covered_cache_epoch_refs, vec![dirty.cache_epoch_id]);
    }

    #[test]
    fn resize_fence_grow_commit_publishes_geometry_and_zero_visible_tail() {
        let mut runtime = fenced_resize_runtime();
        let authority = runtime
            .lifecycle_runtime
            .export_runtime
            .authority_anchor_ref;

        let prepared = runtime.prepare_resize(20, authority);
        let committed = runtime.commit_resize(prepared.transition_id);

        assert_eq!(
            prepared.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Prepared
        );
        assert_eq!(
            prepared.direction_class,
            Some(BlockVolumeResizeDirectionClass::Grow)
        );
        assert_eq!(
            prepared.affected_tail_range,
            Some(BlockRangeRecord::new(16, 4))
        );
        assert_eq!(
            prepared.zero_visible_range,
            Some(BlockRangeRecord::new(16, 4))
        );
        assert_eq!(
            prepared.capacity_target_publication_class,
            BlockVolumeCapacityTargetPublicationClass::PublishedForCommit
        );
        assert_eq!(
            committed.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Committed
        );
        assert_eq!(runtime.current_geometry.block_count, 20);
        assert_eq!(
            runtime
                .lifecycle_runtime
                .queue_runtime
                .queue_set
                .block_count,
            20
        );
        assert_eq!(
            committed.post_resize_geometry,
            Some(BlockVolumeGeometryRecord::new(
                BlockVolumeId::new(87),
                4,
                20,
                2
            ))
        );
    }

    #[test]
    fn resize_fence_shrink_refuses_overlap_until_drain() {
        let mut runtime = fenced_resize_runtime();
        let authority = runtime
            .lifecycle_runtime
            .export_runtime
            .authority_anchor_ref;
        let dirty = runtime
            .cache_runtime
            .open_dirty_epoch(BlockRangeRecord::new(12, 2), 8)
            .expect("dirty tail epoch");

        let refused = runtime.prepare_resize(10, authority);

        assert_eq!(
            refused.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete
        );
        assert_eq!(
            refused.direction_class,
            Some(BlockVolumeResizeDirectionClass::Shrink)
        );
        assert_eq!(
            refused.affected_tail_range,
            Some(BlockRangeRecord::new(10, 6))
        );
        assert_eq!(
            refused.overlapping_dirty_epoch_refs,
            vec![dirty.cache_epoch_id]
        );
        assert_eq!(runtime.current_geometry.block_count, 16);
        assert_eq!(
            runtime
                .lifecycle_runtime
                .queue_runtime
                .queue_set
                .block_count,
            16
        );
    }

    #[test]
    fn resize_fence_shrink_commits_after_dirty_drain_and_fence() {
        let mut runtime = fenced_resize_runtime();
        let authority = runtime
            .lifecycle_runtime
            .export_runtime
            .authority_anchor_ref;
        runtime
            .cache_runtime
            .open_dirty_epoch(BlockRangeRecord::new(12, 2), 8)
            .expect("dirty tail epoch");
        let refused = runtime.prepare_resize(10, authority);
        runtime
            .cache_runtime
            .seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);

        let prepared = runtime.prepare_resize(10, authority);
        let committed = runtime.commit_resize(prepared.transition_id);

        assert_eq!(
            refused.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::RefusedDrainIncomplete
        );
        assert_eq!(
            prepared.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Prepared
        );
        assert!(prepared.overlapping_dirty_epoch_refs.is_empty());
        assert_eq!(
            committed.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Committed
        );
        assert_eq!(runtime.current_geometry.block_count, 10);
        assert_eq!(
            runtime
                .lifecycle_runtime
                .queue_runtime
                .queue_set
                .block_count,
            10
        );
        assert_eq!(
            runtime
                .lifecycle_runtime
                .queue_runtime
                .queue_set
                .shard_count,
            4
        );
    }

    #[test]
    fn resize_fence_refuses_without_fenced_export() {
        let mut runtime = resize_runtime();
        let authority = runtime
            .lifecycle_runtime
            .export_runtime
            .authority_anchor_ref;
        runtime.lifecycle_runtime.admit_export();
        runtime.lifecycle_runtime.start_queues();

        let refused = runtime.prepare_resize(20, authority);

        assert_eq!(
            refused.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced
        );
        assert_eq!(
            runtime.lifecycle_runtime.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive
        );
        assert_eq!(runtime.current_geometry.block_count, 16);
    }

    #[test]
    fn resize_fence_refuses_without_authority_anchor() {
        let mut runtime = fenced_resize_runtime();
        let wrong_authority = BlockVolumeReceiptId(0xBAD);

        let refused = runtime.prepare_resize(20, wrong_authority);

        assert_eq!(
            refused.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::RefusedNoAuthority
        );
        assert_eq!(refused.authority_anchor_ref, wrong_authority);
        assert_eq!(runtime.current_geometry.block_count, 16);
    }

    #[test]
    fn write_past_end_is_refused_without_implicit_resize() {
        let mut image = image();
        let original_geometry = image.geometry;
        let original_len = image.bytes.len();

        let write = image.write_blocks(original_geometry.block_count, &[0xEE; 4]);

        assert_eq!(
            write.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(image.geometry, original_geometry);
        assert_eq!(image.bytes.len(), original_len);
        assert!(image.dirty_epochs.is_empty());
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 7: reconcile_cached_ranges_after_discard_or_resize tests
    // ------------------------------------------------------------------

    #[test]
    fn reconcile_after_discard_invalidates_overlapping_clean_windows() {
        let mut cache = cache_runtime();
        let w1 = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 4), 16, false)
            .expect("w1");
        let w2 = cache
            .fill_read_cache_window(BlockRangeRecord::new(4, 4), 16, false)
            .expect("w2");

        let record = cache.reconcile_cached_ranges_after_discard_or_resize(
            BlockRangeRecord::new(0, 6),
            BlockVolumeCacheTransitionClass::DiscardInvalidation,
        );

        assert_eq!(
            record.transition_class,
            BlockVolumeCacheTransitionClass::DiscardInvalidation
        );
        assert_eq!(record.range, Some(BlockRangeRecord::new(0, 6)));
        assert_eq!(record.affected_cache_window_refs.len(), 2);
        assert!(record
            .affected_cache_window_refs
            .contains(&w1.cache_window_id));
        assert!(record
            .affected_cache_window_refs
            .contains(&w2.cache_window_id));

        // Windows should now be marked absent
        let w1_after = cache
            .read_cache_windows
            .iter()
            .find(|w| w.cache_window_id == w1.cache_window_id)
            .unwrap();
        assert!(w1_after.invalidated_by_mutation);
        assert_eq!(
            w1_after.residency_class,
            BlockVolumeCacheResidencyClass::Absent
        );
    }

    #[test]
    fn reconcile_after_resize_seals_overlapping_dirty_epochs() {
        let mut cache = cache_runtime();
        let epoch = cache
            .open_dirty_epoch(BlockRangeRecord::new(8, 4), 16)
            .expect("epoch");
        assert!(!epoch.sealed_for_barrier);

        cache.reconcile_cached_ranges_after_discard_or_resize(
            BlockRangeRecord::new(8, 4),
            BlockVolumeCacheTransitionClass::CacheLoss,
        );

        let epoch_after = cache
            .dirty_epochs
            .iter()
            .find(|e| e.cache_epoch_id == epoch.cache_epoch_id)
            .unwrap();
        assert!(epoch_after.sealed_for_barrier);
    }

    #[test]
    fn reconcile_resolves_direct_guards_in_range() {
        let mut cache = cache_runtime();
        let guard = cache
            .open_direct_overlap_guard(BlockRangeRecord::new(0, 4))
            .expect("guard");
        assert_eq!(guard.guard_class, BlockVolumeDirectOverlapGuardClass::Open);

        cache.reconcile_cached_ranges_after_discard_or_resize(
            BlockRangeRecord::new(0, 4),
            BlockVolumeCacheTransitionClass::DiscardInvalidation,
        );

        let guard_after = cache
            .direct_guards
            .iter()
            .find(|g| g.direct_guard_id == guard.direct_guard_id)
            .unwrap();
        assert_eq!(
            guard_after.guard_class,
            BlockVolumeDirectOverlapGuardClass::Resolved
        );
    }

    #[test]
    fn reconcile_leaves_non_overlapping_ranges_untouched() {
        let mut cache = cache_runtime();
        let w = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 4), 16, false)
            .expect("w");

        cache.reconcile_cached_ranges_after_discard_or_resize(
            BlockRangeRecord::new(8, 4),
            BlockVolumeCacheTransitionClass::DiscardInvalidation,
        );

        let w_after = cache
            .read_cache_windows
            .iter()
            .find(|cw| cw.cache_window_id == w.cache_window_id)
            .unwrap();
        assert!(!w_after.invalidated_by_mutation);
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 8: evict_or_invalidate_cache_under_fence tests
    // ------------------------------------------------------------------

    #[test]
    fn evict_under_fence_freezes_clean_windows() {
        let mut cache = cache_runtime();
        let w = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 8), 32, false)
            .expect("w");

        let record = cache.evict_or_invalidate_cache_under_fence(
            BlockRangeRecord::new(0, 8),
            BlockVolumeCacheTransitionClass::CacheLoss,
        );

        assert_eq!(record.affected_cache_window_refs.len(), 1);
        assert!(record
            .affected_cache_window_refs
            .contains(&w.cache_window_id));

        let w_after = cache
            .read_cache_windows
            .iter()
            .find(|cw| cw.cache_window_id == w.cache_window_id)
            .unwrap();
        assert!(w_after.invalidated_by_mutation);
        assert_eq!(
            w_after.residency_class,
            BlockVolumeCacheResidencyClass::FrozenTransition
        );
    }

    #[test]
    fn evict_under_fence_seals_dirty_epochs() {
        let mut cache = cache_runtime();
        let epoch = cache
            .open_dirty_epoch(BlockRangeRecord::new(0, 4), 16)
            .expect("epoch");
        assert!(!epoch.sealed_for_barrier);

        cache.evict_or_invalidate_cache_under_fence(
            BlockRangeRecord::new(0, 4),
            BlockVolumeCacheTransitionClass::FailoverFence,
        );

        let epoch_after = cache
            .dirty_epochs
            .iter()
            .find(|e| e.cache_epoch_id == epoch.cache_epoch_id)
            .unwrap();
        assert!(epoch_after.sealed_for_barrier);
    }

    #[test]
    fn evict_under_fence_resolves_direct_guards() {
        let mut cache = cache_runtime();
        let guard = cache
            .open_direct_overlap_guard(BlockRangeRecord::new(4, 4))
            .expect("guard");

        cache.evict_or_invalidate_cache_under_fence(
            BlockRangeRecord::new(4, 4),
            BlockVolumeCacheTransitionClass::FailoverFence,
        );

        let guard_after = cache
            .direct_guards
            .iter()
            .find(|g| g.direct_guard_id == guard.direct_guard_id)
            .unwrap();
        assert_eq!(
            guard_after.guard_class,
            BlockVolumeDirectOverlapGuardClass::Resolved
        );
    }

    #[test]
    fn evict_under_fence_produces_transition_record() {
        let mut cache = cache_runtime();
        cache.fill_read_cache_window(BlockRangeRecord::new(0, 4), 16, false);
        cache.open_dirty_epoch(BlockRangeRecord::new(4, 4), 16);

        let record = cache.evict_or_invalidate_cache_under_fence(
            BlockRangeRecord::new(0, 8),
            BlockVolumeCacheTransitionClass::FailoverFence,
        );

        assert_eq!(
            record.transition_class,
            BlockVolumeCacheTransitionClass::FailoverFence
        );
        assert_eq!(record.range, Some(BlockRangeRecord::new(0, 8)));
        assert!(!record.affected_cache_window_refs.is_empty());
        assert!(!record.affected_epoch_refs.is_empty());
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 9: render_completion_from_barrier_state tests
    // ------------------------------------------------------------------

    #[test]
    fn render_completion_returns_refused_for_unknown_barrier() {
        let cache = cache_runtime();
        let fake_id = BlockVolumeReceiptId(999);
        let result =
            cache.render_completion_from_barrier_state(fake_id, BlockVolumeRequestClass::Write);
        assert_eq!(result, BlockVolumeCompletionClass::RefusedExportFenced);
    }

    #[test]
    fn render_completion_satisfied_none_durability_returns_completed() {
        let mut cache = cache_runtime();
        cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16);
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::None);

        let result = cache.render_completion_from_barrier_state(
            barrier.cache_barrier_id,
            BlockVolumeRequestClass::Write,
        );
        assert_eq!(result, BlockVolumeCompletionClass::Completed);
    }

    #[test]
    fn render_completion_unsatisfied_barrier_returns_refused() {
        let mut cache = cache_runtime();
        cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16);
        let mut barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);
        barrier.satisfied = false;
        // Replace the existing barrier with an unsatisfied one
        if let Some(b) = cache
            .flush_barriers
            .iter_mut()
            .find(|b| b.cache_barrier_id == barrier.cache_barrier_id)
        {
            b.satisfied = false;
        }

        let result = cache.render_completion_from_barrier_state(
            barrier.cache_barrier_id,
            BlockVolumeRequestClass::Flush,
        );
        assert_eq!(result, BlockVolumeCompletionClass::RefusedUnadmittedContext);
    }

    #[test]
    fn render_completion_flush_required_with_sealed_epochs_returns_completed() {
        let mut cache = cache_runtime();
        cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16);
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);

        let result = cache.render_completion_from_barrier_state(
            barrier.cache_barrier_id,
            BlockVolumeRequestClass::Flush,
        );
        assert_eq!(result, BlockVolumeCompletionClass::Completed);
    }

    #[test]
    fn render_completion_fua_required_with_fua_ticket_returns_completed() {
        let mut cache = cache_runtime();
        cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16);
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FuaRequired);

        assert!(barrier.fua_ticket_ref.is_some());
        let result = cache.render_completion_from_barrier_state(
            barrier.cache_barrier_id,
            BlockVolumeRequestClass::Write,
        );
        assert_eq!(result, BlockVolumeCompletionClass::Completed);
    }

    // ------------------------------------------------------------------
    // P6-02 algorithm family 10: drain_dirty_ranges_for_failover_or_cutover tests
    // ------------------------------------------------------------------

    #[test]
    fn drain_seals_all_unsealed_dirty_epochs() {
        let mut cache = cache_runtime();
        let e1 = cache
            .open_dirty_epoch(BlockRangeRecord::new(0, 4), 16)
            .expect("e1");
        let e2 = cache
            .open_dirty_epoch(BlockRangeRecord::new(8, 4), 16)
            .expect("e2");

        let (barrier, transition) = cache.drain_dirty_ranges_for_failover_or_cutover();

        // All epochs sealed
        for epoch in &cache.dirty_epochs {
            assert!(
                epoch.sealed_for_barrier,
                "epoch {} not sealed",
                epoch.cache_epoch_id.0
            );
        }

        // Barrier covers both epochs
        assert_eq!(barrier.covered_cache_epoch_refs.len(), 2);
        assert!(barrier
            .covered_cache_epoch_refs
            .contains(&e1.cache_epoch_id));
        assert!(barrier
            .covered_cache_epoch_refs
            .contains(&e2.cache_epoch_id));
        assert_eq!(
            barrier.required_durability_class,
            BlockVolumeDurabilityClass::FuaRequired
        );
        assert!(barrier.satisfied);
        assert!(barrier.fua_ticket_ref.is_some());

        // Transition recorded
        assert_eq!(
            transition.transition_class,
            BlockVolumeCacheTransitionClass::FailoverFence
        );
    }

    #[test]
    fn drain_only_seals_unsealed_epochs() {
        let mut cache = cache_runtime();
        cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16);
        let barrier1 = cache.seal_flush_barrier(BlockVolumeDurabilityClass::None);
        // Now all epochs are sealed
        cache.open_dirty_epoch(BlockRangeRecord::new(4, 4), 16);

        let (barrier2, _transition) = cache.drain_dirty_ranges_for_failover_or_cutover();

        // barrier2 covers only the unsealed epoch
        assert_eq!(barrier2.covered_cache_epoch_refs.len(), 1);
        assert_ne!(
            barrier2.covered_cache_epoch_refs.first(),
            barrier1.covered_cache_epoch_refs.first()
        );
    }

    #[test]
    fn drain_no_dirty_epochs_returns_empty_barrier() {
        let mut cache = cache_runtime();
        let (barrier, transition) = cache.drain_dirty_ranges_for_failover_or_cutover();

        assert!(barrier.covered_cache_epoch_refs.is_empty());
        assert_eq!(
            transition.transition_class,
            BlockVolumeCacheTransitionClass::FailoverFence
        );
        assert!(transition.affected_epoch_refs.is_empty());
    }

    #[cfg(test)]
    mod device_handle_tests {
        use super::*;

        fn test_backing() -> BlockVolumeImage {
            BlockVolumeImage::open_zeroed(BlockVolumeGeometryRecord::new(
                BlockVolumeId::new(100),
                512,
                16,
                0,
            ))
            .expect("valid image")
        }

        fn active_handle() -> BlockDeviceHandle<BlockVolumeImage> {
            let mut handle = BlockDeviceHandle::new(test_backing());
            handle.begin_open().unwrap();
            handle.complete_open().unwrap();
            handle
        }

        // ------------------------------------------------------------------
        // Lifecycle state transition tests
        // ------------------------------------------------------------------

        #[test]
        fn lifecycle_offline_to_active_path() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            assert_eq!(handle.state, BlockDeviceLifecycleState::Offline);

            assert!(handle.begin_open().is_ok());
            assert_eq!(handle.state, BlockDeviceLifecycleState::Opening);

            assert!(handle.complete_open().is_ok());
            assert_eq!(handle.state, BlockDeviceLifecycleState::Active);
        }

        #[test]
        fn lifecycle_active_to_terminal_path() {
            let mut handle = active_handle();
            assert_eq!(handle.state, BlockDeviceLifecycleState::Active);

            assert!(handle.begin_close().is_ok());
            assert_eq!(handle.state, BlockDeviceLifecycleState::Closing);

            assert!(handle.complete_close().is_ok());
            assert_eq!(handle.state, BlockDeviceLifecycleState::OfflineTerminal);
        }

        #[test]
        fn begin_open_from_non_offline_returns_err() {
            let mut handle = active_handle();
            let err = handle.begin_open().unwrap_err();
            assert_eq!(err, BlockDeviceLifecycleState::Active);
        }

        #[test]
        fn complete_open_from_non_opening_returns_err() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            let err = handle.complete_open().unwrap_err();
            assert_eq!(err, BlockDeviceLifecycleState::Offline);
        }

        #[test]
        fn begin_close_from_non_active_returns_err() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            let err = handle.begin_close().unwrap_err();
            assert_eq!(err, BlockDeviceLifecycleState::Offline);
        }

        #[test]
        fn complete_close_from_non_closing_returns_err() {
            let mut handle = active_handle();
            let err = handle.complete_close().unwrap_err();
            assert_eq!(err, BlockDeviceLifecycleState::Active);
        }

        #[test]
        fn begin_close_refuses_in_offline_terminal() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            handle.complete_close().unwrap();
            let err = handle.begin_close().unwrap_err();
            assert_eq!(err, BlockDeviceLifecycleState::OfflineTerminal);
        }

        // ------------------------------------------------------------------
        // dispatch_read tests
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_read_zero_length_returns_zero() {
            let handle = active_handle();
            let mut buf = [0u8; 64];
            let n = handle.dispatch_read(0, &mut buf[..0]).unwrap();
            assert_eq!(n, 0);
        }

        #[test]
        fn dispatch_read_at_offset_returns_zeroes_from_empty_backing() {
            let handle = active_handle();
            let mut buf = [0xFFu8; 64];
            let n = handle.dispatch_read(0, &mut buf).unwrap();
            assert_eq!(n, 64);
            assert!(buf.iter().all(|&b| b == 0));
        }

        #[test]
        fn dispatch_read_at_capacity_edge_returns_zero() {
            let handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let mut buf = [0xFFu8; 16];
            let n = handle.dispatch_read(cap, &mut buf).unwrap();
            assert_eq!(n, 0);
        }

        #[test]
        fn dispatch_read_short_at_end_of_device() {
            let handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let offset = cap - 32;
            let mut buf = [0xFFu8; 64];
            let n = handle.dispatch_read(offset, &mut buf).unwrap();
            assert_eq!(n, 32);
            // first 32 bytes should be zeroed (read from backing)
            assert!(buf[..32].iter().all(|&b| b == 0));
            // remaining 32 bytes in buf should be untouched (0xFF)
            assert!(buf[32..].iter().all(|&b| b == 0xFF));
        }

        #[test]
        fn dispatch_read_beyond_capacity_returns_zero() {
            let handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let mut buf = [0xFFu8; 16];
            let n = handle.dispatch_read(cap + 1024, &mut buf).unwrap();
            assert_eq!(n, 0);
            // buf untouched
            assert!(buf.iter().all(|&b| b == 0xFF));
        }

        #[test]
        fn dispatch_read_round_trip_after_write() {
            let mut handle = active_handle();
            let data = [0xABu8; 128];
            handle.dispatch_write(64, &data).unwrap();

            let mut buf = [0u8; 128];
            let n = handle.dispatch_read(64, &mut buf).unwrap();
            assert_eq!(n, 128);
            assert_eq!(buf, data);
        }

        #[test]
        fn dispatch_read_partial_spanning_write_boundary() {
            let mut handle = active_handle();
            handle.dispatch_write(0, &[0xAAu8; 256]).unwrap();
            handle.dispatch_write(256, &[0xBBu8; 256]).unwrap();

            // Read 128 bytes at offset 128: first half (0xAA), second half stays 0xAA
            let mut buf = [0u8; 128];
            let n = handle.dispatch_read(128, &mut buf).unwrap();
            assert_eq!(n, 128);
            assert!(buf.iter().all(|&b| b == 0xAA));

            // Read across the boundary: offset 192, len 128
            let mut buf = [0u8; 128];
            let n = handle.dispatch_read(192, &mut buf).unwrap();
            assert_eq!(n, 128);
            assert_eq!(&buf[..64], &[0xAAu8; 64]);
            assert_eq!(&buf[64..], &[0xBBu8; 64]);
        }

        // ------------------------------------------------------------------
        // dispatch_write tests
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_write_zero_length_is_noop() {
            let mut handle = active_handle();
            assert!(handle.dispatch_write(0, &[]).is_ok());
        }

        #[test]
        fn dispatch_write_at_exact_capacity_boundary() {
            let mut handle = active_handle();
            let cap = handle.backing.capacity_bytes() as usize;
            let data = [0xCCu8; 256];
            handle.dispatch_write((cap - 256) as u64, &data).unwrap();

            let mut buf = [0u8; 256];
            let n = handle.dispatch_read((cap - 256) as u64, &mut buf).unwrap();
            assert_eq!(n, 256);
            assert_eq!(buf, data);
        }

        #[test]
        fn dispatch_write_beyond_capacity_returns_out_of_bounds() {
            let mut handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let err = handle.dispatch_write(cap - 1, &[0xDDu8; 128]).unwrap_err();
            assert!(matches!(err, BlockDeviceDispatchError::OutOfBounds));
        }

        #[test]
        fn dispatch_write_at_capacity_plus_one_returns_out_of_bounds() {
            let mut handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let err = handle.dispatch_write(cap, &[0xEEu8; 1]).unwrap_err();
            assert!(matches!(err, BlockDeviceDispatchError::OutOfBounds));
        }

        #[test]
        fn dispatch_write_near_u64_max_returns_out_of_bounds() {
            let mut handle = active_handle();
            let err = handle.dispatch_write(u64::MAX, &[0u8; 1]).unwrap_err();
            assert!(matches!(err, BlockDeviceDispatchError::OutOfBounds));
        }

        #[test]
        fn dispatch_write_offset_overflow_returns_out_of_bounds() {
            let mut handle = active_handle();
            let err = handle
                .dispatch_write(u64::MAX - 10, &[0u8; 20])
                .unwrap_err();
            assert!(matches!(err, BlockDeviceDispatchError::OutOfBounds));
        }

        // ------------------------------------------------------------------
        // Lifecycle state gating tests: reject I/O in non-Active states
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_read_refuses_in_offline() {
            let handle = BlockDeviceHandle::new(test_backing());
            let mut buf = [0u8; 64];
            let err = handle.dispatch_read(0, &mut buf).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Offline)
            ));
        }

        #[test]
        fn dispatch_read_refuses_in_opening() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            handle.begin_open().unwrap();
            let mut buf = [0u8; 64];
            let err = handle.dispatch_read(0, &mut buf).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Opening)
            ));
        }

        #[test]
        fn dispatch_read_refuses_in_closing() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            let mut buf = [0u8; 64];
            let err = handle.dispatch_read(0, &mut buf).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Closing)
            ));
        }

        #[test]
        fn dispatch_read_refuses_in_offline_terminal() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            handle.complete_close().unwrap();
            let mut buf = [0u8; 64];
            let err = handle.dispatch_read(0, &mut buf).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(
                    BlockDeviceLifecycleState::OfflineTerminal
                )
            ));
        }

        #[test]
        fn dispatch_write_refuses_in_offline() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            let err = handle.dispatch_write(0, &[0u8; 64]).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Offline)
            ));
        }

        #[test]
        fn dispatch_write_refuses_in_opening() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            handle.begin_open().unwrap();
            let err = handle.dispatch_write(0, &[0u8; 64]).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Opening)
            ));
        }

        #[test]
        fn dispatch_write_refuses_in_closing() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            let err = handle.dispatch_write(0, &[0u8; 64]).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Closing)
            ));
        }

        #[test]
        fn dispatch_write_refuses_in_offline_terminal() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            handle.complete_close().unwrap();
            let err = handle.dispatch_write(0, &[0u8; 64]).unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(
                    BlockDeviceLifecycleState::OfflineTerminal
                )
            ));
        }

        // ------------------------------------------------------------------
        // dispatch_read with empty backing at various offsets
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_read_mid_device_returns_zeroes() {
            let handle = active_handle();
            let mut buf = [0xFFu8; 128];
            let n = handle.dispatch_read(1024, &mut buf).unwrap();
            assert_eq!(n, 128);
            assert!(buf.iter().all(|&b| b == 0));
        }

        #[test]
        fn dispatch_read_at_offset_zero_returns_full_buffer() {
            let handle = active_handle();
            let mut buf = [0xFFu8; 256];
            let n = handle.dispatch_read(0, &mut buf).unwrap();
            assert_eq!(n, 256);
            assert!(buf.iter().all(|&b| b == 0));
        }

        #[test]
        fn dispatch_read_buffer_larger_than_remaining_capacity() {
            let handle = active_handle();
            let cap = handle.backing.capacity_bytes();
            let offset = cap - 16;
            let mut buf = [0xAAu8; 256];
            let n = handle.dispatch_read(offset, &mut buf).unwrap();
            assert_eq!(n, 16);
            // only first 16 bytes modified (zeroed)
            assert!(buf[..16].iter().all(|&b| b == 0));
            // rest untouched (0xAA)
            assert!(buf[16..].iter().all(|&b| b == 0xAA));
        }

        // ------------------------------------------------------------------
        // BlockDeviceBacking for BlockVolumeImage: edge cases
        // ------------------------------------------------------------------

        #[test]
        fn backing_read_at_offset_past_capacity_returns_zero() {
            let image = test_backing();
            let mut buf = [0xFFu8; 16];
            let n = image.read_at(u64::MAX, &mut buf).unwrap();
            assert_eq!(n, 0);
            assert!(buf.iter().all(|&b| b == 0xFF));
        }

        #[test]
        fn backing_write_at_offset_overflow_returns_error() {
            let mut image = test_backing();
            let err = image.write_at(u64::MAX, &[0u8; 1]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn backing_write_at_past_capacity_returns_error() {
            let mut image = test_backing();
            let cap = image.bytes.len();
            let err = image.write_at(cap as u64, &[0u8; 1]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn backing_write_at_end_offset_plus_len_overflow_returns_error() {
            let mut image = test_backing();
            let cap = image.bytes.len();
            let err = image.write_at((cap - 1) as u64, &[0u8; 2]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        // ------------------------------------------------------------------
        // Dispatch error: Display and source
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_error_display_for_state_violation() {
            let err = BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Offline);
            let msg = format!("{err}");
            assert!(msg.contains("Offline"));
        }

        #[test]
        fn dispatch_error_display_for_out_of_bounds() {
            let err = BlockDeviceDispatchError::OutOfBounds;
            let msg = format!("{err}");
            assert!(msg.contains("exceeds"));
        }

        #[test]
        fn dispatch_error_source_for_io_error() {
            let io_err = io::Error::other("test");
            let err = BlockDeviceDispatchError::Io(io_err);
            assert!(err.source().is_some());
        }

        #[test]
        fn dispatch_error_source_for_non_io_is_none() {
            let err = BlockDeviceDispatchError::OutOfBounds;
            assert!(err.source().is_none());
            let err = BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Active);
            assert!(err.source().is_none());
        }

        // ------------------------------------------------------------------
        // dispatch_flush tests
        // ------------------------------------------------------------------

        #[test]
        fn dispatch_flush_succeeds_on_active_handle() {
            let mut handle = active_handle();
            handle.dispatch_flush().unwrap();
        }

        #[test]
        fn dispatch_flush_after_write_persists_data() {
            let mut handle = active_handle();
            let data = [0xDEu8; 128];
            handle.dispatch_write(0, &data).unwrap();
            handle.dispatch_flush().unwrap();

            // Verify data is still readable
            let mut buf = [0u8; 128];
            let n = handle.dispatch_read(0, &mut buf).unwrap();
            assert_eq!(n, 128);
            assert_eq!(buf, data);
        }

        #[test]
        fn dispatch_flush_refuses_in_offline() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            let err = handle.dispatch_flush().unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Offline)
            ));
        }

        #[test]
        fn dispatch_flush_refuses_in_opening() {
            let mut handle = BlockDeviceHandle::new(test_backing());
            handle.begin_open().unwrap();
            let err = handle.dispatch_flush().unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Opening)
            ));
        }

        #[test]
        fn dispatch_flush_refuses_in_closing() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            let err = handle.dispatch_flush().unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(BlockDeviceLifecycleState::Closing)
            ));
        }

        #[test]
        fn dispatch_flush_refuses_in_offline_terminal() {
            let mut handle = active_handle();
            handle.begin_close().unwrap();
            handle.complete_close().unwrap();
            let err = handle.dispatch_flush().unwrap_err();
            assert!(matches!(
                err,
                BlockDeviceDispatchError::StateViolation(
                    BlockDeviceLifecycleState::OfflineTerminal
                )
            ));
        }
    }
}

#[cfg(test)]
mod adapter_topology_tests {
    use super::*;
    use tidefs_block_allocator::{BlockAllocator, DeviceId, Region};

    fn make_region(block_count: u64) -> Region {
        let len = BlockAllocator::required_bitmap_bytes(block_count);
        Region::new(0, len)
    }

    #[test]
    fn geometry_record_to_device_topology_conversion() {
        let geom = BlockVolumeGeometryRecord::with_topology(
            BlockVolumeId::new(1),
            4096,
            1024,
            0,
            DeviceTopology {
                logical_sector_size: 512,
                physical_sector_size: 4096,
                optimal_io_size: 131072,
                alignment_offset: 0,
                min_io_size: 4096,
            },
        );

        let dt = geom.to_device_topology();
        assert_eq!(dt.logical_sector_size, 512);
        assert_eq!(dt.physical_sector_size, 4096);
        assert_eq!(dt.optimal_io_size, 131072);
        assert_eq!(dt.alignment_offset, 0);
        assert_eq!(dt.min_io_size, 4096);
    }

    #[test]
    fn geometry_record_default_new_has_512_byte_sectors() {
        let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 1024, 0);

        let dt = geom.to_device_topology();
        assert_eq!(dt.logical_sector_size, 512);
        assert_eq!(dt.physical_sector_size, 512);
        assert_eq!(dt.min_io_size, 0);
    }

    #[test]
    fn device_topology_flows_from_adapter_to_allocator() {
        // Create a synthetic geometry record with 512e-style topology:
        // 512-byte logical sectors with a 4K physical placement preference.
        let geom = BlockVolumeGeometryRecord::with_topology(
            BlockVolumeId::new(0),
            4096,
            256,
            0,
            DeviceTopology {
                logical_sector_size: 512,
                physical_sector_size: 4096,
                optimal_io_size: 0,
                alignment_offset: 0,
                min_io_size: 0,
            },
        );
        let dt = geom.to_device_topology();

        // Create an allocator and register the device.
        let ba = BlockAllocator::new(256, 4096, make_region(256));
        ba.register_device(DeviceId(geom.volume_id.0 as u32), dt, 0, 256 * 4096)
            .unwrap();

        assert_eq!(ba.registered_device_count(), 1);

        // Verify the allocator resolves the 4K topology for offsets within
        // the device range.
        let topo = ba.topology_for(0).unwrap();
        assert_eq!(topo.logical_sector_size, 512);
        assert_eq!(topo.sector_size, 4096);

        // offset=1, length=4096 inward-rounds to the 512-byte logical-sector
        // range [512, 4096), which still covers one allocator block.
        let blocks = ba.alloc_bytes_at(1, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);

        // A sub-logical-sector range cannot preserve any aligned bytes.
        let err = ba.alloc_bytes_at(1, 512).unwrap_err();
        assert_eq!(err, tidefs_block_allocator::AllocError::AlignmentImpossible);

        // offset=0, length=4096 → aligned.
        let blocks = ba.alloc_bytes_at(0, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn two_devices_with_different_geometries_flow_to_allocator() {
        // Device 0: 512-byte sectors.
        let geom0 = BlockVolumeGeometryRecord::with_topology(
            BlockVolumeId::new(0),
            4096,
            256,
            0,
            DeviceTopology::default(),
        );
        // Device 1: 4K sectors.
        let geom1 = BlockVolumeGeometryRecord::with_topology(
            BlockVolumeId::new(1),
            4096,
            256,
            0,
            DeviceTopology {
                logical_sector_size: 4096,
                physical_sector_size: 4096,
                optimal_io_size: 0,
                alignment_offset: 0,
                min_io_size: 0,
            },
        );

        let ba = BlockAllocator::new(512, 4096, make_region(512));
        ba.register_device(DeviceId(0), geom0.to_device_topology(), 0, 256 * 4096)
            .unwrap();
        ba.register_device(
            DeviceId(1),
            geom1.to_device_topology(),
            256 * 4096,
            256 * 4096,
        )
        .unwrap();

        assert_eq!(ba.registered_device_count(), 2);

        // dev0 topology
        let topo0 = ba.topology_for(0).unwrap();
        assert_eq!(topo0.sector_size, 512);
        // dev1 topology
        let topo1 = ba.topology_for(256 * 4096).unwrap();
        assert_eq!(topo1.sector_size, 4096);

        // Cross-device allocation rejected.
        let err = ba.alloc_bytes_at(0, 512 * 4096).unwrap_err();
        assert_eq!(err, tidefs_block_allocator::AllocError::MixedDeviceTopology);
    }
}
