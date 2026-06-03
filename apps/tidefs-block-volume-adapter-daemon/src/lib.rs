// Library target for tidefs-block-volume-adapter-daemon.
// Exposes the daemon's product module graph to integration tests and library
// consumers. The binary target at main.rs has its own root; the library
// target duplicates the necessary crate-level items without publishing
// fake ublk-device simulators as product API.

#![deny(clippy::all)]
// clippy::pedantic is allowed for now; future chunks should whittle down this
// allow list by fixing one pedantic lint group at a time.
#![allow(clippy::pedantic)]
#![deny(unsafe_code)]
#![allow(dead_code, unused_imports)]
use std::error::Error;
use std::fmt;

use tidefs_block_volume_adapter_core::{
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeQueuePolicyRecord,
    BlockVolumeQueueRuntime, BlockVolumeQueueSetRecord,
};
use tidefs_types_package_profile_catalog::BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE;
use tidefs_ublk_abi::{
    params_size, UblkParamBasic, UblkParamDiscard, UblkParamSegment, UblkParams,
    UBLK_ABI_GATE_OW_301I, UBLK_ATTR_FUA, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH,
    UBLK_MIN_SEGMENT_SIZE, UBLK_PARAM_TYPE_BASIC, UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_SEGMENT,
};
pub mod kernel_check;
pub mod signal_shutdown;

// Re-export modules for integration tests
mod block_device_validation;
pub mod shutdown;
pub mod storage_backend;
pub mod ublk_completion;
pub mod ublk_control_open;
pub mod ublk_io;
pub mod ublk_io_handler;
pub mod ublk_io_uring;

// Re-export key integration-test types that are defined in private
// sub-modules of ublk_control_open.
pub use ublk_control_open::data_queue_worker::{
    DataQueueWorker, DataQueueWorkerError, DataQueueWorkerReport, DataQueueWorkerResultEntry,
};

// ── Crate-level constants ─────────────────────────────────────────────

// ── barrier_audit: ublk barrier tracing audit log ──────────────────
// Emits structured JSON-line audit entries for every flush and
// FUA-write barrier processed by the ublk I/O handler.

use std::time::{SystemTime, UNIX_EPOCH};

/// Distinctive prefix for barrier audit lines in stderr.
pub const BARRIER_AUDIT_PREFIX: &str = "UBLK_BARRIER_AUDIT";

/// Identifies the kind of barrier that triggered the audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierType {
    Flush,
    FuaWrite,
}

impl BarrierType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Flush => "FLUSH",
            Self::FuaWrite => "FUA_WRITE",
        }
    }
}

/// Outcome of a barrier operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierResult {
    Completed,
    Failed,
}

impl BarrierResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
        }
    }
}

/// Monotonic barrier audit log for the ublk I/O serving path.
///
/// Records structured JSON-line entries on stderr for each barrier
/// (flush or FUA write) processed by the ublk data-queue I/O loop.
/// The `committed_root` field captures the txg committed-root pointer
/// (if available from the backend) to tie guest barriers directly to
/// committed-root publication validation.
#[derive(Debug)]
pub struct BarrierAuditLog {
    next_seq: u64,
    /// Count of flush barriers recorded.
    pub flush_count: u64,
    /// Count of FUA-write barriers recorded.
    pub fua_write_count: u64,
    /// Count of barrier operations that failed.
    pub failed_count: u64,
}

impl BarrierAuditLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            flush_count: 0,
            fua_write_count: 0,
            failed_count: 0,
        }
    }

    pub fn record(&mut self, barrier_type: BarrierType, result: BarrierResult) {
        self.record_with_root(barrier_type, result, None);
    }

    /// Record a barrier event with an optional committed-root anchor.
    ///
    /// `committed_root_opt` encodes the txg committed-root pointer as a hex
    /// string when the backend exposes it (e.g. `BlockVolumeObjectStoreBackend`).
    /// File-image backends produce `None`.
    pub fn record_with_root(
        &mut self,
        barrier_type: BarrierType,
        result: BarrierResult,
        committed_root_opt: Option<u64>,
    ) {
        match barrier_type {
            BarrierType::Flush => self.flush_count += 1,
            BarrierType::FuaWrite => self.fua_write_count += 1,
        };
        if result == BarrierResult::Failed {
            self.failed_count += 1;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root_part = if let Some(cr) = committed_root_opt {
            format!(",\"committed_root\":\"0x{cr:016x}\"")
        } else {
            String::new()
        };
        eprintln!(
            "{BARRIER_AUDIT_PREFIX} {{\"seq\":{seq},\"type\":\"{}\",\"ts_ns\":{now},\"result\":\"{}\"{root_part}}}",
            barrier_type.as_str(),
            result.as_str(),
        );
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Total barrier entries recorded.
    #[must_use]
    pub fn total_entries(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }
}

impl Default for BarrierAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

pub const LINUX_SECTOR_SIZE_BYTES: usize = 512;

pub(crate) const NON_CLAIMS: &[&str] = &[
    "no_dev_ublk_control",
    "no_fio_validation",
    "no_mkfs_mount_or_guest_filesystem",
    "no_production_resize_failover_runtime",
    "parent_ow_301_pc_005_pc_012_remain_open",
];

// ── AppError (shared with main.rs) ────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppError {
    message: String,
}

impl AppError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block-volume adapter app surface failed: {}",
            self.message
        )
    }
}

impl Error for AppError {}

// ── Shared functions (duplicated from main.rs for library target) ─────

pub(crate) fn print_plan_step(step: tidefs_ublk_abi::UblkControlPlanStep) {
    let request = step.request();
    println!("plan.{}.command={}", step.ordinal, step.command.as_str());
    println!(
        "plan.{}.command_nr=0x{:02x}",
        step.ordinal,
        step.command.number()
    );
    println!("plan.{}.ioctl_raw=0x{:08x}", step.ordinal, request.raw());
    println!(
        "plan.{}.ioctl_direction={}",
        step.ordinal,
        request.direction().as_str()
    );
    println!("plan.{}.ioctl_type=u", step.ordinal);
    println!("plan.{}.ioctl_size={}", step.ordinal, request.size());
    println!(
        "plan.{}.mutation_class={}",
        step.ordinal,
        step.mutation_class.as_str()
    );
    println!(
        "plan.{}.mutates_control_state={}",
        step.ordinal,
        step.mutates_control_state()
    );
}

pub(crate) fn build_ublk_parameter_spec_report() -> Result<UblkParameterSpecReport, AppError> {
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_091), 4096, 1024, 1);
    build_ublk_parameter_spec_report_with_geometry(geometry, 4, 64)
}

pub(crate) fn build_ublk_parameter_spec_report_with_geometry(
    geometry: BlockVolumeGeometryRecord,
    nr_hw_queues: u16,
    queue_depth: u16,
) -> Result<UblkParameterSpecReport, AppError> {
    let max_inflight_bytes = 1024 * 1024;
    let shard_count = nr_hw_queues as usize;
    let max_inflight_requests = queue_depth as usize;
    let runtime = BlockVolumeQueueRuntime::open(
        geometry,
        shard_count,
        max_inflight_requests,
        max_inflight_bytes,
    )
    .ok_or_else(|| AppError::new("build demo block-volume queue runtime"))?;
    build_ublk_parameters(geometry, &runtime.queue_policy, &runtime.queue_set)
        .map_err(|err| AppError::new(format!("project ublk parameters: {}", err.as_str())))
}

fn build_ublk_parameters(
    geometry: BlockVolumeGeometryRecord,
    queue_policy: &BlockVolumeQueuePolicyRecord,
    queue_set: &BlockVolumeQueueSetRecord,
) -> Result<UblkParameterSpecReport, UblkParameterSpecError> {
    if geometry.block_size_bytes == 0 {
        return Err(UblkParameterSpecError::ZeroBlockSize);
    }
    if geometry.block_count == 0 {
        return Err(UblkParameterSpecError::ZeroBlockCount);
    }
    if !geometry.block_size_bytes.is_power_of_two() {
        return Err(UblkParameterSpecError::NonPowerOfTwoBlockSize);
    }
    if geometry.block_size_bytes < LINUX_SECTOR_SIZE_BYTES {
        return Err(UblkParameterSpecError::BlockSizeBelowLinuxSector);
    }
    let capacity_bytes = geometry
        .capacity_bytes()
        .ok_or(UblkParameterSpecError::CapacityOverflow)?;
    if capacity_bytes % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(UblkParameterSpecError::CapacityNotSectorAligned);
    }
    if queue_policy.shard_count != queue_set.shard_count {
        return Err(UblkParameterSpecError::QueuePolicyMismatch);
    }
    if queue_set.block_count != geometry.block_count {
        return Err(UblkParameterSpecError::QueueSetGeometryMismatch);
    }
    if queue_set.shard_count == 0 {
        return Err(UblkParameterSpecError::ZeroQueues);
    }
    if queue_set.shard_count > usize::from(UBLK_MAX_NR_QUEUES) {
        return Err(UblkParameterSpecError::TooManyQueues);
    }
    if queue_policy.max_inflight_requests == 0 {
        return Err(UblkParameterSpecError::ZeroQueueDepth);
    }
    if queue_policy.max_inflight_requests > usize::from(UBLK_MAX_QUEUE_DEPTH) {
        return Err(UblkParameterSpecError::QueueDepthTooLarge);
    }
    if queue_policy.max_inflight_bytes < geometry.block_size_bytes {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowBlockSize);
    }
    if queue_policy.max_inflight_bytes % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(UblkParameterSpecError::MaxInflightBytesNotSectorAligned);
    }
    if queue_policy.max_inflight_bytes < UBLK_MIN_SEGMENT_SIZE as usize {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowUblkSegmentMinimum);
    }

    let queue_count =
        u16::try_from(queue_set.shard_count).map_err(|_| UblkParameterSpecError::TooManyQueues)?;
    let queue_depth = u16::try_from(queue_policy.max_inflight_requests)
        .map_err(|_| UblkParameterSpecError::QueueDepthTooLarge)?;
    let dev_sectors = u64::try_from(capacity_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::CapacityOverflow)?;
    let max_sectors = u32::try_from(queue_policy.max_inflight_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::MaxSectorsOverflow)?;
    let block_sectors = u32::try_from(geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::BlockSectorsOverflow)?;
    let (discard_granularity, discard_sectors) = if geometry.admits_discard() {
        (
            project_discard_granularity_bytes(geometry)?,
            project_discard_granularity_sectors(geometry, block_sectors)?,
        )
    } else {
        (
            u32::try_from(geometry.block_size_bytes)
                .map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)?,
            block_sectors,
        )
    };
    let segment_size = u32::try_from(queue_policy.max_inflight_bytes)
        .map_err(|_| UblkParameterSpecError::MaxSegmentSizeOverflow)?;
    let block_shift = geometry.block_size_bytes.trailing_zeros() as u8;
    let logical_bs_shift = device_topology_shift(geometry.logical_sector_size, block_shift);
    let physical_bs_shift = device_topology_shift(geometry.physical_sector_size, block_shift);
    let io_opt_shift = if geometry.optimal_io_size > 0 {
        device_topology_shift(geometry.optimal_io_size, block_shift)
    } else {
        block_shift
    };
    let io_min_shift = if geometry.min_io_size > 0 {
        device_topology_shift(geometry.min_io_size, block_shift)
    } else {
        block_shift
    };
    let param_types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT;
    let params = UblkParams {
        len: params_size() as u32,
        types: param_types,
        basic: UblkParamBasic {
            attrs: UBLK_ATTR_FUA,
            logical_bs_shift,
            physical_bs_shift,
            io_opt_shift,
            io_min_shift,
            max_sectors,
            chunk_sectors: discard_sectors,
            dev_sectors,
            virt_boundary_mask: 0,
        },
        discard: UblkParamDiscard {
            discard_alignment: 0,
            discard_granularity,
            max_discard_sectors: if geometry.admits_discard() {
                max_sectors
            } else {
                0
            },
            max_write_zeroes_sectors: max_sectors,
            max_discard_segments: if geometry.admits_discard() { 1 } else { 0 },
            reserved0: 0,
        },
        seg: UblkParamSegment {
            seg_boundary_mask: u64::from(UBLK_MIN_SEGMENT_SIZE) - 1,
            max_segment_size: segment_size,
            max_segments: 1,
            pad: [0; 2],
        },
        ..UblkParams::default()
    };

    Ok(UblkParameterSpecReport {
        geometry,
        queue_count,
        queue_depth,
        max_inflight_bytes: queue_policy.max_inflight_bytes,
        params,
        params_set_ioctl_issued: false,
    })
}

/// Compute a block-shift value (log2) from a device topology size in bytes.
///
/// The returned shift must be at least `fallback_shift` (derived from
/// the volume block size). Values that are not positive powers of two
/// fall back to `fallback_shift`.
pub(crate) fn device_topology_shift(size_bytes: u64, fallback_shift: u8) -> u8 {
    if size_bytes == 0 || !size_bytes.is_power_of_two() {
        return fallback_shift;
    }
    let shift = size_bytes.trailing_zeros() as u8;
    if shift < fallback_shift {
        fallback_shift
    } else {
        shift
    }
}

fn project_discard_granularity_bytes(
    geometry: BlockVolumeGeometryRecord,
) -> Result<u32, UblkParameterSpecError> {
    let Some(bytes) = geometry
        .discard_granularity_blocks
        .checked_mul(geometry.block_size_bytes)
    else {
        return Err(UblkParameterSpecError::DiscardGranularityOverflow);
    };
    u32::try_from(bytes).map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)
}

fn project_discard_granularity_sectors(
    geometry: BlockVolumeGeometryRecord,
    block_sectors: u32,
) -> Result<u32, UblkParameterSpecError> {
    let blocks = u32::try_from(geometry.discard_granularity_blocks)
        .map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)?;
    blocks
        .checked_mul(block_sectors)
        .ok_or(UblkParameterSpecError::DiscardGranularityOverflow)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UblkParameterSpecReport {
    geometry: BlockVolumeGeometryRecord,
    queue_count: u16,
    queue_depth: u16,
    max_inflight_bytes: usize,
    params: UblkParams,
    params_set_ioctl_issued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkParameterSpecError {
    ZeroBlockSize,
    ZeroBlockCount,
    NonPowerOfTwoBlockSize,
    BlockSizeBelowLinuxSector,
    CapacityOverflow,
    CapacityNotSectorAligned,
    QueuePolicyMismatch,
    QueueSetGeometryMismatch,
    ZeroQueues,
    TooManyQueues,
    ZeroQueueDepth,
    QueueDepthTooLarge,
    MaxInflightBytesBelowBlockSize,
    MaxInflightBytesNotSectorAligned,
    MaxInflightBytesBelowUblkSegmentMinimum,
    MaxSectorsOverflow,
    BlockSectorsOverflow,
    DiscardGranularityOverflow,
    MaxSegmentSizeOverflow,
}

impl UblkParameterSpecError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroBlockSize => "zero_block_size",
            Self::ZeroBlockCount => "zero_block_count",
            Self::NonPowerOfTwoBlockSize => "non_power_of_two_block_size",
            Self::BlockSizeBelowLinuxSector => "block_size_below_linux_sector",
            Self::CapacityOverflow => "capacity_overflow",
            Self::CapacityNotSectorAligned => "capacity_not_sector_aligned",
            Self::QueuePolicyMismatch => "queue_policy_mismatch",
            Self::QueueSetGeometryMismatch => "queue_set_geometry_mismatch",
            Self::ZeroQueues => "zero_queues",
            Self::TooManyQueues => "too_many_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::MaxInflightBytesBelowBlockSize => "max_inflight_bytes_below_block_size",
            Self::MaxInflightBytesNotSectorAligned => "max_inflight_bytes_not_sector_aligned",
            Self::MaxInflightBytesBelowUblkSegmentMinimum => {
                "max_inflight_bytes_below_ublk_segment_minimum"
            }
            Self::MaxSectorsOverflow => "max_sectors_overflow",
            Self::BlockSectorsOverflow => "block_sectors_overflow",
            Self::DiscardGranularityOverflow => "discard_granularity_overflow",
            Self::MaxSegmentSizeOverflow => "max_segment_size_overflow",
        }
    }
}
