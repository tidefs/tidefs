// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use crate::storage_backend::BlockDeviceGeometry;
use crate::LINUX_SECTOR_SIZE_BYTES;
use tidefs_block_volume_adapter_core::{
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeQueuePolicyRecord,
    BlockVolumeQueueSetRecord,
};
use tidefs_ublk_abi::{
    params_size, UblkParamBasic, UblkParamDiscard, UblkParamSegment, UblkParams, UBLK_ATTR_FUA,
    UBLK_ATTR_READ_ONLY, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH, UBLK_MIN_SEGMENT_SIZE,
    UBLK_PARAM_TYPE_BASIC, UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_SEGMENT,
};

pub(crate) fn build_ublk_parameter_spec_report(
) -> Result<UblkParameterSpecReport, UblkParameterSpecError> {
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_091), 4096, 1024, 1);
    build_ublk_parameter_spec_report_with_geometry(geometry, 4, 64, false)
}

pub(crate) fn build_ublk_parameter_spec_report_with_geometry(
    geometry: impl Into<BlockDeviceGeometry>,
    nr_hw_queues: u16,
    queue_depth: u16,
    read_only: bool,
) -> Result<UblkParameterSpecReport, UblkParameterSpecError> {
    let geometry = geometry.into();
    let max_inflight_bytes = 1024 * 1024;
    let shard_count = nr_hw_queues as usize;
    build_ublk_parameters_for_queue(
        geometry,
        shard_count,
        shard_count,
        geometry.block_count,
        queue_depth as usize,
        max_inflight_bytes,
        read_only,
    )
}

pub(crate) fn build_ublk_parameters(
    geometry: impl Into<BlockDeviceGeometry>,
    queue_policy: &BlockVolumeQueuePolicyRecord,
    queue_set: &BlockVolumeQueueSetRecord,
) -> Result<UblkParameterSpecReport, UblkParameterSpecError> {
    let geometry = geometry.into();
    build_ublk_parameters_for_queue(
        geometry,
        queue_policy.shard_count,
        queue_set.shard_count,
        queue_set.block_count,
        queue_policy.max_inflight_requests,
        queue_policy.max_inflight_bytes,
        false,
    )
}

fn build_ublk_parameters_for_queue(
    geometry: BlockDeviceGeometry,
    policy_shard_count: usize,
    queue_set_shard_count: usize,
    queue_set_block_count: usize,
    max_inflight_requests: usize,
    max_inflight_bytes: usize,
    read_only: bool,
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
    if policy_shard_count != queue_set_shard_count {
        return Err(UblkParameterSpecError::QueuePolicyMismatch);
    }
    if queue_set_block_count != geometry.block_count {
        return Err(UblkParameterSpecError::QueueSetGeometryMismatch);
    }
    if queue_set_shard_count == 0 {
        return Err(UblkParameterSpecError::ZeroQueues);
    }
    if queue_set_shard_count > usize::from(UBLK_MAX_NR_QUEUES) {
        return Err(UblkParameterSpecError::TooManyQueues);
    }
    if max_inflight_requests == 0 {
        return Err(UblkParameterSpecError::ZeroQueueDepth);
    }
    if max_inflight_requests > usize::from(UBLK_MAX_QUEUE_DEPTH) {
        return Err(UblkParameterSpecError::QueueDepthTooLarge);
    }
    if max_inflight_bytes < geometry.block_size_bytes {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowBlockSize);
    }
    if max_inflight_bytes % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(UblkParameterSpecError::MaxInflightBytesNotSectorAligned);
    }
    if max_inflight_bytes < UBLK_MIN_SEGMENT_SIZE as usize {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowUblkSegmentMinimum);
    }

    let queue_count =
        u16::try_from(queue_set_shard_count).map_err(|_| UblkParameterSpecError::TooManyQueues)?;
    let queue_depth = u16::try_from(max_inflight_requests)
        .map_err(|_| UblkParameterSpecError::QueueDepthTooLarge)?;
    let dev_sectors = u64::try_from(capacity_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::CapacityOverflow)?;
    let max_sectors = u32::try_from(max_inflight_bytes / LINUX_SECTOR_SIZE_BYTES)
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
    let segment_size = u32::try_from(max_inflight_bytes)
        .map_err(|_| UblkParameterSpecError::MaxSegmentSizeOverflow)?;
    let block_shift = geometry.block_size_bytes.trailing_zeros() as u8;
    let logical_bs_shift = device_topology_shift(geometry.logical_sector_size, block_shift);
    let physical_bs_shift = device_topology_shift(geometry.physical_sector_size, block_shift);
    let io_opt_shift = device_topology_shift(geometry.optimal_io_size, block_shift);
    let io_min_shift = device_topology_shift(geometry.min_io_size, block_shift);
    let params = UblkParams {
        len: params_size() as u32,
        types: UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT,
        basic: UblkParamBasic {
            attrs: UBLK_ATTR_FUA | if read_only { UBLK_ATTR_READ_ONLY } else { 0 },
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
        max_inflight_bytes,
        params,
        params_set_ioctl_issued: false,
    })
}

fn device_topology_shift(size_bytes: u64, fallback_shift: u8) -> u8 {
    if size_bytes == 0 || !size_bytes.is_power_of_two() {
        return fallback_shift;
    }
    size_bytes.trailing_zeros().max(u32::from(fallback_shift)) as u8
}

fn project_discard_granularity_bytes(
    geometry: BlockDeviceGeometry,
) -> Result<u32, UblkParameterSpecError> {
    let bytes = geometry
        .discard_granularity_blocks
        .checked_mul(geometry.block_size_bytes)
        .ok_or(UblkParameterSpecError::DiscardGranularityOverflow)?;
    u32::try_from(bytes).map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)
}

fn project_discard_granularity_sectors(
    geometry: BlockDeviceGeometry,
    block_sectors: u32,
) -> Result<u32, UblkParameterSpecError> {
    let blocks = u32::try_from(geometry.discard_granularity_blocks)
        .map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)?;
    blocks
        .checked_mul(block_sectors)
        .ok_or(UblkParameterSpecError::DiscardGranularityOverflow)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UblkParameterSpecReport {
    pub(crate) geometry: BlockDeviceGeometry,
    pub(crate) queue_count: u16,
    pub(crate) queue_depth: u16,
    pub(crate) max_inflight_bytes: usize,
    pub(crate) params: UblkParams,
    pub(crate) params_set_ioctl_issued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UblkParameterSpecError {
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
    pub(crate) const fn as_str(self) -> &'static str {
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

impl std::fmt::Display for UblkParameterSpecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_pool_geometry_advertises_only_atomic_volume_io() {
        let geometry = BlockDeviceGeometry::from_pool(
            tidefs_pool_runtime::VolumeGeometry::new(4 * 1024 * 1024)
                .expect("create Pool volume geometry"),
        )
        .expect("project Pool volume geometry");

        let report = build_ublk_parameter_spec_report_with_geometry(geometry, 1, 64, false)
            .expect("project ublk parameters");

        assert_eq!(report.params.basic.logical_bs_shift, 12);
        assert_eq!(report.params.basic.physical_bs_shift, 12);
        assert_eq!(report.params.basic.io_min_shift, 12);
    }
}
