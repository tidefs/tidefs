// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeDurabilityClass, BlockVolumeGeometryRecord,
    BlockVolumeRequestClass,
};
use tidefs_ublk_abi::{
    UblkSrvIoDesc, UBLK_IO_F_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ,
    UBLK_IO_OP_REPORT_ZONES, UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES,
    UBLK_IO_OP_ZONE_APPEND, UBLK_IO_OP_ZONE_CLOSE, UBLK_IO_OP_ZONE_FINISH, UBLK_IO_OP_ZONE_OPEN,
    UBLK_IO_OP_ZONE_RESET, UBLK_IO_OP_ZONE_RESET_ALL,
};

use crate::LINUX_SECTOR_SIZE_BYTES;

pub const DEMO_BUFFER_ADDR: u64 = 0x1000_0000;
const SUPPORTED_RAW_FLAGS: u32 = UBLK_IO_F_FUA;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UblkDescriptorClass {
    request_class: BlockVolumeRequestClass,
    durability_class: BlockVolumeDurabilityClass,
    expects_range: bool,
    expects_buffer: bool,
    expects_payload: bool,
}

const fn descriptor_class(
    request_class: BlockVolumeRequestClass,
    durability_class: BlockVolumeDurabilityClass,
    expects_range: bool,
    expects_buffer: bool,
    expects_payload: bool,
) -> UblkDescriptorClass {
    UblkDescriptorClass {
        request_class,
        durability_class,
        expects_range,
        expects_buffer,
        expects_payload,
    }
}

const fn classify_descriptor(
    descriptor: UblkSrvIoDesc,
) -> Result<UblkDescriptorClass, UblkIoDescriptorError> {
    match descriptor.op() {
        UBLK_IO_OP_READ => Ok(descriptor_class(
            BlockVolumeRequestClass::Read,
            BlockVolumeDurabilityClass::None,
            true,
            true,
            true,
        )),
        UBLK_IO_OP_WRITE => {
            let durability_class = if descriptor.op_flags & UBLK_IO_F_FUA != 0 {
                BlockVolumeDurabilityClass::FuaRequired
            } else {
                BlockVolumeDurabilityClass::None
            };
            Ok(descriptor_class(
                BlockVolumeRequestClass::Write,
                durability_class,
                true,
                true,
                true,
            ))
        }
        UBLK_IO_OP_FLUSH => Ok(descriptor_class(
            BlockVolumeRequestClass::Flush,
            BlockVolumeDurabilityClass::FlushRequired,
            false,
            false,
            false,
        )),
        UBLK_IO_OP_DISCARD => Ok(descriptor_class(
            BlockVolumeRequestClass::Discard,
            BlockVolumeDurabilityClass::None,
            true,
            false,
            false,
        )),
        UBLK_IO_OP_WRITE_ZEROES => Ok(descriptor_class(
            BlockVolumeRequestClass::WriteZeroes,
            BlockVolumeDurabilityClass::None,
            true,
            false,
            false,
        )),
        UBLK_IO_OP_WRITE_SAME => Err(UblkIoDescriptorError::UnsupportedWriteSame),
        UBLK_IO_OP_ZONE_OPEN
        | UBLK_IO_OP_ZONE_CLOSE
        | UBLK_IO_OP_ZONE_FINISH
        | UBLK_IO_OP_ZONE_APPEND
        | UBLK_IO_OP_ZONE_RESET_ALL
        | UBLK_IO_OP_ZONE_RESET
        | UBLK_IO_OP_REPORT_ZONES => Err(UblkIoDescriptorError::UnsupportedZonedOperation),
        _ => Err(UblkIoDescriptorError::UnsupportedOperation),
    }
}

fn project_range(
    geometry: BlockVolumeGeometryRecord,
    descriptor: UblkSrvIoDesc,
) -> Result<BlockRangeRecord, UblkIoDescriptorError> {
    let sectors_per_block = geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    if sectors_per_block == 0 {
        return Err(UblkIoDescriptorError::BlockSizeBelowLinuxSector);
    }
    let start_sector = usize::try_from(descriptor.start_sector)
        .map_err(|_| UblkIoDescriptorError::RangeOverflow)?;
    let sector_count = usize::try_from(descriptor.count_or_zones)
        .map_err(|_| UblkIoDescriptorError::RangeOverflow)?;
    if sector_count == 0 {
        return Err(UblkIoDescriptorError::ZeroLengthDataOperation);
    }
    if start_sector % sectors_per_block != 0 || sector_count % sectors_per_block != 0 {
        return Err(UblkIoDescriptorError::SectorRangeNotBlockAligned);
    }
    let start_block = start_sector / sectors_per_block;
    let block_count = sector_count / sectors_per_block;
    let end_block = start_block
        .checked_add(block_count)
        .ok_or(UblkIoDescriptorError::RangeOverflow)?;
    if end_block > geometry.block_count {
        return Err(UblkIoDescriptorError::OutOfRange);
    }
    Ok(BlockRangeRecord::new(start_block, block_count))
}

pub const fn io_desc(
    op: u8,
    raw_flags: u32,
    start_sector: u64,
    count_or_zones: u32,
    addr: u64,
) -> UblkSrvIoDesc {
    UblkSrvIoDesc {
        op_flags: op as u32 | raw_flags,
        count_or_zones,
        start_sector,
        addr,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoDescriptorError {
    QueueRuntimeUnavailable,
    UnsupportedOperation,
    UnsupportedWriteSame,
    UnsupportedZonedOperation,
    UnsupportedFlags,
    FuaOnlyValidForWrite,
    BlockSizeBelowLinuxSector,
    ZeroLengthDataOperation,
    SectorRangeNotBlockAligned,
    RangeOverflow,
    RangeByteOverflow,
    OutOfRange,
    RangeOnFlush,
    TransferLengthMismatch,
    UnexpectedPayload,
    MissingBufferAddress,
    UnexpectedBufferAddress,
    SubmissionContextRefused,
}

impl UblkIoDescriptorError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::QueueRuntimeUnavailable => "queue_runtime_unavailable",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::UnsupportedWriteSame => "unsupported_write_same",
            Self::UnsupportedZonedOperation => "unsupported_zoned_operation",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::FuaOnlyValidForWrite => "fua_only_valid_for_write",
            Self::BlockSizeBelowLinuxSector => "block_size_below_linux_sector",
            Self::ZeroLengthDataOperation => "zero_length_data_operation",
            Self::SectorRangeNotBlockAligned => "sector_range_not_block_aligned",
            Self::RangeOverflow => "range_overflow",
            Self::RangeByteOverflow => "range_byte_overflow",
            Self::OutOfRange => "out_of_range",
            Self::RangeOnFlush => "range_on_flush",
            Self::TransferLengthMismatch => "transfer_length_mismatch",
            Self::UnexpectedPayload => "unexpected_payload",
            Self::MissingBufferAddress => "missing_buffer_address",
            Self::UnexpectedBufferAddress => "unexpected_buffer_address",
            Self::SubmissionContextRefused => "submission_context_refused",
        }
    }
}

/// Dispatch a ublk I/O descriptor through the io_uring dispatcher.
///
/// Classifies the descriptor, validates it against the geometry,
/// builds the appropriate SQE, submits, waits for completion,
/// and returns the byte count (for reads and writes) or unit for
/// non-data operations.
///
/// # Safety
///
/// The caller must ensure `dst` or `src` buffer lifetimes outlive
/// the I/O operation.
pub fn dispatch_ublk_io_descriptor(
    dispatcher: &mut crate::ublk_io_uring::UblkIoUringDispatcher,
    descriptor: UblkSrvIoDesc,
    geometry: BlockVolumeGeometryRecord,
    src_or_dst: Option<&mut [u8]>,
) -> Result<usize, UblkIoDispatchError> {
    let raw_flags = descriptor.op_flags & !0xff;
    let unsupported_flags = raw_flags & !SUPPORTED_RAW_FLAGS;
    if unsupported_flags != 0 {
        return Err(UblkIoDispatchError::UnsupportedFlags);
    }

    let class = classify_descriptor(descriptor)?;

    if raw_flags & UBLK_IO_F_FUA != 0 && class.request_class != BlockVolumeRequestClass::Write {
        return Err(UblkIoDispatchError::FuaOnlyValidForWrite);
    }

    let range = if class.expects_range {
        let block_range = project_range(geometry, descriptor)?;
        let range_bytes = block_range
            .block_count
            .checked_mul(geometry.block_size_bytes)
            .ok_or(UblkIoDispatchError::RangeByteOverflow)?;
        Some((block_range, range_bytes))
    } else {
        if descriptor.start_sector != 0 || descriptor.count_or_zones != 0 {
            return Err(UblkIoDispatchError::RangeOnFlush);
        }
        None
    };

    match class.request_class {
        BlockVolumeRequestClass::Read => {
            let (range, range_bytes) = range.ok_or(UblkIoDispatchError::MissingRange)?;
            let dst = src_or_dst.ok_or(UblkIoDispatchError::MissingBuffer)?;
            let byte_offset = (range.start_block as u64)
                .checked_mul(geometry.block_size_bytes as u64)
                .ok_or(UblkIoDispatchError::RangeByteOverflow)?;
            let n = dispatcher
                .read_at(byte_offset, dst)
                .map_err(UblkIoDispatchError::IoUring)?;
            if n < range_bytes {
                return Err(UblkIoDispatchError::ShortRead {
                    expected: range_bytes,
                    got: n,
                });
            }
            Ok(n)
        }
        BlockVolumeRequestClass::Write => {
            let (range, range_bytes) = range.ok_or(UblkIoDispatchError::MissingRange)?;
            let src = src_or_dst.ok_or(UblkIoDispatchError::MissingBuffer)?;
            let byte_offset = (range.start_block as u64)
                .checked_mul(geometry.block_size_bytes as u64)
                .ok_or(UblkIoDispatchError::RangeByteOverflow)?;
            let n = dispatcher
                .write_at(byte_offset, src)
                .map_err(UblkIoDispatchError::IoUring)?;
            if n < range_bytes {
                return Err(UblkIoDispatchError::ShortWrite {
                    expected: range_bytes,
                    got: n,
                });
            }
            if class.durability_class == BlockVolumeDurabilityClass::FuaRequired {
                dispatcher.flush().map_err(UblkIoDispatchError::IoUring)?;
            }
            Ok(n)
        }
        BlockVolumeRequestClass::Flush => {
            dispatcher.flush().map_err(UblkIoDispatchError::IoUring)?;
            Ok(0)
        }
        BlockVolumeRequestClass::Discard => {
            let (range, range_bytes) = range.ok_or(UblkIoDispatchError::MissingRange)?;
            let byte_offset = (range.start_block as u64)
                .checked_mul(geometry.block_size_bytes as u64)
                .ok_or(UblkIoDispatchError::RangeByteOverflow)?;
            dispatcher
                .discard_at(byte_offset, range_bytes as u64)
                .map_err(UblkIoDispatchError::IoUring)?;
            Ok(0)
        }
        BlockVolumeRequestClass::WriteZeroes => {
            let (range, range_bytes) = range.ok_or(UblkIoDispatchError::MissingRange)?;
            let byte_offset = (range.start_block as u64)
                .checked_mul(geometry.block_size_bytes as u64)
                .ok_or(UblkIoDispatchError::RangeByteOverflow)?;
            dispatcher
                .write_zeroes_at(byte_offset, range_bytes as u64)
                .map_err(UblkIoDispatchError::IoUring)?;
            Ok(0)
        }
    }
}

/// Error returned by [`dispatch_ublk_io_descriptor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UblkIoDispatchError {
    UnsupportedOperation,
    UnsupportedWriteSame,
    UnsupportedZonedOperation,
    UnsupportedFlags,
    FuaOnlyValidForWrite,
    BlockSizeBelowLinuxSector,
    ZeroLengthDataOperation,
    SectorRangeNotBlockAligned,
    RangeOverflow,
    RangeByteOverflow,
    OutOfRange,
    RangeOnFlush,
    MissingRange,
    MissingBuffer,
    ShortRead { expected: usize, got: usize },
    ShortWrite { expected: usize, got: usize },
    IoUring(crate::ublk_io_uring::UblkIoUringDispatcherError),
}

impl UblkIoDispatchError {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::UnsupportedOperation => "unsupported_operation",
            Self::UnsupportedWriteSame => "unsupported_write_same",
            Self::UnsupportedZonedOperation => "unsupported_zoned_operation",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::FuaOnlyValidForWrite => "fua_only_valid_for_write",
            Self::BlockSizeBelowLinuxSector => "block_size_below_linux_sector",
            Self::ZeroLengthDataOperation => "zero_length_data_operation",
            Self::SectorRangeNotBlockAligned => "sector_range_not_block_aligned",
            Self::RangeOverflow => "range_overflow",
            Self::RangeByteOverflow => "range_byte_overflow",
            Self::OutOfRange => "out_of_range",
            Self::RangeOnFlush => "range_on_flush",
            Self::MissingRange => "missing_range",
            Self::MissingBuffer => "missing_buffer",
            Self::ShortRead { .. } => "short_read",
            Self::ShortWrite { .. } => "short_write",
            Self::IoUring(_) => "io_uring_error",
        }
    }
}

impl From<UblkIoDescriptorError> for UblkIoDispatchError {
    fn from(refusal: UblkIoDescriptorError) -> Self {
        match refusal {
            UblkIoDescriptorError::UnsupportedOperation => Self::UnsupportedOperation,
            UblkIoDescriptorError::UnsupportedWriteSame => Self::UnsupportedWriteSame,
            UblkIoDescriptorError::UnsupportedZonedOperation => Self::UnsupportedZonedOperation,
            UblkIoDescriptorError::UnsupportedFlags => Self::UnsupportedFlags,
            UblkIoDescriptorError::FuaOnlyValidForWrite => Self::FuaOnlyValidForWrite,
            UblkIoDescriptorError::BlockSizeBelowLinuxSector => Self::BlockSizeBelowLinuxSector,
            UblkIoDescriptorError::ZeroLengthDataOperation => Self::ZeroLengthDataOperation,
            UblkIoDescriptorError::SectorRangeNotBlockAligned => Self::SectorRangeNotBlockAligned,
            UblkIoDescriptorError::RangeOverflow => Self::RangeOverflow,
            UblkIoDescriptorError::RangeByteOverflow => Self::RangeByteOverflow,
            UblkIoDescriptorError::OutOfRange => Self::OutOfRange,
            UblkIoDescriptorError::RangeOnFlush => Self::RangeOnFlush,
            UblkIoDescriptorError::TransferLengthMismatch => Self::ShortRead {
                expected: 0,
                got: 0,
            },
            UblkIoDescriptorError::UnexpectedPayload => Self::MissingBuffer,
            UblkIoDescriptorError::MissingBufferAddress => Self::MissingBuffer,
            UblkIoDescriptorError::UnexpectedBufferAddress => Self::MissingBuffer,
            UblkIoDescriptorError::SubmissionContextRefused => Self::UnsupportedOperation,
            UblkIoDescriptorError::QueueRuntimeUnavailable => Self::UnsupportedOperation,
        }
    }
}

pub const fn op_name(op: u8) -> &'static str {
    match op {
        UBLK_IO_OP_READ => "read",
        UBLK_IO_OP_WRITE => "write",
        UBLK_IO_OP_FLUSH => "flush",
        UBLK_IO_OP_DISCARD => "discard",
        UBLK_IO_OP_WRITE_SAME => "write_same",
        UBLK_IO_OP_WRITE_ZEROES => "write_zeroes",
        UBLK_IO_OP_ZONE_OPEN => "zone_open",
        UBLK_IO_OP_ZONE_CLOSE => "zone_close",
        UBLK_IO_OP_ZONE_FINISH => "zone_finish",
        UBLK_IO_OP_ZONE_APPEND => "zone_append",
        UBLK_IO_OP_ZONE_RESET_ALL => "zone_reset_all",
        UBLK_IO_OP_ZONE_RESET => "zone_reset",
        UBLK_IO_OP_REPORT_ZONES => "report_zones",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ublk_io_uring::UblkIoUringDispatcher;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use tidefs_block_volume_adapter_core::BlockVolumeId;
    use tidefs_ublk_abi::{UBLK_IO_F_FAILFAST_DEV, UBLK_IO_F_NOUNMAP};

    // ── classify_descriptor direct decode tests ──

    #[test]
    fn classify_descriptor_read_sets_request_class_and_expectations() {
        let desc = io_desc(UBLK_IO_OP_READ, 0, 64, 8, DEMO_BUFFER_ADDR);
        let class = classify_descriptor(desc).expect("read must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Read);
        assert_eq!(class.durability_class, BlockVolumeDurabilityClass::None);
        assert!(class.expects_range);
        assert!(class.expects_buffer);
        assert!(class.expects_payload);
    }

    #[test]
    fn classify_descriptor_write_sets_request_class_and_expectations() {
        let desc = io_desc(UBLK_IO_OP_WRITE, 0, 128, 16, DEMO_BUFFER_ADDR);
        let class = classify_descriptor(desc).expect("write must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Write);
        assert_eq!(class.durability_class, BlockVolumeDurabilityClass::None);
        assert!(class.expects_range);
        assert!(class.expects_buffer);
        assert!(class.expects_payload);
    }

    #[test]
    fn classify_descriptor_fua_write_promotes_durability_to_fua_required() {
        let desc = io_desc(UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 0, 8, DEMO_BUFFER_ADDR);
        let class = classify_descriptor(desc).expect("fua write must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Write);
        assert_eq!(
            class.durability_class,
            BlockVolumeDurabilityClass::FuaRequired
        );
    }

    #[test]
    fn classify_descriptor_flush_rejects_range_buffer_and_payload() {
        let desc = io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
        let class = classify_descriptor(desc).expect("flush must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(
            class.durability_class,
            BlockVolumeDurabilityClass::FlushRequired
        );
        assert!(!class.expects_range);
        assert!(!class.expects_buffer);
        assert!(!class.expects_payload);
    }

    #[test]
    fn classify_descriptor_discard_sets_correct_expectations() {
        let desc = io_desc(UBLK_IO_OP_DISCARD, 0, 32, 16, 0);
        let class = classify_descriptor(desc).expect("discard must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Discard);
        assert_eq!(class.durability_class, BlockVolumeDurabilityClass::None);
        assert!(class.expects_range);
        assert!(!class.expects_buffer);
        assert!(!class.expects_payload);
    }

    #[test]
    fn classify_descriptor_write_zeroes_sets_correct_expectations() {
        let desc = io_desc(UBLK_IO_OP_WRITE_ZEROES, 0, 48, 8, 0);
        let class = classify_descriptor(desc).expect("write_zeroes must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::WriteZeroes);
        assert_eq!(class.durability_class, BlockVolumeDurabilityClass::None);
        assert!(class.expects_range);
        assert!(!class.expects_buffer);
        assert!(!class.expects_payload);
    }

    // ── classify_descriptor error paths ──

    #[test]
    fn classify_descriptor_unknown_opcode_returns_unsupported_operation() {
        // opcode 0xFF is outside the ublk ABI defined range
        let desc = io_desc(0xFF, 0, 0, 0, 0);
        assert_eq!(
            classify_descriptor(desc),
            Err(UblkIoDescriptorError::UnsupportedOperation)
        );
    }

    #[test]
    fn classify_descriptor_zone_open_returns_unsupported_zoned() {
        let desc = io_desc(UBLK_IO_OP_ZONE_OPEN, 0, 0, 0, 0);
        assert_eq!(
            classify_descriptor(desc),
            Err(UblkIoDescriptorError::UnsupportedZonedOperation)
        );
    }

    #[test]
    fn classify_descriptor_write_same_returns_unsupported_write_same() {
        let desc = io_desc(UBLK_IO_OP_WRITE_SAME, 0, 0, 8, DEMO_BUFFER_ADDR);
        assert_eq!(
            classify_descriptor(desc),
            Err(UblkIoDescriptorError::UnsupportedWriteSame)
        );
    }

    // ── io_desc constructor and UblkSrvIoDesc field extraction ──

    #[test]
    fn io_desc_constructor_preserves_all_fields_verbatim() {
        let desc = io_desc(UBLK_IO_OP_READ, UBLK_IO_F_FUA, 1024, 32, 0xDEAD_BEEF);
        assert_eq!(desc.op(), UBLK_IO_OP_READ);
        assert_eq!(desc.flags(), UBLK_IO_F_FUA >> 8);
        assert_eq!(desc.start_sector, 1024);
        assert_eq!(desc.count_or_zones, 32);
        assert_eq!(desc.addr, 0xDEAD_BEEF);
    }

    #[test]
    fn io_desc_op_extracts_low_8_bits_from_op_flags() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH) | UBLK_IO_F_FAILFAST_DEV,
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_FLUSH);
        assert_eq!(desc.flags(), UBLK_IO_F_FAILFAST_DEV >> 8);
    }

    #[test]
    fn io_desc_flags_shifts_upper_24_bits_after_op_extraction() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE) | UBLK_IO_F_FUA | UBLK_IO_F_NOUNMAP,
            count_or_zones: 8,
            start_sector: 0,
            addr: DEMO_BUFFER_ADDR,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
        assert_eq!(desc.flags(), (UBLK_IO_F_FUA | UBLK_IO_F_NOUNMAP) >> 8);
    }

    // ── sector offset, transfer length, and flush field hygiene ──

    #[test]
    fn read_descriptor_round_trips_sector_offset_and_length() {
        let desc = io_desc(UBLK_IO_OP_READ, 0, 256, 64, DEMO_BUFFER_ADDR);
        assert_eq!(desc.op(), UBLK_IO_OP_READ);
        assert_eq!(desc.start_sector, 256);
        assert_eq!(desc.count_or_zones, 64);
        assert_ne!(desc.addr, 0);
    }

    #[test]
    fn write_descriptor_round_trips_sector_offset_and_length() {
        let desc = io_desc(UBLK_IO_OP_WRITE, 0, 512, 128, DEMO_BUFFER_ADDR + 65536);
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
        assert_eq!(desc.start_sector, 512);
        assert_eq!(desc.count_or_zones, 128);
        assert_ne!(desc.addr, 0);
    }

    #[test]
    fn flush_descriptor_has_zero_range_and_buffer_fields() {
        let desc = io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
        assert_eq!(desc.op(), UBLK_IO_OP_FLUSH);
        assert_eq!(desc.start_sector, 0);
        assert_eq!(desc.count_or_zones, 0);
        assert_eq!(desc.addr, 0);
    }

    // ── dispatch routing: op → BlockVolumeRequestClass ──

    #[test]
    fn dispatch_routing_read_op_maps_to_read_class() {
        let desc = io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR);
        let class = classify_descriptor(desc).expect("read must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Read);
    }

    #[test]
    fn dispatch_routing_write_op_maps_to_write_class() {
        let desc = io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR);
        let class = classify_descriptor(desc).expect("write must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Write);
    }

    #[test]
    fn dispatch_routing_flush_op_maps_to_flush_class() {
        let desc = io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
        let class = classify_descriptor(desc).expect("flush must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Flush);
    }

    #[test]
    fn dispatch_routing_discard_op_maps_to_discard_class() {
        let desc = io_desc(UBLK_IO_OP_DISCARD, 0, 0, 8, 0);
        let class = classify_descriptor(desc).expect("discard must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::Discard);
    }

    #[test]
    fn dispatch_routing_write_zeroes_op_maps_to_write_zeroes_class() {
        let desc = io_desc(UBLK_IO_OP_WRITE_ZEROES, 0, 0, 8, 0);
        let class = classify_descriptor(desc).expect("write_zeroes must classify");
        assert_eq!(class.request_class, BlockVolumeRequestClass::WriteZeroes);
    }

    // ── dispatch_ublk_io_descriptor FUA flush tests ─────────────────────

    fn dispatch_test_geometry() -> BlockVolumeGeometryRecord {
        BlockVolumeGeometryRecord::new(BlockVolumeId::new(994), 4096, 64, 1)
    }

    fn dispatch_test_dispatcher() -> (tempfile::TempDir, std::fs::File, UblkIoUringDispatcher) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dispatch-test.img");
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create dispatch test file");
        f.set_len(4096 * 64).expect("set_len");
        f.flush().expect("flush");
        let fd = f.as_raw_fd();
        let dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");
        (dir, f, dispatcher)
    }

    #[test]
    fn dispatch_fua_write_flushes_dispatcher() {
        let (_dir, _f, mut dispatcher) = dispatch_test_dispatcher();
        let geometry = dispatch_test_geometry();
        let mut payload = vec![0x5Fu8; 4096];
        let desc = io_desc(UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 0, 8, DEMO_BUFFER_ADDR);

        let n =
            dispatch_ublk_io_descriptor(&mut dispatcher, desc, geometry, Some(&mut payload[..]))
                .expect("FUA write dispatch");

        assert_eq!(n, 4096);
        assert_eq!(dispatcher.flush_ops, 1, "FUA write must flush");
        assert_eq!(dispatcher.write_ops, 1);
        assert_eq!(dispatcher.completed_ops, 2); // write + flush
    }

    #[test]
    fn dispatch_non_fua_write_does_not_flush() {
        let (_dir, _f, mut dispatcher) = dispatch_test_dispatcher();
        let geometry = dispatch_test_geometry();
        let mut payload = vec![0x3Cu8; 4096];
        let desc = io_desc(
            UBLK_IO_OP_WRITE,
            0, // no FUA flag
            8, // sector 8 = block 1
            8,
            DEMO_BUFFER_ADDR + 4096,
        );

        let n =
            dispatch_ublk_io_descriptor(&mut dispatcher, desc, geometry, Some(&mut payload[..]))
                .expect("non-FUA write dispatch");

        assert_eq!(n, 4096);
        assert_eq!(dispatcher.flush_ops, 0, "non-FUA write must not flush");
        assert_eq!(dispatcher.write_ops, 1);
        assert_eq!(dispatcher.completed_ops, 1);
    }

    #[test]
    fn dispatch_fua_write_data_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fua-persist-test.img");
        let geometry = dispatch_test_geometry();

        // Write via FUA dispatch, then drop the dispatcher and file.
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .expect("create persist test file");
            f.set_len(4096 * 64).expect("set_len");
            f.flush().expect("flush");
            let fd = f.as_raw_fd();
            let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

            let mut payload: Vec<u8> = (0..4096u16).map(|i| (i % 251) as u8).collect();
            let desc = io_desc(UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 0, 8, DEMO_BUFFER_ADDR);

            let n = dispatch_ublk_io_descriptor(
                &mut dispatcher,
                desc,
                geometry,
                Some(&mut payload[..]),
            )
            .expect("FUA write dispatch");

            assert_eq!(n, 4096);
            assert_eq!(dispatcher.flush_ops, 1);
        }

        // Reopen and read back the written block.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("reopen persist test file");
        let fd = f.as_raw_fd();
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let mut read_buf = vec![0u8; 4096];
        let desc = io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR + 65536);

        let n = dispatch_ublk_io_descriptor(&mut dispatcher, desc, geometry, Some(&mut read_buf))
            .expect("read dispatch");

        assert_eq!(n, 4096);
        let expected: Vec<u8> = (0..4096u16).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            &read_buf[..],
            &expected[..],
            "FUA write data must survive reopen"
        );
    }
}
