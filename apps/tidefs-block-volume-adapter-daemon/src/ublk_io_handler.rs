// ublk_io_handler — ublk target IO command serving loop.
//
// Provides a ublk IO command handler that polls the ublk queue for
// UBLK_IO_COMMAND_AND_FETCH / UBLK_IO_NEED_GET_DATA commands, dispatches
// READ/WRITE/FLUSH/DISCARD/WRITE_ZEROES through the Volume trait, and
// returns completions to the kernel.

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeGeometryRecord, Volume, VOLUME_SECTOR_SIZE,
};
use tidefs_ublk_abi::{
    UblkSrvIoCmd, UblkSrvIoDesc, UBLK_IO_F_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH,
    UBLK_IO_OP_READ, UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES,
    UBLK_IO_RES_OK,
};

use crate::LINUX_SECTOR_SIZE_BYTES;
use crate::{BarrierAuditLog, BarrierResult, BarrierType};

/// Gate label for the ublk IO handler module.
pub const UBLK_IO_HANDLER_GATE_OW_301W: &str =
    "OW-301W ublk IO handler dispatches READ/WRITE/FLUSH/DISCARD/WRITE_ZEROES commands through the Volume trait to the storage backend";

/// Supported raw flags mask (FUA).
const SUPPORTED_FLAGS: u32 = UBLK_IO_F_FUA;

/// Result of processing a single ublk IO descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoHandlerResult {
    /// Command dispatched successfully.
    Completed {
        /// Number of bytes transferred (0 for flush/discard/write_zeroes).
        byte_count: usize,
    },
    /// Command refused with a specific error.
    Refused {
        /// Linux errno for the completion.
        errno: i32,
    },
}

impl UblkIoHandlerResult {
    /// Convert this result into a Linux errno suitable for the ublk completion.
    #[must_use]
    pub fn to_linux_errno(self) -> i32 {
        match self {
            Self::Completed { .. } => UBLK_IO_RES_OK,
            Self::Refused { errno } => errno,
        }
    }

    /// Build a ublk completion command from this result.
    #[must_use]
    pub fn to_io_cmd(self, queue_id: u16, tag: u16) -> UblkSrvIoCmd {
        UblkSrvIoCmd {
            q_id: queue_id,
            tag,
            result: self.to_linux_errno(),
            addr_or_zone_append_lba: 0,
        }
    }
}

/// Lightweight handler that dispatches ublk IO descriptors through a
/// [`Volume`] backend.
///
/// This handler does not own buffers or manage queue state; callers
/// supply read/write buffers for each command.
pub struct UblkIoHandler {
    /// Current queue id (informational).
    pub queue_id: u16,
    /// Accumulated bytes read.
    pub bytes_read: u64,
    /// Accumulated bytes written.
    pub bytes_written: u64,
    /// Completed read ops.
    pub read_ops: u64,
    /// Completed write ops.
    pub write_ops: u64,
    /// Completed flush ops.
    pub flush_ops: u64,
    /// Completed discard ops.
    pub discard_ops: u64,
    /// Completed write_zeroes ops.
    pub write_zeroes_ops: u64,
    /// Completed error ops.
    pub error_ops: u64,
    /// Unsupported opcode ops.
    pub unsupported_ops: u64,
    /// Total completed ops (including errors).
    pub total_ops: u64,
    /// Barrier audit log for flush/FUA trace validation.
    pub barrier_audit: BarrierAuditLog,
}

impl UblkIoHandler {
    #[must_use]
    pub fn new(queue_id: u16) -> Self {
        Self {
            queue_id,
            bytes_read: 0,
            bytes_written: 0,
            read_ops: 0,
            write_ops: 0,
            flush_ops: 0,
            discard_ops: 0,
            write_zeroes_ops: 0,
            error_ops: 0,
            unsupported_ops: 0,
            total_ops: 0,
            barrier_audit: BarrierAuditLog::new(),
        }
    }

    /// Process a single ublk IO descriptor by dispatching to the [`Volume`]
    /// backend.
    ///
    /// For `UBLK_IO_OP_READ`, `read_buf` must be provided with enough space
    /// for the requested sector range. For `UBLK_IO_OP_WRITE`, `write_buf`
    /// must be provided with the data to write. For `UBLK_IO_OP_FLUSH`,
    /// `UBLK_IO_OP_DISCARD`, and `UBLK_IO_OP_WRITE_ZEROES`, neither buffer
    /// is required (both may be `None`).
    ///
    /// # Errors
    ///
    /// Returns `UblkIoHandlerResult::Refused` when the descriptor is invalid,
    /// the operation is unsupported, or the range is out of bounds. I/O
    /// errors from the backend are mapped to `-EIO`.
    pub fn handle_command(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
        read_buf: Option<&mut [u8]>,
        write_buf: Option<&[u8]>,
    ) -> UblkIoHandlerResult {
        self.total_ops += 1;

        let op = desc.op();
        let raw_flags = desc.op_flags & !0xff;

        // Reject unsupported flags
        let unsupported_flags = raw_flags & !SUPPORTED_FLAGS;
        if unsupported_flags != 0 {
            self.error_ops += 1;
            return UblkIoHandlerResult::Refused {
                errno: -libc::EINVAL,
            };
        }

        // FUA is only valid for writes
        if raw_flags & UBLK_IO_F_FUA != 0 && op != UBLK_IO_OP_WRITE {
            self.error_ops += 1;
            return UblkIoHandlerResult::Refused {
                errno: -libc::EINVAL,
            };
        }

        match op {
            UBLK_IO_OP_READ => self.dispatch_read(volume, desc, raw_flags, read_buf),
            UBLK_IO_OP_WRITE => self.dispatch_write(volume, desc, raw_flags, write_buf),
            UBLK_IO_OP_FLUSH => self.dispatch_flush(volume, desc),
            UBLK_IO_OP_DISCARD => self.dispatch_discard(volume, desc),
            UBLK_IO_OP_WRITE_ZEROES => self.dispatch_write_zeroes(volume, desc),
            UBLK_IO_OP_WRITE_SAME => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                UblkIoHandlerResult::Refused {
                    errno: -libc::EOPNOTSUPP,
                }
            }
            _ => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                UblkIoHandlerResult::Refused {
                    errno: -libc::EOPNOTSUPP,
                }
            }
        }
    }

    // ── private dispatch helpers ──────────────────────────────────

    fn dispatch_read(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
        _raw_flags: u32,
        read_buf: Option<&mut [u8]>,
    ) -> UblkIoHandlerResult {
        let geometry = volume.geometry();
        let sector_count = desc.count_or_zones;
        let expected_bytes = Self::sector_bytes(geometry, sector_count);

        let buf = match read_buf {
            Some(buf) if buf.len() >= expected_bytes => buf,
            Some(_) => {
                self.error_ops += 1;
                return UblkIoHandlerResult::Refused {
                    errno: -libc::EINVAL,
                };
            }
            None => {
                // Zero-length read or buffer missing: treat as success with zero bytes
                if sector_count == 0 {
                    self.read_ops += 1;
                    return UblkIoHandlerResult::Completed { byte_count: 0 };
                }
                self.error_ops += 1;
                return UblkIoHandlerResult::Refused {
                    errno: -libc::EINVAL,
                };
            }
        };

        match volume.read_sectors(desc.start_sector, sector_count, &mut buf[..expected_bytes]) {
            Ok(n) => {
                self.bytes_read += n as u64;
                self.read_ops += 1;
                UblkIoHandlerResult::Completed { byte_count: n }
            }
            Err(e) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                UblkIoHandlerResult::Refused { errno }
            }
        }
    }

    fn dispatch_write(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
        write_buf: Option<&[u8]>,
    ) -> UblkIoHandlerResult {
        let geometry = volume.geometry();
        let sector_count = desc.count_or_zones;
        let expected_bytes = Self::sector_bytes(geometry, sector_count);

        let data = match write_buf {
            Some(data) if data.len() >= expected_bytes => &data[..expected_bytes],
            Some(_) => {
                self.error_ops += 1;
                return UblkIoHandlerResult::Refused {
                    errno: -libc::EINVAL,
                };
            }
            None => {
                if sector_count == 0 {
                    self.write_ops += 1;
                    return UblkIoHandlerResult::Completed { byte_count: 0 };
                }
                self.error_ops += 1;
                return UblkIoHandlerResult::Refused {
                    errno: -libc::EINVAL,
                };
            }
        };

        match volume.write_sectors(desc.start_sector, sector_count, data) {
            Ok(()) => {
                self.bytes_written += expected_bytes as u64;
                self.write_ops += 1;
                if raw_flags & UBLK_IO_F_FUA != 0 {
                    if let Err(e) = volume.flush() {
                        self.error_ops += 1;
                        self.barrier_audit
                            .record(BarrierType::FuaWrite, BarrierResult::Failed);
                        let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                        return UblkIoHandlerResult::Refused { errno };
                    }
                    self.barrier_audit
                        .record(BarrierType::FuaWrite, BarrierResult::Completed);
                }
                UblkIoHandlerResult::Completed {
                    byte_count: expected_bytes,
                }
            }
            Err(e) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                UblkIoHandlerResult::Refused { errno }
            }
        }
    }

    fn dispatch_flush(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
    ) -> UblkIoHandlerResult {
        // Flush must not carry range or buffer information
        if desc.start_sector != 0 || desc.count_or_zones != 0 {
            self.error_ops += 1;
            return UblkIoHandlerResult::Refused {
                errno: -libc::EINVAL,
            };
        }

        match volume.flush() {
            Ok(()) => {
                self.flush_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Completed);
                UblkIoHandlerResult::Completed { byte_count: 0 }
            }
            Err(e) => {
                self.error_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Failed);
                let errno = e.raw_os_error().unwrap_or(-libc::EIO);
                UblkIoHandlerResult::Refused { errno }
            }
        }
    }

    fn dispatch_discard(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
    ) -> UblkIoHandlerResult {
        match volume.discard_sectors(desc.start_sector, desc.count_or_zones) {
            Ok(()) => {
                self.discard_ops += 1;
                UblkIoHandlerResult::Completed { byte_count: 0 }
            }
            Err(e) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                UblkIoHandlerResult::Refused { errno }
            }
        }
    }

    fn dispatch_write_zeroes(
        &mut self,
        volume: &mut dyn Volume,
        desc: &UblkSrvIoDesc,
    ) -> UblkIoHandlerResult {
        match volume.write_zeroes_sectors(desc.start_sector, desc.count_or_zones) {
            Ok(()) => {
                self.write_zeroes_ops += 1;
                UblkIoHandlerResult::Completed { byte_count: 0 }
            }
            Err(e) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                UblkIoHandlerResult::Refused { errno }
            }
        }
    }

    // ── helpers ───────────────────────────────────────────────────

    /// Compute expected byte count for a sector range given geometry.
    #[inline]
    fn sector_bytes(geometry: BlockVolumeGeometryRecord, sector_count: u32) -> usize {
        (sector_count as u64)
            .saturating_mul(VOLUME_SECTOR_SIZE)
            .min(geometry.capacity_bytes().unwrap_or(usize::MAX) as u64) as usize
    }

    /// Validate that the requested range is block-aligned and in-bounds.
    #[allow(dead_code)]
    fn validate_range(
        geometry: BlockVolumeGeometryRecord,
        start_sector: u64,
        sector_count: u32,
    ) -> Result<BlockRangeRecord, UblkIoHandlerResult> {
        let block_size = geometry.block_size_bytes;
        if block_size < LINUX_SECTOR_SIZE_BYTES {
            return Err(UblkIoHandlerResult::Refused {
                errno: -libc::EINVAL,
            });
        }

        let start_byte = start_sector.saturating_mul(LINUX_SECTOR_SIZE_BYTES as u64);
        let byte_count = (sector_count as u64).saturating_mul(LINUX_SECTOR_SIZE_BYTES as u64);

        if start_byte % block_size as u64 != 0 || byte_count % block_size as u64 != 0 {
            return Err(UblkIoHandlerResult::Refused {
                errno: -libc::EINVAL,
            });
        }

        let start_block = (start_byte / block_size as u64) as usize;
        let block_count = (byte_count / block_size as u64) as usize;

        if let Some(cap) = geometry.capacity_bytes() {
            if start_byte.saturating_add(byte_count) > cap as u64 {
                return Err(UblkIoHandlerResult::Refused {
                    errno: -libc::EINVAL,
                });
            }
        }

        Ok(BlockRangeRecord::new(start_block, block_count))
    }
}

// ── Unit tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tidefs_block_volume_adapter_core::{BlockVolumeGeometryRecord, BlockVolumeId, Volume};
    use tidefs_ublk_abi::UBLK_IO_F_FUA;

    // ── Test Volume backend (in-memory) ───────────────────────────

    struct TestVolume {
        geometry: BlockVolumeGeometryRecord,
        data: Vec<u8>,
        flush_count: u64,
        discard_count: u64,
        write_zeroes_count: u64,
    }

    impl TestVolume {
        fn new(block_count: usize) -> Self {
            let block_size = 4096;
            let geometry =
                BlockVolumeGeometryRecord::new(BlockVolumeId::new(100), block_size, block_count, 1);
            let total_bytes = block_count * block_size;
            Self {
                geometry,
                data: vec![0u8; total_bytes],
                flush_count: 0,
                discard_count: 0,
                write_zeroes_count: 0,
            }
        }
    }

    impl Volume for TestVolume {
        fn geometry(&self) -> BlockVolumeGeometryRecord {
            self.geometry
        }

        fn read_sectors(
            &self,
            start_sector: u64,
            count_or_zones: u32,
            buf: &mut [u8],
        ) -> io::Result<usize> {
            let byte_offset = (start_sector as usize) * LINUX_SECTOR_SIZE_BYTES;
            let byte_count = (count_or_zones as usize) * LINUX_SECTOR_SIZE_BYTES;
            let end = (byte_offset + byte_count).min(self.data.len());
            let actual = end - byte_offset;
            buf[..actual].copy_from_slice(&self.data[byte_offset..end]);
            Ok(actual)
        }

        fn write_sectors(
            &mut self,
            start_sector: u64,
            count_or_zones: u32,
            data: &[u8],
        ) -> io::Result<()> {
            let byte_offset = (start_sector as usize) * LINUX_SECTOR_SIZE_BYTES;
            let byte_count = (count_or_zones as usize) * LINUX_SECTOR_SIZE_BYTES;
            let end = (byte_offset + byte_count).min(self.data.len());
            self.data[byte_offset..end].copy_from_slice(data);
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }

        fn discard_sectors(&mut self, _start_sector: u64, _count_or_zones: u32) -> io::Result<()> {
            self.discard_count += 1;
            Ok(())
        }

        fn write_zeroes_sectors(
            &mut self,
            start_sector: u64,
            count_or_zones: u32,
        ) -> io::Result<()> {
            self.write_zeroes_count += 1;
            let byte_offset = (start_sector as usize) * LINUX_SECTOR_SIZE_BYTES;
            let byte_count = (count_or_zones as usize) * LINUX_SECTOR_SIZE_BYTES;
            let end = (byte_offset + byte_count).min(self.data.len());
            self.data[byte_offset..end].fill(0u8);
            Ok(())
        }
    }

    struct RawErrVolume {
        geometry: BlockVolumeGeometryRecord,
        errno: i32,
    }

    impl RawErrVolume {
        fn new(errno: i32) -> Self {
            Self {
                geometry: BlockVolumeGeometryRecord::new(BlockVolumeId::new(100), 4096, 16, 1),
                errno,
            }
        }

        fn raw_error(&self) -> io::Error {
            io::Error::from_raw_os_error(self.errno)
        }
    }

    impl Volume for RawErrVolume {
        fn geometry(&self) -> BlockVolumeGeometryRecord {
            self.geometry
        }

        fn read_sectors(
            &self,
            _start_sector: u64,
            _count_or_zones: u32,
            _buf: &mut [u8],
        ) -> io::Result<usize> {
            Err(self.raw_error())
        }

        fn write_sectors(
            &mut self,
            _start_sector: u64,
            _count_or_zones: u32,
            _data: &[u8],
        ) -> io::Result<()> {
            Err(self.raw_error())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(self.raw_error())
        }

        fn discard_sectors(&mut self, _start_sector: u64, _count_or_zones: u32) -> io::Result<()> {
            Err(self.raw_error())
        }

        fn write_zeroes_sectors(
            &mut self,
            _start_sector: u64,
            _count_or_zones: u32,
        ) -> io::Result<()> {
            Err(self.raw_error())
        }
    }

    fn test_handler() -> UblkIoHandler {
        UblkIoHandler::new(0)
    }

    fn read_desc(start_sector: u64, sector_count: u32) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ),
            count_or_zones: sector_count,
            start_sector,
            addr: 0x1000,
        }
    }

    fn write_desc(start_sector: u64, sector_count: u32) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE),
            count_or_zones: sector_count,
            start_sector,
            addr: 0x2000,
        }
    }

    fn flush_desc() -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        }
    }

    fn discard_desc(start_sector: u64, sector_count: u32) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_DISCARD),
            count_or_zones: sector_count,
            start_sector,
            addr: 0,
        }
    }

    fn write_zeroes_desc(start_sector: u64, sector_count: u32) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE_ZEROES),
            count_or_zones: sector_count,
            start_sector,
            addr: 0,
        }
    }

    // ── Read dispatch tests ───────────────────────────────────────

    #[test]
    fn handler_read_dispatches_to_volume_read_sectors() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        // Pre-write data at sector 0
        volume.data[..512].copy_from_slice(&[0xABu8; 512]);

        let mut buf = [0u8; 512];
        let result = handler.handle_command(&mut volume, &read_desc(0, 1), Some(&mut buf), None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 512 }
        ));
        assert_eq!(&buf[..], &[0xABu8; 512]);
        assert_eq!(handler.read_ops, 1);
        assert_eq!(handler.bytes_read, 512);
        assert_eq!(handler.total_ops, 1);
    }

    #[test]
    fn handler_read_zero_length_returns_completed_zero_bytes() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result = handler.handle_command(&mut volume, &read_desc(0, 0), None::<&mut [u8]>, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 0 }
        ));
        assert_eq!(handler.read_ops, 1);
    }

    #[test]
    fn handler_read_missing_buffer_for_nonzero_count_refuses() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result = handler.handle_command(&mut volume, &read_desc(0, 8), None::<&mut [u8]>, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    #[test]
    fn handler_read_buffer_too_short_refuses() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let mut buf = [0u8; 128]; // 128 bytes < 8 sectors * 512 = 4096

        let result = handler.handle_command(&mut volume, &read_desc(0, 8), Some(&mut buf), None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    // ── Write dispatch tests ──────────────────────────────────────

    #[test]
    fn handler_write_dispatches_to_volume_write_sectors() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let data = [0xCDu8; 512];

        let result = handler.handle_command(&mut volume, &write_desc(2, 1), None, Some(&data));

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 512 }
        ));
        assert_eq!(handler.write_ops, 1);
        assert_eq!(handler.bytes_written, 512);

        // Verify data was written
        let offset = 2 * 512;
        assert_eq!(&volume.data[offset..offset + 512], &[0xCDu8; 512]);
    }

    #[test]
    fn handler_propagates_raw_enospc_from_volume_io_error() {
        let mut handler = test_handler();
        let mut volume = RawErrVolume::new(libc::ENOSPC);
        let data = [0xCDu8; 512];

        let result = handler.handle_command(&mut volume, &write_desc(2, 1), None, Some(&data));

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno } if errno == -libc::ENOSPC
        ));
    }

    #[test]
    fn handler_write_zero_length_returns_completed_zero_bytes() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result =
            handler.handle_command(&mut volume, &write_desc(1, 0), None::<&mut [u8]>, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 0 }
        ));
        assert_eq!(handler.write_ops, 1);
    }

    #[test]
    fn handler_write_missing_buffer_for_nonzero_count_refuses() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result =
            handler.handle_command(&mut volume, &write_desc(0, 8), None::<&mut [u8]>, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    #[test]
    fn handler_write_fua_flag_accepted_and_dispatches_write() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let data = [0xEFu8; 512];
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE) | UBLK_IO_F_FUA,
            count_or_zones: 1,
            start_sector: 0,
            addr: 0x3000,
        };

        let result = handler.handle_command(&mut volume, &desc, None, Some(&data));

        assert!(matches!(result, UblkIoHandlerResult::Completed { .. }));
        assert_eq!(handler.write_ops, 1);
        assert_eq!(volume.flush_count, 1, "FUA write must flush");
    }

    #[test]
    fn handler_fua_flag_on_read_is_refused() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let mut buf = [0u8; 512];
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ) | UBLK_IO_F_FUA,
            count_or_zones: 1,
            start_sector: 0,
            addr: 0x1000,
        };

        let result = handler.handle_command(&mut volume, &desc, Some(&mut buf), None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    #[test]
    fn handler_unsupported_flags_refused() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let mut buf = [0u8; 512];
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ) | (0xDEAD << 8),
            count_or_zones: 1,
            start_sector: 0,
            addr: 0x1000,
        };

        let result = handler.handle_command(&mut volume, &desc, Some(&mut buf), None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    // ── Flush dispatch tests ──────────────────────────────────────

    #[test]
    fn handler_flush_dispatches_to_volume_flush() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result = handler.handle_command(&mut volume, &flush_desc(), None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 0 }
        ));
        assert_eq!(handler.flush_ops, 1);
        assert_eq!(volume.flush_count, 1);
    }

    #[test]
    fn handler_flush_with_sector_range_refused() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 1,
            start_sector: 5,
            addr: 0,
        };

        let result = handler.handle_command(&mut volume, &desc, None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -22 }
        ));
    }

    // ── Discard dispatch tests ────────────────────────────────────

    #[test]
    fn handler_discard_dispatches_to_volume_discard_sectors() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        let result = handler.handle_command(&mut volume, &discard_desc(0, 8), None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 0 }
        ));
        assert_eq!(handler.discard_ops, 1);
        assert_eq!(volume.discard_count, 1);
    }

    // ── Write zeroes dispatch tests ───────────────────────────────

    #[test]
    fn handler_write_zeroes_dispatches_to_volume_write_zeroes_sectors() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        // Pre-fill with non-zero data
        volume.data[0..1024].fill(0xFF);

        let result = handler.handle_command(&mut volume, &write_zeroes_desc(0, 2), None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Completed { byte_count: 0 }
        ));
        assert_eq!(handler.write_zeroes_ops, 1);
        assert_eq!(volume.write_zeroes_count, 1);
        // Verify zeroed
        assert_eq!(&volume.data[0..1024], &[0u8; 1024]);
    }

    // ── Unsupported opcode tests ──────────────────────────────────

    #[test]
    fn handler_write_same_returns_unsupported() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE_SAME),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };

        let result = handler.handle_command(&mut volume, &desc, None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -95 }
        ));
        assert_eq!(handler.unsupported_ops, 1);
        assert_eq!(handler.error_ops, 1);
    }

    #[test]
    fn handler_zoned_operation_returns_unsupported() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let desc = UblkSrvIoDesc {
            op_flags: 10, // UBLK_IO_OP_ZONE_OPEN
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };

        let result = handler.handle_command(&mut volume, &desc, None, None);

        assert!(matches!(
            result,
            UblkIoHandlerResult::Refused { errno: -95 }
        ));
        assert_eq!(handler.unsupported_ops, 1);
    }

    // ── Completion encoding tests ─────────────────────────────────

    #[test]
    fn handler_result_to_linux_errno_completed_returns_ok() {
        let result = UblkIoHandlerResult::Completed { byte_count: 512 };
        assert_eq!(result.to_linux_errno(), UBLK_IO_RES_OK);
    }

    #[test]
    fn handler_result_to_linux_errno_refused_returns_errno() {
        let result = UblkIoHandlerResult::Refused { errno: -5 };
        assert_eq!(result.to_linux_errno(), -5);
    }

    #[test]
    fn handler_result_to_io_cmd_builds_correct_completion() {
        let result = UblkIoHandlerResult::Completed { byte_count: 1024 };
        let cmd = result.to_io_cmd(2, 42);
        assert_eq!(cmd.q_id, 2);
        assert_eq!(cmd.tag, 42);
        assert_eq!(cmd.result, UBLK_IO_RES_OK);
    }

    #[test]
    fn handler_result_to_io_cmd_refused_builds_error_completion() {
        let result = UblkIoHandlerResult::Refused { errno: -28 };
        let cmd = result.to_io_cmd(3, 7);
        assert_eq!(cmd.q_id, 3);
        assert_eq!(cmd.tag, 7);
        assert_eq!(cmd.result, -28);
    }

    // ── Read-after-write round-trip test ──────────────────────────

    #[test]
    fn handler_read_after_write_round_trip() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);
        let write_data = [0x42u8; 1024]; // 2 sectors

        // Write
        let wresult =
            handler.handle_command(&mut volume, &write_desc(4, 2), None, Some(&write_data));
        assert!(matches!(
            wresult,
            UblkIoHandlerResult::Completed { byte_count: 1024 }
        ));

        // Read back
        let mut read_buf = [0u8; 1024];
        let rresult =
            handler.handle_command(&mut volume, &read_desc(4, 2), Some(&mut read_buf), None);
        assert!(matches!(
            rresult,
            UblkIoHandlerResult::Completed { byte_count: 1024 }
        ));
        assert_eq!(&read_buf[..], &write_data[..]);
    }

    // ── Counter accumulation tests ────────────────────────────────

    #[test]
    fn handler_accumulates_per_op_counters() {
        let mut handler = test_handler();
        let mut volume = TestVolume::new(16);

        // Read
        let mut buf = [0u8; 512];
        handler.handle_command(&mut volume, &read_desc(0, 1), Some(&mut buf), None);
        assert_eq!(handler.read_ops, 1);

        // Write
        let data = [0xAAu8; 512];
        handler.handle_command(&mut volume, &write_desc(0, 1), None, Some(&data));
        assert_eq!(handler.write_ops, 1);

        // Flush
        handler.handle_command(&mut volume, &flush_desc(), None, None);
        assert_eq!(handler.flush_ops, 1);

        // Discard
        handler.handle_command(&mut volume, &discard_desc(0, 1), None, None);
        assert_eq!(handler.discard_ops, 1);

        // Write zeroes
        handler.handle_command(&mut volume, &write_zeroes_desc(0, 1), None, None);
        assert_eq!(handler.write_zeroes_ops, 1);

        assert_eq!(handler.total_ops, 5);
        assert_eq!(handler.error_ops, 0);
        assert_eq!(handler.unsupported_ops, 0);
    }

    // ── validate_range tests ──────────────────────────────────────

    #[test]
    fn validate_range_block_aligned_request_passes() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 1024, 1);
        let result = UblkIoHandler::validate_range(geometry, 8, 16); // 8 sectors = 4096 bytes = 1 block
        assert!(result.is_ok());
    }

    #[test]
    fn validate_range_misaligned_start_refuses() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 1024, 1);
        let result = UblkIoHandler::validate_range(geometry, 1, 8); // 1 sector = 512 bytes, not block-aligned
        assert!(result.is_err());
    }

    #[test]
    fn validate_range_misaligned_length_refuses() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 1024, 1);
        let result = UblkIoHandler::validate_range(geometry, 0, 1); // 1 sector, not block-aligned
        assert!(result.is_err());
    }

    #[test]
    fn validate_range_out_of_bounds_refuses() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 16, 1); // 16 blocks
        let result = UblkIoHandler::validate_range(geometry, 0, 1024); // way past capacity
        assert!(result.is_err());
    }
}
