//! ublk block-volume write-request handler.
//!
//! Provides [`UblkWriteRequest`] as a typed representation of a ublk block
//! write command from the kernel, [`validate_write_request`] for device-capacity
//! and sector-alignment checks, and [`dispatch_write_request`] for LBA-to-byte
//! translation and backend dispatch through the [`UblkIoBackend`] trait.
//!
//! LBA ranges are translated to TideFS byte offsets by multiplying the
//! 512-byte Linux sector address by the sector count.

use std::fmt;

use crate::ublk_io::{UblkIoBackend, UblkIoDescriptor, UblkIoDispatchResult, UblkIoHandlerError};
use crate::DeviceCapacity;

/// A validated ublk block write request from the kernel.
///
/// Holds the parsed LBA range, the data buffer reference (via queue id and tag),
/// and the tag used for io_uring CQE posting after completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkWriteRequest {
    /// Queue id (0..nr_hw_queues-1).
    pub q_id: u16,
    /// Tag (0..queue_depth-1) for CQE posting.
    pub tag: u16,
    /// Starting 512-byte sector (Linux LBA).
    pub start_sector: u64,
    /// Number of 512-byte sectors to write.
    pub sector_count: u32,
    /// Whether the FUA (Force Unit Access) flag is set.
    pub fua: bool,
}

impl UblkWriteRequest {
    /// Construct from a parsed [`UblkIoDescriptor`] when the operation is
    /// known to be a write. Returns `None` if the descriptor is not a write.
    #[must_use]
    pub fn from_io_descriptor(desc: &UblkIoDescriptor) -> Option<Self> {
        if desc.op != crate::ublk_io::UblkIoOp::Write {
            return None;
        }
        Some(Self {
            q_id: desc.q_id,
            tag: desc.tag,
            start_sector: desc.start_sector,
            sector_count: desc.sector_count,
            fua: desc.fua,
        })
    }

    /// Total byte count for this write (sectors × 512).
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.sector_count as u64 * 512
    }

    /// Byte offset into the block device (start_sector × 512).
    #[must_use]
    pub const fn byte_offset(self) -> u64 {
        self.start_sector * 512
    }

    /// Exclusive end byte offset (start_sector + sector_count) × 512.
    /// Returns `None` if the computation would overflow a `u64`.
    #[must_use]
    pub const fn byte_end(self) -> Option<u64> {
        let end_sector = match self.start_sector.checked_add(self.sector_count as u64) {
            Some(s) => s,
            None => return None,
        };
        end_sector.checked_mul(512)
    }
}

impl fmt::Display for UblkWriteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ublk write [q={} tag={}] start_sector={} count={} fua={}",
            self.q_id, self.tag, self.start_sector, self.sector_count, self.fua,
        )
    }
}

/// Error returned by [`validate_write_request`] when a write request fails
/// shape or capacity checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkWriteValidationError {
    /// Sector count is zero.
    ZeroLength,
    /// The request uses a non-512-byte sector size (unsupported).
    UnalignedSector,
    /// The write would start past the end of the device.
    StartPastEndOfDevice {
        /// First sector of the write request.
        start_sector: u64,
        /// Total sector count of the device.
        device_sector_count: u64,
    },
    /// The write extends past the end of the device.
    WritePastEndOfDevice {
        /// First sector of the write request.
        start_sector: u64,
        /// Number of sectors to write.
        sector_count: u32,
        /// Total sector count of the device.
        device_sector_count: u64,
    },
    /// The start_sector + sector_count computation overflows u64.
    SectorRangeOverflow {
        /// First sector of the write request.
        start_sector: u64,
        /// Number of sectors to write.
        sector_count: u32,
    },
}

impl UblkWriteValidationError {
    /// Convert to a Linux errno suitable for posting in a ublk CQE.
    #[must_use]
    pub const fn to_linux_errno(self) -> i32 {
        match self {
            Self::ZeroLength | Self::UnalignedSector | Self::SectorRangeOverflow { .. } => {
                libc::EINVAL
            }
            Self::StartPastEndOfDevice { .. } | Self::WritePastEndOfDevice { .. } => libc::ENOSPC,
        }
    }

    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroLength => "zero_length_write",
            Self::UnalignedSector => "unaligned_sector",
            Self::StartPastEndOfDevice { .. } => "start_past_end_of_device",
            Self::WritePastEndOfDevice { .. } => "write_past_end_of_device",
            Self::SectorRangeOverflow { .. } => "sector_range_overflow",
        }
    }
}

impl fmt::Display for UblkWriteValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLength => write!(f, "zero-length write request"),
            Self::UnalignedSector => write!(f, "sector size must be 512 bytes"),
            Self::StartPastEndOfDevice {
                start_sector,
                device_sector_count,
            } => {
                write!(
                    f,
                    "write start sector {start_sector} past end of device ({device_sector_count} sectors)"
                )
            }
            Self::WritePastEndOfDevice {
                start_sector,
                sector_count,
                device_sector_count,
            } => {
                write!(
                    f,
                    "write range [{start_sector}, +{sector_count}] exceeds device capacity ({device_sector_count} sectors)"
                )
            }
            Self::SectorRangeOverflow {
                start_sector,
                sector_count,
            } => {
                write!(
                    f,
                    "sector range overflow: start={start_sector} + count={sector_count} wraps u64"
                )
            }
        }
    }
}

impl From<UblkWriteValidationError> for UblkIoDispatchResult {
    fn from(err: UblkWriteValidationError) -> Self {
        Self::Refused {
            errno: err.to_linux_errno(),
        }
    }
}

/// Validate a write request against the device capacity.
///
/// Checks performed (in order):
/// 1. Sector count must be non-zero.
/// 2. Sector alignment: we assume 512-byte sectors; non-standard sizes are
///    rejected (the ublk kernel driver uses 512-byte sectors).
/// 3. Overflow guard: `start_sector + sector_count` must not wrap `u64`.
/// 4. Start sector must be within the device capacity.
/// 5. End sector (start + count) must not exceed the device capacity.
///
/// # Errors
///
/// Returns [`UblkWriteValidationError`] if any check fails.
pub fn validate_write_request(
    request: &UblkWriteRequest,
    capacity: &DeviceCapacity,
) -> Result<(), UblkWriteValidationError> {
    if request.sector_count == 0 {
        return Err(UblkWriteValidationError::ZeroLength);
    }

    // Sector size must be 512; non-standard sizes are rejected.
    if capacity.sector_size != 512 {
        return Err(UblkWriteValidationError::UnalignedSector);
    }

    // Overflow guard: start + count must not wrap.
    let end_sector = request
        .start_sector
        .checked_add(request.sector_count as u64)
        .ok_or(UblkWriteValidationError::SectorRangeOverflow {
            start_sector: request.start_sector,
            sector_count: request.sector_count,
        })?;

    // Start must be within device bounds.
    if request.start_sector >= capacity.sector_count {
        return Err(UblkWriteValidationError::StartPastEndOfDevice {
            start_sector: request.start_sector,
            device_sector_count: capacity.sector_count,
        });
    }

    // End must not exceed device capacity.
    if end_sector > capacity.sector_count {
        return Err(UblkWriteValidationError::WritePastEndOfDevice {
            start_sector: request.start_sector,
            sector_count: request.sector_count,
            device_sector_count: capacity.sector_count,
        });
    }

    Ok(())
}

/// Dispatch a validated write request to the backend.
///
/// Translates the LBA range to a byte offset (`start_sector × 512`),
/// extracts the write payload from the data buffer, and delegates to
/// [`UblkIoBackend::write`]. If the FUA flag is set, [`UblkIoBackend::flush`]
/// is called after the write.
///
/// # Errors
///
/// Returns [`UblkIoDispatchResult::Refused`] if the buffer is missing or too
/// short, or [`UblkIoDispatchResult::IoError`] on backend failure.
pub fn dispatch_write_request(
    backend: &mut dyn UblkIoBackend,
    request: &UblkWriteRequest,
    write_buf: &[u8],
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    let byte_offset = request.byte_offset();
    let byte_len = request.byte_len() as usize;

    if byte_len == 0 {
        return Err(UblkIoHandlerError::ZeroLengthDataOperation);
    }
    if write_buf.len() < byte_len {
        return Err(UblkIoHandlerError::MissingBufferAddress);
    }

    match backend.write(byte_offset, &write_buf[..byte_len]) {
        Ok(n) => {
            if request.fua {
                match backend.flush() {
                    Ok(()) => Ok(UblkIoDispatchResult::Completed { byte_count: n }),
                    Err(e) => Err(UblkIoHandlerError::BackendIoError(
                        e.raw_os_error().unwrap_or(libc::EIO),
                    )),
                }
            } else {
                Ok(UblkIoDispatchResult::Completed { byte_count: n })
            }
        }
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

/// Validate and dispatch a ublk write IO descriptor in a single call.
///
/// Combines [`validate_write_request`] and [`dispatch_write_request`] so
/// callers that have a [`DeviceCapacity`] available can perform validated
/// write dispatch in one step.
///
/// Returns the [`UblkIoDispatchResult`] ready for COMMIT_AND_FETCH_REQ
/// posting.
#[must_use]
pub fn handle_write(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    write_buf: &[u8],
    capacity: &DeviceCapacity,
) -> UblkIoDispatchResult {
    let request = match UblkWriteRequest::from_io_descriptor(desc) {
        Some(r) => r,
        None => {
            return UblkIoDispatchResult::Refused {
                errno: libc::EINVAL,
            };
        }
    };

    if let Err(e) = validate_write_request(&request, capacity) {
        return UblkIoDispatchResult::from(e);
    }

    match dispatch_write_request(backend, &request, write_buf) {
        Ok(result) => result,
        Err(e) => UblkIoDispatchResult::Refused {
            errno: e.to_linux_errno(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── Test backend ──────────────────────────────────────────────────

    struct TestBackend {
        blocks: HashMap<u64, Vec<u8>>,
        flush_called: bool,
        capacity: u64,
    }

    impl TestBackend {
        fn new(capacity_bytes: u64) -> Self {
            Self {
                blocks: HashMap::new(),
                flush_called: false,
                capacity: capacity_bytes,
            }
        }
    }

    impl UblkIoBackend for TestBackend {
        fn read(&mut self, byte_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let end = std::cmp::min(byte_offset + buf.len() as u64, self.capacity);
            let len = (end - byte_offset) as usize;
            if let Some(data) = self.blocks.get(&byte_offset) {
                let copy_len = std::cmp::min(len, data.len());
                buf[..copy_len].copy_from_slice(&data[..copy_len]);
                return Ok(copy_len);
            }
            buf[..len].fill(0);
            Ok(len)
        }

        fn write(&mut self, byte_offset: u64, data: &[u8]) -> std::io::Result<usize> {
            let end = byte_offset + data.len() as u64;
            if end > self.capacity {
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.blocks.insert(byte_offset, data.to_vec());
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_called = true;
            Ok(())
        }

        fn discard(&mut self, byte_offset: u64, byte_len: u64) -> std::io::Result<()> {
            let end = std::cmp::min(byte_offset + byte_len, self.capacity);
            for off in (byte_offset..end).step_by(512) {
                self.blocks.remove(&off);
            }
            Ok(())
        }

        fn write_zeroes(&mut self, byte_offset: u64, byte_len: u64) -> std::io::Result<()> {
            let end = std::cmp::min(byte_offset + byte_len, self.capacity);
            for off in (byte_offset..end).step_by(512) {
                self.blocks.insert(off, vec![0u8; 512]);
            }
            Ok(())
        }
    }

    fn capacity(sector_count: u64, sector_size: u32) -> DeviceCapacity {
        DeviceCapacity {
            dev_id: 0,
            sector_count,
            sector_size,
        }
    }

    fn make_request(start_sector: u64, sector_count: u32, fua: bool) -> UblkWriteRequest {
        UblkWriteRequest {
            q_id: 0,
            tag: 0,
            start_sector,
            sector_count,
            fua,
        }
    }

    // ── UblkWriteRequest tests ───────────────────────────────────────

    #[test]
    fn write_request_byte_offset_and_len() {
        let req = make_request(8, 4, false);
        assert_eq!(req.byte_offset(), 4096);
        assert_eq!(req.byte_len(), 2048);
        assert_eq!(req.byte_end(), Some(6144));
    }

    #[test]
    fn write_request_byte_end_no_overflow() {
        let req = make_request(0, 1, false);
        assert_eq!(req.byte_end(), Some(512));
    }

    #[test]
    fn write_request_byte_end_at_u64_boundary() {
        // start=0x1_0000_0000, count=1 → end_sector = 0x1_0000_0001
        let req = make_request(0x1_0000_0000, 1, false);
        assert_eq!(req.byte_end(), Some(0x200_0000_0200));
    }

    #[test]
    fn write_request_byte_end_overflow_returns_none() {
        // start + count wraps u64
        let req = make_request(u64::MAX, 2, false);
        assert_eq!(req.byte_end(), None);
    }

    #[test]
    fn write_request_display() {
        let req = make_request(1024, 8, true);
        let s = format!("{req}");
        assert!(s.contains("start_sector=1024"));
        assert!(s.contains("count=8"));
        assert!(s.contains("fua=true"));
    }

    #[test]
    fn write_request_from_io_descriptor_write() {
        use crate::ublk_io::UblkIoDescriptor;
        let desc = UblkIoDescriptor {
            q_id: 1,
            tag: 42,
            op: crate::ublk_io::UblkIoOp::Write,
            flags: 0,
            fua: false,
            start_sector: 100,
            sector_count: 16,
            buffer_addr: 0x1000,
        };
        let req = UblkWriteRequest::from_io_descriptor(&desc).unwrap();
        assert_eq!(req.q_id, 1);
        assert_eq!(req.tag, 42);
        assert_eq!(req.start_sector, 100);
        assert_eq!(req.sector_count, 16);
        assert!(!req.fua);
    }

    #[test]
    fn write_request_from_io_descriptor_non_write_returns_none() {
        use crate::ublk_io::UblkIoDescriptor;
        let desc = UblkIoDescriptor {
            q_id: 0,
            tag: 0,
            op: crate::ublk_io::UblkIoOp::Read,
            flags: 0,
            fua: false,
            start_sector: 0,
            sector_count: 1,
            buffer_addr: 0,
        };
        assert!(UblkWriteRequest::from_io_descriptor(&desc).is_none());
    }

    // ── validate_write_request tests ─────────────────────────────────

    #[test]
    fn valid_aligned_write_within_bounds_accepted() {
        let req = make_request(0, 8, false);
        let cap = capacity(1024, 512);
        assert!(validate_write_request(&req, &cap).is_ok());
    }

    #[test]
    fn zero_length_write_rejected() {
        let req = make_request(0, 0, false);
        let cap = capacity(1024, 512);
        assert_eq!(
            validate_write_request(&req, &cap),
            Err(UblkWriteValidationError::ZeroLength)
        );
    }

    #[test]
    fn unaligned_sector_size_rejected() {
        let req = make_request(0, 1, false);
        let cap = capacity(1024, 4096);
        assert_eq!(
            validate_write_request(&req, &cap),
            Err(UblkWriteValidationError::UnalignedSector)
        );
    }

    #[test]
    fn start_past_end_of_device_rejected() {
        let req = make_request(2048, 1, false);
        let cap = capacity(1024, 512);
        assert_eq!(
            validate_write_request(&req, &cap),
            Err(UblkWriteValidationError::StartPastEndOfDevice {
                start_sector: 2048,
                device_sector_count: 1024,
            })
        );
    }

    #[test]
    fn write_past_end_of_device_rejected() {
        let req = make_request(1000, 100, false);
        let cap = capacity(1024, 512);
        assert_eq!(
            validate_write_request(&req, &cap),
            Err(UblkWriteValidationError::WritePastEndOfDevice {
                start_sector: 1000,
                sector_count: 100,
                device_sector_count: 1024,
            })
        );
    }

    #[test]
    fn exact_end_of_device_boundary_accepted() {
        let req = make_request(1000, 24, false);
        let cap = capacity(1024, 512);
        assert!(validate_write_request(&req, &cap).is_ok());
    }

    #[test]
    fn sector_range_overflow_rejected() {
        let req = make_request(u64::MAX, 1, false);
        let cap = capacity(u64::MAX, 512);
        assert_eq!(
            validate_write_request(&req, &cap),
            Err(UblkWriteValidationError::SectorRangeOverflow {
                start_sector: u64::MAX,
                sector_count: 1,
            })
        );
    }

    #[test]
    fn single_sector_at_sector_zero_accepted() {
        let req = make_request(0, 1, false);
        let cap = capacity(1024, 512);
        assert!(validate_write_request(&req, &cap).is_ok());
    }

    #[test]
    fn multi_sector_accepted() {
        let req = make_request(512, 128, false);
        let cap = capacity(4096, 512);
        assert!(validate_write_request(&req, &cap).is_ok());
    }

    #[test]
    fn fua_flag_accepted_in_validation() {
        let req = make_request(0, 4, true);
        let cap = capacity(1024, 512);
        assert!(validate_write_request(&req, &cap).is_ok());
    }

    // ── dispatch_write_request tests ────────────────────────────────

    #[test]
    fn dispatch_write_success() {
        let mut backend = TestBackend::new(4096 * 512);
        let req = make_request(8, 4, false);
        let data = vec![0xABu8; 2048];
        let result = dispatch_write_request(&mut backend, &req, &data).unwrap();
        assert_eq!(result, UblkIoDispatchResult::Completed { byte_count: 2048 });
        assert_eq!(backend.blocks.get(&4096).unwrap(), &data);
    }

    #[test]
    fn dispatch_write_with_fua_calls_flush() {
        let mut backend = TestBackend::new(4096 * 512);
        let req = make_request(0, 2, true);
        let data = vec![0xCDu8; 1024];
        let result = dispatch_write_request(&mut backend, &req, &data).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 1024 }
        ));
        assert!(backend.flush_called);
    }

    #[test]
    fn dispatch_write_buffer_too_short() {
        let mut backend = TestBackend::new(4096 * 512);
        let req = make_request(0, 8, false);
        let data = vec![0u8; 512]; // too short: needs 4096 bytes
        let result = dispatch_write_request(&mut backend, &req, &data);
        assert_eq!(result, Err(UblkIoHandlerError::MissingBufferAddress));
    }

    // ── handle_write tests ──────────────────────────────────────────

    #[test]
    fn handle_write_valid_request_succeeds() {
        let mut backend = TestBackend::new(4096 * 512);
        let cap = capacity(4096, 512);
        let desc = UblkIoDescriptor {
            q_id: 0,
            tag: 0,
            op: crate::ublk_io::UblkIoOp::Write,
            flags: 0,
            fua: false,
            start_sector: 16,
            sector_count: 8,
            buffer_addr: 0,
        };
        let data = vec![0xEFu8; 4096];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 4096 }
        ));
    }

    #[test]
    fn handle_write_non_write_descriptor_refused() {
        let mut backend = TestBackend::new(4096 * 512);
        let cap = capacity(4096, 512);
        let desc = UblkIoDescriptor {
            q_id: 0,
            tag: 0,
            op: crate::ublk_io::UblkIoOp::Read,
            flags: 0,
            fua: false,
            start_sector: 0,
            sector_count: 1,
            buffer_addr: 0,
        };
        let data = vec![0u8; 512];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert_eq!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::EINVAL
            }
        );
    }

    #[test]
    fn handle_write_past_capacity_refused() {
        let mut backend = TestBackend::new(512 * 512);
        let cap = capacity(512, 512);
        let desc = UblkIoDescriptor {
            q_id: 0,
            tag: 0,
            op: crate::ublk_io::UblkIoOp::Write,
            flags: 0,
            fua: false,
            start_sector: 500,
            sector_count: 100,
            buffer_addr: 0,
        };
        let data = vec![0u8; 51200];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::ENOSPC
            }
        ));
    }

    // ── UblkWriteValidationError tests ──────────────────────────────

    #[test]
    fn validation_error_to_linux_errno_maps_correctly() {
        assert_eq!(
            UblkWriteValidationError::ZeroLength.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkWriteValidationError::UnalignedSector.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkWriteValidationError::StartPastEndOfDevice {
                start_sector: 0,
                device_sector_count: 0,
            }
            .to_linux_errno(),
            libc::ENOSPC
        );
        assert_eq!(
            UblkWriteValidationError::WritePastEndOfDevice {
                start_sector: 0,
                sector_count: 0,
                device_sector_count: 0,
            }
            .to_linux_errno(),
            libc::ENOSPC
        );
        assert_eq!(
            UblkWriteValidationError::SectorRangeOverflow {
                start_sector: 0,
                sector_count: 0,
            }
            .to_linux_errno(),
            libc::EINVAL
        );
    }

    #[test]
    fn validation_error_as_str_is_stable() {
        assert_eq!(
            UblkWriteValidationError::ZeroLength.as_str(),
            "zero_length_write"
        );
        assert_eq!(
            UblkWriteValidationError::UnalignedSector.as_str(),
            "unaligned_sector"
        );
        assert_eq!(
            UblkWriteValidationError::StartPastEndOfDevice {
                start_sector: 0,
                device_sector_count: 0,
            }
            .as_str(),
            "start_past_end_of_device"
        );
        assert_eq!(
            UblkWriteValidationError::WritePastEndOfDevice {
                start_sector: 0,
                sector_count: 0,
                device_sector_count: 0,
            }
            .as_str(),
            "write_past_end_of_device"
        );
        assert_eq!(
            UblkWriteValidationError::SectorRangeOverflow {
                start_sector: 0,
                sector_count: 0,
            }
            .as_str(),
            "sector_range_overflow"
        );
    }

    #[test]
    fn validation_error_display_contains_key_info() {
        let e = UblkWriteValidationError::ZeroLength;
        assert!(format!("{e}").contains("zero-length"));

        let e = UblkWriteValidationError::UnalignedSector;
        assert!(format!("{e}").contains("512"));

        let e = UblkWriteValidationError::StartPastEndOfDevice {
            start_sector: 42,
            device_sector_count: 10,
        };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("10"));

        let e = UblkWriteValidationError::SectorRangeOverflow {
            start_sector: 1,
            sector_count: 2,
        };
        let s = format!("{e}");
        assert!(s.contains("overflow"));
        assert!(s.contains("1"));
        assert!(s.contains("2"));
    }
}
