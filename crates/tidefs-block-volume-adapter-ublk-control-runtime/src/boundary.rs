// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Capacity-boundary and sector-alignment validation for all ublk I/O
//! types: read, write, discard, write-zeroes.
//!
//! Unified boundary validation for all ublk data I/O types. Each function
//! validates the request against [`DeviceCapacity`] before dispatch — catching
//! sector-alignment violations, capacity overruns, zero-length requests, and
//! sector-range overflow at the ublk layer rather than deferring to backend
//! errors.  Writes use [`handle_write`] which performs the same boundary checks
//! via [`validate_io_request`] before dispatching through the backend.

use crate::ublk_io::{UblkIoBackend, UblkIoDescriptor, UblkIoDispatchResult};
use crate::DeviceCapacity;

/// Error returned when an I/O request fails boundary validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkBoundaryError {
    /// Sector count is zero on a data operation.
    ZeroLength,
    /// Non-512-byte sector size is unsupported.
    UnalignedSector,
    /// Start sector is at or beyond device capacity.
    StartPastEndOfDevice {
        /// First sector of the request.
        start_sector: u64,
        /// Total sectors in the device.
        device_sector_count: u64,
    },
    /// Request span extends beyond device capacity.
    SpanPastEndOfDevice {
        /// First sector of the request.
        start_sector: u64,
        /// Number of sectors requested.
        sector_count: u32,
        /// Total sectors in the device.
        device_sector_count: u64,
    },
    /// start_sector + sector_count overflows u64.
    SectorRangeOverflow {
        /// First sector of the request.
        start_sector: u64,
        /// Number of sectors requested.
        sector_count: u32,
    },
}

impl UblkBoundaryError {
    /// Convert to a Linux errno for ublk CQE posting.
    #[must_use]
    pub const fn to_linux_errno(self) -> i32 {
        match self {
            Self::ZeroLength | Self::UnalignedSector | Self::SectorRangeOverflow { .. } => {
                libc::EINVAL
            }
            Self::StartPastEndOfDevice { .. } | Self::SpanPastEndOfDevice { .. } => libc::ENOSPC,
        }
    }

    /// Stable string label for validation/logging.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroLength => "zero_length",
            Self::UnalignedSector => "unaligned_sector",
            Self::StartPastEndOfDevice { .. } => "start_past_end_of_device",
            Self::SpanPastEndOfDevice { .. } => "span_past_end_of_device",
            Self::SectorRangeOverflow { .. } => "sector_range_overflow",
        }
    }
}

impl From<UblkBoundaryError> for UblkIoDispatchResult {
    fn from(err: UblkBoundaryError) -> Self {
        Self::Refused {
            errno: err.to_linux_errno(),
        }
    }
}

/// Validate a data I/O request against device capacity and sector alignment.
///
/// Checks (in order):
/// 1. Sector count must be non-zero.
/// 2. Sector size must be 512 bytes (required by ublk kernel driver).
/// 3. Overflow guard: `start_sector + sector_count` must not wrap `u64`.
/// 4. Start sector must be within device bounds.
/// 5. End sector (start + count) must not exceed device capacity.
///
/// # Errors
///
/// Returns [`UblkBoundaryError`] if any check fails.
pub fn validate_io_request(
    start_sector: u64,
    sector_count: u32,
    capacity: &DeviceCapacity,
) -> Result<(), UblkBoundaryError> {
    if sector_count == 0 {
        return Err(UblkBoundaryError::ZeroLength);
    }

    if capacity.sector_size != 512 {
        return Err(UblkBoundaryError::UnalignedSector);
    }

    let end_sector = start_sector.checked_add(sector_count as u64).ok_or(
        UblkBoundaryError::SectorRangeOverflow {
            start_sector,
            sector_count,
        },
    )?;

    if start_sector >= capacity.sector_count {
        return Err(UblkBoundaryError::StartPastEndOfDevice {
            start_sector,
            device_sector_count: capacity.sector_count,
        });
    }

    if end_sector > capacity.sector_count {
        return Err(UblkBoundaryError::SpanPastEndOfDevice {
            start_sector,
            sector_count,
            device_sector_count: capacity.sector_count,
        });
    }

    Ok(())
}

// ── Validated dispatch helpers ───────────────────────────────────────

/// Validate and dispatch a ublk read descriptor.
///
/// Capacity-boundary checks are performed before backend dispatch.
#[must_use]
pub fn handle_read(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    read_buf: Option<&mut [u8]>,
    capacity: &DeviceCapacity,
) -> UblkIoDispatchResult {
    if desc.op != crate::ublk_io::UblkIoOp::Read {
        return UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
    }

    if let Err(e) = validate_io_request(desc.start_sector, desc.sector_count, capacity) {
        return UblkIoDispatchResult::from(e);
    }

    match crate::ublk_io::dispatch_io(backend, desc, read_buf, None) {
        Ok(result) => result,
        Err(e) => UblkIoDispatchResult::Refused {
            errno: e.to_linux_errno(),
        },
    }
}

/// Validate and dispatch a ublk discard descriptor.
///
/// A zero-length discard is accepted (no-op). All other boundary checks apply.
#[must_use]
pub fn handle_discard(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    capacity: &DeviceCapacity,
) -> UblkIoDispatchResult {
    if desc.op != crate::ublk_io::UblkIoOp::Discard {
        return UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
    }

    // Zero-length discard is a no-op, skip capacity checks.
    if desc.sector_count > 0 {
        if let Err(e) = validate_io_request(desc.start_sector, desc.sector_count, capacity) {
            return UblkIoDispatchResult::from(e);
        }
    }

    match crate::ublk_io::dispatch_io(backend, desc, None, None) {
        Ok(result) => result,
        Err(e) => UblkIoDispatchResult::Refused {
            errno: e.to_linux_errno(),
        },
    }
}

/// Validate and dispatch a ublk write-zeroes descriptor.
///
/// Capacity-boundary checks are performed before backend dispatch.
#[must_use]
pub fn handle_write_zeroes(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    capacity: &DeviceCapacity,
) -> UblkIoDispatchResult {
    if desc.op != crate::ublk_io::UblkIoOp::WriteZeroes {
        return UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
    }

    if let Err(e) = validate_io_request(desc.start_sector, desc.sector_count, capacity) {
        return UblkIoDispatchResult::from(e);
    }

    match crate::ublk_io::dispatch_io(backend, desc, None, None) {
        Ok(result) => result,
        Err(e) => UblkIoDispatchResult::Refused {
            errno: e.to_linux_errno(),
        },
    }
}

/// Validate and dispatch a ublk write descriptor.
///
/// Capacity-boundary checks are performed before backend dispatch.
#[must_use]
pub fn handle_write(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    write_buf: &[u8],
    capacity: &DeviceCapacity,
) -> UblkIoDispatchResult {
    if desc.op != crate::ublk_io::UblkIoOp::Write {
        return UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
    }

    if let Err(e) = validate_io_request(desc.start_sector, desc.sector_count, capacity) {
        return UblkIoDispatchResult::from(e);
    }

    match crate::ublk_io::dispatch_io(backend, desc, None, Some(write_buf)) {
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
        capacity_bytes: u64,
    }

    impl TestBackend {
        fn new(sector_count: u64) -> Self {
            Self {
                blocks: HashMap::new(),
                capacity_bytes: sector_count * 512,
            }
        }
    }

    impl UblkIoBackend for TestBackend {
        fn read(&mut self, byte_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let end = (byte_offset + buf.len() as u64).min(self.capacity_bytes);
            let len = (end - byte_offset) as usize;
            buf[..len].fill(0);
            Ok(len)
        }

        fn write(&mut self, byte_offset: u64, data: &[u8]) -> std::io::Result<usize> {
            self.blocks.insert(byte_offset, data.to_vec());
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn discard(&mut self, _byte_offset: u64, _byte_len: u64) -> std::io::Result<()> {
            Ok(())
        }

        fn write_zeroes(&mut self, _byte_offset: u64, _byte_len: u64) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capacity(sector_count: u64) -> DeviceCapacity {
        DeviceCapacity {
            dev_id: 1,
            sector_count,
            sector_size: 512,
        }
    }

    fn make_desc(op: crate::ublk_io::UblkIoOp, start: u64, count: u32) -> UblkIoDescriptor {
        UblkIoDescriptor {
            q_id: 0,
            tag: 0,
            op,
            flags: 0,
            fua: false,
            start_sector: start,
            sector_count: count,
            buffer_addr: 0x1000,
        }
    }

    // ── validate_io_request tests ────────────────────────────────────

    #[test]
    fn valid_request_accepted() {
        let cap = capacity(4096);
        assert!(validate_io_request(0, 8, &cap).is_ok());
    }

    #[test]
    fn zero_length_rejected() {
        let cap = capacity(4096);
        assert_eq!(
            validate_io_request(0, 0, &cap),
            Err(UblkBoundaryError::ZeroLength)
        );
    }

    #[test]
    fn unaligned_sector_size_rejected() {
        let cap = DeviceCapacity {
            dev_id: 1,
            sector_count: 4096,
            sector_size: 4096,
        };
        assert_eq!(
            validate_io_request(0, 1, &cap),
            Err(UblkBoundaryError::UnalignedSector)
        );
    }

    #[test]
    fn start_past_end_rejected() {
        let cap = capacity(1024);
        assert_eq!(
            validate_io_request(2048, 1, &cap),
            Err(UblkBoundaryError::StartPastEndOfDevice {
                start_sector: 2048,
                device_sector_count: 1024,
            })
        );
    }

    #[test]
    fn span_past_end_rejected() {
        let cap = capacity(1024);
        assert_eq!(
            validate_io_request(1000, 100, &cap),
            Err(UblkBoundaryError::SpanPastEndOfDevice {
                start_sector: 1000,
                sector_count: 100,
                device_sector_count: 1024,
            })
        );
    }

    #[test]
    fn exact_end_accepted() {
        let cap = capacity(1024);
        assert!(validate_io_request(1000, 24, &cap).is_ok());
    }

    #[test]
    fn overflow_rejected() {
        let cap = capacity(u64::MAX);
        assert_eq!(
            validate_io_request(u64::MAX, 1, &cap),
            Err(UblkBoundaryError::SectorRangeOverflow {
                start_sector: u64::MAX,
                sector_count: 1,
            })
        );
    }

    // ── handle_read tests ────────────────────────────────────────────

    #[test]
    fn handle_read_valid() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Read, 0, 1);
        let mut buf = vec![0u8; 512];
        let result = handle_read(&mut backend, &desc, Some(&mut buf), &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
    }

    #[test]
    fn handle_read_past_capacity_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Read, 5000, 1);
        let mut buf = vec![0u8; 512];
        let result = handle_read(&mut backend, &desc, Some(&mut buf), &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::ENOSPC
            }
        ));
    }

    #[test]
    fn handle_read_non_read_op_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Write, 0, 1);
        let mut buf = vec![0u8; 512];
        let result = handle_read(&mut backend, &desc, Some(&mut buf), &cap);
        assert!(matches!(result, UblkIoDispatchResult::Refused { .. }));
    }

    // ── handle_discard tests ─────────────────────────────────────────

    #[test]
    fn handle_discard_valid() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Discard, 100, 16);
        let result = handle_discard(&mut backend, &desc, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
    }

    #[test]
    fn handle_discard_zero_length_accepted() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Discard, 0, 0);
        let result = handle_discard(&mut backend, &desc, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
    }

    #[test]
    fn handle_discard_past_capacity_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Discard, 4000, 200);
        let result = handle_discard(&mut backend, &desc, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::ENOSPC
            }
        ));
    }

    // ── handle_write_zeroes tests ────────────────────────────────────

    #[test]
    fn handle_write_zeroes_valid() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::WriteZeroes, 50, 8);
        let result = handle_write_zeroes(&mut backend, &desc, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
    }

    #[test]
    fn handle_write_zeroes_past_capacity_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::WriteZeroes, 4000, 200);
        let result = handle_write_zeroes(&mut backend, &desc, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::ENOSPC
            }
        ));
    }

    // ── handle_write tests ───────────────────────────────────────────

    #[test]
    fn handle_write_valid() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Write, 0, 4);
        let data = vec![0xABu8; 2048];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
        assert_eq!(backend.blocks.get(&0).unwrap(), &data);
    }

    #[test]
    fn handle_write_past_capacity_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Write, 4000, 200);
        let data = vec![0u8; 102400];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::ENOSPC
            }
        ));
    }

    #[test]
    fn handle_write_non_write_op_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Read, 0, 1);
        let data = vec![0u8; 512];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Refused { .. }));
    }

    #[test]
    fn handle_write_zero_length_refused() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(4096);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Write, 0, 0);
        let data = vec![0u8; 512];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(
            result,
            UblkIoDispatchResult::Refused {
                errno: libc::EINVAL
            }
        ));
    }

    #[test]
    fn handle_write_exact_end_accepted() {
        let mut backend = TestBackend::new(4096);
        let cap = capacity(1024);
        let desc = make_desc(crate::ublk_io::UblkIoOp::Write, 1000, 24);
        let data = vec![0xCDu8; 12288];
        let result = handle_write(&mut backend, &desc, &data, &cap);
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
    }

    // ── UblkBoundaryError coverage ───────────────────────────────────

    #[test]
    fn boundary_error_to_linux_errno_maps_correctly() {
        assert_eq!(UblkBoundaryError::ZeroLength.to_linux_errno(), libc::EINVAL);
        assert_eq!(
            UblkBoundaryError::UnalignedSector.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkBoundaryError::StartPastEndOfDevice {
                start_sector: 0,
                device_sector_count: 0,
            }
            .to_linux_errno(),
            libc::ENOSPC
        );
        assert_eq!(
            UblkBoundaryError::SpanPastEndOfDevice {
                start_sector: 0,
                sector_count: 0,
                device_sector_count: 0,
            }
            .to_linux_errno(),
            libc::ENOSPC
        );
        assert_eq!(
            UblkBoundaryError::SectorRangeOverflow {
                start_sector: 0,
                sector_count: 0,
            }
            .to_linux_errno(),
            libc::EINVAL
        );
    }

    #[test]
    fn boundary_error_as_str_stable() {
        assert_eq!(UblkBoundaryError::ZeroLength.as_str(), "zero_length");
        assert_eq!(
            UblkBoundaryError::UnalignedSector.as_str(),
            "unaligned_sector"
        );
    }
}
