// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Ublk I/O boundary validator: sector alignment, capacity bounds,
//! overflow guards, zero-length acceptance, and short-I/O detection.
//!
//! The [`BoundaryValidator`] is a pure-function struct parameterised
//! by device capacity and sector size. It produces [`BoundaryError`]
//! variants with Linux errno codes suitable for ublk CQE posting:
//! `EINVAL` for misalignment/overflow, `ENOSPC` for out-of-bounds.
//!
//! After dispatch, [`BoundaryValidator::check_short`] detects partial
//! completions so the caller can raise the ublk `UBLK_IO_RES_NEED_GET_DATA`
//! flag.

use std::fmt;

/// Pure-function boundary validator for ublk I/O requests.
///
/// Holds device capacity and sector size; all validation methods are
/// read-only and side-effect-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryValidator {
    /// Total usable bytes of the block device.
    capacity_bytes: u64,
    /// Logical sector size in bytes (typically 512).
    sector_size: u64,
}

impl BoundaryValidator {
    /// Create a new validator for a device with the given byte capacity
    /// and logical sector size.
    #[must_use]
    pub const fn new(capacity_bytes: u64, sector_size: u64) -> Self {
        Self {
            capacity_bytes,
            sector_size,
        }
    }

    /// Return the configured capacity in bytes.
    #[must_use]
    pub const fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }

    /// Return the configured sector size.
    #[must_use]
    pub const fn sector_size(self) -> u64 {
        self.sector_size
    }

    // ── Pre-dispatch validation ──────────────────────────────────

    /// Validate a read request against sector alignment and capacity
    /// bounds. Zero-length reads are accepted (no-op).
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryError`] with the appropriate Linux errno.
    pub fn validate_read(&self, offset: u64, length: u64) -> Result<(), BoundaryError> {
        self.validate_io(offset, length)
    }

    /// Validate a write request against sector alignment and capacity
    /// bounds. Zero-length writes are accepted (no-op).
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryError`] with the appropriate Linux errno.
    pub fn validate_write(&self, offset: u64, length: u64) -> Result<(), BoundaryError> {
        self.validate_io(offset, length)
    }

    /// Shared validation logic for reads and writes.
    fn validate_io(&self, offset: u64, length: u64) -> Result<(), BoundaryError> {
        // Zero-length I/O: accepted without dispatch.
        if length == 0 {
            return Ok(());
        }

        // Sector-alignment check (both offset and length must be
        // multiples of sector_size).
        if self.sector_size == 0 {
            return Err(BoundaryError::Misaligned {
                offset,
                length,
                sector_size: self.sector_size,
                detail: DetailKind::ZeroSectorSize,
            });
        }
        if offset % self.sector_size != 0 {
            return Err(BoundaryError::Misaligned {
                offset,
                length,
                sector_size: self.sector_size,
                detail: DetailKind::OffsetNotAligned,
            });
        }
        if length % self.sector_size != 0 {
            return Err(BoundaryError::Misaligned {
                offset,
                length,
                sector_size: self.sector_size,
                detail: DetailKind::LengthNotAligned,
            });
        }

        // Overflow guard: offset + length must not wrap u64.
        let end = offset
            .checked_add(length)
            .ok_or(BoundaryError::SectorOverflow { offset, length })?;

        // Out-of-bounds: end must not exceed capacity.
        if end > self.capacity_bytes {
            return Err(BoundaryError::OutOfBounds {
                offset,
                length,
                capacity: self.capacity_bytes,
            });
        }

        Ok(())
    }

    // ── Post-dispatch short-I/O detection ─────────────────────────

    /// Check whether a read or write completion was short (backend
    /// returned fewer bytes than requested).
    ///
    /// Returns `true` when `actual < requested`, indicating the caller
    /// should raise the `UBLK_IO_RES_NEED_GET_DATA` flag.
    #[must_use]
    pub fn check_short(&self, requested: u64, actual: usize) -> bool {
        (actual as u64) < requested
    }

    /// Return the short-I/O ublk result code when a completion is short.
    ///
    /// This is `UBLK_IO_RES_NEED_GET_DATA` (1) when `actual < requested`,
    /// otherwise `UBLK_IO_RES_OK` (0).
    #[must_use]
    pub fn short_io_ublk_result(&self, requested: u64, actual: usize) -> i32 {
        if self.check_short(requested, actual) {
            1 // UBLK_IO_RES_NEED_GET_DATA
        } else {
            0 // UBLK_IO_RES_OK
        }
    }
}

/// Detail discriminator for [`BoundaryError::Misaligned`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailKind {
    /// The sector size is zero (invalid device geometry).
    ZeroSectorSize,
    /// The byte offset is not a multiple of the sector size.
    OffsetNotAligned,
    /// The byte length is not a multiple of the sector size.
    LengthNotAligned,
}

/// Error returned by [`BoundaryValidator`] when an I/O request fails
/// pre-dispatch validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryError {
    /// Offset or length is not a multiple of the sector size.
    Misaligned {
        /// Byte offset of the request.
        offset: u64,
        /// Byte length of the request.
        length: u64,
        /// Configured sector size.
        sector_size: u64,
        /// Which field caused the misalignment.
        detail: DetailKind,
    },
    /// The request spans beyond device capacity.
    OutOfBounds {
        /// Byte offset of the request.
        offset: u64,
        /// Byte length of the request.
        length: u64,
        /// Total device capacity in bytes.
        capacity: u64,
    },
    /// The offset + length computation overflows u64.
    SectorOverflow {
        /// Byte offset of the request.
        offset: u64,
        /// Byte length of the request.
        length: u64,
    },
}

impl BoundaryError {
    /// Convert to a Linux errno for ublk CQE posting.
    ///
    /// Misalignment → `EINVAL`, out-of-bounds → `ENOSPC`,
    /// overflow → `EINVAL`.
    #[must_use]
    pub const fn to_linux_errno(self) -> i32 {
        match self {
            Self::Misaligned { .. } | Self::SectorOverflow { .. } => 22i32,
            Self::OutOfBounds { .. } => 28i32,
        }
    }

    /// Stable string label for validation/logging.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Misaligned { detail, .. } => match detail {
                DetailKind::ZeroSectorSize => "zero_sector_size",
                DetailKind::OffsetNotAligned => "offset_not_aligned",
                DetailKind::LengthNotAligned => "length_not_aligned",
            },
            Self::OutOfBounds { .. } => "out_of_bounds",
            Self::SectorOverflow { .. } => "sector_overflow",
        }
    }
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned {
                offset,
                length,
                sector_size,
                detail,
            } => {
                let what = match detail {
                    DetailKind::ZeroSectorSize => "sector size is zero",
                    DetailKind::OffsetNotAligned => "offset not aligned",
                    DetailKind::LengthNotAligned => "length not aligned",
                };
                write!(
                    f,
                    "misaligned I/O: offset={offset} length={length} sector_size={sector_size} ({what})"
                )
            }
            Self::OutOfBounds {
                offset,
                length,
                capacity,
            } => {
                write!(
                    f,
                    "I/O out of bounds: offset={offset} length={length} exceeds capacity={capacity}"
                )
            }
            Self::SectorOverflow { offset, length } => {
                write!(
                    f,
                    "sector range overflow: offset={offset} + length={length} wraps u64"
                )
            }
        }
    }
}

impl std::error::Error for BoundaryError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn validator_512(capacity_sectors: u64) -> BoundaryValidator {
        BoundaryValidator::new(capacity_sectors * 512, 512)
    }

    fn validator_4k(capacity_sectors: u64) -> BoundaryValidator {
        BoundaryValidator::new(capacity_sectors * 4096, 4096)
    }

    // ── Constructor / accessors ──────────────────────────────────────

    #[test]
    fn new_stores_capacity_and_sector_size() {
        let v = BoundaryValidator::new(1048576, 512);
        assert_eq!(v.capacity_bytes(), 1048576);
        assert_eq!(v.sector_size(), 512);
    }

    #[test]
    fn validator_is_copy_and_eq() {
        let a = BoundaryValidator::new(4096, 512);
        let b = a;
        assert_eq!(a, b);
    }

    // ── validate_read / validate_write ───────────────────────────────

    #[test]
    fn aligned_read_start_of_device_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(0, 512).is_ok());
    }

    #[test]
    fn aligned_read_mid_device_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(1024 * 512, 256 * 512).is_ok());
    }

    #[test]
    fn aligned_read_exact_end_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(1024 * 512, 1024 * 512).is_ok()); // last half
    }

    #[test]
    fn aligned_read_last_sector_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(2047 * 512, 512).is_ok());
    }

    #[test]
    fn aligned_write_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_write(512, 1024).is_ok());
    }

    // ── Zero-length ──────────────────────────────────────────────────

    #[test]
    fn zero_length_read_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(0, 0).is_ok());
    }

    #[test]
    fn zero_length_write_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_write(1024, 0).is_ok());
    }

    #[test]
    fn zero_length_at_capacity_edge_accepted() {
        let v = validator_512(2048);
        assert!(v.validate_read(2048 * 512, 0).is_ok());
    }

    // ── Misaligned offset ────────────────────────────────────────────

    #[test]
    fn read_misaligned_offset_rejected() {
        let v = validator_512(2048);
        let err = v.validate_read(1, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 1,
                length: 512,
                sector_size: 512,
                detail: DetailKind::OffsetNotAligned,
            }
        );
        assert_eq!(err.to_linux_errno(), 22i32);
    }

    #[test]
    fn write_misaligned_offset_rejected() {
        let v = validator_512(2048);
        let err = v.validate_write(513, 1024).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 513,
                length: 1024,
                sector_size: 512,
                detail: DetailKind::OffsetNotAligned,
            }
        );
    }

    // ── Misaligned length ────────────────────────────────────────────

    #[test]
    fn read_misaligned_length_rejected() {
        let v = validator_512(2048);
        let err = v.validate_read(0, 513).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 0,
                length: 513,
                sector_size: 512,
                detail: DetailKind::LengthNotAligned,
            }
        );
    }

    #[test]
    fn write_misaligned_length_rejected() {
        let v = validator_512(2048);
        let err = v.validate_write(1024, 511).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 1024,
                length: 511,
                sector_size: 512,
                detail: DetailKind::LengthNotAligned,
            }
        );
    }

    // ── Out of bounds read ───────────────────────────────────────────

    #[test]
    fn read_past_capacity_rejected() {
        let v = validator_512(1024); // 1024 sectors = 524288 bytes
        let err = v.validate_read(1000 * 512, 100 * 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::OutOfBounds {
                offset: 512000,
                length: 51200,
                capacity: 524288,
            }
        );
        assert_eq!(err.to_linux_errno(), 28i32);
    }

    #[test]
    fn read_at_capacity_exact_fails() {
        // Reading at exact capacity (offset==capacity) with length>0 is out of bounds
        let v = validator_512(1024);
        let err = v.validate_read(1024 * 512, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::OutOfBounds {
                offset: 524288,
                length: 512,
                capacity: 524288,
            }
        );
    }

    // ── Out of bounds write ──────────────────────────────────────────

    #[test]
    fn write_past_capacity_rejected() {
        let v = validator_512(512); // 512 sectors
        let err = v.validate_write(500 * 512, 100 * 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::OutOfBounds {
                offset: 256000,
                length: 51200,
                capacity: 262144,
            }
        );
    }

    #[test]
    fn write_at_offset_past_capacity_rejected() {
        let v = validator_512(512);
        let err = v.validate_write(600 * 512, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::OutOfBounds {
                offset: 307200,
                length: 512,
                capacity: 262144,
            }
        );
    }

    // ── Exact boundary tests ─────────────────────────────────────────

    #[test]
    fn read_exact_last_sector_accepted() {
        let v = validator_512(1024);
        assert!(v.validate_read(1023 * 512, 512).is_ok());
    }

    #[test]
    fn write_exact_last_sector_accepted() {
        let v = validator_512(1024);
        assert!(v.validate_write(1023 * 512, 512).is_ok());
    }

    // ── Overflow ─────────────────────────────────────────────────────

    #[test]
    fn overflow_rejected() {
        let v = BoundaryValidator::new(u64::MAX, 512);
        let err = v.validate_read(u64::MAX - 511, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::SectorOverflow {
                offset: u64::MAX - 511,
                length: 512,
            }
        );
        assert_eq!(err.to_linux_errno(), 22i32);
    }

    // ── Zero sector size ─────────────────────────────────────────────

    #[test]
    fn zero_sector_size_rejected() {
        let v = BoundaryValidator::new(4096, 0);
        let err = v.validate_read(0, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 0,
                length: 512,
                sector_size: 0,
                detail: DetailKind::ZeroSectorSize,
            }
        );
    }

    // ── 4K sector size ───────────────────────────────────────────────

    #[test]
    fn read_aligned_to_4k_sector_accepted() {
        let v = validator_4k(256);
        assert!(v.validate_read(0, 4096).is_ok());
    }

    #[test]
    fn read_misaligned_to_4k_sector_rejected() {
        let v = validator_4k(256);
        let err = v.validate_read(512, 4096).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: 512,
                length: 4096,
                sector_size: 4096,
                detail: DetailKind::OffsetNotAligned,
            }
        );
    }

    // ── Short-I/O detection ──────────────────────────────────────────

    #[test]
    fn check_short_detects_partial_read() {
        let v = validator_512(2048);
        assert!(v.check_short(4096, 2048));
    }

    #[test]
    fn check_short_detects_partial_write() {
        let v = validator_512(2048);
        assert!(v.check_short(8192, 4096));
    }

    #[test]
    fn check_short_returns_false_for_full_completion() {
        let v = validator_512(2048);
        assert!(!v.check_short(4096, 4096));
    }

    #[test]
    fn check_short_returns_false_for_zero_requested() {
        let v = validator_512(2048);
        assert!(!v.check_short(0, 0));
    }

    #[test]
    fn short_io_ublk_result_returns_need_get_data_for_short() {
        let v = validator_512(2048);
        assert_eq!(v.short_io_ublk_result(4096, 2048), 1); // UBLK_IO_RES_NEED_GET_DATA
    }

    #[test]
    fn short_io_ublk_result_returns_ok_for_full() {
        let v = validator_512(2048);
        assert_eq!(v.short_io_ublk_result(4096, 4096), 0); // UBLK_IO_RES_OK
    }

    #[test]
    fn short_io_ublk_result_on_zero_length_request() {
        let v = validator_512(2048);
        // zero-length request with zero actual → not short
        assert_eq!(v.short_io_ublk_result(0, 0), 0);
    }

    // ── BoundaryError Display / as_str ───────────────────────────────

    #[test]
    fn boundary_error_display_contains_details() {
        let e = BoundaryError::Misaligned {
            offset: 1,
            length: 512,
            sector_size: 512,
            detail: DetailKind::OffsetNotAligned,
        };
        let s = format!("{e}");
        assert!(s.contains("misaligned"));
        assert!(s.contains("1"));
        assert!(s.contains("512"));

        let e = BoundaryError::OutOfBounds {
            offset: 100,
            length: 50,
            capacity: 120,
        };
        let s = format!("{e}");
        assert!(s.contains("bounds"));
        assert!(s.contains("100"));
        assert!(s.contains("120"));

        let e = BoundaryError::SectorOverflow {
            offset: u64::MAX,
            length: 1,
        };
        let s = format!("{e}");
        assert!(s.contains("overflow"));
    }

    #[test]
    fn boundary_error_as_str_is_stable() {
        assert_eq!(
            BoundaryError::Misaligned {
                offset: 0,
                length: 0,
                sector_size: 512,
                detail: DetailKind::OffsetNotAligned,
            }
            .as_str(),
            "offset_not_aligned"
        );
        assert_eq!(
            BoundaryError::Misaligned {
                offset: 0,
                length: 0,
                sector_size: 512,
                detail: DetailKind::LengthNotAligned,
            }
            .as_str(),
            "length_not_aligned"
        );
        assert_eq!(
            BoundaryError::OutOfBounds {
                offset: 0,
                length: 0,
                capacity: 0,
            }
            .as_str(),
            "out_of_bounds"
        );
    }

    #[test]
    fn boundary_error_is_error_trait() {
        let e = BoundaryError::OutOfBounds {
            offset: 0,
            length: 0,
            capacity: 0,
        };
        let _: &dyn std::error::Error = &e;
    }

    // ── Full coverage of DetailKind ──────────────────────────────────

    #[test]
    fn detail_kind_misaligned_with_zero_sector_size() {
        let e = BoundaryError::Misaligned {
            offset: 0,
            length: 512,
            sector_size: 0,
            detail: DetailKind::ZeroSectorSize,
        };
        assert_eq!(e.as_str(), "zero_sector_size");
        assert_eq!(e.to_linux_errno(), 22i32);
    }

    // ── Validate at u64 boundaries ───────────────────────────────────

    #[test]
    fn validate_at_u64_max_offset_with_small_length() {
        let v = BoundaryValidator::new(u64::MAX, 512);
        let err = v.validate_read(u64::MAX - 1, 512).unwrap_err();
        assert_eq!(
            err,
            BoundaryError::Misaligned {
                offset: u64::MAX - 1,
                length: 512,
                sector_size: 512,
                detail: DetailKind::OffsetNotAligned,
            }
        );
    }
}
