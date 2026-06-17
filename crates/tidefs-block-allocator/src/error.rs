//! Error types for the block allocator.
//!
//! Every public method on `BlockAllocator` that can fail returns
//! `AllocError`. The error variants cover the full allocation failure
//! space: pool exhaustion (`NoSpace`), per-inode quota breach
//! (`QuotaExceeded`), sector-alignment violations
//! (`AlignmentViolation`, `MisalignedOffset`), cross-device topology
//! mismatches (`MixedDeviceTopology`), registration conflicts
//! (`DeviceAlreadyRegistered`), and I/O failures during bitmap flush
//! (`Io`). Callers match on the variant to decide retry, rollback, or
//! error propagation.

use core::fmt;

/// Errors returned by the block allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocError {
    /// No free blocks remain; pool is exhausted (ENOSPC).
    NoSpace,
    /// Per-inode quota would be exceeded by this allocation.
    QuotaExceeded,
    /// The requested byte range is not aligned to the device's
    /// physical sector / minimum I/O size boundary.
    AlignmentViolation,
    /// The requested start offset is not sector-aligned (e.g. offset=1 on a
    /// 4K-sector device). The caller must pass an aligned offset.
    MisalignedOffset,
    /// The requested range spans two or more devices with different
    /// topologies (sector size, alignment offset, min I/O size).
    /// Allocations must be contained within a single device.
    MixedDeviceTopology,
    /// No device topology is registered for the requested offset and no
    /// default topology is available.
    DeviceNotRegistered,
    /// A device with this DeviceId is already registered.
    DeviceAlreadyRegistered,
    /// I/O error during bitmap read/write.
    Io,
    /// The requested allocation cannot be satisfied because sector-alignment
    /// rounding consumed the entire usable region or exceeded the maximum
    /// allowed slack fraction. The caller should request a larger or
    /// differently-aligned range.
    AlignmentImpossible,
    /// The supplied `DeviceTopology` is invalid — for example,
    /// `logical_sector_size` is not a power of two, or
    /// `alignment_offset >= logical_sector_size`.
    InvalidDeviceTopology,
    /// The requested operation conflicts with a commit-group epoch fence.
    CommitGroupConflict,
}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSpace => write!(f, "no free blocks available"),
            Self::QuotaExceeded => write!(f, "per-inode quota exceeded"),
            Self::AlignmentViolation => {
                write!(f, "allocation violates device sector alignment")
            }
            Self::MisalignedOffset => {
                write!(f, "allocation start offset is not sector-aligned")
            }
            Self::MixedDeviceTopology => {
                write!(
                    f,
                    "allocation range spans devices with different topologies"
                )
            }
            Self::DeviceNotRegistered => {
                write!(f, "no device topology registered for the requested offset")
            }
            Self::DeviceAlreadyRegistered => {
                write!(f, "a device with this DeviceId is already registered")
            }
            Self::Io => write!(f, "I/O error during bitmap flush"),
            Self::AlignmentImpossible => {
                write!(
                    f,
                    "sector alignment consumed too much of the requested range"
                )
            }
            Self::InvalidDeviceTopology => {
                write!(f, "the supplied device topology is invalid")
            }
            Self::CommitGroupConflict => {
                write!(f, "block operation conflicts with commit-group epoch fence")
            }
        }
    }
}
