// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Live-data allocator cursor helpers for the mounted kernel VFS engine.
//!
//! The Kbuild-only `KernelEngine` stores file data in compact physical extents
//! while exposing sparse logical ranges.  Its allocation cursor may rewind only
//! to the maximum reserved tail of surviving DATA extents; otherwise repeated
//! unlink/truncate cycles leak the scratch device tail until xfstests sees
//! false ENOSPC.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveDataAllocatorError {
    InvalidQuantum,
    Overflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveDataAllocatorExtent {
    pub physical_start: u64,
    pub logical_len: u64,
    pub physical_reserved_end: u64,
}

pub fn align_up_to_quantum(value: u64, quantum: u64) -> Result<u64, LiveDataAllocatorError> {
    if quantum == 0 {
        return Err(LiveDataAllocatorError::InvalidQuantum);
    }

    let rem = value % quantum;
    if rem == 0 {
        return Ok(value);
    }

    value
        .checked_add(quantum - rem)
        .ok_or(LiveDataAllocatorError::Overflow)
}

pub fn reserved_extent_tail(
    extent: LiveDataAllocatorExtent,
    quantum: u64,
) -> Result<u64, LiveDataAllocatorError> {
    let used_end = extent
        .physical_start
        .checked_add(extent.logical_len)
        .ok_or(LiveDataAllocatorError::Overflow)?;
    let reserved_end = used_end.max(extent.physical_reserved_end);

    align_up_to_quantum(reserved_end, quantum)
}

pub fn recompute_tail_from_extents(
    extents: &[LiveDataAllocatorExtent],
    quantum: u64,
) -> Result<u64, LiveDataAllocatorError> {
    let mut tail = 0u64;

    for extent in extents {
        tail = tail.max(reserved_extent_tail(*extent, quantum)?);
    }

    Ok(tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const LIVE_BLOCK: u64 = 4096;

    #[test]
    fn recompute_tail_reclaims_deleted_tail_extent() {
        let write_len = 800 * MIB;
        let scratch_capacity = 1024 * MIB;
        let stale_tail = recompute_tail_from_extents(
            &[LiveDataAllocatorExtent {
                physical_start: 0,
                logical_len: write_len,
                physical_reserved_end: write_len,
            }],
            LIVE_BLOCK,
        )
        .unwrap();
        let stale_second_end = stale_tail + align_up_to_quantum(write_len, LIVE_BLOCK).unwrap();

        assert!(stale_second_end > scratch_capacity);
        assert_eq!(recompute_tail_from_extents(&[], LIVE_BLOCK).unwrap(), 0);
        assert!(align_up_to_quantum(write_len, LIVE_BLOCK).unwrap() <= scratch_capacity);
    }

    #[test]
    fn recompute_tail_keeps_surviving_append_reservation() {
        let tail = recompute_tail_from_extents(
            &[LiveDataAllocatorExtent {
                physical_start: 0,
                logical_len: LIVE_BLOCK,
                physical_reserved_end: MIB,
            }],
            LIVE_BLOCK,
        )
        .unwrap();

        assert_eq!(tail, MIB);
    }

    #[test]
    fn recompute_tail_uses_used_end_when_reserved_tail_is_shorter() {
        let tail = recompute_tail_from_extents(
            &[LiveDataAllocatorExtent {
                physical_start: 17,
                logical_len: LIVE_BLOCK,
                physical_reserved_end: 0,
            }],
            LIVE_BLOCK,
        )
        .unwrap();

        assert_eq!(tail, LIVE_BLOCK * 2);
    }

    #[test]
    fn align_up_reports_invalid_quantum_and_overflow() {
        assert_eq!(
            align_up_to_quantum(1, 0),
            Err(LiveDataAllocatorError::InvalidQuantum)
        );
        assert_eq!(
            align_up_to_quantum(u64::MAX, LIVE_BLOCK),
            Err(LiveDataAllocatorError::Overflow)
        );
    }
}
