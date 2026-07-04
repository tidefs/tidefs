// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

use core::mem::size_of;

pub const UBLK_ABI_GATE_OW_301I: &str =
    "OW-301I ublk ABI control-plan surface mirrors Linux ublk UAPI without issuing control ioctls";
pub const UBLK_CMD_TYPE: u8 = b'u';

pub const UBLK_CMD_GET_QUEUE_AFFINITY: u8 = 0x01;
pub const UBLK_CMD_GET_DEV_INFO: u8 = 0x02;
pub const UBLK_CMD_ADD_DEV: u8 = 0x04;
pub const UBLK_CMD_DEL_DEV: u8 = 0x05;
pub const UBLK_CMD_START_DEV: u8 = 0x06;
pub const UBLK_CMD_STOP_DEV: u8 = 0x07;
pub const UBLK_CMD_SET_PARAMS: u8 = 0x08;
pub const UBLK_CMD_GET_PARAMS: u8 = 0x09;
pub const UBLK_CMD_START_USER_RECOVERY: u8 = 0x10;
pub const UBLK_CMD_END_USER_RECOVERY: u8 = 0x11;
pub const UBLK_CMD_GET_DEV_INFO2: u8 = 0x12;
pub const UBLK_CMD_GET_FEATURES: u8 = 0x13;
pub const UBLK_CMD_DEL_DEV_ASYNC: u8 = 0x14;
pub const UBLK_CMD_UPDATE_SIZE: u8 = 0x15;
pub const UBLK_CMD_QUIESCE_DEV: u8 = 0x16;

pub const UBLK_IO_FETCH_REQ: u8 = 0x20;
pub const UBLK_IO_COMMIT_AND_FETCH_REQ: u8 = 0x21;
pub const UBLK_IO_NEED_GET_DATA: u8 = 0x22;
pub const UBLK_IO_REGISTER_IO_BUF: u8 = 0x23;
pub const UBLK_IO_UNREGISTER_IO_BUF: u8 = 0x24;
pub const UBLK_IO_URING_CMD: u8 = 0x25;

pub const UBLK_FEATURES_LEN: usize = 8;
pub const UBLK_MAX_QUEUE_DEPTH: u16 = 4096;
pub const UBLK_IO_BUF_BITS: u8 = 25;
pub const UBLK_TAG_BITS: u8 = 16;
pub const UBLK_QID_BITS: u8 = 12;
pub const UBLK_TAG_OFF: u8 = UBLK_IO_BUF_BITS;
pub const UBLK_QID_OFF: u8 = UBLK_TAG_OFF + UBLK_TAG_BITS;
pub const UBLK_MAX_NR_QUEUES: u16 = 1 << UBLK_QID_BITS;
pub const UBLK_IO_BUF_BITS_MASK: u64 = (1_u64 << UBLK_IO_BUF_BITS) - 1;
pub const UBLK_TAG_BITS_MASK: u64 = (1_u64 << UBLK_TAG_BITS) - 1;
pub const UBLK_QID_BITS_MASK: u64 = (1_u64 << UBLK_QID_BITS) - 1;
pub const UBLKSRV_CMD_BUF_OFFSET: u64 = 0;
pub const UBLKSRV_IO_BUF_OFFSET: u64 = 0x8000_0000;
pub const UBLKSRV_IO_BUF_TOTAL_BITS: u8 = UBLK_QID_OFF + UBLK_QID_BITS;
pub const UBLKSRV_IO_BUF_TOTAL_SIZE: u64 = 1_u64 << UBLKSRV_IO_BUF_TOTAL_BITS;

/// Compute the per-queue command-buffer size for a given queue depth, matching
/// Linux 7.0 __ublk_queue_cmd_buf_size: round_up(depth * sizeof(ublksrv_io_desc), PAGE_SIZE).
#[must_use]
pub const fn ublk_queue_cmd_buf_size(queue_depth: u16) -> usize {
    let raw = (queue_depth as usize) * core::mem::size_of::<UblkSrvIoDesc>();
    let page_mask = 4095_usize;
    (raw + page_mask) & !page_mask
}

/// Maximum possible per-queue command-buffer size across all queue depths.
/// Matches Linux 7.0 ublk_max_cmd_buf_size(). Used as the mmap stride between
/// per-queue command buffers (q_id = phys_off / max_sz in ublk_ch_mmap).
#[must_use]
pub const fn ublk_max_cmd_buf_size() -> usize {
    ublk_queue_cmd_buf_size(UBLK_MAX_QUEUE_DEPTH)
}

#[must_use]
pub const fn ublk_cmd_buf_mmap_offset(queue_id: u16) -> Option<u64> {
    if queue_id as u64 > UBLK_QID_BITS_MASK {
        return None;
    }
    Some(UBLKSRV_CMD_BUF_OFFSET + (queue_id as u64) * (ublk_max_cmd_buf_size() as u64))
}

// Compile-time assertion: UblkSrvIoDesc must match the kernel's struct ublksrv_io_desc size.
// If this fails, the mmap size calculation will not match Linux 7.0's ublk_ch_mmap check.
const _UBLK_SRV_IO_DESC_SIZE_CHECK: () = assert!(
    core::mem::size_of::<UblkSrvIoDesc>() == 24,
    "UblkSrvIoDesc size mismatch with kernel"
);

pub const UBLK_IO_RES_OK: i32 = 0;
pub const UBLK_IO_RES_NEED_GET_DATA: i32 = 1;
pub const UBLK_IO_RES_ABORT: i32 = -19;

pub const UBLK_IO_OP_READ: u8 = 0;
pub const UBLK_IO_OP_WRITE: u8 = 1;
pub const UBLK_IO_OP_FLUSH: u8 = 2;
pub const UBLK_IO_OP_DISCARD: u8 = 3;
pub const UBLK_IO_OP_WRITE_SAME: u8 = 4;
pub const UBLK_IO_OP_WRITE_ZEROES: u8 = 5;
pub const UBLK_IO_OP_ZONE_OPEN: u8 = 10;
pub const UBLK_IO_OP_ZONE_CLOSE: u8 = 11;
pub const UBLK_IO_OP_ZONE_FINISH: u8 = 12;
pub const UBLK_IO_OP_ZONE_APPEND: u8 = 13;
pub const UBLK_IO_OP_ZONE_RESET_ALL: u8 = 14;
pub const UBLK_IO_OP_ZONE_RESET: u8 = 15;
pub const UBLK_IO_OP_REPORT_ZONES: u8 = 18;

pub const UBLK_IO_F_FAILFAST_DEV: u32 = 1 << 8;
pub const UBLK_IO_F_FAILFAST_TRANSPORT: u32 = 1 << 9;
pub const UBLK_IO_F_FAILFAST_DRIVER: u32 = 1 << 10;
pub const UBLK_IO_F_META: u32 = 1 << 11;
pub const UBLK_IO_F_FUA: u32 = 1 << 13;
pub const UBLK_IO_F_NOUNMAP: u32 = 1 << 15;
pub const UBLK_IO_F_SWAP: u32 = 1 << 16;
pub const UBLK_IO_F_NEED_REG_BUF: u32 = 1 << 17;
/// Bitwise OR of every known uBLK I/O flag constant.
/// Used to detect reserved-flag drift in [`UblkSrvIoDesc::validate`].
pub const UBLK_IO_F_ALL_KNOWN: u32 = UBLK_IO_F_FAILFAST_DEV
    | UBLK_IO_F_FAILFAST_TRANSPORT
    | UBLK_IO_F_FAILFAST_DRIVER
    | UBLK_IO_F_META
    | UBLK_IO_F_FUA
    | UBLK_IO_F_NOUNMAP
    | UBLK_IO_F_SWAP
    | UBLK_IO_F_NEED_REG_BUF;

/// Mask of reserved bits in the `flags` portion (`op_flags >> 8`) of an
/// [`UblkSrvIoDesc`].  Any set bit in this mask after masking out the known
/// flag bits indicates reserved-field drift that must be rejected.
pub const UBLK_IO_F_RESERVED_MASK: u32 = !(UBLK_IO_F_ALL_KNOWN >> 8); /* flags occupies bits 8+ of op_flags */

pub const UBLK_ATTR_READ_ONLY: u32 = 1 << 0;
pub const UBLK_ATTR_ROTATIONAL: u32 = 1 << 1;
pub const UBLK_ATTR_VOLATILE_CACHE: u32 = 1 << 2;
pub const UBLK_ATTR_FUA: u32 = 1 << 3;

pub const UBLK_PARAM_TYPE_BASIC: u32 = 1 << 0;
pub const UBLK_PARAM_TYPE_DISCARD: u32 = 1 << 1;
pub const UBLK_PARAM_TYPE_DEVT: u32 = 1 << 2;
pub const UBLK_PARAM_TYPE_ZONED: u32 = 1 << 3;
pub const UBLK_PARAM_TYPE_DMA_ALIGN: u32 = 1 << 4;
pub const UBLK_PARAM_TYPE_SEGMENT: u32 = 1 << 5;
pub const UBLK_MIN_SEGMENT_SIZE: u32 = 4096;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_DIRBITS: u32 = 2;
const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
const IOC_TYPEMASK: u32 = (1 << IOC_TYPEBITS) - 1;
const IOC_SIZEMASK: u32 = (1 << IOC_SIZEBITS) - 1;
const IOC_DIRMASK: u32 = (1 << IOC_DIRBITS) - 1;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

pub const UBLK_IOCTL_MAX_SIZE: usize = IOC_SIZEMASK as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoctlDirection {
    None,
    Write,
    Read,
    ReadWrite,
    Unknown(u32),
}

impl UblkIoctlDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Write => "write",
            Self::Read => "read",
            Self::ReadWrite => "read_write",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoctlRequestError {
    SizeTooLarge { size: usize, max_size: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkIoctlRequest {
    raw: u32,
}

impl UblkIoctlRequest {
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.raw
    }

    #[must_use]
    pub const fn direction_bits(self) -> u32 {
        (self.raw >> IOC_DIRSHIFT) & IOC_DIRMASK
    }

    #[must_use]
    pub const fn direction(self) -> UblkIoctlDirection {
        match self.direction_bits() {
            IOC_NONE => UblkIoctlDirection::None,
            IOC_WRITE => UblkIoctlDirection::Write,
            IOC_READ => UblkIoctlDirection::Read,
            3 => UblkIoctlDirection::ReadWrite,
            other => UblkIoctlDirection::Unknown(other),
        }
    }

    #[must_use]
    pub const fn ty(self) -> u8 {
        ((self.raw >> IOC_TYPESHIFT) & IOC_TYPEMASK) as u8
    }

    #[must_use]
    pub const fn number(self) -> u8 {
        ((self.raw >> IOC_NRSHIFT) & IOC_NRMASK) as u8
    }

    #[must_use]
    pub const fn size(self) -> u16 {
        ((self.raw >> IOC_SIZESHIFT) & IOC_SIZEMASK) as u16
    }
}

#[must_use]
pub const fn ioctl_request(
    direction: UblkIoctlDirection,
    ty: u8,
    number: u8,
    size: usize,
) -> UblkIoctlRequest {
    match try_ioctl_request(direction, ty, number, size) {
        Ok(request) => request,
        Err(_) => panic!("ublk ioctl request size exceeds encoded field"),
    }
}

/// Try to encode an ioctl request; fails if the size exceeds the encoded field width.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
/// Try to encode a read-write ioctl request.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
pub const fn try_ioctl_request(
    direction: UblkIoctlDirection,
    ty: u8,
    number: u8,
    size: usize,
) -> Result<UblkIoctlRequest, UblkIoctlRequestError> {
    if size > UBLK_IOCTL_MAX_SIZE {
        return Err(UblkIoctlRequestError::SizeTooLarge {
            size,
            max_size: UBLK_IOCTL_MAX_SIZE,
        });
    }

    let direction_bits = match direction {
        UblkIoctlDirection::None => IOC_NONE,
        UblkIoctlDirection::Write => IOC_WRITE,
        UblkIoctlDirection::Read => IOC_READ,
        UblkIoctlDirection::ReadWrite => IOC_READ | IOC_WRITE,
        UblkIoctlDirection::Unknown(bits) => bits & IOC_DIRMASK,
    };
    Ok(UblkIoctlRequest {
        raw: (direction_bits << IOC_DIRSHIFT)
            | ((ty as u32) << IOC_TYPESHIFT)
            | ((number as u32) << IOC_NRSHIFT)
            | ((size as u32) << IOC_SIZESHIFT),
    })
}

#[must_use]
pub const fn ioctl_read(number: u8, size: usize) -> UblkIoctlRequest {
    ioctl_request(UblkIoctlDirection::Read, UBLK_CMD_TYPE, number, size)
}

/// Try to encode a read-direction ioctl request.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
/// Try to encode a read-direction ioctl request.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
pub const fn try_ioctl_read(
    number: u8,
    size: usize,
) -> Result<UblkIoctlRequest, UblkIoctlRequestError> {
    try_ioctl_request(UblkIoctlDirection::Read, UBLK_CMD_TYPE, number, size)
}

#[must_use]
pub const fn ioctl_read_write(number: u8, size: usize) -> UblkIoctlRequest {
    ioctl_request(UblkIoctlDirection::ReadWrite, UBLK_CMD_TYPE, number, size)
}

/// Try to encode a read-write ioctl request.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
/// Try to encode an ioctl request; fails if the size exceeds the encoded field width.
///
/// # Errors
///
/// Returns [`UblkIoctlRequestError::SizeTooLarge`] if `size` exceeds [`UBLK_IOCTL_MAX_SIZE`].
pub const fn try_ioctl_read_write(
    number: u8,
    size: usize,
) -> Result<UblkIoctlRequest, UblkIoctlRequestError> {
    try_ioctl_request(UblkIoctlDirection::ReadWrite, UBLK_CMD_TYPE, number, size)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkSrvCtrlCmd {
    pub dev_id: u32,
    pub queue_id: u16,
    pub len: u16,
    pub addr: u64,
    pub data: [u64; 1],
    pub dev_path_len: u16,
    pub pad: u16,
    pub reserved: u32,
}

/// Error returned when a uBLK control command fails validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkCtrlCmdDecodeError {
    /// The `pad` field of the control command is non-zero.
    /// Linux treats this field as reserved space.
    PadFieldNonZero { pad: u16 },
    /// The `reserved` field of the control command is non-zero.
    /// The Linux uBLK UAPI requires this field to be zero.
    ReservedFieldNonZero { reserved: u32 },
}

impl UblkSrvCtrlCmd {
    /// Validate the structural invariants of a control command.
    ///
    /// Returns `Ok(self)` if the reserved fields are zero, or a specific
    /// [`UblkCtrlCmdDecodeError`] naming the first non-zero field.
    pub fn validate(self) -> Result<Self, UblkCtrlCmdDecodeError> {
        if self.pad != 0 {
            return Err(UblkCtrlCmdDecodeError::PadFieldNonZero { pad: self.pad });
        }
        if self.reserved != 0 {
            return Err(UblkCtrlCmdDecodeError::ReservedFieldNonZero {
                reserved: self.reserved,
            });
        }
        Ok(self)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkSrvCtrlDevInfo {
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
    pub state: u16,
    pub pad0: u16,
    pub max_io_buf_bytes: u32,
    pub dev_id: u32,
    pub ublksrv_pid: i32,
    pub pad1: u32,
    pub flags: u64,
    pub ublksrv_flags: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub reserved1: u64,
    pub reserved2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkSrvIoDesc {
    pub op_flags: u32,
    pub count_or_zones: u32,
    pub start_sector: u64,
    pub addr: u64,
}

impl UblkSrvIoDesc {
    #[must_use]
    pub const fn op(self) -> u8 {
        (self.op_flags & 0xff) as u8
    }

    #[must_use]
    pub const fn flags(self) -> u32 {
        self.op_flags >> 8
    }

    /// Validate the structural invariants of an I/O descriptor.
    ///
    /// Returns `Ok(self)` if the descriptor is well-formed, or a specific
    /// [`UblkDescDecodeError`] describing the exact failure reason.
    ///
    /// This is an ABI-layer structural check: it rejects reserved-field
    /// drift and unrecognized opcodes but does not interpret sector
    /// geometry, queue routing, or runtime I/O policy.
    pub fn validate(self) -> Result<Self, UblkDescDecodeError> {
        let opcode = self.op();
        let flags = self.flags();

        if !Self::is_known_opcode(opcode) {
            return Err(UblkDescDecodeError::UnsupportedOpcode { opcode });
        }

        let reserved_bits = flags & UBLK_IO_F_RESERVED_MASK;
        if reserved_bits != 0 {
            return Err(UblkDescDecodeError::ReservedFlagBitsSet {
                flags,
                reserved_bits,
            });
        }

        if opcode == UBLK_IO_OP_FLUSH && self.count_or_zones != 0 {
            return Err(UblkDescDecodeError::NonZeroFlushSectorCount {
                count: self.count_or_zones,
            });
        }

        Ok(self)
    }

    /// Returns `true` if `opcode` is one of the Linux uBLK I/O operation codes
    /// defined by this ABI surface.
    #[must_use]
    pub const fn is_known_opcode(opcode: u8) -> bool {
        matches!(
            opcode,
            UBLK_IO_OP_READ
                | UBLK_IO_OP_WRITE
                | UBLK_IO_OP_FLUSH
                | UBLK_IO_OP_DISCARD
                | UBLK_IO_OP_WRITE_SAME
                | UBLK_IO_OP_WRITE_ZEROES
                | UBLK_IO_OP_ZONE_OPEN
                | UBLK_IO_OP_ZONE_CLOSE
                | UBLK_IO_OP_ZONE_FINISH
                | UBLK_IO_OP_ZONE_APPEND
                | UBLK_IO_OP_ZONE_RESET_ALL
                | UBLK_IO_OP_ZONE_RESET
                | UBLK_IO_OP_REPORT_ZONES,
        )
    }
}

/// Error returned when a uBLK I/O descriptor fails structural validation.
///
/// Each variant preserves the exact failure reason so callers can route
/// or log distinct adapter status values rather than collapsing them into
/// a generic error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDescDecodeError {
    /// The operation code in the low byte of `op_flags` is not a recognized
    /// Linux uBLK I/O operation.
    UnsupportedOpcode { opcode: u8 },
    /// One or more reserved bits in the flags portion of `op_flags` are set.
    /// Reserved bits are any bits in `op_flags` outside the known opcode
    /// range (bits 0-7) and outside the known flag set.
    ReservedFlagBitsSet { flags: u32, reserved_bits: u32 },
    /// A flush operation carries a non-zero sector count.  Flush is a
    /// barrier operation that must not transfer data; `count_or_zones` must
    /// be zero.
    NonZeroFlushSectorCount { count: u32 },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkSrvIoCmd {
    pub q_id: u16,
    pub tag: u16,
    pub result: i32,
    pub addr_or_zone_append_lba: u64,
}

/// Error returned when a uBLK I/O completion command fails validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkCmdResDecodeError {
    /// The `result` field is not one of the recognized uBLK I/O result
    /// status codes (`UBLK_IO_RES_OK`, `UBLK_IO_RES_NEED_GET_DATA`,
    /// `UBLK_IO_RES_ABORT`).
    UnrecognizedResultStatus { result: i32 },
}

impl UblkSrvIoCmd {
    /// Validate the structural invariants of an I/O completion command.
    ///
    /// Returns `Ok(self)` if the result code is a recognized uBLK I/O
    /// result status, or [`UblkCmdResDecodeError::UnrecognizedResultStatus`].
    pub fn validate(self) -> Result<Self, UblkCmdResDecodeError> {
        matches!(
            self.result,
            UBLK_IO_RES_OK | UBLK_IO_RES_NEED_GET_DATA | UBLK_IO_RES_ABORT
        )
        .then_some(self)
        .ok_or(UblkCmdResDecodeError::UnrecognizedResultStatus {
            result: self.result,
        })
    }
}

/// io_uring command descriptor for ublk passthrough block I/O dispatch.
/// Encodes the ublk command operation and I/O parameters submitted
/// via IORING_OP_URING_CMD targeting a ublk device fd.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkIoUringCmdDescriptor {
    pub cmd_op: u32,
    pub flags: u32,
    pub payload: [u8; 80],
}

impl Default for UblkIoUringCmdDescriptor {
    fn default() -> Self {
        Self {
            cmd_op: 0,
            flags: 0,
            payload: [0u8; 80],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamBasic {
    pub attrs: u32,
    pub logical_bs_shift: u8,
    pub physical_bs_shift: u8,
    pub io_opt_shift: u8,
    pub io_min_shift: u8,
    pub max_sectors: u32,
    pub chunk_sectors: u32,
    pub dev_sectors: u64,
    pub virt_boundary_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamDiscard {
    pub discard_alignment: u32,
    pub discard_granularity: u32,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_discard_segments: u16,
    pub reserved0: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamDevt {
    pub char_major: u32,
    pub char_minor: u32,
    pub disk_major: u32,
    pub disk_minor: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamZoned {
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub max_zone_append_sectors: u32,
    pub reserved: [u8; 20],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamDmaAlign {
    pub alignment: u32,
    pub pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParamSegment {
    pub seg_boundary_mask: u64,
    pub max_segment_size: u32,
    pub max_segments: u16,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblkParams {
    pub len: u32,
    pub types: u32,
    pub basic: UblkParamBasic,
    pub discard: UblkParamDiscard,
    pub devt: UblkParamDevt,
    pub zoned: UblkParamZoned,
    pub dma: UblkParamDmaAlign,
    pub seg: UblkParamSegment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkFeatureFlags(pub u64);

impl UblkFeatureFlags {
    pub const SUPPORT_ZERO_COPY: Self = Self(1_u64 << 0);
    pub const URING_CMD_COMP_IN_TASK: Self = Self(1_u64 << 1);
    pub const NEED_GET_DATA: Self = Self(1_u64 << 2);
    pub const USER_RECOVERY: Self = Self(1_u64 << 3);
    pub const USER_RECOVERY_REISSUE: Self = Self(1_u64 << 4);
    pub const UNPRIVILEGED_DEV: Self = Self(1_u64 << 5);
    pub const CMD_IOCTL_ENCODE: Self = Self(1_u64 << 6);
    pub const USER_COPY: Self = Self(1_u64 << 7);
    pub const ZONED: Self = Self(1_u64 << 8);
    pub const USER_RECOVERY_FAIL_IO: Self = Self(1_u64 << 9);
    pub const UPDATE_SIZE: Self = Self(1_u64 << 10);
    pub const AUTO_BUF_REG: Self = Self(1_u64 << 11);
    pub const QUIESCE: Self = Self(1_u64 << 12);
    pub const PER_IO_DAEMON: Self = Self(1_u64 << 13);
    pub const BUF_REG_OFF_DAEMON: Self = Self(1_u64 << 14);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

pub const TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES: UblkFeatureFlags =
    UblkFeatureFlags::CMD_IOCTL_ENCODE
        .union(UblkFeatureFlags::USER_COPY)
        .union(UblkFeatureFlags::USER_RECOVERY)
        .union(UblkFeatureFlags::UPDATE_SIZE)
        .union(UblkFeatureFlags::QUIESCE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoCommand {
    FetchReq,
    CommitAndFetchReq,
    NeedGetData,
    RegisterIoBuf,
    UnregisterIoBuf,
}

impl UblkIoCommand {
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::FetchReq => UBLK_IO_FETCH_REQ,
            Self::CommitAndFetchReq => UBLK_IO_COMMIT_AND_FETCH_REQ,
            Self::NeedGetData => UBLK_IO_NEED_GET_DATA,
            Self::RegisterIoBuf => UBLK_IO_REGISTER_IO_BUF,
            Self::UnregisterIoBuf => UBLK_IO_UNREGISTER_IO_BUF,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FetchReq => "FETCH_REQ",
            Self::CommitAndFetchReq => "COMMIT_AND_FETCH_REQ",
            Self::NeedGetData => "NEED_GET_DATA",
            Self::RegisterIoBuf => "REGISTER_IO_BUF",
            Self::UnregisterIoBuf => "UNREGISTER_IO_BUF",
        }
    }

    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        ioctl_read_write(self.number(), size_of::<UblkSrvIoCmd>())
    }

    #[must_use]
    pub const fn commits_result(self) -> bool {
        matches!(self, Self::CommitAndFetchReq)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDeviceState {
    Dead,
    Live,
    Quiesced,
    FailIo,
    Unknown(u16),
}

impl UblkDeviceState {
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            0 => Self::Dead,
            1 => Self::Live,
            2 => Self::Quiesced,
            3 => Self::FailIo,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Dead => 0,
            Self::Live => 1,
            Self::Quiesced => 2,
            Self::FailIo => 3,
            Self::Unknown(raw) => raw,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::Live => "live",
            Self::Quiesced => "quiesced",
            Self::FailIo => "fail_io",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkCtrlCommand {
    GetQueueAffinity,
    GetDevInfo,
    GetFeatures,
    AddDev,
    SetParams,
    StartDev,
    GetDevInfo2,
    QuiesceDev,
    UpdateSize,
    StopDev,
    DelDev,
    StartUserRecovery,
    EndUserRecovery,
}

impl UblkCtrlCommand {
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::GetFeatures => UBLK_CMD_GET_FEATURES,
            Self::GetQueueAffinity => UBLK_CMD_GET_QUEUE_AFFINITY,
            Self::GetDevInfo => UBLK_CMD_GET_DEV_INFO,
            Self::AddDev => UBLK_CMD_ADD_DEV,
            Self::SetParams => UBLK_CMD_SET_PARAMS,
            Self::StartDev => UBLK_CMD_START_DEV,
            Self::GetDevInfo2 => UBLK_CMD_GET_DEV_INFO2,
            Self::QuiesceDev => UBLK_CMD_QUIESCE_DEV,
            Self::UpdateSize => UBLK_CMD_UPDATE_SIZE,
            Self::StopDev => UBLK_CMD_STOP_DEV,
            Self::DelDev => UBLK_CMD_DEL_DEV,
            Self::StartUserRecovery => UBLK_CMD_START_USER_RECOVERY,
            Self::EndUserRecovery => UBLK_CMD_END_USER_RECOVERY,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetFeatures => "GET_FEATURES",
            Self::GetQueueAffinity => "GET_QUEUE_AFFINITY",
            Self::GetDevInfo => "GET_DEV_INFO",
            Self::AddDev => "ADD_DEV",
            Self::SetParams => "SET_PARAMS",
            Self::StartDev => "START_DEV",
            Self::GetDevInfo2 => "GET_DEV_INFO2",
            Self::QuiesceDev => "QUIESCE_DEV",
            Self::UpdateSize => "UPDATE_SIZE",
            Self::StopDev => "STOP_DEV",
            Self::DelDev => "DEL_DEV",
            Self::StartUserRecovery => "START_USER_RECOVERY",
            Self::EndUserRecovery => "END_USER_RECOVERY",
        }
    }

    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        match self {
            Self::GetFeatures | Self::GetQueueAffinity | Self::GetDevInfo | Self::GetDevInfo2 => {
                ioctl_read(self.number(), size_of::<UblkSrvCtrlCmd>())
            }
            Self::AddDev
            | Self::SetParams
            | Self::StartDev
            | Self::QuiesceDev
            | Self::UpdateSize
            | Self::StopDev
            | Self::StartUserRecovery
            | Self::EndUserRecovery
            | Self::DelDev => ioctl_read_write(self.number(), size_of::<UblkSrvCtrlCmd>()),
        }
    }

    #[must_use]
    pub const fn mutates_control_state(self) -> bool {
        !matches!(
            self,
            Self::GetFeatures | Self::GetQueueAffinity | Self::GetDevInfo | Self::GetDevInfo2
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlMutationClass {
    ReadOnlyProbe,
    CreateDevicePair,
    SetDeviceParameters,
    StartDevice,
    QuiesceDevice,
    UpdateDeviceSize,
    StopDevice,
    DeleteDevice,
    StartUserRecovery,
    EndUserRecovery,
}

impl UblkControlMutationClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyProbe => "read_only_probe",
            Self::CreateDevicePair => "create_device_pair",
            Self::SetDeviceParameters => "set_device_parameters",
            Self::StartDevice => "start_device",
            Self::QuiesceDevice => "quiesce_device",
            Self::UpdateDeviceSize => "update_device_size",
            Self::StopDevice => "stop_device",
            Self::DeleteDevice => "delete_device",
            Self::StartUserRecovery => "start_user_recovery",
            Self::EndUserRecovery => "end_user_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlPlanStep {
    pub ordinal: u8,
    pub command: UblkCtrlCommand,
    pub mutation_class: UblkControlMutationClass,
}

impl UblkControlPlanStep {
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.command.request()
    }

    #[must_use]
    pub const fn mutates_control_state(self) -> bool {
        self.command.mutates_control_state()
    }
}

pub const UBLK_CONTROL_PLAN_STEPS: [UblkControlPlanStep; 9] = [
    UblkControlPlanStep {
        ordinal: 0,
        command: UblkCtrlCommand::GetFeatures,
        mutation_class: UblkControlMutationClass::ReadOnlyProbe,
    },
    UblkControlPlanStep {
        ordinal: 1,
        command: UblkCtrlCommand::AddDev,
        mutation_class: UblkControlMutationClass::CreateDevicePair,
    },
    UblkControlPlanStep {
        ordinal: 2,
        command: UblkCtrlCommand::SetParams,
        mutation_class: UblkControlMutationClass::SetDeviceParameters,
    },
    UblkControlPlanStep {
        ordinal: 3,
        command: UblkCtrlCommand::StartDev,
        mutation_class: UblkControlMutationClass::StartDevice,
    },
    UblkControlPlanStep {
        ordinal: 4,
        command: UblkCtrlCommand::GetDevInfo2,
        mutation_class: UblkControlMutationClass::ReadOnlyProbe,
    },
    UblkControlPlanStep {
        ordinal: 5,
        command: UblkCtrlCommand::QuiesceDev,
        mutation_class: UblkControlMutationClass::QuiesceDevice,
    },
    UblkControlPlanStep {
        ordinal: 6,
        command: UblkCtrlCommand::UpdateSize,
        mutation_class: UblkControlMutationClass::UpdateDeviceSize,
    },
    UblkControlPlanStep {
        ordinal: 7,
        command: UblkCtrlCommand::StopDev,
        mutation_class: UblkControlMutationClass::StopDevice,
    },
    UblkControlPlanStep {
        ordinal: 8,
        command: UblkCtrlCommand::DelDev,
        mutation_class: UblkControlMutationClass::DeleteDevice,
    },
];

#[must_use]
pub const fn ublk_control_plan_steps() -> &'static [UblkControlPlanStep; 9] {
    &UBLK_CONTROL_PLAN_STEPS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkIoBufferAddress {
    pub queue_id: u16,
    pub tag: u16,
    pub io_buffer_offset: u32,
}

impl UblkIoBufferAddress {
    #[must_use]
    pub const fn relative_offset(self) -> Option<u64> {
        if self.queue_id as u64 > UBLK_QID_BITS_MASK
            || self.tag as u64 > UBLK_TAG_BITS_MASK
            || self.io_buffer_offset as u64 > UBLK_IO_BUF_BITS_MASK
        {
            return None;
        }
        Some(
            ((self.queue_id as u64) << UBLK_QID_OFF)
                | ((self.tag as u64) << UBLK_TAG_OFF)
                | self.io_buffer_offset as u64,
        )
    }

    #[must_use]
    pub const fn mmap_offset(self) -> Option<u64> {
        match self.relative_offset() {
            Some(relative) => Some(UBLKSRV_IO_BUF_OFFSET + relative),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkAutoBufReg {
    pub index: u16,
    pub flags: u8,
    pub reserved0: u8,
    pub reserved1: u32,
}

impl UblkAutoBufReg {
    #[must_use]
    pub const fn to_sqe_addr(self) -> u64 {
        self.index as u64
            | ((self.flags as u64) << 16)
            | ((self.reserved0 as u64) << 24)
            | ((self.reserved1 as u64) << 32)
    }

    #[must_use]
    pub const fn from_sqe_addr(sqe_addr: u64) -> Self {
        Self {
            index: sqe_addr as u16,
            flags: (sqe_addr >> 16) as u8,
            reserved0: (sqe_addr >> 24) as u8,
            reserved1: (sqe_addr >> 32) as u32,
        }
    }
}

#[must_use]
pub const fn control_command_size() -> usize {
    size_of::<UblkSrvCtrlCmd>()
}

#[must_use]
pub const fn params_size() -> usize {
    size_of::<UblkParams>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn control_struct_layouts_match_linux_header_shape() {
        assert_eq!(size_of::<UblkSrvCtrlCmd>(), 32);
        assert_eq!(align_of::<UblkSrvCtrlCmd>(), 8);
        assert_eq!(size_of::<UblkSrvCtrlDevInfo>(), 64);
        assert_eq!(size_of::<UblkSrvIoDesc>(), 24);
        assert_eq!(size_of::<UblkSrvIoCmd>(), 16);
        assert_eq!(size_of::<UblkParamBasic>(), 32);
        assert_eq!(size_of::<UblkParamDiscard>(), 20);
        assert_eq!(size_of::<UblkParamDevt>(), 16);
        assert_eq!(size_of::<UblkParamZoned>(), 32);
        assert_eq!(size_of::<UblkParamDmaAlign>(), 8);
        assert_eq!(size_of::<UblkParamSegment>(), 16);
        assert_eq!(size_of::<UblkParams>(), 136);
    }

    #[test]
    fn ioctl_requests_decode_to_ublk_type_number_direction_and_size() {
        let get_features = UblkCtrlCommand::GetFeatures.request();
        assert_eq!(get_features.ty(), b'u');
        assert_eq!(get_features.number(), 0x13);
        assert_eq!(get_features.direction(), UblkIoctlDirection::Read);
        assert_eq!(get_features.size(), 32);

        let add_dev = UblkCtrlCommand::AddDev.request();
        assert_eq!(add_dev.number(), 0x04);
        assert_eq!(add_dev.direction(), UblkIoctlDirection::ReadWrite);
        assert_ne!(add_dev.raw(), get_features.raw());
    }

    #[test]
    fn io_command_requests_decode_to_ublk_type_number_direction_and_size() {
        let commit = UblkIoCommand::CommitAndFetchReq.request();
        assert_eq!(commit.ty(), b'u');
        assert_eq!(commit.number(), UBLK_IO_COMMIT_AND_FETCH_REQ);
        assert_eq!(commit.direction(), UblkIoctlDirection::ReadWrite);
        assert_eq!(commit.size(), size_of::<UblkSrvIoCmd>() as u16);
        assert!(UblkIoCommand::CommitAndFetchReq.commits_result());
        assert!(!UblkIoCommand::FetchReq.commits_result());

        let need_get_data = UblkIoCommand::NeedGetData.request();
        assert_eq!(need_get_data.number(), UBLK_IO_NEED_GET_DATA);
        assert_eq!(need_get_data.size(), commit.size());
    }

    #[test]
    fn checked_ioctl_request_refuses_oversized_size() {
        let max_request =
            try_ioctl_read(UBLK_CMD_GET_FEATURES, UBLK_IOCTL_MAX_SIZE).expect("max size");
        assert_eq!(max_request.size(), UBLK_IOCTL_MAX_SIZE as u16);

        assert_eq!(
            try_ioctl_read_write(UBLK_CMD_ADD_DEV, UBLK_IOCTL_MAX_SIZE + 1),
            Err(UblkIoctlRequestError::SizeTooLarge {
                size: UBLK_IOCTL_MAX_SIZE + 1,
                max_size: UBLK_IOCTL_MAX_SIZE,
            })
        );
    }

    #[test]
    #[should_panic(expected = "ublk ioctl request size exceeds encoded field")]
    const fn ioctl_request_panics_instead_of_truncating_oversized_size() {
        let _request = ioctl_request(
            UblkIoctlDirection::ReadWrite,
            UBLK_CMD_TYPE,
            UBLK_CMD_ADD_DEV,
            UBLK_IOCTL_MAX_SIZE + 1,
        );
    }

    #[test]
    fn control_plan_marks_only_probe_commands_as_non_mutating() {
        let steps = ublk_control_plan_steps();
        assert_eq!(steps[0].command, UblkCtrlCommand::GetFeatures);
        assert!(!steps[0].mutates_control_state());
        assert_eq!(steps[4].command, UblkCtrlCommand::GetDevInfo2);
        assert!(!steps[4].mutates_control_state());
        assert!(steps[1].mutates_control_state());
        assert!(steps[2].mutates_control_state());
        assert!(steps[3].mutates_control_state());
        assert!(steps[5].mutates_control_state());
        assert!(steps[6].mutates_control_state());
        assert!(steps[7].mutates_control_state());
        assert!(steps[8].mutates_control_state());
    }

    #[test]
    fn feature_mask_tracks_required_tidefs_control_capabilities() {
        let features = TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES;
        assert!(features.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(features.contains(UblkFeatureFlags::USER_COPY));
        assert!(features.contains(UblkFeatureFlags::USER_RECOVERY));
        assert!(features.contains(UblkFeatureFlags::UPDATE_SIZE));
        assert!(features.contains(UblkFeatureFlags::QUIESCE));
        assert!(!features.contains(UblkFeatureFlags::ZONED));
    }

    #[test]
    fn io_buffer_address_packing_obeys_header_bit_boundaries() {
        let encoded = UblkIoBufferAddress {
            queue_id: 7,
            tag: 11,
            io_buffer_offset: 4096,
        }
        .relative_offset()
        .expect("valid address");
        assert_eq!((encoded >> UBLK_QID_OFF) & UBLK_QID_BITS_MASK, 7);
        assert_eq!((encoded >> UBLK_TAG_OFF) & UBLK_TAG_BITS_MASK, 11);
        assert_eq!(encoded & UBLK_IO_BUF_BITS_MASK, 4096);
        assert_eq!(
            UblkIoBufferAddress {
                queue_id: 7,
                tag: 11,
                io_buffer_offset: 4096,
            }
            .mmap_offset(),
            Some(UBLKSRV_IO_BUF_OFFSET + encoded)
        );

        assert!(UblkIoBufferAddress {
            queue_id: UBLK_MAX_NR_QUEUES,
            tag: 0,
            io_buffer_offset: 0,
        }
        .relative_offset()
        .is_none());
    }

    #[test]
    fn auto_buffer_registration_round_trips_sqe_addr() {
        let reg = UblkAutoBufReg {
            index: 513,
            flags: 1,
            reserved0: 0,
            reserved1: 0,
        };
        assert_eq!(UblkAutoBufReg::from_sqe_addr(reg.to_sqe_addr()), reg);
    }

    #[test]
    fn io_descriptor_splits_operation_and_flags() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE) | UBLK_IO_F_FUA,
            count_or_zones: 8,
            start_sector: 128,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
        assert_eq!(desc.flags(), UBLK_IO_F_FUA >> 8);
    }
    // -----------------------------------------------------------------------
    // Struct layout completeness: every repr(C) struct must match Linux sizes
    // and natural alignment.
    // -----------------------------------------------------------------------

    #[test]
    fn all_struct_alignments_match_linux_header() {
        // Control plane structs
        assert_eq!(align_of::<UblkSrvCtrlCmd>(), 8);
        assert_eq!(align_of::<UblkSrvCtrlDevInfo>(), 8);
        // IO plane structs
        assert_eq!(align_of::<UblkSrvIoDesc>(), 8);
        assert_eq!(align_of::<UblkSrvIoCmd>(), 8);
        // Parameter sub-structs
        assert_eq!(align_of::<UblkParamBasic>(), 8);
        assert_eq!(align_of::<UblkParamDiscard>(), 4);
        assert_eq!(align_of::<UblkParamDevt>(), 4);
        assert_eq!(align_of::<UblkParamZoned>(), 4);
        assert_eq!(align_of::<UblkParamDmaAlign>(), 4);
        assert_eq!(align_of::<UblkParamSegment>(), 8);
        // Aggregate params
        assert_eq!(align_of::<UblkParams>(), 8);
    }

    // -----------------------------------------------------------------------
    // Compile-time const assertions for struct sizes
    // -----------------------------------------------------------------------

    const _CTRL_CMD_SIZE: () = assert!(size_of::<UblkSrvCtrlCmd>() == 32);
    const _CTRL_DEV_INFO_SIZE: () = assert!(size_of::<UblkSrvCtrlDevInfo>() == 64);
    const _IO_DESC_SIZE: () = assert!(size_of::<UblkSrvIoDesc>() == 24);
    const _IO_CMD_SIZE: () = assert!(size_of::<UblkSrvIoCmd>() == 16);
    const _PARAM_BASIC_SIZE: () = assert!(size_of::<UblkParamBasic>() == 32);
    const _PARAM_DISCARD_SIZE: () = assert!(size_of::<UblkParamDiscard>() == 20);
    const _PARAM_DEVT_SIZE: () = assert!(size_of::<UblkParamDevt>() == 16);
    const _PARAM_ZONED_SIZE: () = assert!(size_of::<UblkParamZoned>() == 32);
    const _PARAM_DMA_SIZE: () = assert!(size_of::<UblkParamDmaAlign>() == 8);
    const _PARAM_SEGMENT_SIZE: () = assert!(size_of::<UblkParamSegment>() == 16);
    const _PARAMS_SIZE: () = assert!(size_of::<UblkParams>() == 136);

    // -----------------------------------------------------------------------
    // Command number constant verification: control commands
    // -----------------------------------------------------------------------

    #[test]
    fn control_command_numbers_match_linux_ublk_uapi() {
        assert_eq!(UBLK_CMD_GET_QUEUE_AFFINITY, 0x01);
        assert_eq!(UBLK_CMD_GET_DEV_INFO, 0x02);
        assert_eq!(UBLK_CMD_ADD_DEV, 0x04);
        assert_eq!(UBLK_CMD_DEL_DEV, 0x05);
        assert_eq!(UBLK_CMD_START_DEV, 0x06);
        assert_eq!(UBLK_CMD_STOP_DEV, 0x07);
        assert_eq!(UBLK_CMD_SET_PARAMS, 0x08);
        assert_eq!(UBLK_CMD_GET_PARAMS, 0x09);
        assert_eq!(UBLK_CMD_START_USER_RECOVERY, 0x10);
        assert_eq!(UBLK_CMD_END_USER_RECOVERY, 0x11);
        assert_eq!(UBLK_CMD_GET_DEV_INFO2, 0x12);
        assert_eq!(UBLK_CMD_GET_FEATURES, 0x13);
        assert_eq!(UBLK_CMD_DEL_DEV_ASYNC, 0x14);
        assert_eq!(UBLK_CMD_UPDATE_SIZE, 0x15);
        assert_eq!(UBLK_CMD_QUIESCE_DEV, 0x16);
    }

    #[test]
    fn control_command_enum_numbers_match_constants() {
        assert_eq!(UblkCtrlCommand::GetFeatures.number(), UBLK_CMD_GET_FEATURES);
        assert_eq!(UblkCtrlCommand::AddDev.number(), UBLK_CMD_ADD_DEV);
        assert_eq!(UblkCtrlCommand::SetParams.number(), UBLK_CMD_SET_PARAMS);
        assert_eq!(UblkCtrlCommand::StartDev.number(), UBLK_CMD_START_DEV);
        assert_eq!(
            UblkCtrlCommand::GetDevInfo2.number(),
            UBLK_CMD_GET_DEV_INFO2
        );
        assert_eq!(UblkCtrlCommand::QuiesceDev.number(), UBLK_CMD_QUIESCE_DEV);
        assert_eq!(UblkCtrlCommand::UpdateSize.number(), UBLK_CMD_UPDATE_SIZE);
        assert_eq!(UblkCtrlCommand::StopDev.number(), UBLK_CMD_STOP_DEV);
        assert_eq!(UblkCtrlCommand::DelDev.number(), UBLK_CMD_DEL_DEV);
    }

    // -----------------------------------------------------------------------
    // Command number constant verification: IO commands
    // -----------------------------------------------------------------------

    #[test]
    fn io_command_numbers_match_linux_ublk_uapi() {
        assert_eq!(UBLK_IO_FETCH_REQ, 0x20);
        assert_eq!(UBLK_IO_COMMIT_AND_FETCH_REQ, 0x21);
        assert_eq!(UBLK_IO_NEED_GET_DATA, 0x22);
        assert_eq!(UBLK_IO_REGISTER_IO_BUF, 0x23);
        assert_eq!(UBLK_IO_UNREGISTER_IO_BUF, 0x24);
    }

    #[test]
    fn io_command_enum_numbers_match_constants() {
        assert_eq!(UblkIoCommand::FetchReq.number(), UBLK_IO_FETCH_REQ);
        assert_eq!(
            UblkIoCommand::CommitAndFetchReq.number(),
            UBLK_IO_COMMIT_AND_FETCH_REQ
        );
        assert_eq!(UblkIoCommand::NeedGetData.number(), UBLK_IO_NEED_GET_DATA);
        assert_eq!(
            UblkIoCommand::RegisterIoBuf.number(),
            UBLK_IO_REGISTER_IO_BUF
        );
        assert_eq!(
            UblkIoCommand::UnregisterIoBuf.number(),
            UBLK_IO_UNREGISTER_IO_BUF
        );
    }

    // -----------------------------------------------------------------------
    // IO operation code constants
    // -----------------------------------------------------------------------

    #[test]
    fn io_operation_codes_match_linux_ublk_uapi() {
        assert_eq!(UBLK_IO_OP_READ, 0);
        assert_eq!(UBLK_IO_OP_WRITE, 1);
        assert_eq!(UBLK_IO_OP_FLUSH, 2);
        assert_eq!(UBLK_IO_OP_DISCARD, 3);
        assert_eq!(UBLK_IO_OP_WRITE_SAME, 4);
        assert_eq!(UBLK_IO_OP_WRITE_ZEROES, 5);
        assert_eq!(UBLK_IO_OP_ZONE_OPEN, 10);
        assert_eq!(UBLK_IO_OP_ZONE_CLOSE, 11);
        assert_eq!(UBLK_IO_OP_ZONE_FINISH, 12);
        assert_eq!(UBLK_IO_OP_ZONE_APPEND, 13);
        assert_eq!(UBLK_IO_OP_ZONE_RESET_ALL, 14);
        assert_eq!(UBLK_IO_OP_ZONE_RESET, 15);
        assert_eq!(UBLK_IO_OP_REPORT_ZONES, 18);
    }

    // -----------------------------------------------------------------------
    // IO flag constants
    // -----------------------------------------------------------------------

    #[test]
    fn io_flag_constants_match_linux_ublk_uapi() {
        assert_eq!(UBLK_IO_F_FAILFAST_DEV, 1 << 8);
        assert_eq!(UBLK_IO_F_FAILFAST_TRANSPORT, 1 << 9);
        assert_eq!(UBLK_IO_F_FAILFAST_DRIVER, 1 << 10);
        assert_eq!(UBLK_IO_F_META, 1 << 11);
        assert_eq!(UBLK_IO_F_FUA, 1 << 13);
        assert_eq!(UBLK_IO_F_NOUNMAP, 1 << 15);
        assert_eq!(UBLK_IO_F_SWAP, 1 << 16);
        assert_eq!(UBLK_IO_F_NEED_REG_BUF, 1 << 17);
    }

    // -----------------------------------------------------------------------
    // Feature flag bit positions
    // -----------------------------------------------------------------------

    #[test]
    fn feature_flag_bits_match_linux_ublk_uapi() {
        assert_eq!(UblkFeatureFlags::SUPPORT_ZERO_COPY.bits(), 1_u64 << 0);
        assert_eq!(UblkFeatureFlags::URING_CMD_COMP_IN_TASK.bits(), 1_u64 << 1);
        assert_eq!(UblkFeatureFlags::NEED_GET_DATA.bits(), 1_u64 << 2);
        assert_eq!(UblkFeatureFlags::USER_RECOVERY.bits(), 1_u64 << 3);
        assert_eq!(UblkFeatureFlags::USER_RECOVERY_REISSUE.bits(), 1_u64 << 4);
        assert_eq!(UblkFeatureFlags::UNPRIVILEGED_DEV.bits(), 1_u64 << 5);
        assert_eq!(UblkFeatureFlags::CMD_IOCTL_ENCODE.bits(), 1_u64 << 6);
        assert_eq!(UblkFeatureFlags::USER_COPY.bits(), 1_u64 << 7);
        assert_eq!(UblkFeatureFlags::ZONED.bits(), 1_u64 << 8);
        assert_eq!(UblkFeatureFlags::USER_RECOVERY_FAIL_IO.bits(), 1_u64 << 9);
        assert_eq!(UblkFeatureFlags::UPDATE_SIZE.bits(), 1_u64 << 10);
        assert_eq!(UblkFeatureFlags::AUTO_BUF_REG.bits(), 1_u64 << 11);
        assert_eq!(UblkFeatureFlags::QUIESCE.bits(), 1_u64 << 12);
        assert_eq!(UblkFeatureFlags::PER_IO_DAEMON.bits(), 1_u64 << 13);
        assert_eq!(UblkFeatureFlags::BUF_REG_OFF_DAEMON.bits(), 1_u64 << 14);
    }

    // -----------------------------------------------------------------------
    // Device attribute constants
    // -----------------------------------------------------------------------

    #[test]
    fn device_attribute_constants_match_linux_ublk_uapi() {
        assert_eq!(UBLK_ATTR_READ_ONLY, 1 << 0);
        assert_eq!(UBLK_ATTR_ROTATIONAL, 1 << 1);
        assert_eq!(UBLK_ATTR_VOLATILE_CACHE, 1 << 2);
        assert_eq!(UBLK_ATTR_FUA, 1 << 3);
    }

    // -----------------------------------------------------------------------
    // Parameter type constants
    // -----------------------------------------------------------------------

    #[test]
    fn param_type_constants_match_linux_ublk_uapi() {
        assert_eq!(UBLK_PARAM_TYPE_BASIC, 1 << 0);
        assert_eq!(UBLK_PARAM_TYPE_DISCARD, 1 << 1);
        assert_eq!(UBLK_PARAM_TYPE_DEVT, 1 << 2);
        assert_eq!(UBLK_PARAM_TYPE_ZONED, 1 << 3);
        assert_eq!(UBLK_PARAM_TYPE_DMA_ALIGN, 1 << 4);
        assert_eq!(UBLK_PARAM_TYPE_SEGMENT, 1 << 5);
    }

    // -----------------------------------------------------------------------
    // Device state encoding
    // -----------------------------------------------------------------------

    #[test]
    fn device_state_raw_values_match_linux_ublk_uapi() {
        assert_eq!(UblkDeviceState::Dead.raw(), 0);
        assert_eq!(UblkDeviceState::Live.raw(), 1);
        assert_eq!(UblkDeviceState::Quiesced.raw(), 2);
        assert_eq!(UblkDeviceState::FailIo.raw(), 3);
    }

    #[test]
    fn device_state_round_trips_through_raw() {
        for raw in [0u16, 1, 2, 3, 99] {
            assert_eq!(UblkDeviceState::from_raw(raw).raw(), raw);
        }
    }

    #[test]
    fn command_buffer_mmap_offset_uses_linux_max_depth_stride() {
        let stride = ublk_max_cmd_buf_size() as u64;
        assert!(
            stride > ublk_queue_cmd_buf_size(64) as u64,
            "multi-queue command buffers are spaced by Linux max depth, not active queue depth"
        );
        assert_eq!(ublk_cmd_buf_mmap_offset(0), Some(UBLKSRV_CMD_BUF_OFFSET));
        assert_eq!(
            ublk_cmd_buf_mmap_offset(1),
            Some(UBLKSRV_CMD_BUF_OFFSET + stride)
        );
        assert_eq!(
            ublk_cmd_buf_mmap_offset(2),
            Some(UBLKSRV_CMD_BUF_OFFSET + 2 * stride)
        );
        assert_eq!(ublk_cmd_buf_mmap_offset(UBLK_MAX_NR_QUEUES), None);
    }

    // -----------------------------------------------------------------------
    // IO result constants
    // -----------------------------------------------------------------------

    #[test]
    fn io_result_constants_match_linux_ublk_uapi() {
        assert_eq!(UBLK_IO_RES_OK, 0);
        assert_eq!(UBLK_IO_RES_NEED_GET_DATA, 1);
        assert_eq!(UBLK_IO_RES_ABORT, -19); // -ENODEV
    }

    // -----------------------------------------------------------------------
    // IOC encoding constants: verify Linux ioctl bitfield layout
    // -----------------------------------------------------------------------

    #[test]
    fn ioc_encoding_constants_match_linux_ioctl_layout() {
        // Linux IOC bitfield: dir(2) | size(14) | type(8) | nr(8)
        // Bit widths
        assert_eq!(UBLK_IOCTL_MAX_SIZE, (1 << 14) - 1);
        // Verify ioctl request encodes type byte correctly
        let req = UblkCtrlCommand::GetFeatures.request();
        assert_eq!(req.ty(), UBLK_CMD_TYPE);
    }

    // -----------------------------------------------------------------------
    // All control command ioctl request encoding
    // -----------------------------------------------------------------------

    #[test]
    fn all_control_command_requests_have_correct_type() {
        for cmd in &[
            UblkCtrlCommand::GetFeatures,
            UblkCtrlCommand::GetQueueAffinity,
            UblkCtrlCommand::GetDevInfo,
            UblkCtrlCommand::AddDev,
            UblkCtrlCommand::SetParams,
            UblkCtrlCommand::StartDev,
            UblkCtrlCommand::GetDevInfo2,
            UblkCtrlCommand::QuiesceDev,
            UblkCtrlCommand::UpdateSize,
            UblkCtrlCommand::StopDev,
            UblkCtrlCommand::DelDev,
            UblkCtrlCommand::StartUserRecovery,
            UblkCtrlCommand::EndUserRecovery,
        ] {
            let req = cmd.request();
            assert_eq!(
                req.ty(),
                UBLK_CMD_TYPE,
                "command {:?} has wrong type",
                cmd.as_str()
            );
        }
    }

    #[test]
    fn read_only_control_commands_use_read_direction() {
        for cmd in &[
            UblkCtrlCommand::GetFeatures,
            UblkCtrlCommand::GetQueueAffinity,
            UblkCtrlCommand::GetDevInfo,
            UblkCtrlCommand::GetDevInfo2,
        ] {
            assert_eq!(
                cmd.request().direction(),
                UblkIoctlDirection::Read,
                "{:?} should be read-direction",
                cmd.as_str()
            );
        }
    }

    #[test]
    fn mutating_control_commands_use_read_write_direction() {
        for cmd in &[
            UblkCtrlCommand::AddDev,
            UblkCtrlCommand::SetParams,
            UblkCtrlCommand::StartDev,
            UblkCtrlCommand::QuiesceDev,
            UblkCtrlCommand::UpdateSize,
            UblkCtrlCommand::StopDev,
            UblkCtrlCommand::DelDev,
            UblkCtrlCommand::StartUserRecovery,
            UblkCtrlCommand::EndUserRecovery,
        ] {
            assert_eq!(
                cmd.request().direction(),
                UblkIoctlDirection::ReadWrite,
                "{:?} should be read-write direction",
                cmd.as_str()
            );
        }
    }

    #[test]
    fn all_control_command_request_numbers_are_unique() {
        let mut seen = [false; 256];
        let commands = [
            UblkCtrlCommand::GetFeatures,
            UblkCtrlCommand::GetQueueAffinity,
            UblkCtrlCommand::GetDevInfo,
            UblkCtrlCommand::AddDev,
            UblkCtrlCommand::SetParams,
            UblkCtrlCommand::StartDev,
            UblkCtrlCommand::GetDevInfo2,
            UblkCtrlCommand::QuiesceDev,
            UblkCtrlCommand::UpdateSize,
            UblkCtrlCommand::StopDev,
            UblkCtrlCommand::DelDev,
            UblkCtrlCommand::StartUserRecovery,
            UblkCtrlCommand::EndUserRecovery,
        ];
        for cmd in &commands {
            let num = cmd.request().number() as usize;
            assert!(!seen[num], "duplicate command number 0x{num:02x}");
            seen[num] = true;
        }
    }

    // -----------------------------------------------------------------------
    // All IO command ioctl request encoding
    // -----------------------------------------------------------------------

    #[test]
    fn all_io_command_requests_have_correct_type_and_direction() {
        for cmd in &[
            UblkIoCommand::FetchReq,
            UblkIoCommand::CommitAndFetchReq,
            UblkIoCommand::NeedGetData,
            UblkIoCommand::RegisterIoBuf,
            UblkIoCommand::UnregisterIoBuf,
        ] {
            let req = cmd.request();
            assert_eq!(
                req.ty(),
                UBLK_CMD_TYPE,
                "IO cmd {:?} has wrong type",
                cmd.as_str()
            );
            assert_eq!(
                req.direction(),
                UblkIoctlDirection::ReadWrite,
                "IO cmd {:?} should be read-write",
                cmd.as_str()
            );
            assert_eq!(req.size(), size_of::<UblkSrvIoCmd>() as u16);
        }
    }

    // -----------------------------------------------------------------------
    // IoDescriptor packing: op_code in lower 8 bits, flags in upper 24
    // -----------------------------------------------------------------------

    #[test]
    fn io_descriptor_packing_separates_op_and_flags_per_linux_layout() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_DISCARD) | UBLK_IO_F_FAILFAST_DEV | UBLK_IO_F_NOUNMAP,
            count_or_zones: 1,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_DISCARD);
        assert_eq!(
            desc.flags(),
            (UBLK_IO_F_FAILFAST_DEV | UBLK_IO_F_NOUNMAP) >> 8
        );
    }

    // -----------------------------------------------------------------------
    // Const-assertions for fixed-size record sizes (compile-time checks)
    // -----------------------------------------------------------------------

    /// Linux ublk `struct ublksrv_ctrl_cmd` = 32 bytes.
    const _: () = assert!(size_of::<UblkSrvCtrlCmd>() == 32);
    /// Linux ublk `struct ublksrv_ctrl_dev_info` = 64 bytes.
    const _: () = assert!(size_of::<UblkSrvCtrlDevInfo>() == 64);
    /// Linux ublk `struct ublksrv_io_desc` = 24 bytes.
    const _: () = assert!(size_of::<UblkSrvIoDesc>() == 24);
    /// Linux ublk `struct ublksrv_io_cmd` = 16 bytes.
    const _: () = assert!(size_of::<UblkSrvIoCmd>() == 16);
    /// Linux ublk `struct ublk_param_basic` = 32 bytes.
    const _: () = assert!(size_of::<UblkParamBasic>() == 32);
    /// Linux ublk `struct ublk_param_discard` = 20 bytes.
    const _: () = assert!(size_of::<UblkParamDiscard>() == 20);
    /// Linux ublk `struct ublk_param_devt` = 16 bytes.
    const _: () = assert!(size_of::<UblkParamDevt>() == 16);
    /// Linux ublk `struct ublk_param_zoned` = 32 bytes.
    const _: () = assert!(size_of::<UblkParamZoned>() == 32);
    /// Linux ublk `struct ublk_param_dma_align` = 8 bytes.
    const _: () = assert!(size_of::<UblkParamDmaAlign>() == 8);
    /// Linux ublk `struct ublk_param_segment` = 16 bytes.
    const _: () = assert!(size_of::<UblkParamSegment>() == 16);
    /// Linux ublk `struct ublk_params` = 136 bytes (sum of all sub-structs).
    const _: () = assert!(size_of::<UblkParams>() == 136);

    // -----------------------------------------------------------------------
    // Control plan step completeness
    // -----------------------------------------------------------------------

    #[test]
    fn control_plan_has_exactly_nine_steps() {
        assert_eq!(ublk_control_plan_steps().len(), 9);
    }

    #[test]
    fn control_plan_ordinals_are_monotonic_from_zero() {
        let steps = ublk_control_plan_steps();
        for (i, step) in steps.iter().enumerate() {
            assert_eq!(step.ordinal, i as u8);
        }
    }

    #[test]
    fn control_plan_step_commands_are_all_distinct() {
        let steps = ublk_control_plan_steps();
        for i in 0..steps.len() {
            for j in (i + 1)..steps.len() {
                assert_ne!(
                    steps[i].command, steps[j].command,
                    "duplicate command at ordinals {i} and {j}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // IoBufferAddress boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn io_buffer_address_rejects_overflowing_queue_id() {
        assert!(UblkIoBufferAddress {
            queue_id: UBLK_MAX_NR_QUEUES,
            tag: 0,
            io_buffer_offset: 0,
        }
        .relative_offset()
        .is_none());
    }

    #[test]
    fn io_buffer_address_rejects_overflowing_offset() {
        let max_off: u32 = UBLK_IO_BUF_BITS_MASK as u32;
        assert!(UblkIoBufferAddress {
            queue_id: 0,
            tag: 0,
            io_buffer_offset: max_off,
        }
        .relative_offset()
        .is_some());
        assert!(UblkIoBufferAddress {
            queue_id: 0,
            tag: 0,
            io_buffer_offset: max_off.wrapping_add(1),
        }
        .relative_offset()
        .is_none());
    }

    // -----------------------------------------------------------------------
    // UblkFeatureFlags set operations
    // -----------------------------------------------------------------------

    #[test]
    fn feature_flags_contains_reflexive() {
        let f = UblkFeatureFlags::SUPPORT_ZERO_COPY;
        assert!(f.contains(f));
    }

    #[test]
    fn feature_flags_contains_subset() {
        let a = UblkFeatureFlags::CMD_IOCTL_ENCODE.union(UblkFeatureFlags::USER_COPY);
        assert!(a.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(a.contains(UblkFeatureFlags::USER_COPY));
        assert!(!a.contains(UblkFeatureFlags::ZONED));
    }

    #[test]
    fn feature_flags_contains_empty() {
        let f = UblkFeatureFlags::QUIESCE;
        assert!(f.contains(UblkFeatureFlags(0)));
    }

    // -----------------------------------------------------------------------
    // UblkIoctlDirection string representation
    // -----------------------------------------------------------------------

    #[test]
    fn ioctl_direction_as_str_is_stable() {
        assert_eq!(UblkIoctlDirection::None.as_str(), "none");
        assert_eq!(UblkIoctlDirection::Write.as_str(), "write");
        assert_eq!(UblkIoctlDirection::Read.as_str(), "read");
        assert_eq!(UblkIoctlDirection::ReadWrite.as_str(), "read_write");
        assert_eq!(UblkIoctlDirection::Unknown(42).as_str(), "unknown");
    }

    // -----------------------------------------------------------------------
    // UblkAutoBufReg round-trip with non-zero reserved fields
    // -----------------------------------------------------------------------

    #[test]
    fn auto_buffer_registration_round_trips_with_reserved_fields() {
        let reg = UblkAutoBufReg {
            index: 0xABCD,
            flags: 0x12,
            reserved0: 0x34,
            reserved1: 0x5678_9ABC,
        };
        assert_eq!(UblkAutoBufReg::from_sqe_addr(reg.to_sqe_addr()), reg);
    }

    // -----------------------------------------------------------------------
    // IO descriptor validation
    // -----------------------------------------------------------------------

    #[test]
    fn valid_read_descriptor_passes_validation() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_READ as u32,
            count_or_zones: 1,
            start_sector: 0,
            addr: 0x1000,
        };
        assert_eq!(desc.validate(), Ok(desc));
    }

    #[test]
    fn valid_write_descriptor_passes_validation() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_WRITE as u32,
            count_or_zones: 8,
            start_sector: 4096,
            addr: 0x2000,
        };
        assert_eq!(desc.validate(), Ok(desc));
    }

    #[test]
    fn valid_flush_descriptor_passes_validation() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_FLUSH as u32,
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.validate(), Ok(desc));
    }

    #[test]
    fn valid_discard_descriptor_passes_validation() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_DISCARD as u32,
            count_or_zones: 0,
            start_sector: 0,
            addr: 0x3000,
        };
        assert_eq!(desc.validate(), Ok(desc));
    }

    #[test]
    fn descriptor_rejects_unsupported_opcode() {
        let desc = UblkSrvIoDesc {
            op_flags: 0xFF,
            count_or_zones: 1,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(
            desc.validate(),
            Err(UblkDescDecodeError::UnsupportedOpcode { opcode: 0xFF })
        );
    }

    #[test]
    fn descriptor_rejects_reserved_flag_bits() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_READ as u32 | (1 << 12),
            count_or_zones: 1,
            start_sector: 0,
            addr: 0,
        };
        let err = desc.validate().unwrap_err();
        match err {
            UblkDescDecodeError::ReservedFlagBitsSet {
                flags: _,
                reserved_bits,
            } => {
                assert_eq!(reserved_bits, 1 << 4);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn descriptor_rejects_nonzero_flush_count() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_FLUSH as u32,
            count_or_zones: 42,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(
            desc.validate(),
            Err(UblkDescDecodeError::NonZeroFlushSectorCount { count: 42 })
        );
    }

    #[test]
    fn descriptor_allows_known_flag_combination() {
        let desc = UblkSrvIoDesc {
            op_flags: UBLK_IO_OP_WRITE as u32 | UBLK_IO_F_FUA | UBLK_IO_F_SWAP | UBLK_IO_F_META,
            count_or_zones: 4,
            start_sector: 100,
            addr: 0x5000,
        };
        assert_eq!(desc.validate(), Ok(desc));
    }

    // -----------------------------------------------------------------------
    // IO completion command validation
    // -----------------------------------------------------------------------

    #[test]
    fn valid_completion_commands_pass_validation() {
        for result in [UBLK_IO_RES_OK, UBLK_IO_RES_NEED_GET_DATA, UBLK_IO_RES_ABORT] {
            let cmd = UblkSrvIoCmd {
                q_id: 0,
                tag: 1,
                result,
                addr_or_zone_append_lba: 0,
            };
            assert_eq!(cmd.validate(), Ok(cmd), "result={}", result);
        }
    }

    #[test]
    fn completion_command_rejects_unrecognized_result() {
        let cmd = UblkSrvIoCmd {
            q_id: 0,
            tag: 1,
            result: -42,
            addr_or_zone_append_lba: 0,
        };
        assert_eq!(
            cmd.validate(),
            Err(UblkCmdResDecodeError::UnrecognizedResultStatus { result: -42 })
        );
    }

    // -----------------------------------------------------------------------
    // Control command validation
    // -----------------------------------------------------------------------

    #[test]
    fn control_command_with_zero_reserved_passes_validation() {
        let cmd = UblkSrvCtrlCmd {
            pad: 0,
            reserved: 0,
            ..UblkSrvCtrlCmd::default()
        };
        assert_eq!(cmd.validate(), Ok(cmd));
    }

    #[test]
    fn control_command_rejects_nonzero_pad() {
        let cmd = UblkSrvCtrlCmd {
            pad: 0xBEEF,
            ..UblkSrvCtrlCmd::default()
        };
        assert_eq!(
            cmd.validate(),
            Err(UblkCtrlCmdDecodeError::PadFieldNonZero { pad: 0xBEEF })
        );
    }

    #[test]
    fn control_command_rejects_nonzero_reserved() {
        let cmd = UblkSrvCtrlCmd {
            reserved: 0xDEAD,
            ..UblkSrvCtrlCmd::default()
        };
        assert_eq!(
            cmd.validate(),
            Err(UblkCtrlCmdDecodeError::ReservedFieldNonZero { reserved: 0xDEAD })
        );
    }

    // -----------------------------------------------------------------------
    // is_known_opcode
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_opcode_accepts_all_defined_opcodes() {
        let known = [
            UBLK_IO_OP_READ,
            UBLK_IO_OP_WRITE,
            UBLK_IO_OP_FLUSH,
            UBLK_IO_OP_DISCARD,
            UBLK_IO_OP_WRITE_SAME,
            UBLK_IO_OP_WRITE_ZEROES,
            UBLK_IO_OP_ZONE_OPEN,
            UBLK_IO_OP_ZONE_CLOSE,
            UBLK_IO_OP_ZONE_FINISH,
            UBLK_IO_OP_ZONE_APPEND,
            UBLK_IO_OP_ZONE_RESET_ALL,
            UBLK_IO_OP_ZONE_RESET,
            UBLK_IO_OP_REPORT_ZONES,
        ];
        for &op in &known {
            assert!(
                UblkSrvIoDesc::is_known_opcode(op),
                "opcode {} should be known",
                op
            );
        }
    }

    #[test]
    fn is_known_opcode_rejects_undefined_opcodes() {
        for op in [6u8, 7, 8, 9, 16, 17, 19, 42, 255] {
            assert!(
                !UblkSrvIoDesc::is_known_opcode(op),
                "opcode {} should be rejected",
                op
            );
        }
    }
}
