#![no_std]
#![forbid(unsafe_code)]

//! `schema_codec` VFS canon for error mapping and fixed-width encode/decode hooks.

pub mod contract;

pub use contract::*;

use core::convert::TryFrom;
use tidefs_types_vfs_core::{
    DirHandleId, EngineDirHandle, EngineFileHandle, FileHandleId, Generation, InodeId, NodeKind,
};

pub mod linux_errno {
    pub const EINTR: i32 = 4;
    pub const ENXIO: i32 = 6;
    pub const E2BIG: i32 = 7;
    pub const EAGAIN: i32 = 11;
    pub const EBUSY: i32 = 16;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EEXIST: i32 = 17;
    pub const ENOTTY: i32 = 25;
    pub const ERANGE: i32 = 34;
    pub const ENOSYS: i32 = 38;
    pub const ENODATA: i32 = 61;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const ENOTEMPTY: i32 = 39;
    pub const EACCES: i32 = 13;
    pub const EPERM: i32 = 1;
    pub const ENOSPC: i32 = 28;
    pub const EMLINK: i32 = 31;
    pub const EXDEV: i32 = 18;
    pub const ENAMETOOLONG: i32 = 36;
    pub const EBADF: i32 = 9;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ESTALE: i32 = 116;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    NotFound,
    NoData,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    InvalidArgument,
    PermissionDenied,
    OperationNotPermitted,
    OutOfSpace,
    TooManyLinks,
    CrossDevice,
    NameTooLong,
    BadFileDescriptor,
    NotSupported,
    NotImplemented,
    Range,
    TooBig,
    NotTTY,
    NoSuchDeviceOrAddress,
    Again,
    Interrupted,
    Busy,
    Stale,
    Io { os_errno: i32 },
}

#[must_use]
pub const fn errno_for_vfs_error(err: VfsError) -> i32 {
    match err {
        VfsError::NotFound => linux_errno::ENOENT,
        VfsError::NoData => linux_errno::ENODATA,
        VfsError::AlreadyExists => linux_errno::EEXIST,
        VfsError::NotADirectory => linux_errno::ENOTDIR,
        VfsError::IsADirectory => linux_errno::EISDIR,
        VfsError::DirectoryNotEmpty => linux_errno::ENOTEMPTY,
        VfsError::InvalidArgument => linux_errno::EINVAL,
        VfsError::PermissionDenied => linux_errno::EACCES,
        VfsError::OperationNotPermitted => linux_errno::EPERM,
        VfsError::OutOfSpace => linux_errno::ENOSPC,
        VfsError::TooManyLinks => linux_errno::EMLINK,
        VfsError::CrossDevice => linux_errno::EXDEV,
        VfsError::NameTooLong => linux_errno::ENAMETOOLONG,
        VfsError::BadFileDescriptor => linux_errno::EBADF,
        VfsError::NotSupported => linux_errno::EOPNOTSUPP,
        VfsError::NotImplemented => linux_errno::ENOSYS,
        VfsError::Range => linux_errno::ERANGE,
        VfsError::TooBig => linux_errno::E2BIG,
        VfsError::NotTTY => linux_errno::ENOTTY,
        VfsError::NoSuchDeviceOrAddress => linux_errno::ENXIO,
        VfsError::Again => linux_errno::EAGAIN,
        VfsError::Interrupted => linux_errno::EINTR,
        VfsError::Busy => linux_errno::EBUSY,
        VfsError::Stale => linux_errno::ESTALE,
        VfsError::Io { os_errno } => normalize_os_errno(os_errno),
    }
}

const fn normalize_os_errno(os_errno: i32) -> i32 {
    if os_errno == 0 || os_errno == i32::MIN {
        linux_errno::EIO
    } else if os_errno < 0 {
        -os_errno
    } else {
        os_errno
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub expected_len: usize,
    pub actual_len: usize,
}

pub trait CanonicalFixedWidth: Sized {
    const ENCODED_LEN: usize;

    fn encode_le(&self, out: &mut [u8]);
    /// Decode a fixed-width value from LE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `bytes.len()` does not match [`ENCODED_LEN`](Self::ENCODED_LEN).
    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Validates that `bytes` has the expected length.
///
/// # Errors
///
/// Returns [`DecodeError`] if `bytes.len()` does not equal `expected_len`.
const fn expect_len(bytes: &[u8], expected_len: usize) -> Result<(), DecodeError> {
    if bytes.len() == expected_len {
        Ok(())
    } else {
        Err(DecodeError {
            expected_len,
            actual_len: bytes.len(),
        })
    }
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0_u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

impl CanonicalFixedWidth for InodeId {
    const ENCODED_LEN: usize = 8;

    fn encode_le(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self(read_u64_le(bytes, 0)))
    }
}

impl CanonicalFixedWidth for Generation {
    const ENCODED_LEN: usize = 8;

    fn encode_le(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self(read_u64_le(bytes, 0)))
    }
}

impl CanonicalFixedWidth for FileHandleId {
    const ENCODED_LEN: usize = 8;

    fn encode_le(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self(read_u64_le(bytes, 0)))
    }
}

impl CanonicalFixedWidth for DirHandleId {
    const ENCODED_LEN: usize = 8;

    fn encode_le(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self(read_u64_le(bytes, 0)))
    }
}

impl CanonicalFixedWidth for NodeKind {
    const ENCODED_LEN: usize = 4;

    fn encode_le(&self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.as_u32().to_le_bytes());
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Self::try_from(read_u32_le(bytes, 0)).map_err(|_| DecodeError {
            expected_len: Self::ENCODED_LEN,
            actual_len: bytes.len(),
        })
    }
}

impl CanonicalFixedWidth for EngineFileHandle {
    const ENCODED_LEN: usize = 28;

    fn encode_le(&self, out: &mut [u8]) {
        write_u64_le(out, 0, self.inode_id.0);
        write_u32_le(out, 8, self.open_flags);
        write_u64_le(out, 12, self.fh_id.0);
        write_u64_le(out, 20, self.lock_owner);
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self {
            inode_id: InodeId(read_u64_le(bytes, 0)),
            open_flags: read_u32_le(bytes, 8),
            fh_id: FileHandleId(read_u64_le(bytes, 12)),
            lock_owner: read_u64_le(bytes, 20),
        })
    }
}

impl CanonicalFixedWidth for EngineDirHandle {
    const ENCODED_LEN: usize = 16;

    fn encode_le(&self, out: &mut [u8]) {
        write_u64_le(out, 0, self.inode_id.0);
        write_u64_le(out, 8, self.dh_id.0);
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self {
            inode_id: InodeId(read_u64_le(bytes, 0)),
            dh_id: DirHandleId(read_u64_le(bytes, 8)),
        })
    }
}

// TURN3_HUMAN_VFS_SCHEMA_CODEC_ALIASES
/// Human-named module for VFS Canonical Schema Codec helpers.
pub mod vfs_schema_codec {
    pub const FAMILY_NAME: &str = "Canonical Schema Codec";
    pub const STABLE_SOURCE_LOCATOR: &str = "schema_codec";
    pub const ROLE: &str = "VFS errno canon and fixed-width codec hooks";

    pub use crate::{errno_for_vfs_error, CanonicalFixedWidth, DecodeError, VfsError};
}

/// Human alias namespace. Prefer `human::vfs_schema_codec::*` in new examples.
pub mod human {
    pub mod vfs_schema_codec {
        pub use crate::vfs_schema_codec::*;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn io_errno_keeps_explicit_errno_or_defaults_to_eio() {
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: -5 }),
            linux_errno::EIO
        );
        assert_eq!(errno_for_vfs_error(VfsError::Io { os_errno: 123 }), 123);
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: 0 }),
            linux_errno::EIO
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: i32::MIN }),
            linux_errno::EIO
        );
    }

    #[test]
    fn engine_file_handle_round_trips_via_le_codec() {
        let handle = EngineFileHandle {
            inode_id: InodeId(11),
            open_flags: 0x1234,
            fh_id: FileHandleId(99),
            lock_owner: 77,
        };
        let mut buf = [0_u8; EngineFileHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineFileHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn engine_dir_handle_round_trips_via_le_codec() {
        let handle = EngineDirHandle {
            inode_id: InodeId(1),
            dh_id: DirHandleId(2),
        };
        let mut buf = [0_u8; EngineDirHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineDirHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn wrong_length_is_rejected() {
        let err = InodeId::decode_le(&[0_u8; 4]).expect_err("must fail");
        assert_eq!(err.expected_len, 8);
        assert_eq!(err.actual_len, 4);
    }

    #[test]
    fn inode_id_round_trips() {
        let id = InodeId(42);
        let mut buf = [0_u8; InodeId::ENCODED_LEN];
        id.encode_le(&mut buf);
        let decoded = InodeId::decode_le(&buf).expect("decode");
        assert_eq!(decoded, id);
    }

    #[test]
    fn generation_round_trips() {
        let gen = Generation(7);
        let mut buf = [0_u8; Generation::ENCODED_LEN];
        gen.encode_le(&mut buf);
        let decoded = Generation::decode_le(&buf).expect("decode");
        assert_eq!(decoded, gen);
    }

    #[test]
    fn file_handle_id_round_trips() {
        let fh_id = FileHandleId(99);
        let mut buf = [0_u8; FileHandleId::ENCODED_LEN];
        fh_id.encode_le(&mut buf);
        let decoded = FileHandleId::decode_le(&buf).expect("decode");
        assert_eq!(decoded, fh_id);
    }

    #[test]
    fn dir_handle_id_round_trips() {
        let dh_id = DirHandleId(2);
        let mut buf = [0_u8; DirHandleId::ENCODED_LEN];
        dh_id.encode_le(&mut buf);
        let decoded = DirHandleId::decode_le(&buf).expect("decode");
        assert_eq!(decoded, dh_id);
    }

    #[test]
    fn node_kind_round_trips() {
        let kind = NodeKind::Dir;
        let mut buf = [0_u8; NodeKind::ENCODED_LEN];
        kind.encode_le(&mut buf);
        let decoded = NodeKind::decode_le(&buf).expect("decode");
        assert_eq!(decoded, NodeKind::Dir);

        let kind = NodeKind::Whiteout;
        kind.encode_le(&mut buf);
        let decoded = NodeKind::decode_le(&buf).expect("decode");
        assert_eq!(decoded, NodeKind::Whiteout);
    }

    #[test]
    fn inode_id_boundary_values() {
        let mut buf = [0_u8; InodeId::ENCODED_LEN];
        InodeId(u64::MIN).encode_le(&mut buf);
        assert_eq!(InodeId::decode_le(&buf), Ok(InodeId(0)));

        InodeId(u64::MAX).encode_le(&mut buf);
        assert_eq!(InodeId::decode_le(&buf), Ok(InodeId(u64::MAX)));
    }

    #[test]
    fn generation_boundary_values() {
        let mut buf = [0_u8; Generation::ENCODED_LEN];
        Generation(u64::MIN).encode_le(&mut buf);
        assert_eq!(Generation::decode_le(&buf), Ok(Generation(0)));

        Generation(u64::MAX).encode_le(&mut buf);
        assert_eq!(Generation::decode_le(&buf), Ok(Generation(u64::MAX)));
    }

    #[test]
    fn file_handle_id_boundary_values() {
        let mut buf = [0_u8; FileHandleId::ENCODED_LEN];
        FileHandleId(u64::MIN).encode_le(&mut buf);
        assert_eq!(FileHandleId::decode_le(&buf), Ok(FileHandleId(0)));

        FileHandleId(u64::MAX).encode_le(&mut buf);
        assert_eq!(FileHandleId::decode_le(&buf), Ok(FileHandleId(u64::MAX)));
    }

    #[test]
    fn dir_handle_id_boundary_values() {
        let mut buf = [0_u8; DirHandleId::ENCODED_LEN];
        DirHandleId(u64::MIN).encode_le(&mut buf);
        assert_eq!(DirHandleId::decode_le(&buf), Ok(DirHandleId(0)));

        DirHandleId(u64::MAX).encode_le(&mut buf);
        assert_eq!(DirHandleId::decode_le(&buf), Ok(DirHandleId(u64::MAX)));
    }

    #[test]
    fn node_kind_all_eight_variants_roundtrip() {
        let kinds = [
            NodeKind::Dir,
            NodeKind::File,
            NodeKind::Symlink,
            NodeKind::CharDev,
            NodeKind::BlockDev,
            NodeKind::Fifo,
            NodeKind::Socket,
            NodeKind::Whiteout,
        ];
        let mut buf = [0_u8; NodeKind::ENCODED_LEN];
        for &kind in &kinds {
            kind.encode_le(&mut buf);
            let decoded = NodeKind::decode_le(&buf).expect("decode");
            assert_eq!(decoded, kind);
        }
    }

    #[test]
    fn node_kind_rejects_invalid_u32_tag() {
        // Valid range is 1..=8; 0, 9, and large values should be rejected
        let mut buf = [0_u8; 4];
        for invalid_tag in [0_u32, 9, 255, u32::MAX] {
            buf.copy_from_slice(&invalid_tag.to_le_bytes());
            let err = NodeKind::decode_le(&buf).expect_err("must reject");
            assert_eq!(err.expected_len, NodeKind::ENCODED_LEN);
            assert_eq!(err.actual_len, 4);
        }
    }

    #[test]
    fn engine_file_handle_boundary_all_zeros() {
        let handle = EngineFileHandle {
            inode_id: InodeId(0),
            open_flags: 0,
            fh_id: FileHandleId(0),
            lock_owner: 0,
        };
        let mut buf = [0_u8; EngineFileHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineFileHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn engine_file_handle_boundary_all_max() {
        let handle = EngineFileHandle {
            inode_id: InodeId(u64::MAX),
            open_flags: u32::MAX,
            fh_id: FileHandleId(u64::MAX),
            lock_owner: u64::MAX,
        };
        let mut buf = [0_u8; EngineFileHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineFileHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn engine_dir_handle_boundary_all_zeros() {
        let handle = EngineDirHandle {
            inode_id: InodeId(0),
            dh_id: DirHandleId(0),
        };
        let mut buf = [0_u8; EngineDirHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineDirHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn engine_dir_handle_boundary_all_max() {
        let handle = EngineDirHandle {
            inode_id: InodeId(u64::MAX),
            dh_id: DirHandleId(u64::MAX),
        };
        let mut buf = [0_u8; EngineDirHandle::ENCODED_LEN];
        handle.encode_le(&mut buf);
        let decoded = EngineDirHandle::decode_le(&buf).expect("decode");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn decode_rejects_empty_input_for_all_types() {
        let empty: &[u8] = &[];
        assert!(InodeId::decode_le(empty).is_err());
        assert!(Generation::decode_le(empty).is_err());
        assert!(FileHandleId::decode_le(empty).is_err());
        assert!(DirHandleId::decode_le(empty).is_err());
        assert!(NodeKind::decode_le(empty).is_err());
        assert!(EngineFileHandle::decode_le(empty).is_err());
        assert!(EngineDirHandle::decode_le(empty).is_err());
    }

    #[test]
    fn decode_rejects_oversized_input() {
        let buf = [0_u8; 64];
        // InodeId expects 8 bytes; feeding 64 should fail
        let err = InodeId::decode_le(&buf).expect_err("oversized must fail");
        assert_eq!(err.expected_len, InodeId::ENCODED_LEN);
        assert_eq!(err.actual_len, 64);
    }

    #[test]
    fn decode_error_preserves_expected_and_actual_lengths() {
        let err = Generation::decode_le(&[0_u8; 1]).expect_err("must fail");
        assert_eq!(err.expected_len, 8);
        assert_eq!(err.actual_len, 1);

        let err = EngineFileHandle::decode_le(&[0_u8; 30]).expect_err("30 != 28");
        assert_eq!(err.expected_len, EngineFileHandle::ENCODED_LEN);
        assert_eq!(err.actual_len, 30);

        let err = EngineDirHandle::decode_le(&[0_u8; 12]).expect_err("12 != 16");
        assert_eq!(err.expected_len, EngineDirHandle::ENCODED_LEN);
        assert_eq!(err.actual_len, 12);
    }

    #[test]
    fn all_static_vfs_errors_map_to_distinct_nonzero_errnos() {
        // Spot-check a representative subset of the 24 static variants
        assert_eq!(errno_for_vfs_error(VfsError::NotFound), linux_errno::ENOENT);
        assert_eq!(
            errno_for_vfs_error(VfsError::AlreadyExists),
            linux_errno::EEXIST
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::NotADirectory),
            linux_errno::ENOTDIR
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::IsADirectory),
            linux_errno::EISDIR
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::DirectoryNotEmpty),
            linux_errno::ENOTEMPTY
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::PermissionDenied),
            linux_errno::EACCES
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::OutOfSpace),
            linux_errno::ENOSPC
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::NameTooLong),
            linux_errno::ENAMETOOLONG
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::NotSupported),
            linux_errno::EOPNOTSUPP
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::NotImplemented),
            linux_errno::ENOSYS
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::BadFileDescriptor),
            linux_errno::EBADF
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::CrossDevice),
            linux_errno::EXDEV
        );
        assert_eq!(
            errno_for_vfs_error(VfsError::TooManyLinks),
            linux_errno::EMLINK
        );
        assert_eq!(errno_for_vfs_error(VfsError::Stale), linux_errno::ESTALE);
    }

    #[test]
    fn io_errno_edge_case_normalization() {
        // Io { os_errno: 0 } -> EIO
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: 0 }),
            linux_errno::EIO
        );
        // Io { os_errno: i32::MIN } -> EIO (because == MIN)
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: i32::MIN }),
            linux_errno::EIO
        );
        // Io { os_errno: -1 } -> 1 (negative absolute value)
        assert_eq!(errno_for_vfs_error(VfsError::Io { os_errno: -1 }), 1);
        // Io { os_errno: 1 } -> 1
        assert_eq!(errno_for_vfs_error(VfsError::Io { os_errno: 1 }), 1);
        // Io { os_errno: i32::MAX } -> i32::MAX
        assert_eq!(
            errno_for_vfs_error(VfsError::Io { os_errno: i32::MAX }),
            i32::MAX
        );
    }
    // ── zeroed input roundtrip ──────────────────────────────────────────

    #[test]
    fn zeroed_buffer_roundtrips_inode_id() {
        let buf = [0_u8; InodeId::ENCODED_LEN];
        let decoded = InodeId::decode_le(&buf).expect("decode zero");
        let mut re_buf = [0_u8; InodeId::ENCODED_LEN];
        decoded.encode_le(&mut re_buf);
        assert_eq!(re_buf, [0_u8; InodeId::ENCODED_LEN]);
    }

    // ── encode: undersized buffer panics ────────────────────────────────

    #[test]
    #[should_panic]
    fn encode_to_undersized_buffer_panics() {
        let val = InodeId(42);
        let mut buf = [0_u8; 4];
        val.encode_le(&mut buf);
    }

    // ── one-byte-off boundaries ─────────────────────────────────────────

    #[test]
    fn exact_size_decode_succeeds_one_byte_off_fails() {
        // exactly ENCODED_LEN works
        let buf = [0_u8; InodeId::ENCODED_LEN];
        assert!(InodeId::decode_le(&buf).is_ok());

        // one byte short
        let buf = [0_u8; InodeId::ENCODED_LEN - 1];
        let err = InodeId::decode_le(&buf).expect_err("one short must fail");
        assert_eq!(err.expected_len, 8);
        assert_eq!(err.actual_len, 7);

        // one byte long
        let buf = [0_u8; InodeId::ENCODED_LEN + 1];
        let err = InodeId::decode_le(&buf).expect_err("one long must fail");
        assert_eq!(err.expected_len, 8);
        assert_eq!(err.actual_len, 9);
    }

    // ── DecodeError properties ──────────────────────────────────────────

    #[test]
    fn decode_error_eq_and_ne() {
        let a = DecodeError {
            expected_len: 8,
            actual_len: 4,
        };
        let b = DecodeError {
            expected_len: 8,
            actual_len: 4,
        };
        assert_eq!(a, b);
        let c = DecodeError {
            expected_len: 16,
            actual_len: 4,
        };
        assert_ne!(a, c);
    }

    // ── golden vector decode tests ─────────────────────────────────────

    /// Decode golden binary → check canonical fields → re-encode must match.
    fn assert_golden_decode_roundtrip<T: CanonicalFixedWidth + core::fmt::Debug + PartialEq>(
        name: &str,
        golden: &[u8],
        check: impl FnOnce(&T),
    ) {
        let decoded = T::decode_le(golden).unwrap_or_else(|e| {
            panic!(
                "golden decode failed for {name}: expected_len={exp}, actual_len={act}",
                exp = e.expected_len,
                act = e.actual_len
            )
        });
        check(&decoded);
        let mut re_buf = std::vec![0_u8; golden.len()];
        decoded.encode_le(&mut re_buf);
        assert_eq!(
            re_buf, golden,
            "re-encode of {name} does not match golden binary"
        );
    }

    #[test]
    fn golden_decode_inode_id() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_inodeid.bin");
        assert_golden_decode_roundtrip::<InodeId>("InodeId", golden, |v| {
            assert_eq!(v.0, 42);
        });
    }

    #[test]
    fn golden_decode_generation() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_generation.bin");
        assert_golden_decode_roundtrip::<Generation>("Generation", golden, |v| {
            assert_eq!(v.0, 7);
        });
    }

    #[test]
    fn golden_decode_file_handle_id() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_filehandleid.bin");
        assert_golden_decode_roundtrip::<FileHandleId>("FileHandleId", golden, |v| {
            assert_eq!(v.0, 100);
        });
    }

    #[test]
    fn golden_decode_dir_handle_id() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_dirhandleid.bin");
        assert_golden_decode_roundtrip::<DirHandleId>("DirHandleId", golden, |v| {
            assert_eq!(v.0, 200);
        });
    }

    #[test]
    fn golden_decode_node_kind() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_nodekind.bin");
        assert_golden_decode_roundtrip::<NodeKind>("NodeKind", golden, |v| {
            assert_eq!(*v, NodeKind::File);
        });
    }

    #[test]
    fn golden_decode_engine_file_handle() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_enginefilehandle.bin");
        assert_golden_decode_roundtrip::<EngineFileHandle>("EngineFileHandle", golden, |v| {
            assert_eq!(v.fh_id.0, 10);
            assert_eq!(v.inode_id.0, 1);
            assert_eq!(v.lock_owner, 0);
            assert_eq!(v.open_flags, 32768);
        });
    }

    #[test]
    fn golden_decode_engine_dir_handle() {
        let golden = include_bytes!("../../../validation/format-golden/vfs_enginedirhandle.bin");
        assert_golden_decode_roundtrip::<EngineDirHandle>("EngineDirHandle", golden, |v| {
            assert_eq!(v.dh_id.0, 20);
            assert_eq!(v.inode_id.0, 2);
        });
    }
}
