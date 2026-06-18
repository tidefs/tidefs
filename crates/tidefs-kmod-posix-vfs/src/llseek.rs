// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel VFS llseek operation -- SEEK_DATA/SEEK_HOLE extent resolution.
//!
//! This module implements `tidefs_llseek()` dispatching SEEK_DATA and SEEK_HOLE
//! through `VfsEngine::data_ranges()` to resolve file extents. SEEK_SET, SEEK_CUR,
//! and SEEK_END are computed from `InodeAttr::size` (obtained via `getattr`) and
//! the caller-supplied current file position.
//!
//! # Semantics
//!
//! - SEEK_SET (0): returns `offset` after bounds validation (0..=file_size).
//! - SEEK_CUR (1): returns `current_pos + offset` after bounds validation.
//! - SEEK_END (2): returns `file_size + offset` after bounds validation.
//! - SEEK_DATA (3): returns the byte offset of the next data extent at or after
//!   `offset`. Returns ENXIO if no data exists at or beyond `offset`.
//! - SEEK_HOLE (4): returns the byte offset of the next hole at or after
//!   `offset`. Returns `file_size` if no hole exists before EOF.
//!
//! BLAKE3 domain: `tidefs-kmod-llseek-v1` for state verification in tests.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};
use tidefs_kmod_bridge::kernel_types::{LseekDataRange, VfsEngine};

use crate::KmodPosixVfs;

const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;
const SEEK_DATA: u32 = 3;
const SEEK_HOLE: u32 = 4;

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Reposition the read/write file offset for a file handle.
    ///
    /// `offset` is the raw offset from lseek(2). `whence` controls how
    /// `offset` is interpreted:
    ///
    /// - `SEEK_SET` (0): absolute position.
    /// - `SEEK_CUR` (1): relative to `current_pos`.
    /// - `SEEK_END` (2): relative to end of file.
    /// - `SEEK_DATA` (3): first data byte at or after `offset`.
    /// - `SEEK_HOLE` (4): first hole byte at or after `offset`.
    ///
    /// `current_pos` is the kernel-tracked file position, meaningful only
    /// for `SEEK_CUR` (it is added to `offset` before bounds checking).
    ///
    /// # Errors
    ///
    /// - `EINVAL`: `whence` is not a recognised value, or the resulting
    ///   offset would overflow i64, or offset is negative.
    /// - `ENXIO`: `SEEK_DATA` was requested but no data extent exists at
    ///   or beyond `offset`.
    /// - `EBADF`: the file handle is not valid.
    /// - Errors surfaced by `getattr` or `data_ranges`.
    pub fn llseek(
        &self,
        fh: &tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: i64,
        whence: u32,
        current_pos: i64,
        ctx: &RequestCtx,
    ) -> Result<i64, Errno> {
        match whence {
            SEEK_SET | SEEK_CUR | SEEK_END => {
                let attr = self.engine.getattr(fh.inode_id, Some(fh), ctx)?;
                let file_size = i64::try_from(attr.posix.size).map_err(|_| Errno::EFBIG)?;

                let target = match whence {
                    SEEK_SET => offset,
                    SEEK_CUR => current_pos.checked_add(offset).ok_or(Errno::EINVAL)?,
                    SEEK_END => file_size.checked_add(offset).ok_or(Errno::EINVAL)?,
                    _ => unreachable!(),
                };

                if target < 0 {
                    return Err(Errno::EINVAL);
                }
                Ok(target.min(file_size))
            }
            SEEK_DATA => {
                let uoff = u64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let remaining = u64::MAX - uoff;
                let ranges = self.engine.data_ranges(fh, uoff, remaining, ctx)?;
                Self::seek_data_from_ranges(&ranges, uoff).map(|v| v as i64)
            }
            SEEK_HOLE => {
                let uoff = u64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let remaining = u64::MAX - uoff;
                let ranges = self.engine.data_ranges(fh, uoff, remaining, ctx)?;
                let attr = self.engine.getattr(fh.inode_id, Some(fh), ctx)?;
                let file_size = attr.posix.size;
                Ok(Self::seek_hole_from_ranges(&ranges, uoff, file_size) as i64)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn seek_data_from_ranges(ranges: &[LseekDataRange], offset: u64) -> Result<u64, Errno> {
        for r in ranges {
            if r.end <= offset {
                continue;
            }
            if r.start <= offset {
                return Ok(offset);
            }
            return Ok(r.start);
        }
        Err(Errno::ENXIO)
    }

    fn seek_hole_from_ranges(ranges: &[LseekDataRange], offset: u64, _file_size: u64) -> u64 {
        let mut cursor = offset;
        for r in ranges {
            if r.end <= cursor {
                continue;
            }
            if r.start <= cursor {
                cursor = r.end;
                continue;
            }
            return cursor;
        }
        cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        EngineFileHandle, FileHandleId, InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs,
    };

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    fn attr(size: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(0),
            generation: tidefs_kmod_bridge::kernel_types::Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o644,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    // SEEK_SET
    #[test]
    fn seek_set_zero() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_SET, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 0);
    }

    #[test]
    fn seek_set_mid_file() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 4096, SEEK_SET, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_set_past_eof_clamped() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 8192, SEEK_SET, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_set_negative_einval() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, -1, SEEK_SET, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::EINVAL));
    }

    // SEEK_CUR
    #[test]
    fn seek_cur_advance() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 512, SEEK_CUR, 1024, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 1536);
    }

    #[test]
    fn seek_cur_rewind() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, -512, SEEK_CUR, 2048, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 1536);
    }

    #[test]
    fn seek_cur_before_zero_einval() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, -2048, SEEK_CUR, 1024, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::EINVAL));
    }

    // SEEK_END
    #[test]
    fn seek_end_zero_offset() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_END, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_end_back_one_byte() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, -1, SEEK_END, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 8191);
    }

    #[test]
    fn seek_end_before_zero_einval() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, -8192, SEEK_END, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::EINVAL));
    }

    // SEEK_DATA
    #[test]
    fn seek_data_offset_in_extent() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 2048, SEEK_DATA, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 2048);
    }

    #[test]
    fn seek_data_before_first_extent() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(4096, 8192)].as_slice(),
            ))
        });
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_DATA, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_data_in_gap() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [
                    LseekDataRange::new(0, 4096),
                    LseekDataRange::new(8192, 12288),
                ]
                .as_slice(),
            ))
        });
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 5000, SEEK_DATA, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 8192);
    }

    #[test]
    fn seek_data_past_all_extents_enxio() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, 4096, SEEK_DATA, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::ENXIO));
    }

    #[test]
    fn seek_data_empty_extent_list() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| Ok(crate::TideVec::new()));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, 0, SEEK_DATA, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::ENXIO));
    }

    #[test]
    fn seek_data_negative_offset_einval() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, -1, SEEK_DATA, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::EINVAL));
    }

    // SEEK_HOLE
    #[test]
    fn seek_hole_at_start() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(4096, 8192)].as_slice(),
            ))
        });
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 0);
    }

    #[test]
    fn seek_hole_inside_data_extent() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(8192)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 1024, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_hole_no_hole_returns_eof() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 4096, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_hole_alternating() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [
                    LseekDataRange::new(0, 4096),
                    LseekDataRange::new(8192, 12288),
                ]
                .as_slice(),
            ))
        });
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(16384)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 4096);
    }

    #[test]
    fn seek_hole_past_eof() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| {
            Ok(crate::TideVec::from(
                [LseekDataRange::new(0, 4096)].as_slice(),
            ))
        });
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(4096)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 8192, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 8192);
    }

    #[test]
    fn seek_hole_empty_file_all_hole() {
        let h = fh(10, 1);
        let mut e = MockEngine::new();
        e.data_ranges_fn = Box::new(|_, _, _, _| Ok(crate::TideVec::new()));
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr(0)));
        let vfs = KmodPosixVfs::new(e);
        let res = vfs
            .llseek(&h, 0, SEEK_HOLE, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(res, 0);
    }

    // Bad whence
    #[test]
    fn bad_whence_einval() {
        let h = fh(10, 1);
        let e = MockEngine::new();
        let vfs = KmodPosixVfs::new(e);
        let res = vfs.llseek(&h, 0, 99, 0, &MockEngine::test_ctx());
        assert_eq!(res, Err(Errno::EINVAL));
    }

    // Internal helper unit tests
    #[test]
    fn seek_data_no_ranges() {
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_data_from_ranges(&[], 0),
            Err(Errno::ENXIO)
        );
    }

    #[test]
    fn seek_data_inside_range() {
        let ranges = &[
            LseekDataRange::new(0, 4096),
            LseekDataRange::new(8192, 12288),
        ];
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_data_from_ranges(ranges, 2048),
            Ok(2048)
        );
    }

    #[test]
    fn seek_data_next_range() {
        let ranges = &[
            LseekDataRange::new(0, 4096),
            LseekDataRange::new(8192, 12288),
        ];
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_data_from_ranges(ranges, 4096),
            Ok(8192)
        );
    }

    #[test]
    fn seek_hole_in_gap() {
        let ranges = &[
            LseekDataRange::new(0, 4096),
            LseekDataRange::new(8192, 12288),
        ];
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_hole_from_ranges(ranges, 5000, 16384),
            5000
        );
    }

    #[test]
    fn seek_hole_no_data_ranges() {
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_hole_from_ranges(&[], 100, 4096),
            100
        );
    }

    #[test]
    fn seek_hole_all_data_no_hole() {
        let ranges = &[LseekDataRange::new(0, 4096)];
        assert_eq!(
            KmodPosixVfs::<MockEngine>::seek_hole_from_ranges(ranges, 0, 4096),
            4096
        );
    }
}
