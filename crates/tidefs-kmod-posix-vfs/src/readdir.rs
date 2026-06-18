// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory iteration for the kernel VFS adapter -- K7-23.
//!
//! Provides handle_readdir() entry point for getdents(2)/readdir(3)
//! through the kernel VFS. Validates directory handles, delegates to
//! VfsEngine::readdir with DirCursor-backed iteration (#5524), and
//! packs DirEntry records into kernel dirent64 format with offset-based
//! pagination and resume-cookie support.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::{KmodPosixVfs, OpenDirState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{DirEntry, Errno, NodeKind, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

/// Map a TideFS [`NodeKind`] to the Linux `DT_*` directory-entry type
/// constant used in `struct linux_dirent64::d_type`.
pub fn node_kind_to_dtype(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Fifo => 6,     // DT_FIFO
        NodeKind::CharDev => 2,  // DT_CHR
        NodeKind::Dir => 4,      // DT_DIR
        NodeKind::BlockDev => 6, // DT_BLK (overlaps DT_FIFO in DT_*)
        NodeKind::File => 8,     // DT_REG
        NodeKind::Symlink => 10, // DT_LNK
        NodeKind::Socket => 12,  // DT_SOCK
        NodeKind::Whiteout => 0, // DT_UNKNOWN
    }
}

/// Pack a single [`DirEntry`] into a kernel `linux_dirent64` record
/// at `buf[pos..]`. Returns the number of bytes written (the record
/// length, `d_reclen`), or `None` if the buffer is too small.
///
/// Wire format matches `struct linux_dirent64`:
///   d_ino: u64 LE
///   d_off: i64 LE
///   d_reclen: u16 LE
///   d_type: u8
///   d_name: NUL-terminated byte sequence, padded to 8-byte alignment
fn pack_dirent64(entry: &DirEntry, buf: &mut [u8], pos: usize) -> Option<usize> {
    let name = &entry.name;
    let name_len = name.len();
    // reclen = offsetof(d_name) + len(name) + NUL, rounded to 8
    let reclen: usize = (8 + 8 + 2 + 1 + name_len + 1 + 7) & !7;
    if pos + reclen > buf.len() {
        return None;
    }
    // d_ino (u64 LE)
    buf[pos..pos + 8].copy_from_slice(&u64::to_le_bytes(entry.inode_id.get()));
    // d_off (i64 LE) — use the cookie as the next offset
    buf[pos + 8..pos + 16].copy_from_slice(&i64::to_le_bytes(entry.cookie as i64));
    // d_reclen (u16 LE)
    buf[pos + 16..pos + 18].copy_from_slice(&u16::to_le_bytes(reclen as u16));
    // d_type (u8)
    buf[pos + 18] = node_kind_to_dtype(entry.kind);
    // d_name + NUL
    buf[pos + 19..pos + 19 + name_len].copy_from_slice(name);
    buf[pos + 19 + name_len] = 0;
    // Zero-fill padding to reclen
    for b in buf[pos + 19 + name_len + 1..pos + reclen].iter_mut() {
        *b = 0;
    }
    Some(reclen)
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Handle a readdir (getdents) request from the kernel VFS.
    ///
    /// Validates the directory handle, delegates to
    /// `VfsEngine::readdir` with DirCursor-backed iteration, and
    /// packs entries into `buf` as kernel `linux_dirent64` records.
    ///
    /// Returns `(bytes_written, resume_offset, more)`:
    /// - `bytes_written`: total bytes packed into `buf` (0 on empty
    ///   directory after `.` and `..`).
    /// - `resume_offset`: the cookie to pass as `offset` on the next
    ///   call; `0` when there are no more entries.
    /// - `more`: true when additional entries remain beyond this
    ///   batch.
    ///
    /// `.` and `..` entries are the adapter's responsibility per the
    /// VfsEngine contract. The Linux kernel VFS injects these
    /// automatically; this adapter delegates raw engine entries
    /// without `.`/`..` injection.
    pub fn handle_readdir(
        &self,
        state: &OpenDirState,
        offset: u64,
        buf: &mut [u8],
        ctx: &RequestCtx,
    ) -> Result<(usize, u64, bool), Errno> {
        let (entries, more) = self.engine.readdir(&state.handle, offset, ctx)?;

        let mut bytes_written: usize = 0;
        let mut last_cookie: u64 = offset;

        for entry in &entries {
            match pack_dirent64(entry, buf, bytes_written) {
                Some(reclen) => {
                    bytes_written += reclen;
                    last_cookie = entry.cookie;
                }
                None => {
                    // Buffer full — return the last successfully
                    // emitted cookie as the resume offset.
                    return Ok((bytes_written, last_cookie, true));
                }
            }
        }

        let resume_offset = if more { last_cookie } else { 0 };
        Ok((bytes_written, resume_offset, more))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{DirHandleId, EngineDirHandle, Generation, InodeId};

    fn de(ino: u64, name: &[u8], cookie: u64) -> DirEntry {
        DirEntry {
            name: name.to_vec(),
            inode_id: InodeId::new(ino),
            kind: NodeKind::File,
            generation: Generation::new(1),
            cookie,
        }
    }

    fn dh(ino: u64, id: u64) -> EngineDirHandle {
        EngineDirHandle {
            inode_id: InodeId::new(ino),
            dh_id: DirHandleId::new(id),
        }
    }

    fn dir_state(ino: u64, dh_id: u64) -> OpenDirState {
        OpenDirState {
            handle: dh(ino, dh_id),
            inode: InodeId::new(ino),
        }
    }

    // ── node_kind_to_dtype ──────────────────────────────────────────

    #[test]
    fn dtype_dir() {
        assert_eq!(node_kind_to_dtype(NodeKind::Dir), 4);
    }

    #[test]
    fn dtype_file() {
        assert_eq!(node_kind_to_dtype(NodeKind::File), 8);
    }

    #[test]
    fn dtype_symlink() {
        assert_eq!(node_kind_to_dtype(NodeKind::Symlink), 10);
    }

    #[test]
    fn dtype_fifo() {
        assert_eq!(node_kind_to_dtype(NodeKind::Fifo), 6);
    }

    #[test]
    fn dtype_socket() {
        assert_eq!(node_kind_to_dtype(NodeKind::Socket), 12);
    }

    #[test]
    fn dtype_chr() {
        assert_eq!(node_kind_to_dtype(NodeKind::CharDev), 2);
    }

    // ── pack_dirent64 ───────────────────────────────────────────────

    #[test]
    fn pack_dirent64_single_entry() {
        let entry = de(42, b"hello.txt", 3);
        let mut buf = [0u8; 512];
        let reclen = pack_dirent64(&entry, &mut buf, 0).unwrap();
        let d_ino = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(d_ino, 42);
        let d_off = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(d_off, 3);
        let d_reclen = u16::from_le_bytes(buf[16..18].try_into().unwrap());
        assert_eq!(d_reclen as usize, reclen);
        assert_eq!(buf[18], 8); // DT_REG
        let name_end = 19 + 9; // "hello.txt"
        assert_eq!(&buf[19..name_end], b"hello.txt");
        assert_eq!(buf[name_end], 0);
        assert_eq!(reclen % 8, 0);
    }

    #[test]
    fn pack_dirent64_short_name() {
        let entry = de(1, b"a", 0);
        let mut buf = [0u8; 256];
        let reclen = pack_dirent64(&entry, &mut buf, 0).unwrap();
        // header 19 + name 1 + NUL 1 = 21, round up to 24
        assert_eq!(reclen, 24);
        assert_eq!(&buf[19..20], b"a");
        assert_eq!(buf[20], 0);
    }

    #[test]
    fn pack_dirent64_buffer_too_small() {
        let entry = de(100, b"a_long_name_that_needs_more_room", 7);
        let mut buf = [0u8; 20];
        assert!(pack_dirent64(&entry, &mut buf, 0).is_none());
    }

    #[test]
    fn pack_dirent64_buffer_exact_fit() {
        // "ab" -> header 19 + 2 + 1 = 22, round to 24
        let entry = de(5, b"ab", 10);
        let mut buf = [0u8; 24];
        let reclen = pack_dirent64(&entry, &mut buf, 0).unwrap();
        assert_eq!(reclen, 24);
    }

    #[test]
    fn pack_dirent64_offset_position() {
        let e1 = de(10, b"first", 1);
        let e2 = de(20, b"second", 2);
        let mut buf = [0u8; 512];
        let r1 = pack_dirent64(&e1, &mut buf, 0).unwrap();
        let r2 = pack_dirent64(&e2, &mut buf, r1).unwrap();
        let d_ino2 = u64::from_le_bytes(buf[r1..r1 + 8].try_into().unwrap());
        assert_eq!(d_ino2, 20);
        assert!(r1 + r2 <= buf.len());
    }

    // ── handle_readdir ──────────────────────────────────────────────

    #[test]
    fn handle_readdir_empty_directory() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Ok((vec![], false)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 0);
        assert_eq!(resume, 0);
        assert!(!more);
    }

    #[test]
    fn handle_readdir_single_entry() {
        let entry = de(100, b"file.txt", 3);
        let entries = vec![entry];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        assert_eq!(resume, 0);
        assert!(!more);
    }

    #[test]
    fn handle_readdir_multiple_entries() {
        let entries = vec![
            de(10, b"file_a", 1),
            de(20, b"file_b", 2),
            de(30, b"file_c", 3),
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 4096];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written >= 3 * 24);
        assert_eq!(resume, 0);
        assert!(!more);
    }

    #[test]
    fn handle_readdir_pagination_buffer_too_small() {
        let entries = vec![
            de(10, b"entry_one", 1),
            de(20, b"entry_two", 2),
            de(30, b"entry_three", 3),
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        // Buffer fits only 1 entry
        let mut buf = [0u8; 64];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        assert!(resume > 0);
        assert!(more);
    }

    #[test]
    fn handle_readdir_with_more_flag() {
        let entries = vec![de(50, b"item", 10)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), true)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        assert_eq!(resume, 10);
        assert!(more);
    }

    #[test]
    fn handle_readdir_offset_resume() {
        let entries = vec![de(60, b"continued", 5), de(70, b"final", 6)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            assert_eq!(offset, 3);
            Ok((entries2.clone(), false))
        });
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 3, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        assert_eq!(resume, 0);
        assert!(!more);
    }

    #[test]
    fn handle_readdir_eio_propagates() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Err(Errno::EIO));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        assert_eq!(
            KmodPosixVfs::new(e)
                .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn handle_readdir_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Err(Errno::ENOTDIR));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        assert_eq!(
            KmodPosixVfs::new(e)
                .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn handle_readdir_ebadf_propagates() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Err(Errno::EBADF));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        assert_eq!(
            KmodPosixVfs::new(e)
                .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF,
        );
    }

    #[test]
    fn handle_readdir_cookie_tracking() {
        let entries = vec![de(1, b"first", 100), de(2, b"second_longer_name", 200)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        // Buffer too small for both entries; first fits, second doesn't
        let mut buf = [0u8; 48];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        assert_eq!(resume, 100);
        assert!(more);
    }

    #[test]
    fn handle_readdir_entries_with_different_kinds() {
        let entries: Vec<DirEntry> = vec![
            DirEntry {
                name: b"dir".to_vec(),
                inode_id: InodeId::new(2),
                kind: NodeKind::Dir,
                generation: Generation::new(1),
                cookie: 0,
            },
            DirEntry {
                name: b"link".to_vec(),
                inode_id: InodeId::new(3),
                kind: NodeKind::Symlink,
                generation: Generation::new(1),
                cookie: 1,
            },
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 512];
        let (written, _resume, _more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert!(written > 0);
        // First entry is a directory, d_type should be DT_DIR (4)
        assert_eq!(buf[18], 4);
    }

    #[test]
    fn handle_readdir_buffer_too_small_for_any_entry() {
        let entries = vec![de(1, b"a_very_long_name", 1)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = dir_state(1, 1);
        let mut buf = [0u8; 8];
        let (written, resume, more) = KmodPosixVfs::new(e)
            .handle_readdir(&state, 0, &mut buf, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 0);
        assert_eq!(resume, 0);
        assert!(more);
    }

    // ── Large-directory pagination boundary tests ────────────────────

    /// Build a deterministic vector of `n` DirEntry records with
    /// ascending inode-ids, ascending cookies, and alternating
    /// File/Dir kinds to exercise d_type coverage.
    fn build_large_directory(n: usize) -> Vec<DirEntry> {
        (0..n)
            .map(|i| {
                let kind = if i % 3 == 0 {
                    NodeKind::Dir
                } else if i % 5 == 0 {
                    NodeKind::Symlink
                } else {
                    NodeKind::File
                };
                DirEntry {
                    name: alloc::format!("entry_{i:08x}").into_bytes(),
                    inode_id: InodeId::new(100 + i as u64),
                    kind,
                    generation: Generation::new(1),
                    cookie: (i + 1) as u64,
                }
            })
            .collect()
    }

    /// Walk an entire directory through `handle_readdir` by repeatedly
    /// calling it with the resume cookie until `more` is false.
    /// Returns all collected entry names in order.
    fn collect_readdir_names(
        kmod: &KmodPosixVfs<MockEngine>,
        state: &OpenDirState,
        chunk: usize,
    ) -> Vec<Vec<u8>> {
        let ctx = MockEngine::test_ctx();
        let mut offset: u64 = 0;
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut safety = 0;
        loop {
            safety += 1;
            if safety > 5000 {
                panic!("collect_readdir_names: too many iterations, likely infinite loop");
            }
            let mut buf = vec![0u8; chunk];
            let (written, resume, more) =
                kmod.handle_readdir(state, offset, &mut buf, &ctx).unwrap();
            // Parse d_name from packed dirent64 records
            let mut pos: usize = 0;
            while pos + 19 < written {
                let d_reclen =
                    u16::from_le_bytes(buf[pos + 16..pos + 18].try_into().unwrap()) as usize;
                if d_reclen == 0 {
                    break;
                }
                let name_start = pos + 19;
                let name_end = buf[name_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|nul| name_start + nul)
                    .unwrap_or(name_start);
                names.push(buf[name_start..name_end].to_vec());
                pos += d_reclen;
            }
            offset = resume;
            if !more || written == 0 {
                break;
            }
        }
        names
    }

    #[test]
    fn handle_readdir_large_64_entries_buffer_4096() {
        let n = 64;
        let entries = build_large_directory(n);
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        // Offset-aware: return entries whose cookie > offset
        e.readdir_fn = Box::new(move |_, offset, _| {
            let filtered: Vec<DirEntry> = entries2
                .iter()
                .filter(|e| e.cookie > offset)
                .cloned()
                .collect();
            Ok((filtered, false))
        });
        let kmod = KmodPosixVfs::new(e);
        let state = dir_state(1, 1);
        let names = collect_readdir_names(&kmod, &state, 4096);
        assert_eq!(names.len(), n);
        for (i, name) in names.iter().enumerate().take(n) {
            assert_eq!(name, &alloc::format!("entry_{i:08x}").into_bytes());
        }
    }

    #[test]
    fn handle_readdir_large_64_entries_paginate_chunks_of_1() {
        let n = 64;
        let entries = build_large_directory(n);
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let filtered: Vec<DirEntry> = entries2
                .iter()
                .filter(|e| e.cookie > offset)
                .cloned()
                .collect();
            Ok((filtered, false))
        });
        let kmod = KmodPosixVfs::new(e);
        let state = dir_state(1, 1);
        // 48-byte buffer fits ~1 entry
        let names = collect_readdir_names(&kmod, &state, 48);
        assert_eq!(names.len(), n);
    }

    #[test]
    fn handle_readdir_large_256_entries_buffer_4096() {
        let n = 256;
        let entries = build_large_directory(n);
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let filtered: Vec<DirEntry> = entries2
                .iter()
                .filter(|e| e.cookie > offset)
                .cloned()
                .collect();
            Ok((filtered, false))
        });
        let kmod = KmodPosixVfs::new(e);
        let state = dir_state(1, 1);
        let names = collect_readdir_names(&kmod, &state, 4096);
        assert_eq!(names.len(), n);
        for (i, name) in names.iter().enumerate().take(n) {
            assert_eq!(name, &alloc::format!("entry_{i:08x}").into_bytes());
        }
    }

    #[test]
    fn handle_readdir_256_entries_paginate_chunks_of_64() {
        let n = 256;
        let entries = build_large_directory(n);
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let filtered: Vec<DirEntry> = entries2
                .iter()
                .filter(|e| e.cookie > offset)
                .cloned()
                .collect();
            Ok((filtered, false))
        });
        let kmod = KmodPosixVfs::new(e);
        let state = dir_state(1, 1);
        // 64-byte buffer: each entry is ~40 bytes, so we get 1 per call
        let names = collect_readdir_names(&kmod, &state, 64);
        assert_eq!(names.len(), n);
    }

    #[test]
    fn handle_readdir_1024_entries_deterministic_order() {
        let n = 1024;
        let entries = build_large_directory(n);
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let filtered: Vec<DirEntry> = entries2
                .iter()
                .filter(|e| e.cookie > offset)
                .cloned()
                .collect();
            Ok((filtered, false))
        });
        let kmod = KmodPosixVfs::new(e);
        let state = dir_state(1, 1);
        let names = collect_readdir_names(&kmod, &state, 4096);
        assert_eq!(names.len(), n);
        for (i, name) in names.iter().enumerate().take(n) {
            assert_eq!(name, &alloc::format!("entry_{i:08x}").into_bytes());
        }
    }

    #[test]
    fn handle_readdir_same_result_regardless_of_chunk_size() {
        let n = 64;
        let entries = build_large_directory(n);
        let mut chunks = vec![];

        // Read with buffer size 64
        {
            let e2 = entries.clone();
            let mut e = MockEngine::new();
            e.readdir_fn = Box::new(move |_, offset, _| {
                let filtered: Vec<DirEntry> =
                    e2.iter().filter(|e| e.cookie > offset).cloned().collect();
                Ok((filtered, false))
            });
            let kmod = KmodPosixVfs::new(e);
            let state = dir_state(1, 1);
            chunks.push(collect_readdir_names(&kmod, &state, 64));
        }
        // Read with buffer size 128
        {
            let e2 = entries.clone();
            let mut e = MockEngine::new();
            e.readdir_fn = Box::new(move |_, offset, _| {
                let filtered: Vec<DirEntry> =
                    e2.iter().filter(|e| e.cookie > offset).cloned().collect();
                Ok((filtered, false))
            });
            let kmod = KmodPosixVfs::new(e);
            let state = dir_state(1, 1);
            chunks.push(collect_readdir_names(&kmod, &state, 128));
        }
        // Read with buffer size 512
        {
            let e2 = entries.clone();
            let mut e = MockEngine::new();
            e.readdir_fn = Box::new(move |_, offset, _| {
                let filtered: Vec<DirEntry> =
                    e2.iter().filter(|e| e.cookie > offset).cloned().collect();
                Ok((filtered, false))
            });
            let kmod = KmodPosixVfs::new(e);
            let state = dir_state(1, 1);
            chunks.push(collect_readdir_names(&kmod, &state, 512));
        }
        // Read with buffer size 4096 (full)
        {
            let e2 = entries.clone();
            let mut e2e = MockEngine::new();
            e2e.readdir_fn = Box::new(move |_, offset, _| {
                let filtered: Vec<DirEntry> =
                    e2.iter().filter(|e| e.cookie > offset).cloned().collect();
                Ok((filtered, false))
            });
            let kmod = KmodPosixVfs::new(e2e);
            let state = dir_state(1, 1);
            chunks.push(collect_readdir_names(&kmod, &state, 4096));
        }

        // All readings must produce identical name sequences
        for (i, names) in chunks.iter().enumerate() {
            assert_eq!(names.len(), n, "chunk variant {i} length mismatch");
            assert_eq!(*names, chunks[0], "chunk variant {i} differs from baseline");
        }
    }
}
