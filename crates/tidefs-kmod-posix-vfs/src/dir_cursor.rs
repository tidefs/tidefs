// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory cursor tracking state across iterative getdents64 calls.
//!
//! The [`DirCursor`] maps the opaque kernel `ctx->pos` to VfsEngine
//! directory entry offsets (cookies). It tracks the current iteration
//! position, an end-of-directory sentinel, and scratch state for
//! emission-buffer packing across multiple `getdents64(2)` calls.
//!
//! # Kernel VFS contract
//!
//! On the first `iterate` call for a directory handle, `ctx->pos` is 0.
//! After each call, the kernel VFS advances `ctx->pos` by the number of
//! bytes emitted into the dirent buffer.  The cursor translates this
//! byte-position to engine cookies: when `ctx->pos` is 0 or the cursor
//! has a saved "resume cookie", the engine is called; otherwise the
//! cursor replays buffered entries from the prior engine batch.
//!
//! At end-of-directory (`more == false` from the engine and no buffered
//! entries remain), the cursor sets the eof sentinel and subsequent
//! calls return 0 immediately.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::{DirEntry, InodeId};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

/// Tracks directory readdir state across iterative getdents64 calls.
///
/// # State machine
///
/// ```text
/// Fresh ──(first call)──► Active ──(buffer drained + more)──► Active
///                             │
///                             └──(buffer drained + !more)──► Ended
///
/// Ended ──(any call)──► returns 0
/// ```
///
/// On reset (e.g., `lseek(fd, 0, SEEK_SET)` or directory modification),
/// the cursor returns to the Fresh state for the next `iterate` call.
#[derive(Clone, Debug)]
pub struct DirCursor {
    /// Directory inode identity. Set on first engine call.
    inode: InodeId,
    /// Current logical resume cookie for the next engine readdir call.
    /// 0 means "start from beginning". Updated after each successful
    /// engine batch or buffer-drain transition.
    resume_cookie: u64,
    /// Buffered entries not yet emitted to the kernel dirent buffer.
    /// Populated by the engine readdir call and drained entry-by-entry
    /// as the kernel VFS consumes dirent records.
    buffered: crate::TideVec<DirEntry>,
    /// Index into `buffered` for the next entry to emit.
    buffered_pos: usize,
    /// End-of-directory sentinel. Set true when the engine returns
    /// `more == false` and all buffered entries have been emitted.
    eof: bool,
    /// Set true when the engine returns `more == false` with entries.
    /// After the last buffered entry is consumed, at_end() returns true
    /// without needing an additional engine call.
    final_batch: bool,
}

impl DirCursor {
    /// Create a fresh cursor for a directory.
    ///
    /// The cursor starts in the Fresh state: no engine call has been
    /// made yet, no entries are buffered, and the resume cookie is 0.
    pub fn new(inode: InodeId) -> Self {
        Self {
            inode,
            resume_cookie: 0,
            buffered: crate::TideVec::new(),
            buffered_pos: 0,
            eof: false,
            final_batch: false,
        }
    }

    /// The directory inode this cursor iterates.
    pub fn inode(&self) -> InodeId {
        self.inode
    }

    /// The current logical offset (resume cookie) for the next engine call.
    ///
    /// Returns 0 when the cursor is in the Fresh state or has been reset.
    /// Returns the last engine cookie when entries are buffered.
    pub fn position(&self) -> u64 {
        self.resume_cookie
    }

    /// Whether the cursor has reached end-of-directory.
    ///
    /// When true, the caller should return 0 without calling the engine.
    pub fn at_end(&self) -> bool {
        self.eof || (self.final_batch && !self.has_buffered())
    }

    /// Whether entries are currently buffered for emission.
    pub fn has_buffered(&self) -> bool {
        self.buffered_pos < self.buffered.len()
    }

    /// Return the number of buffered entries remaining.
    pub fn buffered_remaining(&self) -> usize {
        self.buffered.len().saturating_sub(self.buffered_pos)
    }

    /// Take the next buffered entry for emission, if any.
    ///
    /// Returns `None` when the buffer is exhausted.  The caller should
    /// then call the engine for the next batch.
    pub fn next_buffered(&mut self) -> Option<&DirEntry> {
        if self.buffered_pos < self.buffered.len() {
            let entry = &self.buffered[self.buffered_pos];
            self.buffered_pos += 1;
            Some(entry)
        } else {
            None
        }
    }

    /// Peek at the next buffered entry without consuming it.
    pub fn peek_buffered(&self) -> Option<&DirEntry> {
        self.buffered.get(self.buffered_pos)
    }

    /// Load a new batch of directory entries from the engine.
    ///
    /// Replaces any remaining buffered entries with the new batch.
    /// Updates `resume_cookie` to the last entry's cookie if entries
    /// were returned, or leaves it unchanged for an empty batch.
    ///
    /// When `more` is false, the cursor will set `eof` after the
    /// last buffered entry is consumed.
    pub fn load_batch(&mut self, entries: crate::TideVec<DirEntry>, more: bool) {
        self.buffered = entries;
        self.buffered_pos = 0;
        self.eof = false;
        self.final_batch = false;
        if !more {
            if self.buffered.is_empty() {
                self.eof = true;
            } else {
                self.final_batch = true;
            }
        }
        // Update resume_cookie to the last entry's cookie
        if let Some(last) = self.buffered.last() {
            self.resume_cookie = last.cookie;
        }
    }
    pub fn mark_eof_after_drain(&mut self) {
        if self.buffered.is_empty() {
            self.eof = true;
        }
        // Otherwise eof will be set when the buffer is fully consumed
        // and the caller calls at_end().
    }

    /// Advance the resume cookie to the given value.
    ///
    /// Used when the kernel VFS seeked to a specific position
    /// (e.g., `lseek(fd, offset, SEEK_SET)` on a directory fd).
    pub fn seek(&mut self, cookie: u64) {
        self.resume_cookie = cookie;
        self.buffered.clear();
        self.buffered_pos = 0;
        self.eof = false;
        self.final_batch = false;
    }

    /// Reset the cursor to the Fresh state.
    ///
    /// After reset, the next engine call will start from the beginning
    /// of the directory.  Called on directory modification that
    /// invalidates the current cursor position.
    pub fn reset(&mut self) {
        self.resume_cookie = 0;
        self.buffered.clear();
        self.buffered_pos = 0;
        self.eof = false;
        self.final_batch = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_kmod_bridge::kernel_types::{DirEntry, Generation, InodeId, NodeKind};

    fn dentry(ino: u64, name: &[u8], cookie: u64) -> DirEntry {
        DirEntry {
            name: name.to_vec(),
            inode_id: InodeId::new(ino),
            kind: NodeKind::File,
            generation: Generation::new(1),
            cookie,
        }
    }

    #[test]
    fn cursor_starts_fresh() {
        let c = DirCursor::new(InodeId::new(42));
        assert_eq!(c.inode(), InodeId::new(42));
        assert_eq!(c.position(), 0);
        assert!(!c.at_end());
        assert!(!c.has_buffered());
    }

    #[test]
    fn cursor_load_and_drain_batch() {
        let mut c = DirCursor::new(InodeId::new(1));
        let entries = crate::TideVec::from(
            [
                dentry(10, b"a", 1),
                dentry(20, b"b", 2),
                dentry(30, b"c", 3),
            ]
            .as_slice(),
        );
        c.load_batch(entries, false);

        assert_eq!(c.buffered_remaining(), 3);
        assert_eq!(c.position(), 3); // last cookie

        // Drain first entry
        let e = c.next_buffered().unwrap();
        assert_eq!(e.name, b"a");
        assert_eq!(c.buffered_remaining(), 2);

        // Drain remaining
        assert!(c.next_buffered().is_some());
        assert!(c.next_buffered().is_some());
        assert!(c.next_buffered().is_none());
        assert_eq!(c.buffered_remaining(), 0);
    }

    #[test]
    fn cursor_eof_on_empty_final_batch() {
        let mut c = DirCursor::new(InodeId::new(1));
        assert!(!c.at_end());

        c.load_batch(crate::TideVec::from([].as_slice()), false);
        assert!(c.at_end());
        assert!(!c.has_buffered());
    }

    #[test]
    fn cursor_eof_after_draining_final_batch() {
        let mut c = DirCursor::new(InodeId::new(1));
        let entries = crate::TideVec::from([dentry(10, b"x", 5)].as_slice());
        c.load_batch(entries, false); // more=false, one entry

        assert!(!c.at_end());
        assert!(c.has_buffered());

        // Drain the entry
        let e = c.next_buffered().unwrap();
        assert_eq!(e.name, b"x");

        // Now buffer is empty; eof should be recognized
        assert!(c.at_end());
    }

    #[test]
    fn cursor_more_flag_keeps_cursor_active() {
        let mut c = DirCursor::new(InodeId::new(1));
        let entries = crate::TideVec::from([dentry(10, b"first", 3)].as_slice());
        c.load_batch(entries, true); // more=true

        assert!(!c.at_end());
        let _ = c.next_buffered();
        // Buffer empty but more=true, so not at end
        assert!(!c.at_end());
        assert!(!c.has_buffered());
    }

    #[test]
    fn cursor_seek_resets_state() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(
            crate::TideVec::from([dentry(10, b"a", 1), dentry(20, b"b", 2)].as_slice()),
            false,
        );
        let _ = c.next_buffered(); // consume one

        c.seek(0);
        assert_eq!(c.position(), 0);
        assert!(!c.at_end());
        assert!(!c.has_buffered());
        assert_eq!(c.buffered_remaining(), 0);
    }

    #[test]
    fn cursor_seek_to_cookie() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.seek(42);
        assert_eq!(c.position(), 42);
    }

    #[test]
    fn cursor_reset_to_fresh() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(
            crate::TideVec::from([dentry(10, b"x", 7)].as_slice()),
            false,
        );
        let _ = c.next_buffered();

        c.reset();
        assert_eq!(c.position(), 0);
        assert!(!c.at_end());
        assert!(!c.has_buffered());
    }

    #[test]
    fn cursor_load_batch_updates_cookie() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(
            crate::TideVec::from([dentry(10, b"a", 10), dentry(20, b"b", 20)].as_slice()),
            true,
        );
        assert_eq!(c.position(), 20); // last entry's cookie
    }

    #[test]
    fn cursor_empty_batch_preserves_cookie() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(crate::TideVec::from([dentry(10, b"a", 5)].as_slice()), true);
        assert_eq!(c.position(), 5);
        c.load_batch(crate::TideVec::from([].as_slice()), false);
        assert_eq!(c.position(), 5); // unchanged
    }

    #[test]
    fn cursor_multi_batch_pagination() {
        let mut c = DirCursor::new(InodeId::new(1));
        let mut all_names: crate::TideVec<crate::TideVec<u8>> = crate::TideVec::new();

        // Batch 1: more=true
        c.load_batch(
            crate::TideVec::from([dentry(10, b"entry_0", 1), dentry(20, b"entry_1", 2)].as_slice()),
            true,
        );
        while let Some(e) = c.next_buffered() {
            all_names.push(e.name.clone());
        }

        // Batch 2: more=true
        c.load_batch(
            crate::TideVec::from([dentry(30, b"entry_2", 3), dentry(40, b"entry_3", 4)].as_slice()),
            true,
        );
        while let Some(e) = c.next_buffered() {
            all_names.push(e.name.clone());
        }

        // Batch 3: final
        c.load_batch(
            crate::TideVec::from([dentry(50, b"entry_4", 5)].as_slice()),
            false,
        );
        while let Some(e) = c.next_buffered() {
            all_names.push(e.name.clone());
        }

        assert_eq!(all_names.len(), 5);
        assert!(c.at_end());
        for (i, name) in all_names.iter().enumerate() {
            assert_eq!(name, alloc::format!("entry_{i}").as_bytes());
        }
    }

    #[test]
    fn cursor_load_replaces_remaining_buffered() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(
            crate::TideVec::from([dentry(10, b"a", 1), dentry(20, b"b", 2)].as_slice()),
            false,
        );
        let _ = c.next_buffered(); // consume "a", "b" remains

        // Load new batch: remaining "b" is replaced
        c.load_batch(
            crate::TideVec::from([dentry(30, b"c", 5)].as_slice()),
            false,
        );
        assert_eq!(c.buffered_remaining(), 1);
        let e = c.next_buffered().unwrap();
        assert_eq!(e.name, b"c");
    }

    #[test]
    fn cursor_peek_does_not_consume() {
        let mut c = DirCursor::new(InodeId::new(1));
        c.load_batch(
            crate::TideVec::from([dentry(10, b"peeked", 1)].as_slice()),
            false,
        );
        let peeked = c.peek_buffered().unwrap();
        assert_eq!(peeked.name, b"peeked");
        assert_eq!(c.buffered_remaining(), 1); // still there
    }

    #[test]
    fn cursor_large_directory_1024_entries() {
        let mut c = DirCursor::new(InodeId::new(1));
        let mut total = 0usize;
        let mut _cookie = 0u64;
        let batch_size = 64;

        loop {
            let batch: crate::TideVec<DirEntry> = (0..batch_size)
                .map(|i| {
                    let idx = total + i;
                    dentry(
                        100 + idx as u64,
                        alloc::format!("entry_{idx:04x}").as_bytes(),
                        (idx + 1) as u64,
                    )
                })
                .collect();
            let is_last = total + batch_size >= 1024;
            let more = !is_last;
            let b = if is_last {
                batch[..(1024 - total)].to_vec()
            } else {
                batch
            };
            let b_more = if is_last { false } else { more };
            let b_len = b.len();
            c.load_batch(b, b_more);
            while let Some(e) = c.next_buffered() {
                let expected = alloc::format!("entry_{total:04x}");
                assert_eq!(e.name, expected.as_bytes());
                _cookie = e.cookie;
                total += 1;
            }
            if !b_more && b_len == 0 {
                break;
            }
            if b_len < batch_size {
                break;
            }
        }
        assert_eq!(total, 1024);
        assert!(c.at_end());
    }
}
