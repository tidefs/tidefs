//! Ordered directory cursor with BLAKE3-verified entry iteration.
//!
//! [`DirCursor`] wraps a bounded [`crate::DirIndex`] window and yields
//! directory entries in sorted order with per-entry BLAKE3 integrity tokens.
//! It injects synthetic `.` and `..` entries at offsets 0 and 1, and supports
//! position tracking via opaque offset cookies for FUSE readdir resumption.
//!
//! Production callers should construct cursors with
//! [`DirCursor::new_window`] so each readdir batch retains only the requested
//! entries. The legacy full-snapshot constructor remains available only to
//! unit tests that cover historical cursor behavior.

use alloc::vec::Vec;

use crate::DirIndex;
use tidefs_btree::BTreeError;

/// Domain label for BLAKE3 key derivation in cursor entry tokens.
const CURSOR_TOKEN_DOMAIN: &str = "tidefs-dir-cursor-entry-v1";

/// A directory entry yielded by [`DirCursor`] with a BLAKE3 integrity token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirCursorEntry {
    /// Entry name (not NUL-terminated).
    pub name: Vec<u8>,
    /// Target inode number.
    pub inode_id: u64,
    /// Entry type (`DT_DIR`=0, `DT_FILE`=1, `DT_SYMLINK`=2; 32-bit for
    /// compatibility with `DirMicroEntry`).
    pub entry_type: u32,
    /// Inode generation counter.
    pub generation: u64,
    /// Monotonic offset cookie for telldir/seekdir.
    pub offset: u64,
    /// First 8 bytes of the BLAKE3 keyed hash of the entry payload, used
    /// for integrity verification by callers (e.g. FUSE readdir).
    pub blake3_token: [u8; 8],
}

/// Errors returned by [`DirCursor`] construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirCursorError {
    /// The underlying B+tree node checksums failed verification.
    ChecksumMismatch,
}

impl From<BTreeError> for DirCursorError {
    fn from(e: BTreeError) -> Self {
        match e {
            BTreeError::ChecksumMismatch => DirCursorError::ChecksumMismatch,
            _ => DirCursorError::ChecksumMismatch,
        }
    }
}

/// Ordered directory cursor with BLAKE3-verified entry iteration.
///
/// Created from a bounded [`DirIndex`] window. Yields entries in sorted order,
/// including synthetic `.` and `..` entries when they fall inside the window.
/// Each entry carries a [`blake3_token`](DirCursorEntry::blake3_token) for
/// integrity verification.
#[derive(Clone, Debug)]
pub struct DirCursor {
    /// Directory inode this cursor iterates over.
    dir_ino: u64,
    /// Sorted window entries, including synthetic `.` and `..` when present.
    entries: Vec<DirCursorEntry>,
    /// Current cursor position (index into `entries`).
    position: usize,
}

impl DirCursor {
    /// Create a full-snapshot cursor over `idx`, positioned at `start_offset`.
    ///
    /// `start_offset` is an opaque cookie: 0 means start from the
    /// beginning (including `.` and `..`). On construction the cursor
    /// verifies B+tree checksums when the directory uses the B-tree
    /// representation.
    ///
    /// This constructor is intentionally test-only. Production readdir paths
    /// should use [`Self::new_window`] so cursor allocation is bounded by the
    /// requested batch.
    ///
    /// # Errors
    ///
    /// Returns [`DirCursorError::ChecksumMismatch`] when B+tree node
    /// checksums fail verification.
    #[cfg(test)]
    pub fn new(idx: &DirIndex, start_offset: u64) -> Result<Self, DirCursorError> {
        // Verify B+tree checksums before collecting entries.
        idx.verify_checksums()?;

        let dir_ino = idx.directory_inode_id();

        let mut entries: Vec<DirCursorEntry> = Vec::new();

        // Synthetic "." entry at offset 0.
        entries.push(DirCursorEntry {
            name: b".".to_vec(),
            inode_id: dir_ino,
            entry_type: 0, // DT_DIR
            generation: 0,
            offset: 0,
            blake3_token: [0u8; 8],
        });

        // Synthetic ".." entry at offset 1.
        entries.push(DirCursorEntry {
            name: b"..".to_vec(),
            inode_id: 0,   // parent inode filled by caller
            entry_type: 0, // DT_DIR
            generation: 0,
            offset: 1,
            blake3_token: [0u8; 8],
        });

        // Collect real entries from the index in sorted order.
        let sorted = idx.list(); // name-sorted DirMicroEntry list
        for (i, entry) in sorted.iter().enumerate() {
            let offset = 2 + i as u64; // entry cookies start at 2
            let token = compute_entry_token(
                &entry.name,
                entry.inode_id,
                entry.kind,
                entry.generation,
                offset,
            );
            entries.push(DirCursorEntry {
                name: entry.name.clone(),
                inode_id: entry.inode_id,
                entry_type: entry.kind,
                generation: entry.generation,
                offset,
                blake3_token: token,
            });
        }

        // Position the cursor.
        let position = if start_offset == 0 {
            0
        } else {
            // Seek to the first entry with offset >= start_offset.
            entries
                .iter()
                .position(|e| e.offset >= start_offset)
                .unwrap_or(entries.len())
        };

        Ok(DirCursor {
            dir_ino,
            entries,
            position,
        })
    }

    /// Create a bounded cursor window over `idx`, positioned at `start_offset`.
    ///
    /// This constructor collects at most `max_entries` cursor entries. It
    /// preserves the historical offset convention: offsets 0 and 1 are
    /// synthetic `.` and `..`, and real entries start at offset 2 in sorted
    /// name order. The returned boolean is `true` when more entries remain
    /// after the window.
    ///
    /// This is the preferred constructor for one-shot readdir batches because
    /// it bounds the cursor allocation by the caller's batch size.
    pub fn new_window(
        idx: &DirIndex,
        start_offset: u64,
        max_entries: usize,
    ) -> Result<(Self, bool), DirCursorError> {
        idx.verify_checksums()?;

        let dir_ino = idx.directory_inode_id();
        let total_entries = idx.len().saturating_add(2);
        let start = if start_offset == 0 {
            0usize
        } else {
            usize::try_from(start_offset)
                .unwrap_or(usize::MAX)
                .min(total_entries)
        };
        let end = start.saturating_add(max_entries).min(total_entries);
        let mut entries: Vec<DirCursorEntry> = Vec::with_capacity(end.saturating_sub(start));

        if start == 0 && end > 0 {
            entries.push(DirCursorEntry {
                name: b".".to_vec(),
                inode_id: dir_ino,
                entry_type: 0,
                generation: 0,
                offset: 0,
                blake3_token: [0u8; 8],
            });
        }

        if start <= 1 && end > 1 {
            entries.push(DirCursorEntry {
                name: b"..".to_vec(),
                inode_id: 0,
                entry_type: 0,
                generation: 0,
                offset: 1,
                blake3_token: [0u8; 8],
            });
        }

        if end > 2 {
            let real_start = start.saturating_sub(2);
            let real_end = end - 2;
            let real_entries = idx.entries_from_sorted_index(real_start, real_end - real_start);
            for (i, entry) in real_entries.iter().enumerate() {
                let offset = (2 + real_start + i) as u64;
                let token = compute_entry_token(
                    &entry.name,
                    entry.inode_id,
                    entry.kind,
                    entry.generation,
                    offset,
                );
                entries.push(DirCursorEntry {
                    name: entry.name.clone(),
                    inode_id: entry.inode_id,
                    entry_type: entry.kind,
                    generation: entry.generation,
                    offset,
                    blake3_token: token,
                });
            }
        }

        let has_more = end < total_entries;
        Ok((
            DirCursor {
                dir_ino,
                entries,
                position: 0,
            },
            has_more,
        ))
    }

    /// Return the next entry in sorted order, advancing the cursor.
    ///
    /// Returns `None` when all entries have been yielded.
    pub fn next_entry(&mut self) -> Option<&DirCursorEntry> {
        if self.position >= self.entries.len() {
            return None;
        }
        let entry = &self.entries[self.position];
        self.position += 1;
        Some(entry)
    }

    /// Reset the cursor to the beginning (including `.` and `..`).
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Seek the cursor to the first entry with offset >= `cookie`.
    ///
    /// After seeking, the next call to [`next_entry`](Self::next_entry)
    /// returns the first entry whose offset is at least `cookie`.
    pub fn seek_to(&mut self, cookie: u64) {
        if cookie == 0 {
            self.position = 0;
            return;
        }
        self.position = self
            .entries
            .iter()
            .position(|e| e.offset >= cookie)
            .unwrap_or(self.entries.len());
    }

    /// Return the offset cookie of the entry at the current position.
    ///
    /// If the cursor is exhausted (past the last entry), returns the
    /// offset of the last entry. If the directory is empty (only `.`
    /// and `..` exist), returns 1.
    pub fn current_offset(&self) -> u64 {
        if self.entries.is_empty() {
            return 0;
        }
        if self.position == 0 {
            return 0;
        }
        let idx = (self.position - 1).min(self.entries.len() - 1);
        self.entries[idx].offset
    }

    /// Number of entries remaining in the cursor.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.entries.len().saturating_sub(self.position)
    }

    /// Whether the cursor has yielded all entries.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.position >= self.entries.len()
    }

    /// Total number of entries in the cursor (including `.` and `..`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cursor contains no entries at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the cursor has no real entries (only `.` and `..`).
    #[must_use]
    pub fn is_empty_dir(&self) -> bool {
        self.entries.len() <= 2
    }

    /// Return the directory inode this cursor iterates over.
    #[must_use]
    pub fn dir_ino(&self) -> u64 {
        self.dir_ino
    }
}

/// Compute a BLAKE3 integrity token for a directory entry.
///
/// The token is the first 8 bytes of a BLAKE3 keyed hash over the
/// canonical entry payload: name_len(u32 LE) + name + inode_id(u64 LE)
/// + entry_type(u32 LE) + generation(u64 LE) + offset(u64 LE).
///
/// Domain-separation via [`CURSOR_TOKEN_DOMAIN`] ensures tokens are
/// distinct from other BLAKE3 uses in the tree.
fn compute_entry_token(
    name: &[u8],
    inode_id: u64,
    entry_type: u32,
    generation: u64,
    offset: u64,
) -> [u8; 8] {
    let key = blake3::derive_key(CURSOR_TOKEN_DOMAIN, b"");
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&(name.len() as u32).to_le_bytes());
    hasher.update(name);
    hasher.update(&inode_id.to_le_bytes());
    hasher.update(&entry_type.to_le_bytes());
    hasher.update(&generation.to_le_bytes());
    hasher.update(&offset.to_le_bytes());
    let hash = hasher.finalize();
    let mut token = [0u8; 8];
    token.copy_from_slice(&hash.as_bytes()[..8]);
    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatasetDirPolicy, DirIndex};
    use alloc::vec;

    fn test_policy() -> DatasetDirPolicy {
        DatasetDirPolicy {
            dir_micro_max_entries: 6,
            dir_micro_max_name_bytes: 512,
            dir_btree_downshift_entries: 3,
            dir_btree_downshift_name_bytes: 128,
        }
    }

    // ── Construction and synthetic entries ──────────────────────────

    #[test]
    fn empty_dir_yields_dot_and_dotdot() {
        let idx = DirIndex::new(42, test_policy());
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.len(), 2);
        assert!(cursor.is_empty_dir());
        let entries: Vec<_> = cursor.entries.iter().collect();
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[0].inode_id, 42);
        assert_eq!(entries[0].offset, 0);
        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[1].inode_id, 0);
        assert_eq!(entries[1].offset, 1);
    }

    #[test]
    fn empty_dir_iteration_exhausted_immediately() {
        let idx = DirIndex::new(1, test_policy());
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        assert!(cursor.next_entry().is_some()); // "."
        assert!(cursor.next_entry().is_some()); // ".."
        assert!(cursor.next_entry().is_none());
        assert!(cursor.is_exhausted());
    }

    #[test]
    fn single_entry_dir_yields_dot_dotdot_entry() {
        let mut idx = DirIndex::new(10, test_policy());
        idx.insert(b"hello", 100, 1, 1).unwrap(); // DT_FILE
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.len(), 3);
        let names: Vec<_> = cursor.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names,
            vec![b".".to_vec(), b"..".to_vec(), b"hello".to_vec()]
        );
    }

    #[test]
    fn entries_sorted_by_name_after_synthetics() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"zulu", 26, 0, 1).unwrap();
        idx.insert(b"alpha", 1, 0, 1).unwrap();
        idx.insert(b"mike", 13, 0, 1).unwrap();
        let cursor = DirCursor::new(&idx, 0).unwrap();
        let names: Vec<_> = cursor.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names,
            vec![
                b".".to_vec(),
                b"..".to_vec(),
                b"alpha".to_vec(),
                b"mike".to_vec(),
                b"zulu".to_vec()
            ]
        );
    }

    // ── Offsets ─────────────────────────────────────────────────────

    #[test]
    fn real_entries_get_monotonic_offsets() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        idx.insert(b"c", 30, 0, 1).unwrap();
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.entries[0].offset, 0); // "."
        assert_eq!(cursor.entries[1].offset, 1); // ".."
        assert_eq!(cursor.entries[2].offset, 2); // "a"
        assert_eq!(cursor.entries[3].offset, 3); // "b"
        assert_eq!(cursor.entries[4].offset, 4); // "c"
    }

    // ── next_entry ──────────────────────────────────────────────────

    #[test]
    fn next_entry_advances_and_returns_correct_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"file", 99, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();

        let dot = cursor.next_entry().unwrap();
        assert_eq!(dot.name, b".");
        assert_eq!(cursor.current_offset(), 0);

        let dotdot = cursor.next_entry().unwrap();
        assert_eq!(dotdot.name, b"..");

        let file = cursor.next_entry().unwrap();
        assert_eq!(file.name, b"file");
        assert_eq!(file.inode_id, 99);
        assert_eq!(cursor.current_offset(), 2);

        assert!(cursor.next_entry().is_none());
    }

    #[test]
    fn next_entry_past_end_returns_none() {
        let idx = DirIndex::new(1, test_policy());
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        assert!(cursor.next_entry().is_some()); // "."
        assert!(cursor.next_entry().is_some()); // ".."
        assert!(cursor.next_entry().is_none());
        assert!(cursor.next_entry().is_none()); // still None
    }

    // ── reset ───────────────────────────────────────────────────────

    #[test]
    fn reset_after_partial_iteration() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();

        cursor.next_entry(); // "."
        cursor.next_entry(); // ".."
        cursor.next_entry(); // "a"
        assert_eq!(cursor.current_offset(), 2);

        cursor.reset();
        assert_eq!(cursor.position, 0);
        assert!(!cursor.is_exhausted());
        let first = cursor.next_entry().unwrap();
        assert_eq!(first.name, b".");
    }

    // ── seek_to ─────────────────────────────────────────────────────

    #[test]
    fn seek_to_cookie_zero_resets() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        cursor.next_entry(); // "."
        cursor.next_entry(); // ".."
        cursor.seek_to(0);
        let first = cursor.next_entry().unwrap();
        assert_eq!(first.name, b".");
    }

    #[test]
    fn seek_to_entry_offset_resumes_correctly() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        idx.insert(b"c", 30, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();

        // Seek to offset 3 (should skip ".", "..", "a", returning "b" next).
        cursor.seek_to(3);
        let next = cursor.next_entry().unwrap();
        assert_eq!(next.name, b"b");
        assert_eq!(next.offset, 3);
    }

    #[test]
    fn seek_to_exact_first_real_entry() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"first", 1, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        cursor.seek_to(2); // first real entry offset
        let next = cursor.next_entry().unwrap();
        assert_eq!(next.name, b"first");
    }

    #[test]
    fn seek_to_dotdot_offset() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        cursor.seek_to(1);
        let next = cursor.next_entry().unwrap();
        assert_eq!(next.name, b"..");
    }

    #[test]
    fn seek_past_end_exhausts_cursor() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"x", 1, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        cursor.seek_to(999);
        assert!(cursor.is_exhausted());
        assert!(cursor.next_entry().is_none());
    }

    // ── BLAKE3 tokens ───────────────────────────────────────────────

    #[test]
    fn synthetic_entries_have_zero_tokens() {
        let idx = DirIndex::new(1, test_policy());
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.entries[0].blake3_token, [0u8; 8]);
        assert_eq!(cursor.entries[1].blake3_token, [0u8; 8]);
    }

    #[test]
    fn real_entries_have_nonzero_tokens() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"test", 42, 0, 1).unwrap();
        let cursor = DirCursor::new(&idx, 0).unwrap();
        let token = cursor.entries[2].blake3_token;
        assert_ne!(token, [0u8; 8], "real entry must have non-zero token");
    }

    #[test]
    fn token_is_deterministic() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"test", 42, 0, 1).unwrap();
        let cursor1 = DirCursor::new(&idx, 0).unwrap();
        let cursor2 = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(
            cursor1.entries[2].blake3_token,
            cursor2.entries[2].blake3_token
        );
    }

    #[test]
    fn different_entries_have_different_tokens() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 1).unwrap();
        idx.insert(b"beta", 2, 0, 1).unwrap();
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_ne!(
            cursor.entries[2].blake3_token,
            cursor.entries[3].blake3_token
        );
    }

    #[test]
    fn token_changes_with_inode_id() {
        let mut idx1 = DirIndex::new(1, test_policy());
        idx1.insert(b"name", 10, 0, 1).unwrap();
        let mut idx2 = DirIndex::new(1, test_policy());
        idx2.insert(b"name", 20, 0, 1).unwrap();
        let c1 = DirCursor::new(&idx1, 0).unwrap();
        let c2 = DirCursor::new(&idx2, 0).unwrap();
        assert_ne!(c1.entries[2].blake3_token, c2.entries[2].blake3_token);
    }

    // ── BTree checksum verification ─────────────────────────────────

    #[test]
    fn btree_mode_verifies_checksums_on_construction() {
        let mut idx = DirIndex::new(1, test_policy());
        // Fill beyond micro-list threshold to trigger BTree switch.
        for i in 0..10u64 {
            let name = alloc::format!("entry_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), crate::DirStorageKind::BTREE);
        let cursor = DirCursor::new(&idx, 0);
        assert!(cursor.is_ok(), "checksum verification must pass");
    }

    #[test]
    fn btree_cursor_contains_all_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10u64 {
            let name = alloc::format!("entry_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), crate::DirStorageKind::BTREE);
        let cursor = DirCursor::new(&idx, 0).unwrap();
        // 2 synthetic + 10 real
        assert_eq!(cursor.len(), 12);
        // Walk all entries
        let mut count = 0;
        let mut c = cursor.clone();
        while c.next_entry().is_some() {
            count += 1;
        }
        assert_eq!(count, 12);
    }

    // ── current_offset and remaining ────────────────────────────────

    #[test]
    fn current_offset_tracks_position() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.current_offset(), 0);
        cursor.next_entry(); // "."
        assert_eq!(cursor.current_offset(), 0);
        cursor.next_entry(); // ".."
        assert_eq!(cursor.current_offset(), 1);
        cursor.next_entry(); // "a"
        assert_eq!(cursor.current_offset(), 2);
        cursor.next_entry(); // "b"
        assert_eq!(cursor.current_offset(), 3);
        cursor.next_entry(); // None
        assert_eq!(cursor.current_offset(), 3); // still last
    }

    #[test]
    fn remaining_counts_correctly() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.remaining(), 3); // ".", "..", "a"
        cursor.next_entry();
        assert_eq!(cursor.remaining(), 2);
        cursor.next_entry();
        assert_eq!(cursor.remaining(), 1);
        cursor.next_entry();
        assert_eq!(cursor.remaining(), 0);
    }

    // ── Large directory ─────────────────────────────────────────────

    #[test]
    fn large_directory_iterates_all_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        let n = 200u64;
        for i in 0..n {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.len(), n as usize + 2);
        let mut count = 0;
        while cursor.next_entry().is_some() {
            count += 1;
        }
        assert_eq!(count, n as usize + 2);
    }

    #[test]
    fn large_directory_seek_and_resume() {
        let mut idx = DirIndex::new(1, test_policy());
        let n = 100u64;
        for i in 0..n {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        let mut cursor = DirCursor::new(&idx, 0).unwrap();
        // Seek to offset 50 (skip ".", ".." and entries 0..48)
        cursor.seek_to(50);
        let next = cursor.next_entry().unwrap();
        assert_eq!(next.offset, 50);
        let remaining_after = cursor.remaining();
        assert_eq!(remaining_after, cursor.len() - 51);
    }

    #[test]
    fn window_limits_btree_cursor_entries_and_reports_more() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..200u64 {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }

        let (cursor, has_more) = DirCursor::new_window(&idx, 0, 10).unwrap();
        assert!(has_more);
        assert_eq!(cursor.len(), 10);
        let names: Vec<Vec<u8>> = cursor.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names[0], b".".to_vec());
        assert_eq!(names[1], b"..".to_vec());
        assert_eq!(names[2], b"entry_0000".to_vec());
        assert_eq!(names[9], b"entry_0007".to_vec());
    }

    #[test]
    fn window_resumes_from_offset_without_early_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..100u64 {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }

        let (cursor, has_more) = DirCursor::new_window(&idx, 50, 4).unwrap();
        assert!(has_more);
        assert_eq!(cursor.len(), 4);
        let offsets: Vec<u64> = cursor.entries.iter().map(|e| e.offset).collect();
        let names: Vec<Vec<u8>> = cursor.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(offsets, vec![50, 51, 52, 53]);
        assert_eq!(
            names,
            vec![
                b"entry_0048".to_vec(),
                b"entry_0049".to_vec(),
                b"entry_0050".to_vec(),
                b"entry_0051".to_vec()
            ]
        );
    }

    #[test]
    fn window_past_end_is_empty_without_more() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"only", 1, 0, 1).unwrap();

        let (cursor, has_more) = DirCursor::new_window(&idx, 999, 16).unwrap();
        assert!(!has_more);
        assert_eq!(cursor.len(), 0);
        assert!(cursor.is_exhausted());
    }

    // ── is_empty_dir ────────────────────────────────────────────────

    #[test]
    fn is_empty_dir_true_for_no_real_entries() {
        let idx = DirIndex::new(1, test_policy());
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert!(cursor.is_empty_dir());
    }

    #[test]
    fn is_empty_dir_false_with_real_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"x", 1, 0, 1).unwrap();
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert!(!cursor.is_empty_dir());
    }

    // ── dir_ino ─────────────────────────────────────────────────────

    #[test]
    fn dir_ino_matches_constructor() {
        let idx = DirIndex::new(99, test_policy());
        let cursor = DirCursor::new(&idx, 0).unwrap();
        assert_eq!(cursor.dir_ino(), 99);
    }

    // ── Construction with nonzero start_offset ──────────────────────

    #[test]
    fn start_offset_skips_early_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 10, 0, 1).unwrap();
        idx.insert(b"b", 20, 0, 1).unwrap();
        idx.insert(b"c", 30, 0, 1).unwrap();
        let mut cursor = DirCursor::new(&idx, 3).unwrap(); // start at "b"
        let first = cursor.next_entry().unwrap();
        assert_eq!(first.name, b"b");
    }

    #[test]
    fn start_offset_past_end_exhausts() {
        let idx = DirIndex::new(1, test_policy());
        let cursor = DirCursor::new(&idx, 999).unwrap();
        assert!(cursor.is_exhausted());
    }
}
