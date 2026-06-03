//! Directory cursor abstraction for stable iteration.
//!
//! Provides [`DirectoryCursor`] supporting `readdir` with seek position,
//! dataset namespace filtering, and stable iteration across transactional
//! boundaries. The cursor is the canonical directory traversal primitive
//! used by both the FUSE daemon and block-volume paths.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{DirEntry, InodeId, NodeKind};

/// Position within a directory iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorPosition {
    /// Before any entries (start of directory).
    Start,
    /// Resuming from a specific cookie offset.
    At(u64),
    /// Past the last entry.
    End,
}

/// Filter controlling which directory entries are yielded during
/// iteration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryFilter {
    /// When set, only entries whose inode belongs to this dataset
    /// namespace are returned. Namespace membership is resolved via
    /// the cursor's namespace map.
    pub dataset_namespace: Option<u64>,
    /// When set, only entries of this node kind are returned.
    pub kind_filter: Option<NodeKind>,
}

impl DirectoryFilter {
    /// Create a filter that accepts all entries.
    #[must_use]
    pub fn all() -> Self {
        Self {
            dataset_namespace: None,
            kind_filter: None,
        }
    }
}

impl Default for DirectoryFilter {
    fn default() -> Self {
        Self::all()
    }
}

/// Cursor for iterating over directory entries.
///
/// Maintains stable iteration state so callers can resume `readdir`
/// from a cookie across calls, even when the underlying directory
/// changes between transactional boundaries. Entries are stored in
/// cookie order.
#[derive(Clone, Debug)]
pub struct DirectoryCursor {
    /// All entries in the directory, keyed by cookie.
    entries: BTreeMap<u64, DirEntry>,
    /// Current iteration position.
    position: CursorPosition,
    /// Active filter.
    filter: DirectoryFilter,
    /// Per-inode dataset namespace mapping (inode_id -> namespace).
    /// Populated by the consumer before iteration.
    namespace_map: BTreeMap<u64, u64>,
    /// Whether the underlying directory has been fully loaded.
    loaded: bool,
}

impl DirectoryCursor {
    /// Create an empty cursor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            position: CursorPosition::Start,
            filter: DirectoryFilter::all(),
            namespace_map: BTreeMap::new(),
            loaded: false,
        }
    }

    /// Set the active filter.
    pub fn set_filter(&mut self, filter: DirectoryFilter) {
        self.filter = filter;
    }

    /// Return the current filter.
    #[must_use]
    pub fn filter(&self) -> &DirectoryFilter {
        &self.filter
    }

    /// Set the dataset namespace for a specific inode.
    pub fn set_namespace(&mut self, inode_id: InodeId, namespace: u64) {
        self.namespace_map.insert(inode_id.get(), namespace);
    }

    /// Load entries into the cursor, replacing current contents.
    pub fn load(&mut self, entries: Vec<DirEntry>) {
        self.entries.clear();
        for entry in entries {
            self.entries.insert(entry.cookie, entry);
        }
        self.loaded = true;
        self.position = CursorPosition::Start;
    }

    /// Seek to a specific position.
    ///
    /// Use `CursorPosition::Start` to reset, or `CursorPosition::At(cookie)`
    /// to resume from the cookie of the last-read entry.
    pub fn seek(&mut self, position: CursorPosition) {
        self.position = position;
    }

    /// Read the next batch of entries, up to `max_entries`.
    ///
    /// Returns the matching entries and whether more entries remain
    /// after this batch. When `max_entries` is 0, returns an empty
    /// vector and reports whether any entries remain.
    pub fn readdir(&self, max_entries: usize) -> (Vec<DirEntry>, bool) {
        if self.position == CursorPosition::End {
            return (Vec::new(), false);
        }

        if max_entries == 0 {
            let start_cookie = match self.position {
                CursorPosition::Start => 0,
                CursorPosition::At(c) => c,
                CursorPosition::End => unreachable!(),
            };
            let has_more = self
                .entries
                .range((start_cookie + 1)..)
                .any(|(_, e)| self.filter_entry(e));
            return (Vec::new(), has_more);
        }

        let start_cookie = match self.position {
            CursorPosition::Start => 0,
            CursorPosition::At(c) => c,
            CursorPosition::End => unreachable!(),
        };

        let mut result = Vec::new();
        let mut count = 0;

        for (&cookie, entry) in self.entries.range(start_cookie..) {
            // When positioned at a specific cookie, skip that exact
            // entry (it was already returned in the previous batch).
            if matches!(self.position, CursorPosition::At(c) if c == cookie) {
                continue;
            }

            if !self.filter_entry(entry) {
                continue;
            }

            if max_entries > 0 && count >= max_entries {
                break;
            }

            result.push(entry.clone());
            count += 1;
        }

        // Determine if more entries exist past the returned batch.
        let last_returned = result.last().map(|e| e.cookie).unwrap_or(start_cookie);
        let has_more = self
            .entries
            .range((last_returned + 1)..)
            .any(|(_, e)| self.filter_entry(e));

        (result, has_more)
    }

    /// Whether the cursor has reached the end of the directory.
    #[must_use]
    pub fn is_at_end(&self) -> bool {
        matches!(self.position, CursorPosition::End)
    }

    /// Reset the cursor to the start of the directory.
    pub fn reset(&mut self) {
        self.position = CursorPosition::Start;
    }

    /// Number of loaded entries (unfiltered count).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the directory contents have been loaded.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    fn filter_entry(&self, entry: &DirEntry) -> bool {
        if let Some(kind) = self.filter.kind_filter {
            if entry.kind != kind {
                return false;
            }
        }
        if let Some(ns) = self.filter.dataset_namespace {
            let entry_ns = self.namespace_map.get(&entry.inode_id.get()).copied();
            if entry_ns != Some(ns) {
                return false;
            }
        }
        true
    }
}

impl Default for DirectoryCursor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Generation;

    fn de(name: &[u8], inode_id: u64, cookie: u64, kind: NodeKind) -> DirEntry {
        DirEntry::new(
            name.to_vec(),
            InodeId::new(inode_id),
            kind,
            Generation::new(1),
            cookie,
        )
    }

    // ── Construction / load ────────────────────────────────────────────

    #[test]
    fn cursor_new_is_empty() {
        let c = DirectoryCursor::new();
        assert_eq!(c.entry_count(), 0);
        assert!(!c.is_loaded());
    }

    #[test]
    fn cursor_load_populates_entries() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
        ]);
        assert!(c.is_loaded());
        assert_eq!(c.entry_count(), 2);
    }

    #[test]
    fn cursor_load_resets_position() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![de(b"x", 10, 1, NodeKind::File)]);
        c.seek(CursorPosition::End);
        c.load(alloc::vec![de(b"y", 20, 2, NodeKind::File)]);
        // After load, position returns to Start.
        let (batch, _) = c.readdir(1);
        assert_eq!(batch.len(), 1);
    }

    // ── readdir basic ──────────────────────────────────────────────────

    #[test]
    fn cursor_readdir_from_start() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
            de(b"c", 12, 3, NodeKind::File),
        ]);
        let (batch, has_more) = c.readdir(2);
        assert_eq!(batch.len(), 2);
        assert!(has_more);
        assert_eq!(batch[0].inode_id, InodeId::new(10));
        assert_eq!(batch[1].inode_id, InodeId::new(11));
    }

    #[test]
    fn cursor_readdir_all() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
        ]);
        let (batch, has_more) = c.readdir(100);
        assert_eq!(batch.len(), 2);
        assert!(!has_more);
    }

    #[test]
    fn cursor_readdir_zero_max_returns_empty_but_reports_more() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![de(b"a", 10, 1, NodeKind::File)]);
        let (batch, has_more) = c.readdir(0);
        assert!(batch.is_empty());
        assert!(has_more);
    }

    #[test]
    fn cursor_readdir_from_end_returns_empty_no_more() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![de(b"a", 10, 1, NodeKind::File)]);
        c.seek(CursorPosition::End);
        let (batch, has_more) = c.readdir(10);
        assert!(batch.is_empty());
        assert!(!has_more);
    }

    // ── Seek and resume ────────────────────────────────────────────────

    #[test]
    fn cursor_seek_resume_batches() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
            de(b"c", 12, 3, NodeKind::File),
            de(b"d", 13, 4, NodeKind::File),
        ]);
        let (b1, more1) = c.readdir(2);
        assert_eq!(b1.len(), 2);
        assert!(more1);

        c.seek(CursorPosition::At(b1[1].cookie));
        let (b2, more2) = c.readdir(10);
        assert_eq!(b2.len(), 2);
        assert!(!more2);
        assert_eq!(b2[0].inode_id, InodeId::new(12));
        assert_eq!(b2[1].inode_id, InodeId::new(13));
    }

    #[test]
    fn cursor_seek_at_cookie_skips_exact_match() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
        ]);
        c.seek(CursorPosition::At(1));
        let (batch, _) = c.readdir(10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].inode_id, InodeId::new(11));
    }

    #[test]
    fn cursor_reset() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![de(b"a", 10, 1, NodeKind::File)]);
        c.seek(CursorPosition::At(1));
        c.reset();
        let (batch, _) = c.readdir(10);
        assert_eq!(batch.len(), 1);
    }

    // ── Filtering ──────────────────────────────────────────────────────

    #[test]
    fn cursor_filter_by_kind() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"f1", 10, 1, NodeKind::File),
            de(b"d1", 20, 2, NodeKind::Dir),
            de(b"f2", 30, 3, NodeKind::File),
        ]);
        c.set_filter(DirectoryFilter {
            kind_filter: Some(NodeKind::Dir),
            ..DirectoryFilter::all()
        });
        let (batch, has_more) = c.readdir(10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].inode_id, InodeId::new(20));
        assert!(!has_more);
    }

    #[test]
    fn cursor_filter_by_namespace() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"a", 10, 1, NodeKind::File),
            de(b"b", 11, 2, NodeKind::File),
            de(b"c", 12, 3, NodeKind::File),
        ]);
        c.set_namespace(InodeId::new(10), 42);
        c.set_namespace(InodeId::new(11), 99);
        c.set_namespace(InodeId::new(12), 42);
        c.set_filter(DirectoryFilter {
            dataset_namespace: Some(42),
            ..DirectoryFilter::all()
        });
        let (batch, _) = c.readdir(10);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].inode_id, InodeId::new(10));
        assert_eq!(batch[1].inode_id, InodeId::new(12));
    }

    #[test]
    fn cursor_filter_combined() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![
            de(b"f1", 10, 1, NodeKind::File),
            de(b"d1", 20, 2, NodeKind::Dir),
            de(b"f2", 30, 3, NodeKind::File),
        ]);
        c.set_namespace(InodeId::new(10), 1);
        c.set_namespace(InodeId::new(20), 1);
        c.set_namespace(InodeId::new(30), 2);
        c.set_filter(DirectoryFilter {
            dataset_namespace: Some(1),
            kind_filter: Some(NodeKind::Dir),
        });
        let (batch, _) = c.readdir(10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].inode_id, InodeId::new(20));
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn cursor_empty_directory() {
        let mut c = DirectoryCursor::new();
        c.load(alloc::vec![]);
        assert!(c.is_loaded());
        assert_eq!(c.entry_count(), 0);
        let (batch, has_more) = c.readdir(10);
        assert!(batch.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn cursor_default() {
        let c = DirectoryCursor::default();
        assert_eq!(c.entry_count(), 0);
    }
}
