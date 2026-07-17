// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Persistent directory index with DirEntry/DirPage binary format, object-store
//! CRUD, ordered iteration, and hysteresis-driven representation switching.
//!
//! Wraps [`DirStorage`] from [`tidefs_types_polymorphic_directory_index_core`]
//! and provides lookup, insert, delete, and readdir operations with
//! hysteresis-driven representation switching between inline micro-list
//! (O(n), n ≤ 50) and B+tree (O(log n), any size).
//!
//! When built with the `persistent-dir-index` feature, the crate links
//! `tidefs-local-object-store` for binary page persistence. The `in-memory-dir-index`
//! feature provides the original no-dependencies stub for namespaces that
//! do not need persistence.
//!
//! [`DirStorage::BTree`] carries runtime metadata only. Persistent page
//! identity is owned by `format::dir_page_key`, not by a numeric root
//! locator in the shared type crate.

extern crate alloc;

pub mod format;
#[cfg(feature = "persistent-dir-index")]
pub mod pages;
#[cfg(feature = "persistent-dir-index")]
pub mod persistent;
#[cfg(feature = "persistent-dir-index")]
pub mod redundancy;

pub mod cursor;
#[cfg(feature = "kernel")]
pub mod kernel_reader;

/// Re-export the object store for namespace integration.
#[cfg(feature = "persistent-dir-index")]
pub use tidefs_local_object_store;

use alloc::{collections::BTreeMap, vec::Vec};
pub use cursor::{DirCursor, DirCursorEntry, DirCursorError};
use tidefs_btree::BPlusTree;
pub use tidefs_types_polymorphic_directory_index_core::{
    DatasetDirPolicy, DirCookie, DirMicroEntry, DirStorage, DirStorageKind,
};
use tidefs_types_polymorphic_directory_index_core::{
    DirBtreeLeafEntry, DirBtreeRuntimeState, DirMicroListV1,
};

/// Directory entry stored in a [`DirIndex`].
pub type DirEntry = DirMicroEntry;

type DirHashTree = BPlusTree<u64, Vec<DirBtreeLeafEntry>, 128, 128>;
type DirNameTree = BTreeMap<Vec<u8>, DirBtreeLeafEntry>;

fn dir_entry_from_btree_leaf(entry: &DirBtreeLeafEntry) -> DirEntry {
    DirEntry {
        name_len: u32::from(entry.name_len),
        inode_id: entry.inode_id,
        generation: entry.generation,
        kind: entry.kind,
        name: entry.name.clone(),
    }
}

// ---------------------------------------------------------------------------
// DirIndexError
// ---------------------------------------------------------------------------

/// Errors returned by directory index operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirIndexError {
    /// Insert attempted but an entry with this name already exists.
    EntryAlreadyExists,
    /// Lookup or delete attempted but no entry with this name was found.
    EntryNotFound,
    /// Attempted to remove a directory that still has entries.
    DirNotEmpty,
    /// The readdir cursor cookie is stale because the directory was
    /// mutated between paginated readdir batches.
    StaleCursor,
}

// ---------------------------------------------------------------------------
// SwapMode — rename operation mode
// ---------------------------------------------------------------------------

/// Controls the behaviour of [`DirIndex::atomic_swap`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwapMode {
    /// Standard rename (flags=0): atomically move the source entry to the
    /// destination slot, replacing any existing destination entry.
    Rename,
    /// `RENAME_NOREPLACE`: fail with [`DirIndexError::EntryAlreadyExists`]
    /// if the destination name already exists.
    NoReplace,
    /// `RENAME_EXCHANGE`: atomically swap the source and destination
    /// directory entries. Both must exist; no entry is removed.
    Exchange,
}

// ---------------------------------------------------------------------------
// DirIterator — FUSE readdir cursor trait
// ---------------------------------------------------------------------------

/// Trait for iterating directory entries with cursor-based position tracking.
///
/// The FUSE dispatch layer uses this trait to drive `opendir`/`readdir`/
/// `releasedir`. Implementations walk entries in stable name-sorted order
/// and expose a [`DirCookie`] cursor for kernel offset resumption.
pub trait DirIterator {
    /// The error type for iteration failures.
    type Error;

    /// Advance the cursor and return the next entry in name-sorted order,
    /// or `None` when all entries have been yielded.
    fn next_entry(&mut self) -> Option<DirEntry>;

    /// Reset the cursor to the beginning of the directory.
    fn reset_cursor(&mut self);

    /// Seek the cursor to the position immediately after `cookie`.
    ///
    /// After a successful seek, the next call to [`next_entry`](Self::next_entry)
    /// returns the entry following `cookie`. Seeking to
    /// [`DirCookie::START`] is equivalent to [`reset_cursor`](Self::reset_cursor).
    fn seek_to_cursor(&mut self, cookie: DirCookie);

    /// Return the current cursor position.
    ///
    /// The returned cookie is suitable as `d_off` in a FUSE dirent.
    fn current_cursor(&self) -> DirCookie;
}

// ---------------------------------------------------------------------------
// Cookie <-> sorted-index helpers
// ---------------------------------------------------------------------------

/// Encode a name-sorted entry index as a cookie, respecting the directory
/// representation so the kernel can resume correctly across readdir calls.
fn cookie_from_index(index: usize, is_btree: bool) -> DirCookie {
    if is_btree {
        // Map sequential sorted index to (page, entry) for B-tree cookies.
        // Each "page" holds up to 128 entries in the sequential mapping.
        let page = (index / 128) as u16;
        let entry = (index % 128) as u16;
        DirCookie(DirCookie::encode_btree(page, entry))
    } else {
        DirCookie(DirCookie::encode_micro(index as u32))
    }
}

/// Decode a cookie to a name-sorted entry index, clamping to `total`.
fn index_from_cookie(cookie: DirCookie, total: usize) -> usize {
    if cookie.0 == 0 {
        return 0;
    }
    if cookie.is_micro() {
        return (cookie.as_micro_entry_index().unwrap_or(0) as usize).min(total);
    }
    // B-tree cookies: decode (page, entry) and map back to sequential index.
    if let Some((page, entry)) = cookie.as_btree_indices() {
        ((page as usize).saturating_mul(128) + (entry as usize)).min(total)
    } else {
        // Fallback: treat payload as raw index (best-effort).
        (cookie.payload() as usize).min(total)
    }
}
// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Deterministic 64-bit hash of an entry name (FNV-1a).
///
/// This is an in-memory hash; the design spec calls for BLAKE3-64 for
/// on-disk persistence. Collision-resilience is provided by full-name
/// verification in lookup and per-bucket entry vectors in the B+tree.
pub fn name_hash(name: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET;
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// DirIndex
// ---------------------------------------------------------------------------

/// Runtime polymorphic directory index.
#[derive(Clone, Debug)]
pub struct DirIndex {
    storage: DirStorage,
    policy: DatasetDirPolicy,
    btree: Option<DirHashTree>,
    /// Secondary name-ordered map used for bounded readdir/range scans.
    ///
    /// The primary B-tree remains keyed by name hash for lookup and collision
    /// buckets. The secondary map is keyed by full name so callers that page by
    /// name do not have to clone and sort the entire directory.
    name_btree: Option<DirNameTree>,
    directory_inode_id: u64,
    directory_version: u64,
    cursor: usize,
    /// Prefetch window for directory entry readahead, advanced on each
    /// iteration step to trigger background metadata cache priming.
    prefetch_window: DirPrefetchWindow,
    dirty: bool,
}

impl DirIndex {
    /// Create a new, empty directory index.
    #[must_use]
    pub fn new(directory_inode_id: u64, policy: DatasetDirPolicy) -> Self {
        DirIndex {
            storage: DirStorage::MicroList(DirMicroListV1 {
                directory_inode_id,
                directory_version: 0,
                entry_count: 0,
                total_name_bytes: 0,
                flags: 0,
                reserved: [0u8; 7],
                entries: Vec::new(),
            }),
            policy,
            btree: None,
            name_btree: None,
            directory_inode_id,
            directory_version: 0,
            cursor: 0,
            prefetch_window: DirPrefetchWindow::new(),
            dirty: true,
        }
    }

    #[must_use]
    pub fn representation(&self) -> DirStorageKind {
        self.storage.kind()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.storage.entry_count() as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn directory_version(&self) -> u64 {
        self.directory_version
    }

    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Return the owning directory inode id.
    #[must_use]
    pub fn directory_inode_id(&self) -> u64 {
        self.directory_inode_id
    }

    /// Verify BLAKE3-256 checksums of all B+tree nodes.
    ///
    /// Returns `Ok(())` when the directory uses the micro-list
    /// representation (no checksums to verify). When using the B-tree
    /// representation, traverses all nodes and verifies their checksums.
    ///
    /// # Errors
    ///
    /// Returns [`BTreeError::ChecksumMismatch`] when any node checksum
    /// does not match its recomputed value.
    pub fn verify_checksums(&self) -> Result<(), tidefs_btree::BTreeError> {
        if let Some(btree) = self.btree.as_ref() {
            btree.verify_checksums()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<DirMicroEntry> {
        match &self.storage {
            DirStorage::MicroList(list) => list.entries.iter().find(|e| e.name == name).cloned(),
            DirStorage::BTree(_) => {
                let tree = self
                    .btree
                    .as_ref()
                    .expect("btree must exist for BTree storage");
                let hash = name_hash(name);
                if let Some(bucket) = tree.get(&hash) {
                    for entry in bucket {
                        if entry.name == name {
                            return Some(DirMicroEntry {
                                name_len: u32::from(entry.name_len),
                                inode_id: entry.inode_id,
                                generation: entry.generation,
                                kind: entry.kind,
                                name: entry.name.clone(),
                            });
                        }
                    }
                }
                None
            }
        }
    }

    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.lookup(name).is_some()
    }

    // ------------------------------------------------------------------
    // Insert / Replace
    // ------------------------------------------------------------------

    pub fn insert(
        &mut self,
        name: &[u8],
        inode_id: u64,
        generation: u64,
        kind: u32,
    ) -> Result<(), DirIndexError> {
        if self.contains(name) {
            return Err(DirIndexError::EntryAlreadyExists);
        }
        self.insert_inner(name, inode_id, generation, kind);
        self.directory_version += 1;
        self.dirty = true;
        self.check_and_switch();
        Ok(())
    }

    /// Rename an entry from `old_name` to `new_name` within the same directory.
    ///
    /// Returns `EntryNotFound` if the source does not exist and
    /// `EntryAlreadyExists` if the target already exists.
    /// Renaming to the same name is a no-op.
    pub fn rename(&mut self, old_name: &[u8], new_name: &[u8]) -> Result<(), DirIndexError> {
        let entry = self.lookup(old_name).ok_or(DirIndexError::EntryNotFound)?;
        if old_name == new_name {
            return Ok(());
        }
        if self.contains(new_name) {
            return Err(DirIndexError::EntryAlreadyExists);
        }
        let inode_id = entry.inode_id;
        let generation = entry.generation;
        let kind = entry.kind;
        // Atomic within the same directory: delete old, insert new.
        self.delete_inner(old_name);
        self.insert_inner(new_name, inode_id, generation, kind);
        self.dirty = true;
        self.directory_version += 1;
        self.check_and_switch();
        Ok(())
    }

    /// Rename an entry within the same directory, replacing an existing target.
    ///
    /// Returns the overwritten target entry when one existed. Renaming to the
    /// same name is a no-op and does not overwrite the source entry.
    pub fn rename_overwrite(
        &mut self,
        old_name: &[u8],
        new_name: &[u8],
    ) -> Result<Option<DirEntry>, DirIndexError> {
        let entry = self.lookup(old_name).ok_or(DirIndexError::EntryNotFound)?;
        if old_name == new_name {
            return Ok(None);
        }

        let overwritten = self.lookup(new_name);
        if overwritten.is_some() {
            self.delete_inner(new_name);
        }
        self.delete_inner(old_name);
        self.dirty = true;
        self.insert_inner(new_name, entry.inode_id, entry.generation, entry.kind);
        self.directory_version += 1;
        self.check_and_switch();
        Ok(overwritten)
    }

    /// Move an entry from this directory into `dst_dir`, replacing an existing target.
    ///
    /// Returns the overwritten target entry when one existed. Call
    /// [`rename_overwrite`](Self::rename_overwrite) for same-directory moves.
    pub fn move_entry_to(
        &mut self,
        src_name: &[u8],
        dst_dir: &mut Self,
        dst_name: &[u8],
    ) -> Result<Option<DirEntry>, DirIndexError> {
        let entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
        let overwritten = dst_dir.lookup(dst_name);

        if overwritten.is_some() {
            dst_dir.delete_inner(dst_name);
        }
        self.delete_inner(src_name);
        self.dirty = true;
        dst_dir.insert_inner(dst_name, entry.inode_id, entry.generation, entry.kind);

        self.directory_version += 1;
        self.dirty = true;
        dst_dir.directory_version += 1;
        dst_dir.dirty = true;
        self.check_and_switch();
        dst_dir.check_and_switch();
        Ok(overwritten)
    }

    /// Atomically move or exchange a directory entry from `self` (source
    /// directory) into `dst_dir` (destination directory).
    ///
    /// The `mode` parameter controls overwrite and exchange semantics:
    ///
    /// - [`SwapMode::Rename`]: move the source entry to the destination slot,
    ///   replacing any existing destination entry. Returns the overwritten
    ///   entry (if any) so the caller can update the overwritten inode's
    ///   link count.
    /// - [`SwapMode::NoReplace`]: move the source entry, but fail with
    ///   [`DirIndexError::EntryAlreadyExists`] if the destination already
    ///   exists.
    /// - [`SwapMode::Exchange`]: atomically swap the two entries' inode
    ///   references. Both entries must exist (returns
    ///   [`DirIndexError::EntryNotFound`] otherwise). Names stay in their
    ///   respective directories; only inode references are swapped.
    ///
    /// This method is designed for cross-directory operations (when `self`
    /// and `dst_dir` are different directories). For same-directory renames,
    /// use [`rename`](Self::rename), [`rename_overwrite`](Self::rename_overwrite),
    /// or [`replace`](Self::replace) directly.
    ///
    /// # Errors
    ///
    /// Returns [`DirIndexError::EntryNotFound`] when the source does not
    /// exist, or when both source and destination are required (Exchange
    /// mode) and the destination is missing.
    ///
    /// Returns [`DirIndexError::EntryAlreadyExists`] in NoReplace mode when
    /// the destination already exists.
    pub fn atomic_swap(
        &mut self,
        src_name: &[u8],
        dst_dir: &mut Self,
        dst_name: &[u8],
        mode: SwapMode,
    ) -> Result<Option<DirEntry>, DirIndexError> {
        // ── Exchange mode ──────────────────────────────────────────
        if mode == SwapMode::Exchange {
            let src_entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
            let dst_entry = dst_dir
                .lookup(dst_name)
                .ok_or(DirIndexError::EntryNotFound)?;

            // Swap inode references: names stay, inode references cross.
            self.delete_inner(src_name);
            dst_dir.delete_inner(dst_name);

            self.insert_inner(
                src_name,
                dst_entry.inode_id,
                dst_entry.generation,
                dst_entry.kind,
            );
            dst_dir.insert_inner(
                dst_name,
                src_entry.inode_id,
                src_entry.generation,
                src_entry.kind,
            );

            self.directory_version += 1;
            self.dirty = true;
            dst_dir.directory_version += 1;
            dst_dir.dirty = true;
            self.check_and_switch();
            dst_dir.check_and_switch();
            return Ok(None);
        }

        // ── NoReplace mode ─────────────────────────────────────────
        if mode == SwapMode::NoReplace {
            if dst_dir.contains(dst_name) {
                return Err(DirIndexError::EntryAlreadyExists);
            }

            let entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
            self.delete_inner(src_name);
            dst_dir.insert_inner(dst_name, entry.inode_id, entry.generation, entry.kind);
            self.directory_version += 1;
            self.dirty = true;
            dst_dir.directory_version += 1;
            dst_dir.dirty = true;
            self.check_and_switch();
            dst_dir.check_and_switch();
            return Ok(None);
        }

        // ── Rename mode (default, flags=0) ─────────────────────────
        self.move_entry_to(src_name, dst_dir, dst_name)
    }

    pub fn replace(&mut self, name: &[u8], inode_id: u64, generation: u64, kind: u32) {
        self.delete_inner(name);
        self.insert_inner(name, inode_id, generation, kind);
        self.directory_version += 1;
        self.dirty = true;
        self.check_and_switch();
    }

    fn insert_inner(&mut self, name: &[u8], inode_id: u64, generation: u64, kind: u32) {
        match &mut self.storage {
            DirStorage::MicroList(list) => {
                list.entry_count += 1;
                list.total_name_bytes += name.len() as u64;
                list.entries.push(DirMicroEntry {
                    name_len: name.len() as u32,
                    inode_id,
                    generation,
                    kind,
                    name: name.to_vec(),
                });
            }
            DirStorage::BTree(root) => {
                let tree = self
                    .btree
                    .as_mut()
                    .expect("btree must exist for BTree storage");
                let name_tree = self
                    .name_btree
                    .as_mut()
                    .expect("name btree must exist for BTree storage");
                let hash = name_hash(name);
                let leaf_entry = DirBtreeLeafEntry {
                    name_hash: hash,
                    name_len: name.len() as u16,
                    inode_id,
                    generation,
                    kind,
                    flags: 0,
                    reserved: [0u8; 1],
                    name: name.to_vec(),
                };

                let exists = tree.contains_key(&hash);
                if exists {
                    tree.update(&hash, |bucket| {
                        bucket.push(leaf_entry.clone());
                    });
                } else {
                    tree.insert(hash, alloc::vec![leaf_entry.clone()]);
                }
                name_tree.insert(leaf_entry.name.clone(), leaf_entry);
                root.entry_count += 1;
                root.total_name_bytes += name.len() as u64;
            }
        }
    }

    // ------------------------------------------------------------------
    // Delete
    // ------------------------------------------------------------------

    pub fn delete(&mut self, name: &[u8]) -> Result<(), DirIndexError> {
        self.remove(name)
            .map(|_| ())
            .ok_or(DirIndexError::EntryNotFound)
    }

    pub fn remove(&mut self, name: &[u8]) -> Option<DirEntry> {
        let entry = self.lookup(name)?;
        self.delete_inner(name);
        self.directory_version += 1;
        self.dirty = true;
        self.check_and_switch();
        Some(entry)
    }

    fn delete_inner(&mut self, name: &[u8]) {
        match &mut self.storage {
            DirStorage::MicroList(list) => {
                if let Some(pos) = list.entries.iter().position(|e| e.name == name) {
                    list.total_name_bytes -= list.entries[pos].name.len() as u64;
                    list.entries.remove(pos);
                    list.entry_count -= 1;
                }
            }
            DirStorage::BTree(root) => {
                let tree = self
                    .btree
                    .as_mut()
                    .expect("btree must exist for BTree storage");
                let hash = name_hash(name);
                if let Some(bucket) = tree.get(&hash) {
                    let name_len = name.len() as u64;
                    // Must collect and re-insert since BPlusTree doesn't allow
                    // mutable access through get().
                    let mut bucket_clone: Vec<DirBtreeLeafEntry> = bucket.clone();
                    bucket_clone.retain(|e| e.name != name);
                    if bucket_clone.is_empty() {
                        tree.delete(&hash);
                    } else {
                        tree.insert(hash, bucket_clone);
                    }
                    if let Some(name_tree) = self.name_btree.as_mut() {
                        let key = name.to_vec();
                        name_tree.remove(&key);
                    }
                    root.entry_count -= 1;
                    root.total_name_bytes -= name_len;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // List (readdir)
    // ------------------------------------------------------------------

    #[must_use]
    pub fn list(&self) -> Vec<DirEntry> {
        match &self.storage {
            DirStorage::MicroList(_) => {
                let mut entries = self.unsorted_entries();
                entries.sort_by(|left, right| left.name.cmp(&right.name));
                entries
            }
            DirStorage::BTree(_) => self.btree_entries_from_sorted_index(0, usize::MAX),
        }
    }

    /// Return directory entries starting from the position encoded in
    /// `cookie`.  Returns all remaining entries and the cookie for the
    /// next page, with directory-version evidence bound into the returned
    /// cookie.
    ///
    /// `DirCookie::START` is the only unversioned cookie accepted.  Every
    /// non-zero resume cookie must carry version evidence (bit 62 set) that
    /// matches the current [`Self::directory_version`]; otherwise this returns
    /// [`DirIndexError::StaleCursor`].
    ///
    /// Pass [`DirCookie::START`] to begin from the first entry.
    pub fn list_from(
        &self,
        cookie: DirCookie,
    ) -> Result<(Vec<DirEntry>, DirCookie), DirIndexError> {
        let version = self.directory_version();
        let start = crate::format::dir_cookie_resume_skip(cookie.0, version)
            .ok_or(DirIndexError::StaleCursor)?;

        let entries = match &self.storage {
            DirStorage::MicroList(_) => {
                let entries = self.list();
                if start >= entries.len() {
                    Vec::new()
                } else {
                    entries[start..].to_vec()
                }
            }
            DirStorage::BTree(_) => self.btree_entries_from_sorted_index(start, usize::MAX),
        };
        let next_skip = start.saturating_add(entries.len());
        let next_raw = crate::format::dir_cookie_encode_versioned(next_skip as u64, version);
        Ok((entries, DirCookie(next_raw)))
    }

    /// Return up to `max_entries` directory entries in sorted name order
    /// starting after `start_name` (exclusive).
    ///
    /// Empty `start_name` means "start from the first entry." This is
    /// the standard readdir pagination contract: callers pass the last
    /// name returned by the previous call as the next `start_name`.
    ///
    /// Returns an empty vector when there are no entries after `start_name`
    /// or when the directory is empty.
    #[must_use]
    pub fn range_scan(&self, start_name: &[u8], max_entries: usize) -> Vec<DirEntry> {
        if max_entries == 0 {
            return Vec::new();
        }

        match &self.storage {
            DirStorage::MicroList(_) => {
                let entries = self.list();
                let start_idx = if start_name.is_empty() {
                    0
                } else {
                    match entries.binary_search_by(|e| e.name.as_slice().cmp(start_name)) {
                        Ok(idx) => idx + 1, // skip the exact match
                        Err(idx) => idx,    // start at insertion point (first entry > start_name)
                    }
                };
                if start_idx >= entries.len() {
                    return Vec::new();
                }
                let end = (start_idx + max_entries).min(entries.len());
                entries[start_idx..end].to_vec()
            }
            DirStorage::BTree(_) => {
                let name_tree = self
                    .name_btree
                    .as_ref()
                    .expect("name btree must exist for BTree storage");
                if start_name.is_empty() {
                    name_tree
                        .values()
                        .take(max_entries)
                        .map(dir_entry_from_btree_leaf)
                        .collect()
                } else {
                    name_tree
                        .range((
                            core::ops::Bound::Excluded(start_name.to_vec()),
                            core::ops::Bound::Unbounded,
                        ))
                        .take(max_entries)
                        .map(|(_, entry)| dir_entry_from_btree_leaf(entry))
                        .collect()
                }
            }
        }
    }

    fn btree_entries_from_sorted_index(&self, start: usize, max_entries: usize) -> Vec<DirEntry> {
        if max_entries == 0 {
            return Vec::new();
        }
        let name_tree = self
            .name_btree
            .as_ref()
            .expect("name btree must exist for BTree storage");
        name_tree
            .values()
            .skip(start)
            .take(max_entries)
            .map(dir_entry_from_btree_leaf)
            .collect()
    }

    pub(crate) fn entries_from_sorted_index(
        &self,
        start: usize,
        max_entries: usize,
    ) -> Vec<DirEntry> {
        if max_entries == 0 {
            return Vec::new();
        }
        match &self.storage {
            DirStorage::MicroList(_) => {
                let entries = self.list();
                if start >= entries.len() {
                    return Vec::new();
                }
                let end = start.saturating_add(max_entries).min(entries.len());
                entries[start..end].to_vec()
            }
            DirStorage::BTree(_) => self.btree_entries_from_sorted_index(start, max_entries),
        }
    }

    fn unsorted_entries(&self) -> Vec<DirEntry> {
        match &self.storage {
            DirStorage::MicroList(list) => list.entries.clone(),
            DirStorage::BTree(_) => {
                let tree = self
                    .btree
                    .as_ref()
                    .expect("btree must exist for BTree storage");
                let mut entries: Vec<DirEntry> = Vec::new();
                for (_hash, bucket) in tree.entries() {
                    for entry in &bucket {
                        entries.push(DirEntry {
                            name_len: u32::from(entry.name_len),
                            inode_id: entry.inode_id,
                            generation: entry.generation,
                            kind: entry.kind,
                            name: entry.name.clone(),
                        });
                    }
                }
                entries
            }
        }
    }

    // ------------------------------------------------------------------
    // Hysteresis switching
    // ------------------------------------------------------------------

    pub fn check_and_switch(&mut self) {
        let cnt = self.storage.entry_count();
        let nbytes = self.storage.total_name_bytes();
        match &self.storage {
            DirStorage::MicroList(_) => {
                if self.policy.should_use_btree(cnt, nbytes) {
                    self.promote_to_btree();
                }
            }
            DirStorage::BTree(_) => {
                if self.policy.should_use_micro_from_btree(cnt, nbytes) {
                    self.demote_to_micro();
                }
            }
        }
    }

    fn promote_to_btree(&mut self) {
        let list = match &self.storage {
            DirStorage::MicroList(l) => l,
            _ => return,
        };
        let mut tree: DirHashTree = BPlusTree::new();
        let mut name_tree: DirNameTree = BTreeMap::new();
        let mut cnt: u64 = 0;
        let mut nbytes: u64 = 0;
        for e in &list.entries {
            let h = name_hash(&e.name);
            let leaf = DirBtreeLeafEntry {
                name_hash: h,
                name_len: u16::try_from(e.name_len).unwrap_or(u16::MAX),
                inode_id: e.inode_id,
                generation: e.generation,
                kind: e.kind,
                flags: 0,
                reserved: [0u8; 1],
                name: e.name.clone(),
            };
            nbytes += e.name.len() as u64;
            cnt += 1;
            if tree.contains_key(&h) {
                tree.update(&h, |b| b.push(leaf.clone()));
            } else {
                tree.insert(h, alloc::vec![leaf.clone()]);
            }
            name_tree.insert(e.name.clone(), leaf);
        }
        let mut root = DirBtreeRuntimeState::new(self.directory_inode_id, self.directory_version);
        root.entry_count = cnt;
        root.total_name_bytes = nbytes;
        root.depth = tree.depth();
        root.flags = list.flags & 0x01;
        self.storage = DirStorage::BTree(root);
        self.btree = Some(tree);
        self.name_btree = Some(name_tree);
    }

    fn demote_to_micro(&mut self) {
        let tree = match &self.btree {
            Some(t) => t,
            None => return,
        };
        let mut entries: Vec<DirMicroEntry> = Vec::new();
        let mut cnt: u64 = 0;
        let mut nbytes: u64 = 0;
        let has_subdirs = match &self.storage {
            DirStorage::BTree(r) => r.has_subdirs(),
            _ => false,
        };
        for (_h, bucket) in tree.entries() {
            for e in &bucket {
                entries.push(DirMicroEntry {
                    name_len: u32::from(e.name_len),
                    inode_id: e.inode_id,
                    generation: e.generation,
                    kind: e.kind,
                    name: e.name.clone(),
                });
                nbytes += e.name.len() as u64;
                cnt += 1;
            }
        }
        let flags: u8 = if has_subdirs { 0x01 } else { 0 };
        self.storage = DirStorage::MicroList(DirMicroListV1 {
            directory_inode_id: self.directory_inode_id,
            directory_version: self.directory_version,
            entry_count: cnt,
            total_name_bytes: nbytes,
            flags,
            reserved: [0u8; 7],
            entries,
        });
        self.btree = None;
        self.name_btree = None;
    }

    // ------------------------------------------------------------------
    // Subdirectory tracking
    // ------------------------------------------------------------------

    #[must_use]
    pub fn has_subdirs(&self) -> bool {
        match &self.storage {
            DirStorage::MicroList(l) => l.has_subdirs(),
            DirStorage::BTree(r) => r.has_subdirs(),
        }
    }

    pub fn set_has_subdirs(&mut self, v: bool) {
        let changed = self.has_subdirs() != v;
        match &mut self.storage {
            DirStorage::MicroList(l) => l.set_has_subdirs(v),
            DirStorage::BTree(r) => {
                if v {
                    r.flags |= 0x01;
                } else {
                    r.flags &= !0x01;
                }
            }
        }
        if changed {
            self.dirty = true;
        }
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    #[must_use]
    pub fn policy(&self) -> DatasetDirPolicy {
        self.policy
    }

    #[must_use]
    pub fn storage(&self) -> &DirStorage {
        &self.storage
    }

    /// Return a reference to the prefetch window.
    ///
    /// The window is advanced in lock-step with the cursor during
    /// [`DirIterator::next_entry`] calls.
    /// Callers use [`DirPrefetchWindow::should_prefetch`] to decide
    /// when to issue background cache priming.
    #[must_use]
    pub fn prefetch_window(&self) -> &DirPrefetchWindow {
        &self.prefetch_window
    }
}

// ===========================================================================
// Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

impl DirIndex {
    /// Serialize the directory index to a byte vector.
    ///
    /// Entries are written in sorted name order.
    ///
    /// Format:
    /// - 8 bytes: directory_inode_id (u64 LE)
    /// - 8 bytes: directory_version (u64 LE)
    /// - 8 bytes: flags (u64 LE) — bit 0: has_subdirs
    /// - 8 bytes: entry_count (u64 LE)
    /// - entries, each:
    ///   - 4 bytes: name_len (u32 LE)
    ///   - name_len bytes: name
    ///   - 8 bytes: inode_id (u64 LE)
    ///   - 8 bytes: generation (u64 LE)
    ///   - 4 bytes: kind (u32 LE)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let entries = self.list(); // sorted by name
        let mut buf = Vec::with_capacity(32 + entries.len() * 256);
        buf.extend_from_slice(&self.directory_inode_id.to_le_bytes());
        buf.extend_from_slice(&self.directory_version.to_le_bytes());
        let flags: u64 = if self.has_subdirs() { 1 } else { 0 };
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for e in &entries {
            buf.extend_from_slice(&(e.name_len).to_le_bytes());
            buf.extend_from_slice(&e.name);
            buf.extend_from_slice(&e.inode_id.to_le_bytes());
            buf.extend_from_slice(&e.generation.to_le_bytes());
            buf.extend_from_slice(&e.kind.to_le_bytes());
        }
        buf
    }

    /// Deserialize a directory index from bytes produced by
    /// [`to_bytes`](Self::to_bytes).
    ///
    /// Returns `None` if the buffer is too short or contains an
    /// inconsistent entry count.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], policy: DatasetDirPolicy) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let mut arr8 = [0u8; 8];
        arr8.copy_from_slice(&bytes[0..8]);
        let directory_inode_id = u64::from_le_bytes(arr8);
        arr8.copy_from_slice(&bytes[8..16]);
        let directory_version = u64::from_le_bytes(arr8);
        arr8.copy_from_slice(&bytes[16..24]);
        let flags = u64::from_le_bytes(arr8);
        arr8.copy_from_slice(&bytes[24..32]);
        let entry_count = u64::from_le_bytes(arr8) as usize;

        let mut idx = Self::new(directory_inode_id, policy);
        idx.directory_version = directory_version;
        idx.set_has_subdirs(flags & 1 != 0);
        idx.dirty = false;

        let mut offset: usize = 32;
        for _ in 0..entry_count {
            if offset + 4 > bytes.len() {
                return None;
            }
            let mut arr4 = [0u8; 4];
            arr4.copy_from_slice(&bytes[offset..offset + 4]);
            let name_len = u32::from_le_bytes(arr4) as usize;
            offset += 4;
            if offset + name_len + 20 > bytes.len() {
                return None;
            }
            let name = bytes[offset..offset + name_len].to_vec();
            offset += name_len;
            arr8.copy_from_slice(&bytes[offset..offset + 8]);
            let inode_id = u64::from_le_bytes(arr8);
            offset += 8;
            arr8.copy_from_slice(&bytes[offset..offset + 8]);
            let generation = u64::from_le_bytes(arr8);
            offset += 8;
            arr4.copy_from_slice(&bytes[offset..offset + 4]);
            let kind = u32::from_le_bytes(arr4);
            offset += 4;
            idx.insert_inner(&name, inode_id, generation, kind);
        }

        idx.check_and_switch();
        idx.dirty = false;
        Some(idx)
    }
}

// ---------------------------------------------------------------------------
// DirIterator impl for DirIndex
// ---------------------------------------------------------------------------

impl DirIterator for DirIndex {
    type Error = DirIndexError;

    fn next_entry(&mut self) -> Option<DirEntry> {
        let total = self.len();
        // Sync the prefetch window with the current directory size when
        // it differs (including the first call where the window defaults
        // to 0 entries). For an empty directory this sets exhausted=true.
        if self.prefetch_window.total_entries() != total || self.cursor == 0 {
            self.prefetch_window.set_total_entries(total);
            self.prefetch_window.seek_to(self.cursor);
        }
        if self.cursor >= total {
            return None;
        }
        let entry = match &self.storage {
            DirStorage::MicroList(_) => {
                let entries = self.list();
                if self.cursor >= entries.len() {
                    return None;
                }
                entries[self.cursor].clone()
            }
            DirStorage::BTree(_) => self
                .btree_entries_from_sorted_index(self.cursor, 1)
                .into_iter()
                .next()?,
        };
        self.cursor += 1;
        // Advance the prefetch window in lock-step with the cursor.
        self.prefetch_window.advance();
        Some(entry)
    }

    fn reset_cursor(&mut self) {
        self.cursor = 0;
        self.prefetch_window.reset();
    }

    fn seek_to_cursor(&mut self, cookie: DirCookie) {
        let total = self.len();
        self.cursor = index_from_cookie(cookie, total);
        self.prefetch_window.set_total_entries(total);
        self.prefetch_window.seek_to(self.cursor);
    }

    fn current_cursor(&self) -> DirCookie {
        let is_btree = matches!(self.storage, DirStorage::BTree(_));
        cookie_from_index(self.cursor, is_btree)
    }
}

// ---------------------------------------------------------------------------
// DirIndexIter — standalone cursor yielding entries with offset cookies
// ---------------------------------------------------------------------------

/// Cursor that iterates directory entries in hash-bucket (storage-native)
/// order, yielding a `(DirEntry, DirCookie)` pair per entry.
///
/// The offset cookie is stable within a representation and monotonically
/// increasing, allowing FUSE `readdir` to resume from a previous cookie.
/// When the directory representation is a micro-list, entries are yielded
/// in insertion order with micro-list cookies.  When it is a B-tree, entries
/// are yielded in hash-bucket traversal order with B-tree cookies.
#[derive(Clone, Debug)]
pub struct DirIndexIter {
    entries: Vec<(DirEntry, DirCookie)>,
    position: usize,
}

impl DirIndexIter {
    /// Create an iterator over all entries in `idx`.
    ///
    /// Entries are collected in hash-bucket order for B-tree or insertion
    /// order for micro-list, and assigned a monotonic [`DirCookie`] at
    /// collection time.  The resulting iterator is a snapshot and does not
    /// see subsequent mutations.
    #[must_use]
    pub fn new(idx: &DirIndex) -> Self {
        let mut entries: Vec<(DirEntry, DirCookie)> = Vec::new();

        match &idx.storage {
            DirStorage::MicroList(list) => {
                for (i, entry) in list.entries.iter().enumerate() {
                    let cookie = DirCookie(DirCookie::encode_micro(i as u32));
                    entries.push((entry.clone(), cookie));
                }
            }
            DirStorage::BTree(_) => {
                let tree = idx
                    .btree
                    .as_ref()
                    .expect("btree must exist for BTree storage");
                let mut page: u16 = 0;
                let mut entry_in_page: u16 = 0;
                for (_hash, bucket) in tree.entries() {
                    for bt_entry in bucket {
                        let cookie = DirCookie(DirCookie::encode_btree(page, entry_in_page));
                        entries.push((
                            DirEntry {
                                name_len: u32::from(bt_entry.name_len),
                                inode_id: bt_entry.inode_id,
                                generation: bt_entry.generation,
                                kind: bt_entry.kind,
                                name: bt_entry.name.clone(),
                            },
                            cookie,
                        ));
                        entry_in_page = entry_in_page.saturating_add(1);
                        if entry_in_page == 128 {
                            entry_in_page = 0;
                            page = page.saturating_add(1);
                        }
                    }
                }
            }
        }

        DirIndexIter {
            entries,
            position: 0,
        }
    }

    /// Number of entries remaining in the iterator.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len().saturating_sub(self.position)
    }

    /// Whether the iterator is exhausted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.position >= self.entries.len()
    }

    #[allow(clippy::should_implement_trait)]
    /// Advance and return the next `(entry, cookie)` pair, or `None` when
    /// exhausted.
    pub fn next(&mut self) -> Option<(DirEntry, DirCookie)> {
        if self.position >= self.entries.len() {
            return None;
        }
        let pair = self.entries[self.position].clone();
        self.position += 1;
        Some(pair)
    }

    /// Reset to the beginning of the directory.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Seek to the position immediately after `cookie`.
    ///
    /// The next call to [`next`](Self::next) returns the entry following
    /// the one identified by `cookie`.  Seeking to [`DirCookie::START`]
    /// is equivalent to [`reset`](Self::reset).
    pub fn seek_to(&mut self, cookie: DirCookie) {
        if cookie.0 == 0 {
            self.position = 0;
            return;
        }
        // Find the first entry whose cookie is strictly greater than the
        // seek target.  Since cookies are monotonic within the snapshot,
        // a linear scan is amortised O(n).
        let start = self.position.min(self.entries.len());
        for i in start..self.entries.len() {
            if self.entries[i].1 .0 > cookie.0 {
                self.position = i;
                return;
            }
        }
        self.position = self.entries.len(); // cookie past end -> exhausted
    }

    /// Return the current cursor cookie, or [`DirCookie::START`] if
    /// at the beginning.
    #[must_use]
    pub fn current_cookie(&self) -> DirCookie {
        if self.position == 0 {
            DirCookie::START
        } else if self.position > self.entries.len() {
            self.entries
                .last()
                .map(|(_, c)| *c)
                .unwrap_or(DirCookie::START)
        } else {
            self.entries[self.position - 1].1
        }
    }
}
// ---------------------------------------------------------------------------
// DirPrefetchWindow — directory entry prefetch window with boundary detection
// ---------------------------------------------------------------------------

/// Default number of entries in the lookahead window.
pub const DEFAULT_PREFETCH_WINDOW_SIZE: usize = 64;

/// Fraction of the window that must be consumed before the next prefetch
/// is triggered (represented as numerator/denominator).
const PREFETCH_TRIGGER_NUMERATOR: usize = 3;
const PREFETCH_TRIGGER_DENOMINATOR: usize = 4; // trigger at 75% consumption

/// A bounded lookahead window for directory entry prefetch.
///
/// Maintains a sliding window over directory entries, tracked by the
/// current cursor position. When the cursor consumes 75% of the current
/// window, [`should_prefetch`](Self::should_prefetch) returns `true`,
/// signalling that the next window of entries should be fetched and
/// primed into caches.
///
/// The caller drives the window by calling [`advance`](Self::advance) as
/// entries are consumed and [`prefetch_acknowledged`](Self::prefetch_acknowledged)
/// after a prefetch completes.
///
/// # Example
///
/// ```ignore
/// let mut window = DirPrefetchWindow::new();
/// window.set_total_entries(200);
/// for _ in 0..200 {
///     if window.should_prefetch() {
///         let (start, end) = window.next_window_range().unwrap();
///         // issue prefetch for entries[start..end]
///         window.prefetch_acknowledged();
///     }
///     window.advance();
/// }
/// ```
#[derive(Clone, Debug)]
pub struct DirPrefetchWindow {
    /// Maximum number of entries in the lookahead window.
    window_size: usize,
    /// Current cursor position (0-based index into the sorted entry list).
    cursor: usize,
    /// Total number of entries in the directory.
    total_entries: usize,
    /// Whether a prefetch has been triggered for the window beyond the
    /// current one.
    prefetch_triggered: bool,
    /// Whether the cursor has reached the end of the directory.
    exhausted: bool,
}

impl DirPrefetchWindow {
    /// Create a new prefetch window with the default window size (64
    /// entries).
    #[must_use]
    pub fn new() -> Self {
        DirPrefetchWindow {
            window_size: DEFAULT_PREFETCH_WINDOW_SIZE,
            cursor: 0,
            total_entries: 0,
            prefetch_triggered: false,
            exhausted: false,
        }
    }

    /// Create a prefetch window with a specific window size.
    ///
    /// The window size is clamped to a minimum of 1 entry.
    #[must_use]
    pub fn with_window_size(window_size: usize) -> Self {
        DirPrefetchWindow {
            window_size: window_size.max(1),
            cursor: 0,
            total_entries: 0,
            prefetch_triggered: false,
            exhausted: false,
        }
    }

    /// Set the total number of entries in the directory.
    ///
    /// Call this when the directory is opened or when the total entry
    /// count is known. Resets cursor and trigger state.
    pub fn set_total_entries(&mut self, total: usize) {
        self.total_entries = total;
        self.cursor = 0;
        self.prefetch_triggered = false;
        self.exhausted = total == 0;
    }

    /// Advance the cursor by one position.
    ///
    /// Returns `true` if the cursor advanced successfully (was not at
    /// the end of the directory).
    pub fn advance(&mut self) -> bool {
        if self.exhausted || self.cursor >= self.total_entries {
            self.exhausted = true;
            return false;
        }
        let old_window_start = self.window_start();
        self.cursor += 1;
        if self.cursor >= self.total_entries {
            self.exhausted = true;
        }
        // When the cursor crosses into a new window, reset the trigger
        // flag so the next window's prefetch boundary can fire.
        if self.window_start() != old_window_start {
            self.prefetch_triggered = false;
        }
        true
    }

    /// Whether a prefetch should be initiated for the next window.
    ///
    /// Returns `true` when the cursor has consumed at least 75% of the
    /// current window, the next window has not yet been triggered, and
    /// the cursor is not in the last window.
    ///
    /// For directories smaller than the window size, all entries fit in
    /// one window and this always returns `false`.
    #[must_use]
    pub fn should_prefetch(&self) -> bool {
        if self.prefetch_triggered || self.exhausted {
            return false;
        }
        // Small directory: all entries fit in one window, no prefetch
        // needed.
        if self.total_entries <= self.window_size {
            return false;
        }
        // Compute how far the cursor has advanced within the current
        // window.
        let window_start = self.window_start();
        let consumed_in_window = self.cursor.saturating_sub(window_start);
        let trigger_at =
            self.window_size * PREFETCH_TRIGGER_NUMERATOR / PREFETCH_TRIGGER_DENOMINATOR;
        // Trigger at 75% consumption, but only when not in the last
        // window.
        consumed_in_window >= trigger_at && !self.is_in_last_window()
    }

    /// Acknowledge that the prefetch for the next window has been
    /// issued.
    ///
    /// After calling this, [`should_prefetch`](Self::should_prefetch)
    /// returns `false` until the cursor enters the next window's
    /// trigger zone.
    pub fn prefetch_acknowledged(&mut self) {
        self.prefetch_triggered = true;
    }

    /// Reset the cursor to the beginning of the directory.
    ///
    /// Clears the trigger flag; the next advance into the 75% zone
    /// will re-trigger.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.prefetch_triggered = false;
        self.exhausted = self.total_entries == 0;
    }

    /// Seek the cursor to a specific position.
    ///
    /// Clamps to `[0, total_entries]`. Resets the trigger flag so the
    /// window state machine re-evaluates from the new position.
    pub fn seek_to(&mut self, position: usize) {
        if position >= self.total_entries {
            self.cursor = self.total_entries;
            self.exhausted = true;
        } else {
            self.cursor = position;
            self.exhausted = false;
        }
        self.prefetch_triggered = false;
    }

    // --- Accessors ---

    /// Whether the cursor has reached the end of the directory.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Number of entries remaining from the cursor to the end.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.total_entries.saturating_sub(self.cursor)
    }

    /// Current cursor position (0-based).
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Total entries in the directory.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }

    /// Window size.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Start index of the current window (inclusive).
    #[must_use]
    pub fn window_start(&self) -> usize {
        if self.total_entries == 0 {
            return 0;
        }
        (self.cursor / self.window_size) * self.window_size
    }

    /// End index of the current window (exclusive).
    #[must_use]
    pub fn window_end(&self) -> usize {
        let start = self.window_start();
        (start + self.window_size).min(self.total_entries)
    }

    /// Whether the cursor is in the last window of the directory.
    #[must_use]
    pub fn is_in_last_window(&self) -> bool {
        if self.total_entries == 0 {
            return true;
        }
        self.window_end() >= self.total_entries
    }

    /// Start index of the next window (for prefetch), or `None` if in
    /// the last window.
    #[must_use]
    pub fn next_window_start(&self) -> Option<usize> {
        if self.is_in_last_window() {
            None
        } else {
            Some(self.window_end())
        }
    }

    /// Range of entries in the next window `(start_inclusive,
    /// end_exclusive)`, or `None` if in the last window.
    #[must_use]
    pub fn next_window_range(&self) -> Option<(usize, usize)> {
        let start = self.next_window_start()?;
        let end = (start + self.window_size).min(self.total_entries);
        Some((start, end))
    }
}

impl Default for DirPrefetchWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Persistence (std — uses tidefs-local-object-store)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
impl DirIndex {
    /// Flush the directory index to an object store.
    ///
    /// Serializes and writes via
    /// [`LocalObjectStore::put_named`] with a deterministic key
    /// derived from the directory inode id. Sets `dirty` to `false`
    /// on success.
    ///
    /// [`LocalObjectStore::put_named`]:
    ///     tidefs_local_object_store::LocalObjectStore::put_named
    pub fn flush(
        &mut self,
        store: &mut tidefs_local_object_store::LocalObjectStore,
    ) -> tidefs_local_object_store::Result<()> {
        let name = alloc::format!("dir:{}", self.directory_inode_id);
        let payload = self.to_bytes();
        store.put_named(name, &payload)?;
        self.dirty = false;
        Ok(())
    }

    /// Load a directory index from an object store.
    ///
    /// Looks up the deterministic key derived from `dir_inode_id`
    /// and deserializes the payload via [`from_bytes`](Self::from_bytes).
    /// Returns `Ok(None)` when no stored directory exists for this inode.
    pub fn load(
        store: &tidefs_local_object_store::LocalObjectStore,
        dir_inode_id: u64,
        policy: DatasetDirPolicy,
    ) -> tidefs_local_object_store::Result<Option<Self>> {
        let name = alloc::format!("dir:{dir_inode_id}");
        let key = tidefs_local_object_store::ObjectKey::from_name(name);
        match store.get(key)? {
            Some(payload) => Ok(Self::from_bytes(&payload, policy)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
impl DirIndex {
    /// Force-insert an entry with a caller-specified hash value into the
    /// B+tree representation (promotes from micro-list first if needed).
    /// This exists only to test hash-collision bucket behaviour when no
    /// natural FNV-1a collisions are available for short names.
    fn insert_with_forced_hash(
        &mut self,
        name: &[u8],
        forced_hash: u64,
        inode_id: u64,
        generation: u64,
        kind: u32,
    ) {
        // Ensure we are in BTree representation
        match &self.storage {
            DirStorage::MicroList(_) => {
                self.promote_to_btree();
            }
            DirStorage::BTree(_) => {}
        }

        let tree = self
            .btree
            .as_mut()
            .expect("btree must exist after promotion");
        let name_tree = self
            .name_btree
            .as_mut()
            .expect("name btree must exist after promotion");

        let leaf_entry = DirBtreeLeafEntry {
            name_hash: forced_hash,
            name_len: name.len() as u16,
            inode_id,
            generation,
            kind,
            flags: 0,
            reserved: [0u8; 1],
            name: name.to_vec(),
        };

        let root = match &mut self.storage {
            DirStorage::BTree(r) => r,
            _ => unreachable!(),
        };

        if tree.contains_key(&forced_hash) {
            tree.update(&forced_hash, |bucket| {
                bucket.push(leaf_entry.clone());
            });
        } else {
            tree.insert(forced_hash, alloc::vec![leaf_entry.clone()]);
        }
        name_tree.insert(leaf_entry.name.clone(), leaf_entry);
        root.entry_count += 1;
        root.total_name_bytes += name.len() as u64;
        self.directory_version += 1;
        self.dirty = true;
    }

    /// Look up an entry by forced hash (bypasses `name_hash`). Only
    /// works when the index is in BTree representation and the entry
    /// was inserted via [`insert_with_forced_hash`](Self::insert_with_forced_hash).
    fn lookup_by_hash(&self, forced_hash: u64, name: &[u8]) -> Option<DirMicroEntry> {
        let tree = self.btree.as_ref()?;
        let bucket = tree.get(&forced_hash)?;
        for entry in bucket {
            if entry.name == name {
                return Some(DirMicroEntry {
                    name_len: u32::from(entry.name_len),
                    inode_id: entry.inode_id,
                    generation: entry.generation,
                    kind: entry.kind,
                    name: entry.name.clone(),
                });
            }
        }
        None
    }

    /// Delete an entry by forced hash (bypasses `name_hash`). Only
    /// works when the index is in BTree representation and the entry
    /// was inserted via [`insert_with_forced_hash`](Self::insert_with_forced_hash).
    fn delete_by_hash(&mut self, forced_hash: u64, name: &[u8]) -> Result<(), DirIndexError> {
        if self.lookup_by_hash(forced_hash, name).is_none() {
            return Err(DirIndexError::EntryNotFound);
        }
        // Manually remove from the B+tree bucket and update root metadata
        let tree = self.btree.as_mut().expect("btree must exist");
        if let Some(bucket) = tree.get(&forced_hash) {
            let mut bucket_clone: Vec<DirBtreeLeafEntry> = bucket.clone();
            bucket_clone.retain(|e| e.name != name);
            if bucket_clone.is_empty() {
                tree.delete(&forced_hash);
            } else {
                tree.insert(forced_hash, bucket_clone);
            }
        }
        if let Some(name_tree) = self.name_btree.as_mut() {
            let key = name.to_vec();
            name_tree.remove(&key);
        }
        let root = match &mut self.storage {
            DirStorage::BTree(r) => r,
            _ => return Err(DirIndexError::EntryNotFound),
        };
        root.entry_count -= 1;
        root.total_name_bytes -= name.len() as u64;
        self.directory_version += 1;
        self.dirty = true;
        Ok(())
    }

    /// Read-only accessor for the B+tree's entry count (number of hash buckets).
    fn btree_bucket_count(&self) -> usize {
        self.btree.as_ref().map_or(0, |t| t.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // DirIterator trait unit tests
    // ------------------------------------------------------------------

    /// In-memory [`DirIterator`] implementation backed by a sorted `Vec`.
    struct InMemoryDirIterator {
        entries: Vec<DirEntry>,
        cursor: usize,
    }

    impl InMemoryDirIterator {
        fn new(mut entries: Vec<DirEntry>) -> Self {
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            InMemoryDirIterator { entries, cursor: 0 }
        }
    }

    impl DirIterator for InMemoryDirIterator {
        type Error = &'static str;

        fn next_entry(&mut self) -> Option<DirEntry> {
            if self.cursor >= self.entries.len() {
                return None;
            }
            let entry = self.entries[self.cursor].clone();
            self.cursor += 1;
            Some(entry)
        }

        fn reset_cursor(&mut self) {
            self.cursor = 0;
        }

        fn seek_to_cursor(&mut self, cookie: DirCookie) {
            self.cursor = index_from_cookie(cookie, self.entries.len());
        }

        fn current_cursor(&self) -> DirCookie {
            cookie_from_index(self.cursor, false)
        }
    }

    #[test]
    fn dir_iterator_empty_yields_none() {
        let mut iter = InMemoryDirIterator::new(Vec::new());
        assert!(iter.next_entry().is_none());
        assert_eq!(iter.current_cursor(), DirCookie::START);
    }

    #[test]
    fn dir_iterator_stable_order_iteration() {
        let entries = alloc::vec![
            DirMicroEntry {
                name_len: 5,
                inode_id: 2,
                generation: 0,
                kind: 0,
                name: b"delta".to_vec()
            },
            DirMicroEntry {
                name_len: 5,
                inode_id: 1,
                generation: 0,
                kind: 0,
                name: b"alpha".to_vec()
            },
            DirMicroEntry {
                name_len: 7,
                inode_id: 3,
                generation: 0,
                kind: 0,
                name: b"charlie".to_vec()
            },
            DirMicroEntry {
                name_len: 4,
                inode_id: 4,
                generation: 0,
                kind: 0,
                name: b"beta".to_vec()
            },
        ];
        let mut iter = InMemoryDirIterator::new(entries);

        // Entries must yield in sorted order: alpha, beta, charlie, delta
        let e1 = iter.next_entry().unwrap();
        assert_eq!(e1.name, b"alpha");
        assert_eq!(e1.inode_id, 1);

        let e2 = iter.next_entry().unwrap();
        assert_eq!(e2.name, b"beta");

        let e3 = iter.next_entry().unwrap();
        assert_eq!(e3.name, b"charlie");

        let e4 = iter.next_entry().unwrap();
        assert_eq!(e4.name, b"delta");

        assert!(iter.next_entry().is_none());

        // Reset and confirm same stable order
        iter.reset_cursor();
        let e1b = iter.next_entry().unwrap();
        assert_eq!(e1b.name, b"alpha");
        assert_eq!(e1b.inode_id, 1);
    }
    // ------------------------------------------------------------------
    // DirIterator tests on DirIndex itself
    // ------------------------------------------------------------------

    #[test]
    fn dirindex_iter_empty_returns_none() {
        let mut idx = DirIndex::new(1, test_policy());
        assert!(idx.next_entry().is_none());
        assert_eq!(idx.current_cursor(), DirCookie::START);
    }

    #[test]
    fn dirindex_iter_single_entry_micro() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"hello", 42, 1, 0).unwrap();

        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, b"hello");
        assert_eq!(e.inode_id, 42);
        assert_eq!(e.generation, 1);
        assert_eq!(e.kind, 0);

        // After yielding the single entry, cursor should be at 1.
        let cookie = idx.current_cursor();
        assert!(cookie.is_micro());
        assert_eq!(cookie.as_micro_entry_index(), Some(1));
        assert!(idx.next_entry().is_none());
    }

    #[test]
    fn dirindex_iter_multi_micro_stable_sorted_order() {
        let mut idx = DirIndex::new(1, test_policy());
        // Insert in unsorted order.
        idx.insert(b"zulu", 26, 0, 0).unwrap();
        idx.insert(b"alpha", 1, 0, 0).unwrap();
        idx.insert(b"mike", 13, 0, 0).unwrap();
        idx.insert(b"beta", 2, 0, 0).unwrap();

        // Iteration must yield in name-sorted order.
        let e1 = idx.next_entry().unwrap();
        assert_eq!(e1.name, b"alpha");
        assert_eq!(e1.inode_id, 1);
        let c1 = idx.current_cursor();
        assert!(c1.is_micro());
        assert_eq!(c1.as_micro_entry_index(), Some(1));

        let e2 = idx.next_entry().unwrap();
        assert_eq!(e2.name, b"beta");
        let c2 = idx.current_cursor();
        assert_eq!(c2.as_micro_entry_index(), Some(2));

        let e3 = idx.next_entry().unwrap();
        assert_eq!(e3.name, b"mike");
        let c3 = idx.current_cursor();
        assert_eq!(c3.as_micro_entry_index(), Some(3));

        let e4 = idx.next_entry().unwrap();
        assert_eq!(e4.name, b"zulu");
        let c4 = idx.current_cursor();
        assert_eq!(c4.as_micro_entry_index(), Some(4));

        assert!(idx.next_entry().is_none());
        // Cursor stays at last position.
        assert_eq!(idx.current_cursor(), c4);
    }

    #[test]
    fn dirindex_iter_seek_to_middle_and_resume() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..5u64 {
            let name = alloc::format!("entry_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 0).unwrap();
        }

        // Seek to cookie at position 3 (after entry_02).
        let seek_cookie = DirCookie(DirCookie::encode_micro(3));
        idx.seek_to_cursor(seek_cookie);

        // Next entry should be entry_03.
        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, b"entry_03");
        assert_eq!(idx.current_cursor().as_micro_entry_index(), Some(4));

        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, b"entry_04");
    }
    #[test]
    fn dirindex_iter_seek_to_zero_restarts() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 0).unwrap();
        idx.insert(b"beta", 2, 0, 0).unwrap();

        // Consume all entries.
        assert!(idx.next_entry().is_some());
        assert!(idx.next_entry().is_some());
        assert!(idx.next_entry().is_none());

        // Seek to START resets.
        idx.seek_to_cursor(DirCookie::START);
        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, b"alpha");
    }

    #[test]
    fn dirindex_iter_seek_past_end_returns_none() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"only", 1, 0, 0).unwrap();

        // Seek past the only entry.
        let past_end = DirCookie(DirCookie::encode_micro(5));
        idx.seek_to_cursor(past_end);
        assert!(idx.next_entry().is_none());
    }

    #[test]
    fn dirindex_iter_reset_restarts() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 0).unwrap();
        idx.insert(b"b", 2, 0, 0).unwrap();

        assert!(idx.next_entry().is_some());
        assert!(idx.next_entry().is_some());
        assert!(idx.next_entry().is_none());

        idx.reset_cursor();
        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, b"a");
    }

    #[test]
    fn dirindex_iter_offset_cookies_monotonic() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..5u64 {
            let name = alloc::format!("f{i}");
            idx.insert(name.as_bytes(), i, 0, 0).unwrap();
        }

        let mut cookies: Vec<u64> = Vec::new();
        while let Some(_entry) = idx.next_entry() {
            cookies.push(idx.current_cursor().0);
        }

        // Cookies must be strictly increasing.
        for w in cookies.windows(2) {
            assert!(
                w[0] < w[1],
                "cookies must be monotonic: {} >= {}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn dirindex_iter_offset_cookies_stable_across_reset() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"x", 10, 0, 0).unwrap();
        idx.insert(b"y", 20, 0, 0).unwrap();

        let e1 = idx.next_entry().unwrap();
        let c1_first = idx.current_cursor();
        let e2 = idx.next_entry().unwrap();
        let c2_first = idx.current_cursor();

        idx.reset_cursor();
        let _ = idx.next_entry().unwrap();
        let c1_second = idx.current_cursor();
        let _ = idx.next_entry().unwrap();
        let c2_second = idx.current_cursor();

        assert_eq!(c1_first, c1_second);
        assert_eq!(c2_first, c2_second);
        assert_eq!(e1.name, b"x");
        assert_eq!(e2.name, b"y");
    }

    #[test]
    fn dirindex_iter_btree_emits_btree_cookies() {
        let mut idx = DirIndex::new(1, test_policy());
        // Promote to B-tree by inserting >6 entries.
        for i in 0..7u64 {
            let name = alloc::format!("btree_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        let _e = idx.next_entry().unwrap();
        let cookie = idx.current_cursor();
        assert!(
            cookie.is_btree(),
            "B-tree dir must emit B-tree cookies, got {cookie:?}"
        );
        // The cookie should be decodable as (page, entry).
        let (page, _entry) = cookie.as_btree_indices().unwrap();
        // First entry should be page 0.
        assert_eq!(page, 0);
    }

    #[test]
    fn dirindex_iter_btree_seek_and_resume() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..7u64 {
            let name = alloc::format!("bt_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        // Collect all names and cookies from a full iteration.
        let mut all: Vec<(Vec<u8>, DirCookie)> = Vec::new();
        idx.reset_cursor();
        while let Some(e) = idx.next_entry() {
            all.push((e.name.clone(), idx.current_cursor()));
        }
        assert_eq!(all.len(), 7);

        // Seek to the cookie of the third entry and resume.
        let seek_target = all[2].1;
        idx.seek_to_cursor(seek_target);
        let resumed = idx.next_entry().unwrap();
        // resumed should be the entry after seek_target (i.e. all[3]).
        assert_eq!(resumed.name, all[3].0);
    }

    #[test]
    fn dirindex_iter_btree_cookies_survive_roundtrip() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"apple", 1, 0, 0).unwrap();
        idx.insert(b"banana", 2, 0, 0).unwrap();
        // Force B-tree promotion.
        for i in 0..5u64 {
            let name = alloc::format!("pad_{i}");
            idx.insert(name.as_bytes(), 100 + i, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        // Serialize and reload to verify cookies survive a roundtrip.
        let bytes = idx.to_bytes();
        let mut reloaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert_eq!(reloaded.representation(), DirStorageKind::BTREE);

        // Iterate the reloaded directory.
        let mut count = 0;
        reloaded.reset_cursor();
        while let Some(_e) = reloaded.next_entry() {
            let cookie = reloaded.current_cursor();
            assert!(
                cookie.is_btree(),
                "reloaded B-tree must emit B-tree cookies"
            );
            count += 1;
        }
        assert_eq!(count, 7);
    }

    // ------------------------------------------------------------------
    // DirIndexIter unit tests
    // ------------------------------------------------------------------

    #[test]
    fn dirindexiter_empty_len_zero() {
        let idx = DirIndex::new(1, test_policy());
        let iter = DirIndexIter::new(&idx);
        assert_eq!(iter.len(), 0);
        assert!(iter.is_empty());
        assert_eq!(iter.current_cookie(), DirCookie::START);
    }

    #[test]
    fn dirindexiter_single_entry_yields_cookie() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"only", 42, 1, 0).unwrap();
        let mut iter = DirIndexIter::new(&idx);
        assert_eq!(iter.len(), 1);

        let (entry, cookie) = iter.next().unwrap();
        assert_eq!(entry.name, b"only");
        assert_eq!(entry.inode_id, 42);
        assert!(cookie.is_micro());
        assert_eq!(cookie.as_micro_entry_index(), Some(0));

        assert!(iter.next().is_none());
        assert_eq!(iter.current_cookie(), cookie);
    }

    #[test]
    fn dirindexiter_multi_entry_cookies_monotonic() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"c", 3, 0, 0).unwrap();
        idx.insert(b"a", 1, 0, 0).unwrap();
        idx.insert(b"b", 2, 0, 0).unwrap();

        let mut iter = DirIndexIter::new(&idx);
        let mut prev_cookie: Option<u64> = None;
        let mut count = 0;
        while let Some((_entry, cookie)) = iter.next() {
            if let Some(p) = prev_cookie {
                assert!(
                    cookie.0 > p,
                    "cookies must be strictly increasing: {} <= {}",
                    cookie.0,
                    p
                );
            }
            prev_cookie = Some(cookie.0);
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn dirindexiter_seek_to_middle() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..5u64 {
            idx.insert(alloc::format!("f{i}").as_bytes(), i, 0, 0)
                .unwrap();
        }

        let mut iter = DirIndexIter::new(&idx);
        // Collect all entries and cookies.
        let all: Vec<(Vec<u8>, DirCookie)> = (0..)
            .map_while(|_| iter.next())
            .map(|(e, c)| (e.name.clone(), c))
            .collect();
        assert_eq!(all.len(), 5);

        // Seek to the cookie of the third entry (index 2).
        let seek_target = all[2].1;
        let mut iter = DirIndexIter::new(&idx);
        iter.seek_to(seek_target);
        let (resumed, _cookie) = iter.next().unwrap();
        assert_eq!(resumed.name, all[3].0, "resume should return next entry");
    }

    #[test]
    fn dirindexiter_seek_to_start_is_reset() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"first", 1, 0, 0).unwrap();
        idx.insert(b"second", 2, 0, 0).unwrap();

        let mut iter = DirIndexIter::new(&idx);
        let (e1, _c1) = iter.next().unwrap();
        assert_eq!(e1.name, b"first");
        let (e2, _c2) = iter.next().unwrap();
        assert_eq!(e2.name, b"second");
        assert!(iter.next().is_none());

        // Seek to START should restart.
        iter.seek_to(DirCookie::START);
        let (e3, _c3) = iter.next().unwrap();
        assert_eq!(e3.name, b"first");
    }

    #[test]
    fn dirindexiter_seek_past_end_exhausts() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"x", 1, 0, 0).unwrap();

        let mut iter = DirIndexIter::new(&idx);
        // Use a B-tree cookie with a high payload to seek past the only entry.
        let past = DirCookie(DirCookie::encode_btree(10, 10));
        iter.seek_to(past);
        assert!(iter.next().is_none());
        assert!(iter.is_empty());
    }

    #[test]
    fn dirindexiter_reset_restarts_iteration() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 0).unwrap();
        idx.insert(b"b", 2, 0, 0).unwrap();

        let mut iter = DirIndexIter::new(&idx);
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());

        iter.reset();
        assert_eq!(iter.len(), 2);
        let (e, _c) = iter.next().unwrap();
        assert_eq!(e.name, b"a");
    }

    #[test]
    fn dirindexiter_btree_entries_have_btree_cookies() {
        let mut idx = DirIndex::new(1, test_policy());
        // Promote to B-tree.
        for i in 0..7u64 {
            idx.insert(alloc::format!("bt{i:02}").as_bytes(), i, 0, 0)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        let mut iter = DirIndexIter::new(&idx);
        let mut count = 0;
        while let Some((_entry, cookie)) = iter.next() {
            assert!(
                cookie.is_btree(),
                "DirIndexIter must emit B-tree cookies for B-tree dirs, got {cookie:?}"
            );
            count += 1;
        }
        assert_eq!(count, 7);
    }

    #[test]
    fn dirindexiter_snapshot_unaffected_by_mutations() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 0).unwrap();
        idx.insert(b"beta", 2, 0, 0).unwrap();

        let mut iter = DirIndexIter::new(&idx);
        // Mutate the directory after creating the iterator.
        idx.insert(b"gamma", 3, 0, 0).unwrap();
        idx.delete(b"alpha").unwrap();
        idx.replace(b"beta", 22, 0, 0);

        // The iterator should reflect the snapshot at creation time (2 entries).
        let mut count = 0;
        while let Some((_entry, _cookie)) = iter.next() {
            count += 1;
        }
        assert_eq!(count, 2, "snapshot must reflect state at creation time");
    }

    fn test_policy() -> DatasetDirPolicy {
        DatasetDirPolicy {
            dir_micro_max_entries: 6,
            dir_micro_max_name_bytes: 512,
            dir_btree_downshift_entries: 3,
            dir_btree_downshift_name_bytes: 128,
        }
    }

    fn names(entries: &[DirEntry]) -> Vec<Vec<u8>> {
        entries.iter().map(|entry| entry.name.clone()).collect()
    }

    #[test]
    fn new_is_micro_and_empty() {
        let idx = DirIndex::new(1, test_policy());
        assert!(idx.is_empty());
        assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
    }

    #[test]
    fn insert_lookup_contains() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"hello.txt", 10, 0, 1).unwrap();
        let e = idx.lookup(b"hello.txt").unwrap();
        assert_eq!(e.inode_id, 10);
        assert_eq!(e.kind, 1);
        assert!(idx.contains(b"hello.txt"));
    }

    #[test]
    fn insert_duplicate_is_error() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"dup", 1, 0, 0).unwrap();
        assert_eq!(
            idx.insert(b"dup", 2, 0, 0),
            Err(DirIndexError::EntryAlreadyExists)
        );
    }

    #[test]
    fn replace_upserts() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.replace(b"file", 99, 1, 1);
        let e = idx.lookup(b"file").unwrap();
        assert_eq!(e.inode_id, 99);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn replace_existing_updates_attrs() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"file", 10, 1, 1).unwrap();

        let version = idx.directory_version();
        idx.replace(b"file", 20, 2, 3);

        let entry = idx.lookup(b"file").unwrap();
        assert_eq!(entry.inode_id, 20);
        assert_eq!(entry.generation, 2);
        assert_eq!(entry.kind, 3);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.directory_version(), version + 1);
    }

    #[test]
    fn replace_preserves_siblings() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 10, 1).unwrap();
        idx.insert(b"beta", 2, 20, 2).unwrap();
        idx.insert(b"gamma", 3, 30, 3).unwrap();

        let version = idx.directory_version();
        idx.replace(b"beta", 22, 220, 222);

        let alpha = idx.lookup(b"alpha").unwrap();
        assert_eq!(alpha.inode_id, 1);
        assert_eq!(alpha.generation, 10);
        assert_eq!(alpha.kind, 1);
        let beta = idx.lookup(b"beta").unwrap();
        assert_eq!(beta.inode_id, 22);
        assert_eq!(beta.generation, 220);
        assert_eq!(beta.kind, 222);
        let gamma = idx.lookup(b"gamma").unwrap();
        assert_eq!(gamma.inode_id, 3);
        assert_eq!(gamma.generation, 30);
        assert_eq!(gamma.kind, 3);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.directory_version(), version + 1);
    }

    #[test]
    fn replace_inserts_new_name() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"existing", 1, 0, 1).unwrap();

        let version = idx.directory_version();
        idx.replace(b"new", 2, 3, 4);

        assert_eq!(idx.lookup(b"existing").unwrap().inode_id, 1);
        let entry = idx.lookup(b"new").unwrap();
        assert_eq!(entry.inode_id, 2);
        assert_eq!(entry.generation, 3);
        assert_eq!(entry.kind, 4);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.directory_version(), version + 1);
    }

    #[test]
    fn replace_works_with_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..7 {
            idx.insert(alloc::format!("entry{i:02}").as_bytes(), i as u64, 0, 1)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        let version = idx.directory_version();
        idx.replace(b"entry03", 33, 44, 55);

        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        let entry = idx.lookup(b"entry03").unwrap();
        assert_eq!(entry.inode_id, 33);
        assert_eq!(entry.generation, 44);
        assert_eq!(entry.kind, 55);
        assert_eq!(idx.lookup(b"entry00").unwrap().inode_id, 0);
        assert_eq!(idx.lookup(b"entry06").unwrap().inode_id, 6);
        assert_eq!(idx.len(), 7);
        assert_eq!(idx.directory_version(), version + 1);
    }

    #[test]
    fn delete_removes_entry() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"bye", 1, 0, 0).unwrap();
        idx.delete(b"bye").unwrap();
        assert!(!idx.contains(b"bye"));
        assert!(idx.is_empty());
    }

    #[test]
    fn remove_returns_removed_entry() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"gone", 7, 2, 1).unwrap();
        let removed = idx.remove(b"gone").unwrap();
        assert_eq!(removed.name, b"gone");
        assert_eq!(removed.inode_id, 7);
        assert_eq!(removed.generation, 2);
        assert_eq!(removed.kind, 1);
        assert!(idx.remove(b"gone").is_none());
        assert!(idx.is_empty());
    }

    #[test]
    fn delete_not_found_is_error() {
        let mut idx = DirIndex::new(1, test_policy());
        assert_eq!(idx.delete(b"ghost"), Err(DirIndexError::EntryNotFound));
    }

    #[test]
    fn version_bumps_on_mutation() {
        let mut idx = DirIndex::new(1, test_policy());
        assert_eq!(idx.directory_version(), 0);
        idx.insert(b"a", 1, 0, 0).unwrap();
        assert_eq!(idx.directory_version(), 1);
        idx.delete(b"a").unwrap();
        assert_eq!(idx.directory_version(), 2);
    }

    #[test]
    fn micro_list_list_from() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"z", 1, 0, 0).unwrap();
        idx.insert(b"a", 2, 0, 0).unwrap();
        idx.insert(b"m", 3, 0, 0).unwrap();
        let (entries, _) = idx.list_from(DirCookie::START).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn list_from_rejects_stale_versioned_cookie() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10 {
            idx.insert(alloc::format!("entry_{i:02}").as_bytes(), i, 0, 0)
                .unwrap();
        }

        let (entries, cookie) = idx.list_from(DirCookie::START).unwrap();
        assert_eq!(entries.len(), 10);
        assert!(cookie.0 & crate::format::DIR_COOKIE_VERSIONED_MASK != 0);
        assert_eq!(crate::format::dir_cookie_skip(cookie.0), 10);
        assert_eq!(idx.list_from(DirCookie(1)), Err(DirIndexError::StaleCursor));

        idx.insert(b"entry_new", 100, 0, 0).unwrap();

        assert_eq!(idx.list_from(cookie), Err(DirIndexError::StaleCursor));
    }

    #[test]
    fn list_orders_micro_entries_by_name() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"zeta", 1, 0, 0).unwrap();
        idx.insert(b"alpha", 2, 0, 0).unwrap();
        idx.insert(b"middle", 3, 0, 0).unwrap();
        assert_eq!(
            names(&idx.list()),
            alloc::vec![b"alpha".to_vec(), b"middle".to_vec(), b"zeta".to_vec()]
        );
    }

    #[test]
    fn promote_on_count() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..7 {
            idx.insert(alloc::format!("f{i}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        // Entries survive promotion
        assert!(idx.contains(b"f0"));
        assert!(idx.contains(b"f6"));
    }

    #[test]
    fn demote_after_promotion() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10 {
            idx.insert(alloc::format!("x{i}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        for i in 3..10 {
            idx.delete(alloc::format!("x{i}").as_bytes()).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
        assert_eq!(idx.len(), 3);
    }

    #[test]
    fn hysteresis_band_no_flapping() {
        let mut idx = DirIndex::new(1, test_policy());
        // threshold = 6, downshift = 3. 5 entries → micro.
        for i in 0..5 {
            idx.insert(alloc::format!("e{i}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
        idx.delete(b"e0").unwrap();
        idx.insert(b"e0", 0, 0, 0).unwrap();
        assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
    }

    #[test]
    fn btree_large_dir_lookup() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..100 {
            idx.insert(alloc::format!("entry_{i:04}").as_bytes(), i as u64, 0, 1)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert!(idx.lookup(b"entry_0042").is_some());
        assert!(idx.lookup(b"entry_0099").is_some());
        assert!(!idx.contains(b"entry_0100"));
    }

    #[test]
    fn list_from_orders_btree_entries_by_name() {
        let mut idx = DirIndex::new(1, test_policy());
        let inserted = [
            b"k09".as_slice(),
            b"k01",
            b"k07",
            b"k03",
            b"k05",
            b"k00",
            b"k04",
        ];
        for (index, name) in inserted.iter().enumerate() {
            idx.insert(name, index as u64, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        let (entries, cookie) = idx.list_from(DirCookie::START).unwrap();
        // Cookie carries version evidence
        assert!(cookie.0 & crate::format::DIR_COOKIE_VERSIONED_MASK != 0);
        assert_eq!(
            names(&entries),
            alloc::vec![
                b"k00".to_vec(),
                b"k01".to_vec(),
                b"k03".to_vec(),
                b"k04".to_vec(),
                b"k05".to_vec(),
                b"k07".to_vec(),
                b"k09".to_vec()
            ]
        );
    }

    #[test]
    fn btree_delete_some() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..20 {
            idx.insert(alloc::format!("k{i:02}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        for i in 0..10 {
            idx.delete(alloc::format!("k{i:02}").as_bytes()).unwrap();
        }
        assert_eq!(idx.len(), 10);
        assert!(!idx.contains(b"k05"));
        assert!(idx.contains(b"k15"));
    }

    #[test]
    fn subdir_flag_micro_and_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.set_has_subdirs(true);
        assert!(idx.has_subdirs());
        for i in 0..10 {
            idx.insert(alloc::format!("d{i}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        assert!(idx.has_subdirs()); // survives promotion
        idx.set_has_subdirs(false);
        assert!(!idx.has_subdirs());
    }

    #[test]
    fn storage_accessor() {
        let idx = DirIndex::new(42, test_policy());
        assert_eq!(idx.storage().entry_count(), 0);
    }

    #[test]
    fn policy_default() {
        let idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        assert_eq!(idx.policy().dir_micro_max_entries, 50);
    }

    #[test]
    fn empty_dir_readdir() {
        let idx = DirIndex::new(1, test_policy());
        let (entries, c) = idx.list_from(DirCookie::START).unwrap();
        assert!(entries.is_empty());
        assert!(c.0 & crate::format::DIR_COOKIE_VERSIONED_MASK != 0);
        assert_eq!(crate::format::dir_cookie_skip(c.0), 0);
    }

    // ------------------------------------------------------------------
    // Rename tests
    // ------------------------------------------------------------------

    #[test]
    fn rename_basic() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"old", 10, 1, 1).unwrap();
        idx.rename(b"old", b"new").unwrap();
        assert!(!idx.contains(b"old"));
        let e = idx.lookup(b"new").unwrap();
        assert_eq!(e.inode_id, 10);
        assert_eq!(e.generation, 1);
        assert_eq!(e.kind, 1);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn rename_source_not_found() {
        let mut idx = DirIndex::new(1, test_policy());
        assert_eq!(
            idx.rename(b"ghost", b"real"),
            Err(DirIndexError::EntryNotFound)
        );
    }

    #[test]
    fn rename_target_exists() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 0).unwrap();
        idx.insert(b"beta", 2, 0, 0).unwrap();
        assert_eq!(
            idx.rename(b"alpha", b"beta"),
            Err(DirIndexError::EntryAlreadyExists)
        );
        // Both entries remain intact
        assert!(idx.contains(b"alpha"));
        assert!(idx.contains(b"beta"));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn rename_target_exists_preserves_version() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 0).unwrap();
        idx.insert(b"beta", 2, 0, 0).unwrap();

        let version = idx.directory_version();
        assert_eq!(
            idx.rename(b"alpha", b"beta"),
            Err(DirIndexError::EntryAlreadyExists)
        );

        assert_eq!(idx.directory_version(), version);
        assert_eq!(idx.lookup(b"alpha").unwrap().inode_id, 1);
        assert_eq!(idx.lookup(b"beta").unwrap().inode_id, 2);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn rename_self_preserves_entry_siblings_and_version() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"same", 42, 3, 2).unwrap();
        idx.insert(b"sibling", 99, 4, 1).unwrap();

        let version = idx.directory_version();
        idx.rename(b"same", b"same").unwrap();

        let entry = idx.lookup(b"same").unwrap();
        assert_eq!(entry.name, b"same");
        assert_eq!(entry.inode_id, 42);
        assert_eq!(entry.generation, 3);
        assert_eq!(entry.kind, 2);
        assert_eq!(idx.lookup(b"sibling").unwrap().inode_id, 99);
        assert_eq!(idx.directory_version(), version);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn rename_preserves_attributes() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"src", 99, 5, 3).unwrap();
        idx.rename(b"src", b"dst").unwrap();
        let e = idx.lookup(b"dst").unwrap();
        assert_eq!(e.inode_id, 99);
        assert_eq!(e.generation, 5);
        assert_eq!(e.kind, 3);
    }

    #[test]
    fn rename_version_bump() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 0).unwrap();
        let v1 = idx.directory_version();
        idx.rename(b"a", b"b").unwrap();
        assert!(idx.directory_version() > v1);
    }

    #[test]
    fn rename_in_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10 {
            idx.insert(alloc::format!("entry{i:02}").as_bytes(), i as u64, 0, 0)
                .unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        idx.rename(b"entry05", b"renamed").unwrap();
        assert!(!idx.contains(b"entry05"));
        let e = idx.lookup(b"renamed").unwrap();
        assert_eq!(e.inode_id, 5);
        assert_eq!(idx.len(), 10);
    }

    #[test]
    fn rename_overwrite_replaces_target_and_returns_old_entry() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"source", 10, 1, 2).unwrap();
        idx.insert(b"target", 20, 3, 4).unwrap();

        let version = idx.directory_version();
        let overwritten = idx.rename_overwrite(b"source", b"target").unwrap();

        let overwritten = overwritten.expect("target entry should be returned");
        assert_eq!(overwritten.name, b"target");
        assert_eq!(overwritten.inode_id, 20);
        assert_eq!(overwritten.generation, 3);
        assert_eq!(overwritten.kind, 4);
        assert!(!idx.contains(b"source"));
        let target = idx.lookup(b"target").unwrap();
        assert_eq!(target.inode_id, 10);
        assert_eq!(target.generation, 1);
        assert_eq!(target.kind, 2);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.directory_version(), version + 1);
    }

    #[test]
    fn rename_overwrite_without_target_preserves_entry() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"source", 10, 1, 2).unwrap();

        let overwritten = idx.rename_overwrite(b"source", b"target").unwrap();

        assert!(overwritten.is_none());
        assert!(!idx.contains(b"source"));
        let target = idx.lookup(b"target").unwrap();
        assert_eq!(target.inode_id, 10);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn rename_overwrite_same_name_is_noop() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"same", 42, 3, 2).unwrap();

        let version = idx.directory_version();
        let overwritten = idx.rename_overwrite(b"same", b"same").unwrap();

        assert!(overwritten.is_none());
        assert_eq!(idx.directory_version(), version);
        assert_eq!(idx.lookup(b"same").unwrap().inode_id, 42);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn move_entry_to_moves_between_directories() {
        let mut source_dir = DirIndex::new(1, test_policy());
        let mut target_dir = DirIndex::new(2, test_policy());
        source_dir.insert(b"old", 10, 1, 2).unwrap();
        target_dir.insert(b"keep", 20, 3, 4).unwrap();

        let source_version = source_dir.directory_version();
        let target_version = target_dir.directory_version();
        let overwritten = source_dir
            .move_entry_to(b"old", &mut target_dir, b"new")
            .unwrap();

        assert!(overwritten.is_none());
        assert!(!source_dir.contains(b"old"));
        assert_eq!(source_dir.len(), 0);
        assert_eq!(target_dir.lookup(b"new").unwrap().inode_id, 10);
        assert_eq!(target_dir.lookup(b"keep").unwrap().inode_id, 20);
        assert_eq!(target_dir.len(), 2);
        assert_eq!(source_dir.directory_version(), source_version + 1);
        assert_eq!(target_dir.directory_version(), target_version + 1);
    }

    #[test]
    fn move_entry_to_overwrites_target_and_returns_old_entry() {
        let mut source_dir = DirIndex::new(1, test_policy());
        let mut target_dir = DirIndex::new(2, test_policy());
        source_dir.insert(b"old", 10, 1, 2).unwrap();
        target_dir.insert(b"new", 20, 3, 4).unwrap();

        let overwritten = source_dir
            .move_entry_to(b"old", &mut target_dir, b"new")
            .unwrap()
            .expect("target entry should be returned");

        assert_eq!(overwritten.name, b"new");
        assert_eq!(overwritten.inode_id, 20);
        assert!(!source_dir.contains(b"old"));
        let target = target_dir.lookup(b"new").unwrap();
        assert_eq!(target.inode_id, 10);
        assert_eq!(target.generation, 1);
        assert_eq!(target.kind, 2);
        assert_eq!(target_dir.len(), 1);
    }

    #[test]
    fn move_entry_to_source_not_found_leaves_directories_unchanged() {
        let mut source_dir = DirIndex::new(1, test_policy());
        let mut target_dir = DirIndex::new(2, test_policy());
        target_dir.insert(b"new", 20, 3, 4).unwrap();

        let source_version = source_dir.directory_version();
        let target_version = target_dir.directory_version();
        assert_eq!(
            source_dir.move_entry_to(b"missing", &mut target_dir, b"new"),
            Err(DirIndexError::EntryNotFound)
        );

        assert!(source_dir.is_empty());
        assert_eq!(target_dir.lookup(b"new").unwrap().inode_id, 20);
        assert_eq!(source_dir.directory_version(), source_version);
        assert_eq!(target_dir.directory_version(), target_version);
    }

    #[test]
    fn move_entry_to_works_with_btree_directories() {
        let mut source_dir = DirIndex::new(1, test_policy());
        let mut target_dir = DirIndex::new(2, test_policy());
        for index in 0..10 {
            source_dir
                .insert(alloc::format!("source{index:02}").as_bytes(), index, 0, 0)
                .unwrap();
            target_dir
                .insert(
                    alloc::format!("target{index:02}").as_bytes(),
                    100 + index,
                    0,
                    0,
                )
                .unwrap();
        }
        assert_eq!(source_dir.representation(), DirStorageKind::BTREE);
        assert_eq!(target_dir.representation(), DirStorageKind::BTREE);

        let overwritten = source_dir
            .move_entry_to(b"source05", &mut target_dir, b"target05")
            .unwrap()
            .expect("target entry should be returned");

        assert_eq!(overwritten.inode_id, 105);
        assert!(!source_dir.contains(b"source05"));
        assert_eq!(target_dir.lookup(b"target05").unwrap().inode_id, 5);
        assert_eq!(source_dir.len(), 9);
        assert_eq!(target_dir.len(), 10);
    }

    #[test]
    fn promote_on_name_bytes() {
        let mut idx = DirIndex::new(1, test_policy());
        let long = b"this_is_a_very_long_filename_that_exceeds_name_bytes_threshold_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        for i in 0..3 {
            let mut name = long.to_vec();
            name.extend_from_slice(alloc::format!("_{i}").as_bytes());
            idx.insert(&name, i as u64, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
    }

    #[test]
    fn insert_empty_name() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"", 10, 0, 1).unwrap();
        assert_eq!(idx.len(), 1);
        let e = idx.lookup(b"").unwrap();
        assert_eq!(e.inode_id, 10);
        assert_eq!(e.name_len, 0);
        assert_eq!(idx.list().len(), 1);
    }

    #[test]
    fn insert_long_name_works_and_can_promote() {
        let mut idx = DirIndex::new(1, test_policy());
        let long_name = alloc::vec![b'x'; 255];
        idx.insert(&long_name, 42, 1, 2).unwrap();
        assert_eq!(idx.len(), 1);
        let e = idx.lookup(&long_name).unwrap();
        assert_eq!(e.inode_id, 42);
        assert_eq!(e.name_len, 255);
        assert_eq!(idx.list().len(), 1);
        assert!(idx.contains(&long_name));
    }

    #[test]
    fn insert_many_long_names_promotes_on_bytes() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..5 {
            let mut name = alloc::vec![b'a' + (i as u8 % 26); 128];
            name.extend_from_slice(alloc::format!("_{i}").as_bytes());
            idx.insert(&name, i as u64, 0, 0).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), 5);
    }

    // ── Serialization round-trip ────────────────────────────────────

    #[test]
    fn to_bytes_from_bytes_roundtrip_empty() {
        let idx = DirIndex::new(42, test_policy());
        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert_eq!(loaded.directory_inode_id, 42);
        assert_eq!(loaded.directory_version, 0);
        assert!(loaded.is_empty());
        assert!(!loaded.is_dirty()); // loaded from disk
    }

    #[test]
    fn to_bytes_from_bytes_roundtrip_with_entries() {
        let mut idx = DirIndex::new(10, test_policy());
        idx.insert(b"delta", 4, 40, 1).unwrap();
        idx.insert(b"alpha", 1, 10, 2).unwrap();
        idx.insert(b"charlie", 3, 30, 1).unwrap();
        idx.insert(b"bravo", 2, 20, 2).unwrap();
        idx.set_has_subdirs(true);

        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

        assert_eq!(loaded.directory_inode_id, 10);
        assert_eq!(loaded.directory_version, 4); // 4 inserts -> version 4
        assert_eq!(loaded.len(), 4);
        assert!(loaded.has_subdirs());
        assert!(!loaded.is_dirty());

        // Entries recoverable in sorted order
        assert_eq!(
            names(&loaded.list()),
            alloc::vec![
                b"alpha".to_vec(),
                b"bravo".to_vec(),
                b"charlie".to_vec(),
                b"delta".to_vec()
            ]
        );
        assert_eq!(loaded.lookup(b"alpha").unwrap().inode_id, 1);
        assert_eq!(loaded.lookup(b"bravo").unwrap().generation, 20);
        assert_eq!(loaded.lookup(b"charlie").unwrap().kind, 1);
        assert_eq!(loaded.lookup(b"delta").unwrap().inode_id, 4);
    }

    #[test]
    fn to_bytes_from_bytes_preserves_version() {
        let mut idx = DirIndex::new(7, test_policy());
        idx.insert(b"a", 1, 0, 0).unwrap();
        idx.insert(b"b", 2, 0, 0).unwrap();
        idx.delete(b"a").unwrap();
        // version should be 3 (insert a, insert b, delete a)

        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert_eq!(loaded.directory_version, 3);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(b"b"));
        assert!(!loaded.contains(b"a"));
    }

    #[test]
    fn from_bytes_short_buffer_returns_none() {
        assert!(DirIndex::from_bytes(&[0u8; 16], test_policy()).is_none());
    }

    #[test]
    fn to_bytes_from_bytes_large_directory_10k_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10000u64 {
            let name = alloc::format!("file_{i:05}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), 10000);

        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

        assert_eq!(loaded.len(), 10000);
        assert_eq!(loaded.directory_version, 10000);
        // Spot-check entries
        assert_eq!(loaded.lookup(b"file_00000").unwrap().inode_id, 0);
        assert_eq!(loaded.lookup(b"file_05000").unwrap().inode_id, 5000);
        assert_eq!(loaded.lookup(b"file_09999").unwrap().inode_id, 9999);
        // Entries are in sorted order
        let entries = loaded.list();
        assert_eq!(entries.len(), 10000);
        assert_eq!(names(&entries[..1]), alloc::vec![b"file_00000".to_vec()]);
        assert_eq!(names(&entries[9999..]), alloc::vec![b"file_09999".to_vec()]);
    }

    #[test]
    fn to_bytes_from_bytes_empty_name_and_long_name() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"", 100, 1, 2).unwrap();
        let long = alloc::vec![b'y'; 255];
        idx.insert(&long, 200, 2, 1).unwrap();

        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.lookup(b"").unwrap().inode_id, 100);
        let e = loaded.lookup(&long).unwrap();
        assert_eq!(e.inode_id, 200);
        assert_eq!(e.name_len, 255);
    }

    #[test]
    fn new_is_dirty_loaded_is_not() {
        let idx = DirIndex::new(1, test_policy());
        assert!(idx.is_dirty());

        let bytes = idx.to_bytes();
        let loaded = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert!(!loaded.is_dirty());
    }

    #[test]
    fn dirty_set_on_all_mutations() {
        // Start with loaded (clean) state
        let bytes = DirIndex::new(1, test_policy()).to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.insert(b"entry", 10, 0, 1).unwrap();
        assert!(idx.is_dirty());

        // "Flush" by loading again
        let bytes = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.delete(b"entry").unwrap();
        assert!(idx.is_dirty());

        let bytes = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.insert(b"a", 1, 0, 0).unwrap();
        idx.insert(b"b", 2, 0, 0).unwrap();
        let bytes2 = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes2, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.rename(b"a", b"c").unwrap();
        assert!(idx.is_dirty());

        let bytes3 = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes3, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.replace(b"c", 99, 0, 0);
        assert!(idx.is_dirty());

        let bytes4 = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes4, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        idx.set_has_subdirs(true);
        assert!(idx.is_dirty());

        let bytes5 = idx.to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes5, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        // No-op set_has_subdirs should NOT set dirty
        idx.set_has_subdirs(true);
        assert!(!idx.is_dirty());
    }

    // ── Object-store flush/load round-trip (std only) ───────────────

    #[cfg(feature = "std")]
    #[test]
    fn flush_load_roundtrip_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(tmp.path()).unwrap();
        let mut idx = DirIndex::new(100, test_policy());

        idx.flush(&mut store).unwrap();
        assert!(!idx.is_dirty());

        let loaded = DirIndex::load(&store, 100, test_policy()).unwrap().unwrap();
        assert!(loaded.is_empty());
        assert_eq!(loaded.directory_inode_id, 100);
        assert!(!loaded.is_dirty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn flush_load_roundtrip_with_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(tmp.path()).unwrap();
        let mut idx = DirIndex::new(200, test_policy());
        idx.insert(b"zulu", 26, 0, 1).unwrap();
        idx.insert(b"alpha", 1, 0, 2).unwrap();
        idx.insert(b"mike", 13, 0, 1).unwrap();
        idx.set_has_subdirs(true);

        idx.flush(&mut store).unwrap();
        assert!(!idx.is_dirty());

        let loaded = DirIndex::load(&store, 200, test_policy()).unwrap().unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.has_subdirs());
        assert_eq!(loaded.directory_version, 3);
        assert_eq!(
            names(&loaded.list()),
            alloc::vec![b"alpha".to_vec(), b"mike".to_vec(), b"zulu".to_vec()]
        );
        assert_eq!(loaded.lookup(b"alpha").unwrap().inode_id, 1);
        assert_eq!(loaded.lookup(b"mike").unwrap().kind, 1);
        assert_eq!(loaded.lookup(b"zulu").unwrap().inode_id, 26);
    }

    #[cfg(feature = "std")]
    #[test]
    fn load_non_existent_returns_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = tidefs_local_object_store::LocalObjectStore::open(tmp.path()).unwrap();
        let result = DirIndex::load(&store, 999, test_policy()).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn flush_load_preserves_dirty_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(tmp.path()).unwrap();
        let mut idx = DirIndex::new(300, test_policy());
        idx.insert(b"data", 42, 1, 1).unwrap();
        assert!(idx.is_dirty());

        idx.flush(&mut store).unwrap();
        assert!(!idx.is_dirty());

        let loaded = DirIndex::load(&store, 300, test_policy()).unwrap().unwrap();
        assert!(!loaded.is_dirty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn flush_overwrites_and_load_recovers_latest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(tmp.path()).unwrap();
        let mut idx = DirIndex::new(400, test_policy());
        idx.insert(b"first", 1, 0, 0).unwrap();
        idx.flush(&mut store).unwrap();

        idx.insert(b"second", 2, 0, 0).unwrap();
        idx.delete(b"first").unwrap();
        idx.flush(&mut store).unwrap();

        let loaded = DirIndex::load(&store, 400, test_policy()).unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(b"second"));
        assert!(!loaded.contains(b"first"));
        assert_eq!(loaded.directory_version, 3); // insert first (1), insert second (2), delete first (3)
    }

    // ── range_scan pagination ────────────────────────────────────────

    #[test]
    fn range_scan_empty_start_returns_all() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"c", 3, 0, 1).unwrap();
        idx.insert(b"a", 1, 0, 1).unwrap();
        idx.insert(b"b", 2, 0, 1).unwrap();

        let result = idx.range_scan(b"", 10);
        assert_eq!(result.len(), 3);
        assert_eq!(
            names(&result),
            alloc::vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn range_scan_max_entries_limits() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..10u64 {
            let name = alloc::format!("entry_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }

        let result = idx.range_scan(b"", 3);
        assert_eq!(result.len(), 3);
        assert_eq!(
            names(&result),
            alloc::vec![
                b"entry_00".to_vec(),
                b"entry_01".to_vec(),
                b"entry_02".to_vec()
            ]
        );
    }

    #[test]
    fn range_scan_start_name_exclusive() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 1).unwrap();
        idx.insert(b"beta", 2, 0, 1).unwrap();
        idx.insert(b"gamma", 3, 0, 1).unwrap();
        idx.insert(b"delta", 4, 0, 1).unwrap();

        // Start after "beta" → should return delta, gamma
        let result = idx.range_scan(b"beta", 10);
        assert_eq!(result.len(), 2);
        assert_eq!(
            names(&result),
            alloc::vec![b"delta".to_vec(), b"gamma".to_vec()]
        );
    }

    #[test]
    fn range_scan_start_name_not_found() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"apple", 1, 0, 1).unwrap();
        idx.insert(b"cherry", 3, 0, 1).unwrap();

        // "banana" is not present but falls between apple and cherry
        let result = idx.range_scan(b"banana", 10);
        assert_eq!(result.len(), 1);
        assert_eq!(names(&result), alloc::vec![b"cherry".to_vec()]);
    }

    #[test]
    fn range_scan_past_end_returns_empty() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"zulu", 1, 0, 1).unwrap();

        let result = idx.range_scan(b"zulu", 10);
        assert!(result.is_empty());
    }

    #[test]
    fn range_scan_max_entries_zero() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 1).unwrap();

        let result = idx.range_scan(b"", 0);
        assert!(result.is_empty());
    }

    #[test]
    fn range_scan_page_by_page() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..20u64 {
            let name = alloc::format!("file_{i:03}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        // 20 entries, pages of 7 → 3 pages
        let page_size = 7;

        let page1 = idx.range_scan(b"", page_size);
        assert_eq!(page1.len(), 7);
        assert_eq!(names(&page1[..1]), alloc::vec![b"file_000".to_vec()]);
        let last1 = &page1.last().unwrap().name;
        assert_eq!(last1, b"file_006");

        let page2 = idx.range_scan(last1, page_size);
        assert_eq!(page2.len(), 7);
        assert_eq!(names(&page2[..1]), alloc::vec![b"file_007".to_vec()]);
        let last2 = &page2.last().unwrap().name;
        assert_eq!(last2, b"file_013");

        let page3 = idx.range_scan(last2, page_size);
        assert_eq!(page3.len(), 6);
        assert_eq!(names(&page3[..1]), alloc::vec![b"file_014".to_vec()]);
        let last3 = &page3.last().unwrap().name;
        assert_eq!(last3, b"file_019");

        let page4 = idx.range_scan(last3, page_size);
        assert!(page4.is_empty());
    }

    #[test]
    fn range_scan_empty_dir() {
        let idx = DirIndex::new(1, test_policy());
        assert!(idx.range_scan(b"", 10).is_empty());
        assert!(idx.range_scan(b"something", 10).is_empty());
    }

    #[test]
    fn range_scan_btree_large_pagination() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..1000u64 {
            let name = alloc::format!("item_{i:04}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        let page = idx.range_scan(b"item_0500", 5);
        assert_eq!(page.len(), 5);
        assert_eq!(
            names(&page),
            alloc::vec![
                b"item_0501".to_vec(),
                b"item_0502".to_vec(),
                b"item_0503".to_vec(),
                b"item_0504".to_vec(),
                b"item_0505".to_vec(),
            ]
        );
    }

    #[test]
    fn range_scan_btree_name_index_tracks_collision_bucket_edits() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert_with_forced_hash(b"zulu", 1, 26, 0, 1);
        idx.insert_with_forced_hash(b"alpha", 1, 1, 0, 1);
        idx.insert_with_forced_hash(b"mike", 1, 13, 0, 1);
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.btree_bucket_count(), 1);

        let first_page = idx.range_scan(b"", 2);
        assert_eq!(
            names(&first_page),
            alloc::vec![b"alpha".to_vec(), b"mike".to_vec()]
        );

        idx.delete_by_hash(1, b"mike").unwrap();
        idx.insert_with_forced_hash(b"bravo", 1, 2, 0, 1);

        let after_alpha = idx.range_scan(b"alpha", 8);
        assert_eq!(
            names(&after_alpha),
            alloc::vec![b"bravo".to_vec(), b"zulu".to_vec()]
        );
    }

    #[test]
    fn range_scan_dirty_state_unchanged() {
        let bytes = DirIndex::new(1, test_policy()).to_bytes();
        let mut idx = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
        idx.insert(b"entry", 1, 0, 1).unwrap();

        // Flush to clear dirty
        let bytes2 = idx.to_bytes();
        let idx = DirIndex::from_bytes(&bytes2, test_policy()).unwrap();
        assert!(!idx.is_dirty());

        // range_scan is read-only — must not mark dirty
        let _results = idx.range_scan(b"", 10);
        assert!(!idx.is_dirty());
    }

    // ── name_hash ─────────────────────────────────────────────────

    #[test]
    fn name_hash_deterministic() {
        let a = name_hash(b"hello");
        let b = name_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn name_hash_empty() {
        assert_eq!(name_hash(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn name_hash_single_byte() {
        let expected = (0xcbf29ce484222325u64 ^ 0x61u64).wrapping_mul(0x100000001b3);
        assert_eq!(name_hash(b"a"), expected);
    }

    #[test]
    fn name_hash_different_inputs() {
        let h1 = name_hash(b"alpha");
        let h2 = name_hash(b"beta");
        let h3 = name_hash(b"gamma");
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn name_hash_length_matters() {
        assert_ne!(name_hash(b"abc"), name_hash(b"abcd"));
    }

    // ── Case sensitivity ──────────────────────────────────────────

    #[test]
    fn case_sensitivity_distinct_entries() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"Hello", 10, 0, 1).unwrap();
        idx.insert(b"hello", 20, 0, 2).unwrap();
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn case_sensitivity_lookup_exact_match() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"Hello", 10, 0, 1).unwrap();
        assert_eq!(idx.lookup(b"Hello").unwrap().inode_id, 10);
        assert!(idx.lookup(b"hello").is_none());
        assert!(idx.lookup(b"HELLO").is_none());
        assert!(idx.lookup(b"HElLO").is_none());
    }

    #[test]
    fn case_sensitivity_rename_exact_match() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"Hello", 10, 0, 1).unwrap();
        idx.rename(b"Hello", b"hello").unwrap();
        assert!(idx.lookup(b"Hello").is_none());
        assert_eq!(idx.lookup(b"hello").unwrap().inode_id, 10);
    }

    #[test]
    fn case_sensitivity_delete_exact_match() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"Hello", 10, 0, 1).unwrap();
        idx.insert(b"hello", 20, 0, 2).unwrap();
        idx.delete(b"Hello").unwrap();
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.lookup(b"hello").unwrap().inode_id, 20);
    }

    #[test]
    fn case_sensitivity_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"Alpha", 1, 0, 1).unwrap();
        idx.insert(b"alpha", 2, 0, 1).unwrap();
        idx.insert(b"Beta", 3, 0, 1).unwrap();
        idx.insert(b"beta", 4, 0, 1).unwrap();
        idx.insert(b"Gamma", 5, 0, 1).unwrap();
        idx.insert(b"gamma", 6, 0, 1).unwrap();
        idx.insert(b"Delta", 7, 0, 1).unwrap(); // triggers promotion: 7 > 6
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), 7);
        assert_eq!(idx.lookup(b"Alpha").unwrap().inode_id, 1);
        assert_eq!(idx.lookup(b"alpha").unwrap().inode_id, 2);
        assert_eq!(idx.lookup(b"Beta").unwrap().inode_id, 3);
        assert_eq!(idx.lookup(b"beta").unwrap().inode_id, 4);
        assert!(idx.lookup(b"ALPHA").is_none());
    }

    // ── Consistency after mixed operations ─────────────────────────

    #[test]
    fn len_consistent_after_insert_delete_reinsert() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 1).unwrap();
        idx.insert(b"b", 2, 0, 1).unwrap();
        idx.delete(b"a").unwrap();
        idx.insert(b"c", 3, 0, 1).unwrap();
        assert_eq!(idx.len(), 2);
        assert!(idx.contains(b"b"));
        assert!(idx.contains(b"c"));
        assert!(!idx.contains(b"a"));
    }

    #[test]
    fn len_consistent_after_replace() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 1).unwrap();
        idx.insert(b"b", 2, 0, 1).unwrap();
        idx.replace(b"a", 99, 0, 1);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.lookup(b"a").unwrap().inode_id, 99);
    }

    #[test]
    fn len_consistent_after_rename_overwrite() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 1).unwrap();
        idx.insert(b"b", 2, 0, 1).unwrap();
        idx.insert(b"c", 3, 0, 1).unwrap();
        let overwritten = idx.rename_overwrite(b"a", b"b").unwrap().unwrap();
        assert_eq!(overwritten.inode_id, 2);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.lookup(b"b").unwrap().inode_id, 1);
        assert!(idx.contains(b"c"));
        assert!(!idx.contains(b"a"));
    }

    // ────────────────────────────────────────────────────────────────
    // Hash-collision handling (BTree buckets)
    //
    // Because FNV-1a produces no natural collisions across the entire
    // 3-byte name space, these tests use the test-only
    // `insert_with_forced_hash` / `lookup_by_hash` / `delete_by_hash`
    // helpers to exercise the B+tree collision-bucket code paths.
    // Correctness is verified through the helpers and through `list()`
    // (which iterates B+tree entries directly, independent of hashing).
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn btree_collision_two_entries_same_hash_both_reachable() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0xABCD_EF01_2345_6789u64;
        idx.insert_with_forced_hash(b"collision_alpha", shared_hash, 10, 1, 1);
        idx.insert_with_forced_hash(b"collision_beta", shared_hash, 20, 2, 2);

        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), 2);
        // Single hash bucket contains both entries
        assert_eq!(idx.btree_bucket_count(), 1);

        let alpha = idx.lookup_by_hash(shared_hash, b"collision_alpha").unwrap();
        assert_eq!(alpha.inode_id, 10);
        assert_eq!(alpha.generation, 1);
        assert_eq!(alpha.kind, 1);

        let beta = idx.lookup_by_hash(shared_hash, b"collision_beta").unwrap();
        assert_eq!(beta.inode_id, 20);
        assert_eq!(beta.generation, 2);
        assert_eq!(beta.kind, 2);

        // Both appear in sorted iteration
        let entries = idx.list();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            names(&entries),
            alloc::vec![b"collision_alpha".to_vec(), b"collision_beta".to_vec()]
        );
    }

    #[test]
    fn btree_collision_many_entries_same_hash_all_reachable() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0xDEAD_BEEF_CAFE_BABEu64;
        let count = 10u64;
        for i in 0..count {
            let name = alloc::format!("collision_entry_{i:02}");
            idx.insert_with_forced_hash(name.as_bytes(), shared_hash, i, 0, 1);
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), count as usize);
        assert_eq!(idx.btree_bucket_count(), 1);

        for i in 0..count {
            let name = alloc::format!("collision_entry_{i:02}");
            let e = idx.lookup_by_hash(shared_hash, name.as_bytes()).unwrap();
            assert_eq!(e.inode_id, i, "entry {i} should be reachable");
        }

        let entries = idx.list();
        assert_eq!(entries.len(), count as usize);
        for (idx, e) in entries.iter().enumerate() {
            let expected_name = alloc::format!("collision_entry_{idx:02}");
            assert_eq!(e.name, expected_name.as_bytes());
        }
    }

    #[test]
    fn btree_collision_delete_one_preserves_others() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0x1111_2222_3333_4444u64;
        idx.insert_with_forced_hash(b"keep_me", shared_hash, 1, 0, 1);
        idx.insert_with_forced_hash(b"remove_me", shared_hash, 2, 0, 1);
        idx.insert_with_forced_hash(b"also_keep", shared_hash, 3, 0, 1);
        assert_eq!(idx.len(), 3);

        idx.delete_by_hash(shared_hash, b"remove_me").unwrap();

        assert_eq!(idx.len(), 2);
        assert!(idx.lookup_by_hash(shared_hash, b"keep_me").is_some());
        assert!(idx.lookup_by_hash(shared_hash, b"also_keep").is_some());
        assert!(idx.lookup_by_hash(shared_hash, b"remove_me").is_none());

        let entries = idx.list();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            names(&entries),
            alloc::vec![b"also_keep".to_vec(), b"keep_me".to_vec()]
        );
    }

    #[test]
    fn btree_collision_delete_all_same_hash_empties_bucket() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0xAAAA_BBBB_CCCC_DDDDu64;
        idx.insert_with_forced_hash(b"a", shared_hash, 1, 0, 1);
        idx.insert_with_forced_hash(b"b", shared_hash, 2, 0, 1);

        idx.delete_by_hash(shared_hash, b"a").unwrap();
        assert_eq!(idx.len(), 1);
        assert!(idx.lookup_by_hash(shared_hash, b"b").is_some());

        idx.delete_by_hash(shared_hash, b"b").unwrap();
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert_eq!(idx.list().len(), 0);
        assert_eq!(idx.btree_bucket_count(), 0);

        // Re-insert after bucket emptied: must still work
        idx.insert_with_forced_hash(b"c", shared_hash, 3, 0, 1);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.lookup_by_hash(shared_hash, b"c").unwrap().inode_id, 3);
    }

    #[test]
    fn btree_collision_mixed_hash_buckets() {
        let mut idx = DirIndex::new(1, test_policy());
        let hash_a = 0x1000_0000_0000_0001u64;
        let hash_b = 0x2000_0000_0000_0002u64;

        // Bucket A: two entries
        idx.insert_with_forced_hash(b"a_one", hash_a, 1, 0, 1);
        idx.insert_with_forced_hash(b"a_two", hash_a, 2, 0, 1);
        // Bucket B: one entry
        idx.insert_with_forced_hash(b"b_one", hash_b, 3, 0, 1);

        assert_eq!(idx.len(), 3);
        assert_eq!(idx.btree_bucket_count(), 2);
        assert!(idx.lookup_by_hash(hash_a, b"a_one").is_some());
        assert!(idx.lookup_by_hash(hash_a, b"a_two").is_some());
        assert!(idx.lookup_by_hash(hash_b, b"b_one").is_some());

        // Delete from bucket A
        idx.delete_by_hash(hash_a, b"a_one").unwrap();
        assert_eq!(idx.len(), 2);
        assert!(idx.lookup_by_hash(hash_a, b"a_two").is_some());
        assert!(idx.lookup_by_hash(hash_b, b"b_one").is_some());
        assert!(idx.lookup_by_hash(hash_a, b"a_one").is_none());
    }

    #[test]
    fn btree_collision_replace_in_bucket() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0x9999_8888_7777_6666u64;
        idx.insert_with_forced_hash(b"target", shared_hash, 10, 1, 1);
        idx.insert_with_forced_hash(b"sibling", shared_hash, 20, 2, 2);

        let version = idx.directory_version();
        // Manual replace: delete then re-insert via forced-hash helpers
        idx.delete_by_hash(shared_hash, b"target").unwrap();
        idx.insert_with_forced_hash(b"target", shared_hash, 99, 9, 9);

        assert_eq!(idx.len(), 2);
        assert_eq!(idx.btree_bucket_count(), 1);
        let e = idx.lookup_by_hash(shared_hash, b"target").unwrap();
        assert_eq!(e.inode_id, 99);
        assert_eq!(e.generation, 9);
        assert_eq!(e.kind, 9);
        assert_eq!(
            idx.lookup_by_hash(shared_hash, b"sibling")
                .unwrap()
                .inode_id,
            20
        );
        assert_eq!(idx.directory_version(), version + 2); // one delete + one insert
    }

    #[test]
    fn btree_collision_iteration_after_insert_order_irrelevant() {
        let mut idx = DirIndex::new(1, test_policy());
        let shared_hash = 0xF00D_BEEF_CAFE_0001u64;
        // Insert in non-alphabetical order into same bucket
        idx.insert_with_forced_hash(b"zulu", shared_hash, 26, 0, 1);
        idx.insert_with_forced_hash(b"alpha", shared_hash, 1, 0, 1);
        idx.insert_with_forced_hash(b"mike", shared_hash, 13, 0, 1);

        let entries = idx.list();
        // list() sorts by name, not insertion order
        assert_eq!(
            names(&entries),
            alloc::vec![b"alpha".to_vec(), b"mike".to_vec(), b"zulu".to_vec()]
        );
    }
    // ────────────────────────────────────────────────────────────────
    // Snapshot isolation (list returns independent copy)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn list_returns_snapshot_unchanged_by_later_mutations() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"alpha", 1, 0, 1).unwrap();
        idx.insert(b"beta", 2, 0, 1).unwrap();
        idx.insert(b"gamma", 3, 0, 1).unwrap();

        let snapshot = idx.list();
        assert_eq!(snapshot.len(), 3);

        // Mutate after taking snapshot
        idx.insert(b"delta", 4, 0, 1).unwrap();
        idx.delete(b"alpha").unwrap();
        idx.replace(b"beta", 99, 0, 99);

        // Snapshot must be unchanged
        assert_eq!(snapshot.len(), 3);
        assert_eq!(
            names(&snapshot),
            alloc::vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
        );
        assert_eq!(snapshot[0].inode_id, 1);
        assert_eq!(snapshot[1].inode_id, 2);
        assert_eq!(snapshot[2].inode_id, 3);

        // Live index reflects mutations
        assert_eq!(idx.len(), 3);
        assert!(!idx.contains(b"alpha"));
        assert!(idx.contains(b"delta"));
        assert_eq!(idx.lookup(b"beta").unwrap().inode_id, 99);
    }

    #[test]
    fn list_snapshot_isolated_from_rename() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"old", 10, 1, 1).unwrap();
        idx.insert(b"other", 20, 2, 2).unwrap();

        let snapshot = idx.list();
        assert_eq!(snapshot.len(), 2);

        idx.rename(b"old", b"renamed").unwrap();

        // Snapshot unchanged
        assert_eq!(snapshot[0].name, b"old");
        assert_eq!(snapshot[0].inode_id, 10);

        // Live index updated
        assert!(idx.contains(b"renamed"));
        assert!(!idx.contains(b"old"));
    }

    #[test]
    fn list_snapshot_isolated_after_promotion() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..5u64 {
            let name = alloc::format!("pre_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

        let snapshot = idx.list();
        assert_eq!(snapshot.len(), 5);

        // Trigger promotion by inserting more entries
        idx.insert(b"trigger_promotion_a", 100, 0, 1).unwrap();
        idx.insert(b"trigger_promotion_b", 101, 0, 1).unwrap();
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        // Snapshot unchanged
        assert_eq!(snapshot.len(), 5);
        assert_eq!(names(&snapshot)[0], b"pre_00");
    }

    // ────────────────────────────────────────────────────────────────
    // Insert-delete-reinsert same entry (no stale state leak)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn insert_delete_reinsert_same_name_micro() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"cycle", 10, 1, 1).unwrap();
        assert_eq!(idx.len(), 1);
        let v1 = idx.directory_version();

        idx.delete(b"cycle").unwrap();
        assert_eq!(idx.len(), 0);
        assert!(!idx.contains(b"cycle"));
        let v2 = idx.directory_version();
        assert!(v2 > v1);

        idx.insert(b"cycle", 20, 2, 2).unwrap();
        assert_eq!(idx.len(), 1);
        let e = idx.lookup(b"cycle").unwrap();
        assert_eq!(e.inode_id, 20);
        assert_eq!(e.generation, 2);
        assert_eq!(e.kind, 2);
        let v3 = idx.directory_version();
        assert!(v3 > v2);

        assert_eq!(idx.list().len(), 1);
        assert_eq!(names(&idx.list()), alloc::vec![b"cycle".to_vec()]);
    }

    #[test]
    fn insert_delete_reinsert_same_name_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        // Fill to promote
        for i in 0..7u64 {
            let name = alloc::format!("filler_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);

        idx.insert(b"cycle", 10, 1, 1).unwrap();
        idx.delete(b"cycle").unwrap();
        idx.insert(b"cycle", 20, 2, 2).unwrap();

        let e = idx.lookup(b"cycle").unwrap();
        assert_eq!(e.inode_id, 20);
        assert_eq!(e.generation, 2);
        assert_eq!(e.kind, 2);
    }

    // ────────────────────────────────────────────────────────────────
    // Delete all entries → empty index
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn delete_all_entries_micro_results_in_empty() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"a", 1, 0, 1).unwrap();
        idx.insert(b"b", 2, 0, 1).unwrap();
        idx.insert(b"c", 3, 0, 1).unwrap();
        assert_eq!(idx.len(), 3);

        idx.delete(b"a").unwrap();
        idx.delete(b"b").unwrap();
        idx.delete(b"c").unwrap();

        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert_eq!(idx.list().len(), 0);
        assert_eq!(idx.range_scan(b"", 10).len(), 0);
        let (entries, _) = idx.list_from(DirCookie::START).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn delete_all_entries_btree_results_in_empty() {
        let mut idx = DirIndex::new(1, test_policy());
        let names: Vec<Vec<u8>> = (0..10u64)
            .map(|i| alloc::format!("entry_{i:02}").into_bytes())
            .collect();
        for name in &names {
            idx.insert(name, 1, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        assert_eq!(idx.len(), 10);

        for name in &names {
            idx.delete(name).unwrap();
        }

        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert_eq!(idx.list().len(), 0);
    }

    // ────────────────────────────────────────────────────────────────
    // Single-entry iteration
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn list_single_entry_micro() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"lonely", 42, 5, 3).unwrap();
        let entries = idx.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"lonely");
        assert_eq!(entries[0].inode_id, 42);
        assert_eq!(entries[0].generation, 5);
        assert_eq!(entries[0].kind, 3);
    }

    #[test]
    fn list_single_entry_btree() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..7u64 {
            let name = alloc::format!("pad_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(idx.representation(), DirStorageKind::BTREE);
        // Delete all but one
        for i in 0..6u64 {
            let name = alloc::format!("pad_{i:02}");
            idx.delete(name.as_bytes()).unwrap();
        }
        assert_eq!(idx.len(), 1);
        let entries = idx.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"pad_06");
    }

    // ────────────────────────────────────────────────────────────────
    // Concurrency design invariant: &self exposes no mutation paths
    // ────────────────────────────────────────────────────────────────

    /// Test that documents the design invariant: `DirIndex` uses `&mut self`
    /// for all mutation methods. Rust's borrow checker enforces at most one
    /// mutable reference at a time, preventing data races without locks.
    /// This test exercises the read-only API through a shared reference.
    #[test]
    fn shared_reference_exposes_only_read_only_operations() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"test", 10, 0, 1).unwrap();

        let shared: &DirIndex = &idx;

        // All of these are &self methods and must compile/run
        let _ = shared.lookup(b"test");
        let _ = shared.contains(b"test");
        let _ = shared.len();
        let _ = shared.is_empty();
        let _ = shared.representation();
        let _ = shared.directory_version();
        let _ = shared.is_dirty();
        let _ = shared.has_subdirs();
        let _ = shared.policy();
        let _ = shared.storage();
        let _ = shared.list();
        let _ = shared.list_from(DirCookie::START).unwrap();
        let _ = shared.range_scan(b"", 10);
        let _ = shared.to_bytes();
        // No mutation method is callable through &DirIndex — the borrow
        // checker would reject insert/delete/rename/replace/etc.
    }

    // ------------------------------------------------------------------
    // DirPrefetchWindow tests
    // ------------------------------------------------------------------

    #[test]
    fn prefetch_window_new_defaults() {
        let w = DirPrefetchWindow::new();
        assert_eq!(w.window_size(), DEFAULT_PREFETCH_WINDOW_SIZE);
        assert_eq!(w.cursor(), 0);
        assert_eq!(w.total_entries(), 0);
        assert!(!w.is_exhausted());
        assert!(!w.should_prefetch());
        assert!(w.is_in_last_window());
    }

    #[test]
    fn prefetch_window_with_custom_size() {
        let w = DirPrefetchWindow::with_window_size(32);
        assert_eq!(w.window_size(), 32);
    }

    #[test]
    fn prefetch_window_minimum_size_is_one() {
        let w = DirPrefetchWindow::with_window_size(0);
        assert_eq!(w.window_size(), 1);
    }

    #[test]
    fn prefetch_window_set_total_entries() {
        let mut w = DirPrefetchWindow::new();
        w.set_total_entries(200);
        assert_eq!(w.total_entries(), 200);
        assert_eq!(w.cursor(), 0);
        assert!(!w.is_exhausted());
        assert!(!w.is_in_last_window()); // 200 > 64, first window
    }

    #[test]
    fn prefetch_window_empty_directory_exhausted() {
        let mut w = DirPrefetchWindow::new();
        w.set_total_entries(0);
        assert!(w.is_exhausted());
        assert!(w.is_in_last_window());
        assert!(!w.should_prefetch());
        assert_eq!(w.remaining(), 0);
    }

    #[test]
    fn prefetch_window_advance_basic() {
        let mut w = DirPrefetchWindow::new();
        w.set_total_entries(10);
        for i in 0..10 {
            assert!(w.advance());
            assert_eq!(w.cursor(), i + 1);
        }
        assert!(w.is_exhausted());
        // Advancing past the end returns false
        assert!(!w.advance());
        assert_eq!(w.cursor(), 10);
        assert!(w.is_exhausted());
    }

    #[test]
    fn prefetch_window_small_directory_no_trigger() {
        // Directory smaller than window size: never triggers prefetch
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(30);
        // Walk through all entries
        for _ in 0..30 {
            assert!(
                !w.should_prefetch(),
                "small dir should not trigger prefetch"
            );
            w.advance();
        }
        assert!(w.is_exhausted());
        assert!(!w.should_prefetch());
    }

    #[test]
    fn prefetch_window_exact_window_size_no_trigger() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(64);
        for _ in 0..64 {
            assert!(
                !w.should_prefetch(),
                "exact-fit dir should not trigger prefetch"
            );
            w.advance();
        }
        assert!(w.is_exhausted());
    }

    #[test]
    fn prefetch_window_boundary_detection_at_75_percent() {
        // With window_size=64, trigger should fire at cursor 48 (75% of 64)
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(200); // 3+ windows

        // Walk to cursor 47 (just before trigger point)
        for _ in 0..47 {
            assert!(!w.should_prefetch(), "should not trigger before 75%");
            w.advance();
        }
        assert_eq!(w.cursor(), 47);
        // Still no trigger at 47 (one position before threshold)
        assert!(!w.should_prefetch());

        // Step to 48 → trigger fires
        w.advance();
        assert_eq!(w.cursor(), 48);
        assert!(w.should_prefetch(), "should trigger at 75% of window");
    }

    #[test]
    fn prefetch_window_acknowledge_suppresses_repeat_trigger() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(200);

        // Walk to trigger point
        for _ in 0..48 {
            w.advance();
        }
        assert!(w.should_prefetch());

        // Acknowledge the prefetch
        w.prefetch_acknowledged();
        assert!(
            !w.should_prefetch(),
            "should not re-trigger after acknowledge"
        );

        // Continue walking through the rest of this window — no re-trigger
        for _ in 48..64 {
            w.advance();
        }
        assert!(
            !w.should_prefetch(),
            "should not re-trigger in same window after ack"
        );

        // Walk past window boundary to 64 (start of second window)
        // At cursor 64, we're at the start of window 2. The trigger state
        // should re-evaluate. Let's advance further toward the second
        // window's trigger point (64 + 48 = 112).
        // But advance() doesn't reset prefetch_triggered.
        // Let's check if we're still in last_window... No, window_end is 128.
        // prefetch_triggered is still true, so should_prefetch is false.
        // The caller must reset or call a new method to clear the flag at
        // window boundaries. This is by design: the caller advances and
        // should clear prefetch_triggered when entering a new window.
        // Testing that here:
        assert!(!w.should_prefetch(), "still suppressed after one ack");
    }

    #[test]
    fn prefetch_window_seek_to_resets_trigger() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(200);

        // Walk to trigger point and acknowledge
        for _ in 0..48 {
            w.advance();
        }
        assert!(w.should_prefetch());
        w.prefetch_acknowledged();
        assert!(!w.should_prefetch());

        // Seek to a new position: trigger flag should reset
        w.seek_to(70);
        assert_eq!(w.cursor(), 70);
        assert!(!w.is_exhausted());

        // Now at cursor 70, we're in the second window (64-128).
        // consumed_in_window = 70 - 64 = 6, which is < 48, so no trigger yet.
        assert!(!w.should_prefetch());

        // Advance to 112 (64 + 48): trigger should fire again
        for _ in 70..112 {
            w.advance();
        }
        assert_eq!(w.cursor(), 112);
        assert!(
            w.should_prefetch(),
            "should re-trigger after seek and advance"
        );
    }

    #[test]
    fn prefetch_window_reset() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(200);

        for _ in 0..50 {
            w.advance();
        }
        assert_eq!(w.cursor(), 50);
        assert!(w.should_prefetch());

        w.reset();
        assert_eq!(w.cursor(), 0);
        assert!(!w.is_exhausted());
        assert!(!w.should_prefetch(), "reset should clear trigger flag");
    }

    #[test]
    fn prefetch_window_last_window_no_trigger() {
        // Directory with 100 entries, window_size=64
        // Window 1: [0, 64), Window 2: [64, 100) — last window has only 36 entries
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(100);

        // Walk into the second (last) window
        for _ in 0..65 {
            w.advance();
        }
        assert_eq!(w.cursor(), 65);
        assert!(
            w.is_in_last_window(),
            "at entry 65 of 100 should be last window"
        );
        // 75% of window_size = 48. consumed_in_window = 65 - 64 = 1 < 48, but
        // is_in_last_window prevents trigger.
        assert!(
            !w.should_prefetch(),
            "last window should not trigger prefetch"
        );

        // Walk further into last window
        for _ in 65..100 {
            w.advance();
        }
        assert!(w.is_exhausted());
        assert!(!w.should_prefetch());
    }

    #[test]
    fn prefetch_window_remaining_and_accessors() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(150);

        assert_eq!(w.remaining(), 150);
        for _ in 0..30 {
            w.advance();
        }
        assert_eq!(w.remaining(), 120);
        assert_eq!(w.cursor(), 30);
    }

    #[test]
    fn prefetch_window_window_boundaries() {
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(200);

        // Cursor 0: window_start=0, window_end=64
        assert_eq!(w.window_start(), 0);
        assert_eq!(w.window_end(), 64);
        assert!(!w.is_in_last_window());
        assert_eq!(w.next_window_start(), Some(64));
        assert_eq!(w.next_window_range(), Some((64, 128)));

        // Advance to cursor 64: second window
        for _ in 0..64 {
            w.advance();
        }
        assert_eq!(w.cursor(), 64);
        assert_eq!(w.window_start(), 64);
        assert_eq!(w.window_end(), 128);
        assert!(!w.is_in_last_window());
        assert_eq!(w.next_window_start(), Some(128));
        assert_eq!(w.next_window_range(), Some((128, 192)));

        // Advance to cursor 192: last window
        for _ in 64..192 {
            w.advance();
        }
        assert_eq!(w.cursor(), 192);
        assert_eq!(w.window_start(), 192);
        assert_eq!(w.window_end(), 200); // clamped to total
        assert!(w.is_in_last_window());
        assert_eq!(w.next_window_start(), None);
        assert_eq!(w.next_window_range(), None);
    }

    #[test]
    fn prefetch_window_partial_last_window() {
        // 70 entries with window_size=64: [0,64) then [64,70)
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(70);

        // First window
        assert_eq!(w.window_start(), 0);
        assert_eq!(w.window_end(), 64);
        assert!(!w.is_in_last_window());

        // Second window
        for _ in 0..65 {
            w.advance();
        }
        assert_eq!(w.cursor(), 65);
        assert_eq!(w.window_start(), 64);
        assert_eq!(w.window_end(), 70);
        assert!(w.is_in_last_window());
        assert_eq!(w.next_window_range(), None);
    }

    #[test]
    fn prefetch_window_multi_trigger_across_windows() {
        // 300 entries, window_size=64: windows at [0,64), [64,128), [128,192), [192,256), [256,300)
        // Each window except the last should trigger at 75% consumption.
        let mut w = DirPrefetchWindow::with_window_size(64);
        w.set_total_entries(300);

        let mut trigger_count = 0u32;
        loop {
            if w.should_prefetch() {
                trigger_count += 1;
                w.prefetch_acknowledged();
            }
            if !w.advance() {
                break;
            }
            // advance() resets prefetch_triggered when crossing a window
            // boundary, so the next window's trigger can fire.
        }

        // Windows: 0-64 (trigger), 64-128 (trigger), 128-192 (trigger),
        // 192-256 (trigger), 256-300 (last window, no trigger)
        assert_eq!(trigger_count, 4);
    }

    #[test]
    fn prefetch_window_advance_past_end_returns_false() {
        let mut w = DirPrefetchWindow::with_window_size(10);
        w.set_total_entries(3);
        assert!(w.advance()); // → 1
        assert!(w.advance()); // → 2
        assert!(w.advance()); // → 3 (exhausted)
        assert!(!w.advance()); // past end
        assert!(w.is_exhausted());
    }

    #[test]
    fn prefetch_window_seek_to_end_exhausted() {
        let mut w = DirPrefetchWindow::with_window_size(10);
        w.set_total_entries(50);
        w.seek_to(50);
        assert!(w.is_exhausted());
        assert_eq!(w.remaining(), 0);
        assert!(!w.should_prefetch());
    }

    #[test]
    fn prefetch_window_seek_to_beyond_total_clamped() {
        let mut w = DirPrefetchWindow::with_window_size(10);
        w.set_total_entries(50);
        w.seek_to(999);
        assert_eq!(w.cursor(), 50);
        assert!(w.is_exhausted());
    }

    #[test]
    fn prefetch_window_default_trait() {
        let w = DirPrefetchWindow::default();
        assert_eq!(w.window_size(), DEFAULT_PREFETCH_WINDOW_SIZE);
    }

    #[test]
    fn prefetch_window_re_set_total_entries_resets_state() {
        let mut w = DirPrefetchWindow::new();
        w.set_total_entries(200);
        for _ in 0..50 {
            w.advance();
        }
        assert_eq!(w.cursor(), 50);
        assert!(w.should_prefetch());

        // Re-set: should reset everything
        w.set_total_entries(100);
        assert_eq!(w.total_entries(), 100);
        assert_eq!(w.cursor(), 0);
        assert!(!w.is_exhausted());
        assert!(!w.should_prefetch());
    }

    // ── DirIndex + DirPrefetchWindow integration tests ───────────────

    #[test]
    fn dirindex_prefetch_window_initialized_on_new() {
        let idx = DirIndex::new(1, test_policy());
        let w = idx.prefetch_window();
        assert_eq!(w.window_size(), DEFAULT_PREFETCH_WINDOW_SIZE);
        assert_eq!(w.cursor(), 0);
        assert_eq!(w.total_entries(), 0);
    }

    #[test]
    fn dirindex_prefetch_window_syncs_on_iteration() {
        let mut idx = DirIndex::new(1, test_policy());
        // Insert entries larger than window size to trigger prefetch
        for i in 0..100u64 {
            let name = alloc::format!("entry_{i:03}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        // Walk through all entries
        let mut prefetch_triggers = 0u32;
        for _ in 0..100 {
            // Check the prefetch window before advancing.
            // Cannot call prefetch_acknowledged through &DirIndex, so we
            // count every time should_prefetch fires (it fires on every
            // step after the threshold until the window crosses).
            if idx.prefetch_window().should_prefetch() {
                prefetch_triggers += 1;
            }
            let entry = idx.next_entry();
            assert!(entry.is_some(), "should yield all entries");
        }
        // With 100 entries and window_size=64: first window [0,64) triggers
        // at cursor 48 and continues firing through cursor 63 (16 steps).
        // advance() clears the flag at cursor 64. Second window [64,100) is
        // too small (36 entries < 48 threshold) so no further triggers.
        assert_eq!(
            prefetch_triggers, 16,
            "trigger should fire from 48 to 63 inclusive"
        );
        assert!(idx.next_entry().is_none(), "exhausted after all entries");
    }

    #[test]
    fn dirindex_prefetch_window_reset_on_reset_cursor() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..100u64 {
            let name = alloc::format!("entry_{i:03}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        // Walk partway
        for _ in 0..50 {
            idx.next_entry();
        }
        assert_eq!(idx.prefetch_window().cursor(), 50);

        // Reset
        idx.reset_cursor();
        assert_eq!(idx.prefetch_window().cursor(), 0);
        assert!(!idx.prefetch_window().is_exhausted());
    }

    #[test]
    fn dirindex_prefetch_window_seek_to_updates_window() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..100u64 {
            let name = alloc::format!("entry_{i:03}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        idx.seek_to_cursor(DirCookie(DirCookie::encode_micro(70)));
        assert_eq!(idx.prefetch_window().cursor(), 70);
        assert!(!idx.prefetch_window().is_exhausted());
    }

    #[test]
    fn dirindex_prefetch_window_small_dir_no_trigger() {
        let mut idx = DirIndex::new(1, test_policy());
        for i in 0..30u64 {
            let name = alloc::format!("entry_{i:02}");
            idx.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        let mut triggered = false;
        for _ in 0..30 {
            if idx.prefetch_window().should_prefetch() {
                triggered = true;
            }
            idx.next_entry();
        }
        assert!(
            !triggered,
            "small dir within window_size should not trigger"
        );
    }

    #[test]
    fn dirindex_prefetch_window_empty_dir() {
        let mut idx = DirIndex::new(1, test_policy());
        assert!(idx.next_entry().is_none());
        assert!(idx.prefetch_window().is_exhausted());
        assert!(!idx.prefetch_window().should_prefetch());
    }

    #[test]
    fn dirindex_prefetch_window_accessor_available() {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"test", 1, 0, 1).unwrap();

        // Access prefetch window via immutable reference
        let w = idx.prefetch_window();
        let _ = w.window_size();
        let _ = w.cursor();
        let _ = w.total_entries();
        let _ = w.should_prefetch();

        // Advance iterator, check window follows
        idx.next_entry();
        assert_eq!(idx.prefetch_window().cursor(), 1);
    }

    // ────────────────────────────────────────────────────────────────
    // atomic_swap tests (cross-directory rename / exchange)
    //
    // Same-directory operations are covered by `rename`, `rename_overwrite`,
    // and `replace` tests elsewhere in this module.
    // ────────────────────────────────────────────────────────────────

    /// Helper: build a DirIndex with entries.
    fn dir_with_entries(ino: u64, entries: &[(&[u8], u64, u64, u32)]) -> DirIndex {
        let mut dir = DirIndex::new(ino, test_policy());
        for &(name, inode_id, gen, kind) in entries {
            dir.insert(name, inode_id, gen, kind).unwrap();
        }
        dir
    }

    // ── Cross-directory Rename mode ─────────────────────────────────

    #[test]
    fn atomic_swap_cross_dir_rename() {
        let mut src = dir_with_entries(1, &[(b"file", 10, 1, 1)]);
        let mut dst = DirIndex::new(2, test_policy());
        let overwritten =
            DirIndex::atomic_swap(&mut src, b"file", &mut dst, b"moved", SwapMode::Rename).unwrap();
        assert!(overwritten.is_none());
        assert!(!src.contains(b"file"));
        assert!(dst.contains(b"moved"));
        assert_eq!(dst.lookup(b"moved").unwrap().inode_id, 10);
        assert_eq!(src.len(), 0);
        assert_eq!(dst.len(), 1);
    }

    #[test]
    fn atomic_swap_cross_dir_rename_overwrite() {
        let mut src = dir_with_entries(1, &[(b"src_file", 10, 1, 1)]);
        let mut dst = dir_with_entries(2, &[(b"dst_file", 20, 2, 1)]);
        let overwritten = DirIndex::atomic_swap(
            &mut src,
            b"src_file",
            &mut dst,
            b"dst_file",
            SwapMode::Rename,
        )
        .unwrap();
        assert!(overwritten.is_some());
        assert_eq!(overwritten.unwrap().inode_id, 20);
        assert!(!src.contains(b"src_file"));
        assert!(dst.contains(b"dst_file"));
        assert_eq!(dst.lookup(b"dst_file").unwrap().inode_id, 10);
        assert_eq!(src.len(), 0);
        assert_eq!(dst.len(), 1);
    }

    #[test]
    fn atomic_swap_cross_dir_rename_missing_source() {
        let mut src = DirIndex::new(1, test_policy());
        let mut dst = DirIndex::new(2, test_policy());
        let result = DirIndex::atomic_swap(&mut src, b"nope", &mut dst, b"dest", SwapMode::Rename);
        assert_eq!(result, Err(DirIndexError::EntryNotFound));
    }

    // ── NoReplace mode ──────────────────────────────────────────────

    #[test]
    fn atomic_swap_noreplace_cross_dir_succeeds_when_target_absent() {
        let mut src = dir_with_entries(1, &[(b"file", 10, 1, 1)]);
        let mut dst = DirIndex::new(2, test_policy());
        let result =
            DirIndex::atomic_swap(&mut src, b"file", &mut dst, b"fresh", SwapMode::NoReplace);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(!src.contains(b"file"));
        assert!(dst.contains(b"fresh"));
        assert_eq!(dst.lookup(b"fresh").unwrap().inode_id, 10);
    }

    #[test]
    fn atomic_swap_noreplace_cross_dir_rejects_existing_target() {
        let mut src = dir_with_entries(1, &[(b"src_file", 10, 1, 1)]);
        let mut dst = dir_with_entries(2, &[(b"dst_file", 20, 2, 1)]);
        let result = DirIndex::atomic_swap(
            &mut src,
            b"src_file",
            &mut dst,
            b"dst_file",
            SwapMode::NoReplace,
        );
        assert_eq!(result, Err(DirIndexError::EntryAlreadyExists));
        assert!(src.contains(b"src_file"));
        assert!(dst.contains(b"dst_file"));
    }

    // ── Exchange mode ───────────────────────────────────────────────

    #[test]
    fn atomic_swap_exchange_cross_dir_swaps_inode_references() {
        let mut src = dir_with_entries(1, &[(b"alpha", 10, 1, 1)]);
        let mut dst = dir_with_entries(2, &[(b"beta", 20, 2, 1)]);
        let result =
            DirIndex::atomic_swap(&mut src, b"alpha", &mut dst, b"beta", SwapMode::Exchange);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(src.lookup(b"alpha").unwrap().inode_id, 20);
        assert_eq!(dst.lookup(b"beta").unwrap().inode_id, 10);
        assert_eq!(src.len(), 1);
        assert_eq!(dst.len(), 1);
    }

    #[test]
    fn atomic_swap_exchange_cross_dir_missing_source() {
        let mut src = DirIndex::new(1, test_policy());
        let mut dst = dir_with_entries(2, &[(b"beta", 20, 2, 1)]);
        let result =
            DirIndex::atomic_swap(&mut src, b"alpha", &mut dst, b"beta", SwapMode::Exchange);
        assert_eq!(result, Err(DirIndexError::EntryNotFound));
    }

    #[test]
    fn atomic_swap_exchange_cross_dir_missing_destination() {
        let mut src = dir_with_entries(1, &[(b"alpha", 10, 1, 1)]);
        let mut dst = DirIndex::new(2, test_policy());
        let result =
            DirIndex::atomic_swap(&mut src, b"alpha", &mut dst, b"beta", SwapMode::Exchange);
        assert_eq!(result, Err(DirIndexError::EntryNotFound));
    }

    // ── Directory version bumping ───────────────────────────────────

    #[test]
    fn atomic_swap_bumps_directory_version_on_both_sides() {
        let mut src = dir_with_entries(1, &[(b"file", 10, 1, 1)]);
        let mut dst = DirIndex::new(2, test_policy());
        let sv1 = src.directory_version();
        let dv1 = dst.directory_version();

        DirIndex::atomic_swap(&mut src, b"file", &mut dst, b"moved", SwapMode::Rename).unwrap();

        assert!(src.directory_version() > sv1);
        assert!(dst.directory_version() > dv1);
    }

    #[test]
    fn atomic_swap_exchange_bumps_both_versions() {
        let mut src = dir_with_entries(1, &[(b"a", 10, 1, 1)]);
        let mut dst = dir_with_entries(2, &[(b"b", 20, 2, 1)]);
        let sv1 = src.directory_version();
        let dv1 = dst.directory_version();

        DirIndex::atomic_swap(&mut src, b"a", &mut dst, b"b", SwapMode::Exchange).unwrap();

        assert!(src.directory_version() > sv1);
        assert!(dst.directory_version() > dv1);
    }

    // ── BTree coverage ──────────────────────────────────────────────

    #[test]
    fn atomic_swap_rename_works_across_btree_directories() {
        let mut src = DirIndex::new(1, test_policy());
        for i in 0..7u64 {
            let name = alloc::format!("pad_{i:02}");
            src.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        assert_eq!(src.representation(), DirStorageKind::BTREE);
        src.insert(b"target", 99, 1, 1).unwrap();

        let mut dst = DirIndex::new(2, test_policy());

        DirIndex::atomic_swap(&mut src, b"target", &mut dst, b"landed", SwapMode::Rename).unwrap();

        assert!(!src.contains(b"target"));
        assert!(dst.contains(b"landed"));
        assert_eq!(dst.lookup(b"landed").unwrap().inode_id, 99);
    }

    #[test]
    fn atomic_swap_exchange_works_across_btree_directories() {
        let mut src = DirIndex::new(1, test_policy());
        for i in 0..7u64 {
            let name = alloc::format!("src_pad_{i:02}");
            src.insert(name.as_bytes(), i, 0, 1).unwrap();
        }
        src.insert(b"alpha", 10, 1, 1).unwrap();
        assert_eq!(src.representation(), DirStorageKind::BTREE);

        let mut dst = DirIndex::new(2, test_policy());
        for i in 0..7u64 {
            let name = alloc::format!("dst_pad_{i:02}");
            dst.insert(name.as_bytes(), 100 + i, 0, 1).unwrap();
        }
        dst.insert(b"beta", 20, 2, 1).unwrap();
        assert_eq!(dst.representation(), DirStorageKind::BTREE);

        DirIndex::atomic_swap(&mut src, b"alpha", &mut dst, b"beta", SwapMode::Exchange).unwrap();

        assert_eq!(src.lookup(b"alpha").unwrap().inode_id, 20);
        assert_eq!(dst.lookup(b"beta").unwrap().inode_id, 10);
        assert!(src.contains(b"src_pad_00"));
        assert!(dst.contains(b"dst_pad_00"));
    }

    // ── Cross-directory directory moves ─────────────────────────────

    #[test]
    fn atomic_swap_cross_dir_move_directory_entry() {
        let mut src = dir_with_entries(1, &[(b"subdir", 100, 1, 0 /* KIND_DIR */)]);
        let mut dst = DirIndex::new(2, test_policy());

        DirIndex::atomic_swap(
            &mut src,
            b"subdir",
            &mut dst,
            b"moved_subdir",
            SwapMode::Rename,
        )
        .unwrap();

        assert!(!src.contains(b"subdir"));
        assert!(dst.contains(b"moved_subdir"));
        assert_eq!(dst.lookup(b"moved_subdir").unwrap().inode_id, 100);
        assert_eq!(dst.lookup(b"moved_subdir").unwrap().kind, 0);
    }

    // ── Overwrite returns correct entry ─────────────────────────────

    #[test]
    fn atomic_swap_overwrite_returns_correct_victim() {
        let mut src = dir_with_entries(1, &[(b"winner", 10, 1, 1)]);
        let mut dst = dir_with_entries(2, &[(b"victim", 99, 5, 1)]);
        let overwritten =
            DirIndex::atomic_swap(&mut src, b"winner", &mut dst, b"victim", SwapMode::Rename)
                .unwrap();
        assert!(overwritten.is_some());
        let victim = overwritten.unwrap();
        assert_eq!(victim.inode_id, 99);
        assert_eq!(victim.generation, 5);
        assert_eq!(victim.kind, 1);
    }
}
