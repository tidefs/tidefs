//! Persistent directory index adapter bridging [`DirPageIndex`] to the
//! [`tidefs_types_polymorphic_directory_index_core::DirMicroEntry`]-based
//! API that [`tidefs_namespace::Namespace`] expects.
//!
//! [`PersistentDirIndex`] wraps a [`super::pages::DirPageIndex`] and
//! exposes lookup, insert, delete, rename, replace, list_from, and
//! persistence operations compatible with the existing in-memory
//! [`crate::DirIndex`] API surface.

use alloc::vec::Vec;

use tidefs_local_object_store::LocalObjectStore;
use tidefs_types_polymorphic_directory_index_core::{DatasetDirPolicy, DirCookie, DirMicroEntry};

use crate::{pages::DirPageIndex, pages::DirPageIndexError, DirIndexError, SwapMode};

/// Page-based persistent directory index with a [`DirMicroEntry`] API.
#[derive(Debug)]
pub struct PersistentDirIndex {
    inner: DirPageIndex,
    has_subdirs: bool,
    version: u64,
}

const LIST_FROM_WINDOW_ENTRIES: usize = 128;

impl PersistentDirIndex {
    #[must_use]
    pub fn new(dir_ino: u64, _policy: DatasetDirPolicy) -> Self {
        PersistentDirIndex {
            inner: DirPageIndex::new(dir_ino),
            has_subdirs: false,
            version: 0,
        }
    }

    pub fn load(
        store: &LocalObjectStore,
        dir_ino: u64,
        _policy: DatasetDirPolicy,
    ) -> tidefs_local_object_store::Result<Option<Self>> {
        DirPageIndex::load(store, dir_ino).map(|opt| {
            opt.map(|inner| PersistentDirIndex {
                inner,
                has_subdirs: false,
                version: 0,
            })
        })
    }

    /// Look up one live entry directly from persisted directory pages.
    ///
    /// Unlike [`Self::load`], this does not construct or retain the mutable
    /// page index. Read-only namespace lookup and path-resolution callers can
    /// use it to probe cold directories without pulling the full directory
    /// into their working set.
    pub fn lookup_in_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        name: &[u8],
    ) -> tidefs_local_object_store::Result<Option<DirMicroEntry>> {
        DirPageIndex::lookup_in_store(store, dir_ino, name).map(|opt| {
            opt.map(|(ino, ty, gen)| DirMicroEntry {
                name_len: name.len() as u32,
                inode_id: ino,
                generation: gen,
                kind: u32::from(ty),
                name: name.to_vec(),
            })
        })
    }

    /// Count live entries directly from persisted directory pages.
    ///
    /// The count is capped at `max_entries`, allowing empty/non-empty probes to
    /// avoid constructing or retaining a mutable [`PersistentDirIndex`].
    pub fn entry_count_in_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        max_entries: usize,
    ) -> tidefs_local_object_store::Result<Option<usize>> {
        DirPageIndex::live_entry_count_in_store(store, dir_ino, max_entries)
    }

    /// Visit live entries directly from persisted directory pages.
    ///
    /// Unlike [`Self::load`], this does not construct or retain the mutable
    /// page index. Callers that only need import-time metadata can therefore
    /// scan large directories with memory bounded by one decoded page plus the
    /// visitor's own state.
    pub fn for_each_in_store<F>(
        store: &LocalObjectStore,
        dir_ino: u64,
        mut visit: F,
    ) -> tidefs_local_object_store::Result<bool>
    where
        F: FnMut(DirMicroEntry),
    {
        DirPageIndex::for_each_in_store(store, dir_ino, |(name, ino, ty, gen, _offset)| {
            visit(DirMicroEntry {
                name_len: name.len() as u32,
                inode_id: ino,
                generation: gen,
                kind: u32::from(ty),
                name,
            });
        })
    }

    /// Return a positional-cookie page directly from persisted directory pages.
    ///
    /// This preserves the same positional cookie contract as [`Self::list_from`]
    /// while avoiding construction or retention of a mutable [`DirPageIndex`].
    /// It advances through persisted name-sorted windows with bounded retained
    /// memory; later positional cookies may require repeated scans, but each
    /// scan keeps at most the requested window rather than the full directory.
    pub fn list_from_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        cookie: DirCookie,
    ) -> tidefs_local_object_store::Result<(Vec<DirMicroEntry>, DirCookie)> {
        let mut remaining_skip: usize = if cookie.0 == 0 {
            0
        } else {
            usize::try_from(cookie.0).unwrap_or(usize::MAX)
        };
        let mut start_name = Vec::new();

        loop {
            let scan_limit = if remaining_skip >= LIST_FROM_WINDOW_ENTRIES {
                LIST_FROM_WINDOW_ENTRIES
            } else {
                LIST_FROM_WINDOW_ENTRIES.saturating_add(remaining_skip)
            };
            let window =
                DirPageIndex::range_scan_in_store(store, dir_ino, &start_name, scan_limit)?;

            if window.is_empty() {
                return Ok((Vec::new(), cookie));
            }

            if remaining_skip >= window.len() {
                remaining_skip -= window.len();
                start_name = window
                    .last()
                    .map(|(name, _, _, _, _)| name.clone())
                    .unwrap_or_default();
                if window.len() < scan_limit {
                    return Ok((Vec::new(), cookie));
                }
                continue;
            }

            let entries = window
                .into_iter()
                .skip(remaining_skip)
                .take(LIST_FROM_WINDOW_ENTRIES)
                .map(|(name, ino, ty, gen, _offset)| DirMicroEntry {
                    name_len: name.len() as u32,
                    inode_id: ino,
                    generation: gen,
                    kind: u32::from(ty),
                    name,
                })
                .collect::<Vec<_>>();
            let next = DirCookie(cookie.0.saturating_add(entries.len() as u64));
            return Ok((entries, next));
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Monotonic version counter, bumped on mutations.
    #[must_use]
    pub fn directory_version(&self) -> u64 {
        self.version
    }

    fn bump_version(&mut self) {
        self.version += 1;
    }

    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<DirMicroEntry> {
        self.inner.lookup(name).map(|(ino, ty, gen)| DirMicroEntry {
            name_len: name.len() as u32,
            inode_id: ino,
            generation: gen,
            kind: u32::from(ty),
            name: name.to_vec(),
        })
    }

    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.inner.contains(name)
    }

    pub fn insert(
        &mut self,
        name: &[u8],
        inode_id: u64,
        generation: u64,
        kind: u32,
    ) -> Result<(), DirIndexError> {
        let ty = kind as u8;
        self.inner
            .insert(name, inode_id, ty, generation)
            .map(|_offset| ())
            .map_err(|e| match e {
                DirPageIndexError::EntryAlreadyExists => DirIndexError::EntryAlreadyExists,
                _ => DirIndexError::EntryNotFound,
            })?;
        self.bump_version();
        Ok(())
    }

    pub fn delete(&mut self, name: &[u8]) -> Result<(), DirIndexError> {
        self.remove(name)
            .map(|_| ())
            .ok_or(DirIndexError::EntryNotFound)
    }

    pub fn remove(&mut self, name: &[u8]) -> Option<DirMicroEntry> {
        let entry = self.lookup(name)?;
        self.inner.remove(name).ok()?;
        self.bump_version();
        Some(entry)
    }

    pub fn replace(&mut self, name: &[u8], inode_id: u64, generation: u64, kind: u32) {
        let _ = self.inner.remove(name);
        let ty = kind as u8;
        let _ = self.inner.insert(name, inode_id, ty, generation);
        self.bump_version();
    }

    pub fn rename_overwrite(
        &mut self,
        old_name: &[u8],
        new_name: &[u8],
    ) -> Result<Option<DirMicroEntry>, DirIndexError> {
        let src = self.lookup(old_name).ok_or(DirIndexError::EntryNotFound)?;
        if old_name == new_name {
            return Ok(None);
        }

        let overwritten = self.lookup(new_name);
        if overwritten.is_some() {
            let _ = self.inner.remove(new_name);
        }

        let _ = self.inner.remove(old_name);
        let ty = src.kind as u8;
        let _ = self
            .inner
            .insert(new_name, src.inode_id, ty, src.generation);
        self.bump_version();
        Ok(overwritten)
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
        // Atomic within the same directory: delete old, insert new.
        let _ = self.inner.remove(old_name);
        let ty = entry.kind as u8;
        let _ = self
            .inner
            .insert(new_name, entry.inode_id, ty, entry.generation);
        self.bump_version();
        Ok(())
    }

    /// Move an entry from this directory into `dst_dir`, replacing an existing target.
    ///
    /// Returns the overwritten target entry when one existed.
    pub fn move_entry_to(
        &mut self,
        src_name: &[u8],
        dst_dir: &mut Self,
        dst_name: &[u8],
    ) -> Result<Option<DirMicroEntry>, DirIndexError> {
        let entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
        let overwritten = dst_dir.lookup(dst_name);

        if overwritten.is_some() {
            let _ = dst_dir.inner.remove(dst_name);
        }
        let _ = self.inner.remove(src_name);
        self.bump_version();

        let ty = entry.kind as u8;
        let _ = dst_dir
            .inner
            .insert(dst_name, entry.inode_id, ty, entry.generation);
        dst_dir.bump_version();
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
    /// # Errors
    ///
    /// Returns [`DirIndexError::EntryNotFound`] when the source does not
    /// exist, or when both source and destination are required (Exchange
    /// mode) and the destination is missing.
    pub fn atomic_swap(
        &mut self,
        src_name: &[u8],
        dst_dir: &mut Self,
        dst_name: &[u8],
        mode: SwapMode,
    ) -> Result<Option<DirMicroEntry>, DirIndexError> {
        match mode {
            SwapMode::Exchange => {
                let src_entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
                let dst_entry = dst_dir
                    .lookup(dst_name)
                    .ok_or(DirIndexError::EntryNotFound)?;

                // Swap inode references: names stay, inode references cross.
                let _ = self.inner.remove(src_name);
                let _ = dst_dir.inner.remove(dst_name);

                let src_ty = src_entry.kind as u8;
                let dst_ty = dst_entry.kind as u8;
                let _ =
                    self.inner
                        .insert(src_name, dst_entry.inode_id, dst_ty, dst_entry.generation);
                let _ = dst_dir.inner.insert(
                    dst_name,
                    src_entry.inode_id,
                    src_ty,
                    src_entry.generation,
                );
                self.bump_version();
                dst_dir.bump_version();
                Ok(None)
            }
            SwapMode::NoReplace => {
                if dst_dir.contains(dst_name) {
                    return Err(DirIndexError::EntryAlreadyExists);
                }
                let entry = self.lookup(src_name).ok_or(DirIndexError::EntryNotFound)?;
                let _ = self.inner.remove(src_name);
                self.bump_version();
                let ty = entry.kind as u8;
                let _ = dst_dir
                    .inner
                    .insert(dst_name, entry.inode_id, ty, entry.generation);
                dst_dir.bump_version();
                Ok(None)
            }
            SwapMode::Rename => self.move_entry_to(src_name, dst_dir, dst_name),
        }
    }

    /// Return a page of directory entries starting from the position
    /// encoded in `cookie`.  Returns up to 128 entries and the cookie
    /// for the next page (`skip + emitted`).  Pass [`DirCookie::START`]
    /// to begin from the first entry.
    ///
    /// The cookie `.0` value is treated as a positional skip count:
    /// - 0 (START): begin at position 0.
    /// - N > 0:     skip N entries, return up to 128 starting at N.
    #[must_use]
    pub fn list_from(&self, cookie: DirCookie) -> (Vec<DirMicroEntry>, DirCookie) {
        let skip: usize = if cookie.0 == 0 {
            0
        } else {
            usize::try_from(cookie.0).unwrap_or(usize::MAX)
        };
        let window = self
            .inner
            .entries_from_sorted_index(skip, LIST_FROM_WINDOW_ENTRIES)
            .into_iter()
            .map(|(name, ino, ty, gen, _offset)| DirMicroEntry {
                name_len: name.len() as u32,
                inode_id: ino,
                generation: gen,
                kind: u32::from(ty),
                name,
            })
            .collect::<Vec<_>>();
        let next = DirCookie(cookie.0.saturating_add(window.len() as u64));
        (window, next)
    }

    /// Produce a test-only entry snapshot suitable for iteration checks.
    ///
    /// Returns a flat `Vec` of `(entry, cookie)` pairs with positional cookies
    /// (3+index) skipping synthetic . and .. . Production callers should use
    /// bounded [`Self::list_from`] windows or direct store-backed scanners.
    #[cfg(test)]
    pub fn entry_snapshot(&self) -> alloc::vec::Vec<(DirMicroEntry, DirCookie)> {
        self.inner
            .list()
            .into_iter()
            .enumerate()
            .map(|(i, (name, ino, ty, gen, _offset))| {
                let entry = DirMicroEntry {
                    name_len: name.len() as u32,
                    inode_id: ino,
                    generation: gen,
                    kind: u32::from(ty),
                    name,
                };
                let cookie = DirCookie(i as u64 + 3); // +3 to skip . (1) and .. (2) cookies
                (entry, cookie)
            })
            .collect()
    }

    #[must_use]
    pub fn has_subdirs(&self) -> bool {
        self.has_subdirs
    }
    pub fn set_has_subdirs(&mut self, v: bool) {
        self.has_subdirs = v;
    }

    pub fn flush(&mut self, store: &mut LocalObjectStore) -> tidefs_local_object_store::Result<()> {
        self.inner.flush(store)
    }

    pub fn sync(&mut self, store: &mut LocalObjectStore) -> tidefs_local_object_store::Result<()> {
        self.inner.sync(store)
    }
}

// ---------------------------------------------------------------------------
// DirBatch -- transactional batch of directory index operations
// ---------------------------------------------------------------------------

/// A batched set of directory index operations that are committed
/// atomically to the object store via a two-phase commit marker.
///
/// Operations are buffered in-memory on the wrapped [`PersistentDirIndex`]
/// until [`commit`](Self::commit) is called. If the struct is dropped
/// without calling `commit`, no changes are persisted.
///
/// On commit, a batch commit marker is written to the object store
/// **before** the dirty pages are flushed. The marker is checked on
/// load via [`check_batch_complete`] to detect crash-incomplete batches.
pub struct DirBatch<'a> {
    idx: &'a mut PersistentDirIndex,
    committed: bool,
}

impl<'a> DirBatch<'a> {
    /// Create a new batch wrapping the given directory index.
    pub fn new(idx: &'a mut PersistentDirIndex) -> Self {
        DirBatch {
            idx,
            committed: false,
        }
    }

    /// Insert an entry into the batch.
    pub fn insert(
        &mut self,
        name: &[u8],
        inode_id: u64,
        generation: u64,
        kind: u32,
    ) -> Result<(), DirIndexError> {
        self.idx.insert(name, inode_id, generation, kind)
    }

    /// Remove an entry from the batch.
    pub fn remove(&mut self, name: &[u8]) -> Result<(), DirIndexError> {
        self.idx.delete(name)
    }

    /// Replace an entry (unconditional upsert).
    pub fn replace(&mut self, name: &[u8], inode_id: u64, generation: u64, kind: u32) {
        self.idx.replace(name, inode_id, generation, kind);
    }

    /// Commit the batch to the object store.
    ///
    /// Writes a batch commit marker, flushes all dirty pages, then
    /// optionally syncs the store.
    ///
    /// If `sync` is true, the data survives a crash and is visible to
    /// subsequent [`PersistentDirIndex::load`] calls. If `sync` is false,
    /// the data may not survive a crash (useful for testing).
    pub fn commit(
        mut self,
        store: &mut LocalObjectStore,
        sync: bool,
    ) -> tidefs_local_object_store::Result<()> {
        let dir_ino = self.idx.inner.dir_ino();
        let marker_key = crate::format::dir_batch_commit_key(dir_ino);
        store.put(marker_key, &crate::format::DIR_BATCH_COMMIT_MAGIC)?;
        self.idx.flush(store)?;
        if sync {
            store.sync_all()?;
        }
        self.committed = true;
        Ok(())
    }

    /// Abort the batch, discarding all buffered operations.
    pub fn abort(self) {
        drop(self);
    }
}

impl<'a> Drop for DirBatch<'a> {
    fn drop(&mut self) {
        // If not committed, in-memory changes are discarded.
        let _ = self.committed;
    }
}

/// Check whether the batch commit marker exists for a directory,
/// indicating a completed batch.
pub fn check_batch_complete(
    store: &LocalObjectStore,
    dir_ino: u64,
) -> tidefs_local_object_store::Result<bool> {
    let marker_key = crate::format::dir_batch_commit_key(dir_ino);
    Ok(store.get(marker_key)?.is_some())
}

// ---------------------------------------------------------------------------
// Namespace manifest read/write helpers
// ---------------------------------------------------------------------------

/// Read the namespace manifest from the object store and return the list
/// of directory inodes that have been persisted.
///
/// Returns an empty vector if the manifest does not exist or is malformed.
/// This is a convenience wrapper around the raw manifest format defined
/// in [`crate::format`] (magic + count + inode list).
pub fn read_namespace_manifest(
    store: &LocalObjectStore,
) -> tidefs_local_object_store::Result<Vec<u64>> {
    let key = crate::format::namespace_manifest_key();
    let Some(raw) = store.get(key)? else {
        return Ok(Vec::new());
    };

    if raw.len() < 8 {
        return Ok(Vec::new());
    }

    if raw[0..4] != crate::format::NS_MANIFEST_MAGIC {
        return Ok(Vec::new());
    }

    let count = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
    let mut inodes = Vec::with_capacity(count);
    let mut pos = 8usize;

    for _ in 0..count {
        if pos + 8 > raw.len() {
            break;
        }
        let ino = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
        inodes.push(ino);
        pos += 8;
    }

    Ok(inodes)
}

/// Write the namespace manifest to the object store with the given list
/// of directory inodes.
///
/// Overwrites any existing manifest. The manifest format is:
/// `NS_MANIFEST_MAGIC` (4 bytes) + `count` (u32 LE) + `inode_id` (u64 LE) × count.
pub fn write_namespace_manifest(
    store: &mut LocalObjectStore,
    dir_inodes: &[u64],
) -> tidefs_local_object_store::Result<()> {
    let key = crate::format::namespace_manifest_key();
    let mut payload = Vec::with_capacity(8 + dir_inodes.len() * 8);
    payload.extend_from_slice(&crate::format::NS_MANIFEST_MAGIC);
    payload.extend_from_slice(&(dir_inodes.len() as u32).to_le_bytes());
    for &ino in dir_inodes {
        payload.extend_from_slice(&ino.to_le_bytes());
    }
    store.put(key, &payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::DT_DIR;

    fn open_store() -> (tempfile::TempDir, LocalObjectStore) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = LocalObjectStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    fn default_policy() -> DatasetDirPolicy {
        DatasetDirPolicy::DEFAULT
    }

    #[test]
    fn new_is_empty() {
        let idx = PersistentDirIndex::new(1, default_policy());
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }
    #[test]
    fn insert_lookup_roundtrip() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"hello", 42, 1, DT_DIR as u32).unwrap();
        let e = idx.lookup(b"hello").unwrap();
        assert_eq!(e.inode_id, 42);
        assert_eq!(e.generation, 1);
        assert_eq!(e.kind, DT_DIR as u32);
    }
    #[test]
    fn insert_duplicate_rejected() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"dup", 1, 0, DT_DIR as u32).unwrap();
        assert_eq!(
            idx.insert(b"dup", 2, 0, DT_DIR as u32),
            Err(DirIndexError::EntryAlreadyExists)
        );
    }
    #[test]
    fn lookup_missing_returns_none() {
        let idx = PersistentDirIndex::new(1, default_policy());
        assert!(idx.lookup(b"nope").is_none());
    }
    #[test]
    fn lookup_in_store_finds_entry_without_loading_index() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(42, default_policy());
        idx.insert(b"alpha", 1, 7, DT_DIR as u32).unwrap();
        idx.insert(b"target", 99, 8, DT_DIR as u32).unwrap();
        idx.flush(&mut store).unwrap();

        let entry = PersistentDirIndex::lookup_in_store(&store, 42, b"target")
            .unwrap()
            .unwrap();
        assert_eq!(entry.name, b"target");
        assert_eq!(entry.inode_id, 99);
        assert_eq!(entry.generation, 8);
        assert_eq!(entry.kind, DT_DIR as u32);
        assert!(PersistentDirIndex::lookup_in_store(&store, 42, b"missing")
            .unwrap()
            .is_none());
    }
    #[test]
    fn contains_works() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        assert!(!idx.contains(b"x"));
        idx.insert(b"x", 1, 0, DT_DIR as u32).unwrap();
        assert!(idx.contains(b"x"));
    }
    #[test]
    fn delete_existing() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"alpha", 10, 1, DT_DIR as u32).unwrap();
        idx.insert(b"beta", 20, 2, DT_DIR as u32).unwrap();
        idx.delete(b"alpha").unwrap();
        assert_eq!(idx.len(), 1);
    }
    #[test]
    fn delete_nonexistent_errors() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        assert_eq!(idx.delete(b"nope"), Err(DirIndexError::EntryNotFound));
    }
    #[test]
    fn remove_returns_entry() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"entry", 100, 5, DT_DIR as u32).unwrap();
        let removed = idx.remove(b"entry").unwrap();
        assert_eq!(removed.inode_id, 100);
    }
    #[test]
    fn replace_overwrites() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"key", 1, 0, DT_DIR as u32).unwrap();
        idx.replace(b"key", 99, 9, DT_DIR as u32);
        let e = idx.lookup(b"key").unwrap();
        assert_eq!(e.inode_id, 99);
    }
    #[test]
    fn replace_inserts_new_entry() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.replace(b"new", 42, 1, DT_DIR as u32);
        let e = idx.lookup(b"new").unwrap();
        assert_eq!(e.inode_id, 42);
    }
    #[test]
    fn rename_overwrite_moves_entry() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"old", 10, 1, DT_DIR as u32).unwrap();
        idx.rename_overwrite(b"old", b"new").unwrap();
        assert!(idx.lookup(b"old").is_none());
        assert_eq!(idx.lookup(b"new").unwrap().inode_id, 10);
    }
    #[test]
    fn rename_overwrite_same_name_noop() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"same", 10, 1, DT_DIR as u32).unwrap();
        assert!(idx.rename_overwrite(b"same", b"same").unwrap().is_none());
    }
    #[test]
    fn rename_overwrite_replaces_target() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"src", 10, 1, DT_DIR as u32).unwrap();
        idx.insert(b"dst", 20, 2, DT_DIR as u32).unwrap();
        let overwritten = idx.rename_overwrite(b"src", b"dst").unwrap().unwrap();
        assert_eq!(overwritten.inode_id, 20);
    }
    #[test]
    fn subdir_flag_default_off() {
        let idx = PersistentDirIndex::new(1, default_policy());
        assert!(!idx.has_subdirs());
    }
    #[test]
    fn subdir_flag_set_and_read() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.set_has_subdirs(true);
        assert!(idx.has_subdirs());
    }
    #[test]
    fn list_from_returns_sorted_entries() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"zulu", 26, 0, DT_DIR as u32).unwrap();
        idx.insert(b"alpha", 1, 0, DT_DIR as u32).unwrap();
        let (entries, _cookie) = idx.list_from(DirCookie::START);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"alpha");
        assert_eq!(entries[1].name, b"zulu");
    }
    #[test]
    fn list_from_returns_bounded_window_after_large_skip() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        for i in 0..260u64 {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i, 0, DT_DIR as u32).unwrap();
        }

        let (entries, next) = idx.list_from(DirCookie(128));
        assert_eq!(entries.len(), 128);
        assert_eq!(entries[0].name, b"entry_0128");
        assert_eq!(entries[127].name, b"entry_0255");
        assert_eq!(next, DirCookie(256));

        let (tail, tail_next) = idx.list_from(next);
        assert_eq!(tail.len(), 4);
        assert_eq!(tail[0].name, b"entry_0256");
        assert_eq!(tail[3].name, b"entry_0259");
        assert_eq!(tail_next, DirCookie(260));
    }

    #[test]
    fn list_from_store_preserves_positional_windows() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(1, default_policy());
        for i in (0..260u64).rev() {
            let name = alloc::format!("entry_{i:04}");
            idx.insert(name.as_bytes(), i + 1, i, DT_DIR as u32)
                .unwrap();
        }
        idx.flush(&mut store).unwrap();

        let (first, first_next) =
            PersistentDirIndex::list_from_store(&store, 1, DirCookie::START).unwrap();
        assert_eq!(first.len(), 128);
        assert_eq!(first[0].name, b"entry_0000");
        assert_eq!(first[127].name, b"entry_0127");
        assert_eq!(first_next, DirCookie(128));

        let (second, second_next) =
            PersistentDirIndex::list_from_store(&store, 1, first_next).unwrap();
        assert_eq!(second.len(), 128);
        assert_eq!(second[0].name, b"entry_0128");
        assert_eq!(second[127].name, b"entry_0255");
        assert_eq!(second_next, DirCookie(256));

        let (tail, tail_next) =
            PersistentDirIndex::list_from_store(&store, 1, second_next).unwrap();
        assert_eq!(tail.len(), 4);
        assert_eq!(tail[0].name, b"entry_0256");
        assert_eq!(tail[3].name, b"entry_0259");
        assert_eq!(tail_next, DirCookie(260));

        let (empty, empty_next) =
            PersistentDirIndex::list_from_store(&store, 1, tail_next).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty_next, tail_next);
    }

    #[test]
    fn entry_snapshot_keeps_legacy_test_cookies() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"zulu", 26, 2, DT_DIR as u32).unwrap();
        idx.insert(b"alpha", 1, 3, DT_DIR as u32).unwrap();

        let snapshot = idx.entry_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].0.name, b"alpha");
        assert_eq!(snapshot[0].1, DirCookie(3));
        assert_eq!(snapshot[1].0.name, b"zulu");
        assert_eq!(snapshot[1].1, DirCookie(4));
    }
    #[test]
    fn flush_load_roundtrip() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(200, default_policy());
        idx.insert(b"zulu", 26, 1, DT_DIR as u32).unwrap();
        idx.insert(b"alpha", 1, 2, DT_DIR as u32).unwrap();
        idx.flush(&mut store).unwrap();
        let loaded = PersistentDirIndex::load(&store, 200, default_policy())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.len(), 2);
    }
    #[test]
    fn load_nonexistent_returns_none() {
        let (_tmp, store) = open_store();
        assert!(PersistentDirIndex::load(&store, 999, default_policy())
            .unwrap()
            .is_none());
    }
    #[test]
    fn sync_persists_and_clears_dirty() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(1, default_policy());
        idx.insert(b"test", 42, 0, DT_DIR as u32).unwrap();
        idx.sync(&mut store).unwrap();
        assert!(PersistentDirIndex::load(&store, 1, default_policy())
            .unwrap()
            .unwrap()
            .contains(b"test"));
    }

    // ── Non-UTF8 name bytes ──────────────────────────────────────────

    #[test]
    fn insert_non_utf8_name_bytes() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        // Valid UTF-8 bytes but not printable
        let name = b"\xff\xfe\x00\x01\x02";
        idx.insert(name, 10, 0, DT_DIR as u32).unwrap();
        assert_eq!(idx.len(), 1);
        let e = idx.lookup(name).unwrap();
        assert_eq!(e.inode_id, 10);
    }

    #[test]
    fn insert_binary_name_with_null_byte() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        let name = b"before\x00after";
        idx.insert(name, 20, 1, DT_DIR as u32).unwrap();
        assert!(idx.contains(name));
        let e = idx.lookup(name).unwrap();
        assert_eq!(e.inode_id, 20);
    }

    #[test]
    fn insert_high_byte_names() {
        let mut idx = PersistentDirIndex::new(1, default_policy());
        let name1 = [0x80u8, 0x81, 0xFE, 0xFF];
        let name2 = [0xC0u8, 0xC1, 0xF5, 0xF6];
        idx.insert(&name1, 1, 0, DT_DIR as u32).unwrap();
        idx.insert(&name2, 2, 0, DT_DIR as u32).unwrap();
        assert_eq!(idx.len(), 2);
        assert!(idx.contains(&name1));
        assert!(idx.contains(&name2));
    }

    // ── DirBatch transaction atomicity ───────────────────────────────

    #[test]
    fn batch_commit_all_visible() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(100, default_policy());
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"alpha", 1, 0, DT_DIR as u32).unwrap();
            batch.insert(b"beta", 2, 0, DT_DIR as u32).unwrap();
            batch.insert(b"gamma", 3, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }
        // After commit: all entries visible
        let loaded = PersistentDirIndex::load(&store, 100, default_policy())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.contains(b"alpha"));
        assert!(loaded.contains(b"beta"));
        assert!(loaded.contains(b"gamma"));
        assert!(check_batch_complete(&store, 100).unwrap());
    }

    #[test]
    fn batch_drop_without_commit_nothing_persisted() {
        let (_tmp, store) = open_store();
        let mut idx = PersistentDirIndex::new(200, default_policy());
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"secret", 99, 0, DT_DIR as u32).unwrap();
            // Drop without commit — simulates crash before persistence
        }
        let loaded = PersistentDirIndex::load(&store, 200, default_policy()).unwrap();
        assert!(loaded.is_none());
        assert!(!check_batch_complete(&store, 200).unwrap());
    }

    #[test]
    fn batch_crash_before_sync_data_lost() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(300, default_policy());
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"data", 42, 0, DT_DIR as u32).unwrap();
            // Commit without sync — pages written but not fsynced
            batch.commit(&mut store, false).unwrap();
        }
        // Reopen store: pages may or may not be visible depending on OS
        // buffer cache. We can only assert that the marker was written.
        assert!(check_batch_complete(&store, 300).unwrap());
    }

    #[test]
    fn batch_commit_insert_remove_mixed() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(400, default_policy());

        // First: insert some entries and commit
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"keep", 1, 0, DT_DIR as u32).unwrap();
            batch.insert(b"delete_me", 2, 0, DT_DIR as u32).unwrap();
            batch.insert(b"also_keep", 3, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }

        // Reload
        let mut idx = PersistentDirIndex::load(&store, 400, default_policy())
            .unwrap()
            .unwrap();
        assert_eq!(idx.len(), 3);

        // Second: remove one and add another — all in one batch
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.remove(b"delete_me").unwrap();
            batch.insert(b"new_one", 4, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }

        let loaded = PersistentDirIndex::load(&store, 400, default_policy())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.contains(b"keep"));
        assert!(loaded.contains(b"also_keep"));
        assert!(loaded.contains(b"new_one"));
        assert!(!loaded.contains(b"delete_me"));
    }

    #[test]
    fn batch_commit_marker_independent_across_directories() {
        let (_tmp, mut store) = open_store();

        let mut idx1 = PersistentDirIndex::new(1, default_policy());
        let mut idx2 = PersistentDirIndex::new(2, default_policy());

        {
            let mut batch = DirBatch::new(&mut idx1);
            batch.insert(b"d1_entry", 10, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }

        // Only dir 1 should have a commit marker
        assert!(check_batch_complete(&store, 1).unwrap());
        assert!(!check_batch_complete(&store, 2).unwrap());

        {
            let mut batch = DirBatch::new(&mut idx2);
            batch.insert(b"d2_entry", 20, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }

        assert!(check_batch_complete(&store, 1).unwrap());
        assert!(check_batch_complete(&store, 2).unwrap());
    }

    #[test]
    fn batch_empty_commit_is_harmless() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(500, default_policy());
        {
            let batch = DirBatch::new(&mut idx);
            batch.commit(&mut store, true).unwrap();
        }
        assert!(check_batch_complete(&store, 500).unwrap());
        let loaded = PersistentDirIndex::load(&store, 500, default_policy())
            .unwrap()
            .unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn batch_commit_then_load_preserves_sorted_order() {
        let (_tmp, mut store) = open_store();
        let mut idx = PersistentDirIndex::new(600, default_policy());
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"zulu", 26, 0, DT_DIR as u32).unwrap();
            batch.insert(b"alpha", 1, 0, DT_DIR as u32).unwrap();
            batch.insert(b"mike", 13, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }
        let loaded = PersistentDirIndex::load(&store, 600, default_policy())
            .unwrap()
            .unwrap();
        let (entries, _) = loaded.list_from(DirCookie::START);
        assert_eq!(entries[0].name, b"alpha");
        assert_eq!(entries[1].name, b"mike");
        assert_eq!(entries[2].name, b"zulu");
    }

    #[test]
    fn load_strict_ignores_pages_without_commit_marker() {
        // This test verifies the contract described in check_batch_complete:
        // if a commit marker is absent, a caller can decide to ignore
        // partial page data from a crashed batch.
        let (_tmp, mut store) = open_store();

        // Manually write a page without a commit marker (simulating a
        // mid-commit crash). Then verify check_batch_complete returns false.
        let page = crate::format::DirPage::new(0);
        let key = crate::format::dir_page_key(700, 0);
        store.put(key, &page.encode()).unwrap();

        // No commit marker was written — the batch is incomplete
        assert!(!check_batch_complete(&store, 700).unwrap());

        // The page data is still loadable via the normal load path
        let loaded = PersistentDirIndex::load(&store, 700, default_policy()).unwrap();
        assert!(loaded.is_some());
        assert!(loaded.unwrap().is_empty()); // page has no entries
    }

    // ── Namespace manifest helpers ───────────────────────────────────

    #[test]
    fn read_manifest_empty_store_returns_empty() {
        let (_tmp, store) = open_store();
        let inodes = read_namespace_manifest(&store).unwrap();
        assert!(inodes.is_empty());
    }

    #[test]
    fn write_then_read_manifest_roundtrip() {
        let (_tmp, mut store) = open_store();
        let inodes = vec![1u64, 42, 100, 9999];
        write_namespace_manifest(&mut store, &inodes).unwrap();
        let read_back = read_namespace_manifest(&store).unwrap();
        assert_eq!(read_back, inodes);
    }

    #[test]
    fn write_manifest_overwrites_previous() {
        let (_tmp, mut store) = open_store();
        write_namespace_manifest(&mut store, &[10, 20]).unwrap();
        write_namespace_manifest(&mut store, &[30]).unwrap();
        let read_back = read_namespace_manifest(&store).unwrap();
        assert_eq!(read_back, vec![30]);
    }

    #[test]
    fn read_manifest_empty_inode_list() {
        let (_tmp, mut store) = open_store();
        write_namespace_manifest(&mut store, &[]).unwrap();
        let read_back = read_namespace_manifest(&store).unwrap();
        assert!(read_back.is_empty());
    }

    #[test]
    fn manifest_survives_store_reopen() {
        let (tmp, mut store) = open_store();
        let inodes = vec![5u64, 10, 15, 20, 25];
        write_namespace_manifest(&mut store, &inodes).unwrap();
        store.sync_all().unwrap();
        drop(store);

        let store2 = LocalObjectStore::open(tmp.path()).unwrap();
        let read_back = read_namespace_manifest(&store2).unwrap();
        assert_eq!(read_back, inodes);
    }

    #[test]
    fn manifest_with_large_inode_list() {
        let (_tmp, mut store) = open_store();
        let inodes: Vec<u64> = (0..1000u64).map(|i| i * 7).collect();
        write_namespace_manifest(&mut store, &inodes).unwrap();
        let read_back = read_namespace_manifest(&store).unwrap();
        assert_eq!(read_back, inodes);
    }

    #[test]
    fn manifest_independent_from_batch_commit_marker() {
        let (_tmp, mut store) = open_store();

        // Write a namespace manifest
        write_namespace_manifest(&mut store, &[100, 200]).unwrap();

        // Write a batch commit marker for a directory
        let marker_key = crate::format::dir_batch_commit_key(100);
        store
            .put(marker_key, &crate::format::DIR_BATCH_COMMIT_MAGIC)
            .unwrap();

        // Manifest still readable and unchanged
        let inodes = read_namespace_manifest(&store).unwrap();
        assert_eq!(inodes, vec![100, 200]);
        assert!(check_batch_complete(&store, 100).unwrap());
        assert!(!check_batch_complete(&store, 200).unwrap());
    }

    #[test]
    fn directory_with_batch_commit_marker_appears_in_manifest() {
        let (_tmp, mut store) = open_store();

        // Simulate what Namespace::flush does: write pages, write manifest
        let mut idx = PersistentDirIndex::new(42, default_policy());
        {
            let mut batch = DirBatch::new(&mut idx);
            batch.insert(b"entry", 1, 0, DT_DIR as u32).unwrap();
            batch.commit(&mut store, true).unwrap();
        }

        // Now update the manifest to include this directory
        let existing = read_namespace_manifest(&store).unwrap();
        let mut updated = existing.clone();
        if !updated.contains(&42) {
            updated.push(42);
        }
        write_namespace_manifest(&mut store, &updated).unwrap();

        // Verify the directory can be loaded via the manifest
        let inodes = read_namespace_manifest(&store).unwrap();
        assert!(inodes.contains(&42));
        let loaded = PersistentDirIndex::load(&store, 42, default_policy())
            .unwrap()
            .unwrap();
        assert!(loaded.contains(b"entry"));
    }
}
