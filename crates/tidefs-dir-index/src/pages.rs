// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page-based persistent directory index backed by the object store.
//!
//! [`DirPageIndex`] stores directory entries in fixed-size 4 KiB [`DirPage`]
//! objects (defined in [`crate::format`]), one per logical page, keyed by
//! directory inode and page number. This enables incremental persistence,
//! random-access lookup, and readdir-pagination without loading the entire
//! directory into memory.
//!
//! ## Page lifecycle
//!
//! - **insert**: Appended to the last page. When the last page is full, a new
//!   page is allocated and the entry written there.
//! - **remove**: The entry's `inode_id` field is zeroed (tombstone). No
//!   compaction; deferred to periodic GC.
//! - **flush**: Each dirty page is written to the object store via
//!   `put`. Clean pages are skipped.
//! - **load**: Pages are read in sequence by page number from the object store
//!   and reconstructed into the in-memory page set.

#[cfg(feature = "persistent-dir-index")]
use crate::redundancy::{replicated_get, replicated_put, ReplicatedReadResult};
use alloc::vec::Vec;

use std::sync::Mutex;
use tidefs_local_object_store::LocalObjectStore;

use crate::format::{self, DirEntry, DirPage, DIR_PAGE_SIZE};

type ReplicaPagePayloads = Vec<(u32, Vec<u8>)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirPageIndexError {
    EntryAlreadyExists,
    EntryNotFound,
    StoreError,
    CorruptPage,
}

#[derive(Debug)]
pub struct DirPageIndex {
    dir_ino: u64,
    next_offset: u64,
    pages: Vec<DirPage>,
    dirty: bool,
    dirty_pages: Vec<u32>,
    entries: Vec<(Vec<u8>, u64, u8, u64, u64)>,
    /// Optional replica object stores for metadata redundancy.
    /// When set, flush writes to all replicas and load falls back
    /// to replicas on primary miss.
    replicas: Mutex<Vec<LocalObjectStore>>,
}

impl DirPageIndex {
    #[must_use]
    pub fn new(dir_ino: u64) -> Self {
        let mut idx = DirPageIndex {
            dir_ino,
            next_offset: 0,
            pages: Vec::new(),
            dirty: false,
            dirty_pages: Vec::new(),
            entries: Vec::new(),
            replicas: Mutex::new(Vec::new()),
        };
        idx.pages.push(DirPage::new(0));
        idx.dirty_pages.push(0);
        idx.dirty = true;
        idx
    }

    /// Attach replica object stores for metadata redundancy.
    ///
    /// When replicas are configured, [`flush`](Self::flush) writes each
    /// dirty page to all replica stores in addition to the primary.
    /// [`load`](Self::load) reads from the primary and falls back to
    /// replicas for missing pages.
    pub fn set_replicas(&mut self, replicas: Vec<LocalObjectStore>) {
        *self.replicas.get_mut().unwrap() = replicas;
    }

    /// Whether replica stores are configured.
    #[must_use]
    pub fn has_replicas(&self) -> bool {
        !self.replicas.lock().unwrap().is_empty()
    }

    /// Run a closure with the replica stores locked for reading.
    #[allow(dead_code)] // only used in replicas-enabled path
    pub fn with_replicas<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[LocalObjectStore]) -> R,
    {
        f(&self.replicas.lock().unwrap())
    }

    /// Run a closure with the replica stores locked for writing.
    #[allow(dead_code)]
    pub fn with_replicas_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Vec<LocalObjectStore>) -> R,
    {
        let mut guard = self.replicas.lock().unwrap();
        f(&mut guard)
    }

    fn dir_page_from_payload(payload: &[u8]) -> Option<DirPage> {
        if payload.len() != DIR_PAGE_SIZE {
            return None;
        }
        let mut buf = [0u8; DIR_PAGE_SIZE];
        buf.copy_from_slice(payload);
        DirPage::decode(&buf)
    }

    fn entry_tuple(entry: &DirEntry) -> (Vec<u8>, u64, u8, u64, u64) {
        (
            entry.name.clone(),
            entry.inode_id,
            entry.entry_type,
            entry.generation,
            entry.offset,
        )
    }

    fn insert_limited_sorted_entry(
        entries: &mut Vec<(Vec<u8>, u64, u8, u64, u64)>,
        candidate: &DirEntry,
        max_entries: usize,
    ) {
        let pos = entries
            .binary_search_by(|entry| entry.0.as_slice().cmp(candidate.name.as_slice()))
            .unwrap_or_else(|idx| idx);
        if pos < max_entries {
            entries.insert(pos, Self::entry_tuple(candidate));
            if entries.len() > max_entries {
                entries.pop();
            }
        }
    }

    /// Look up one live directory entry directly from persisted pages.
    ///
    /// This scans the directory page sequence and returns as soon as the
    /// requested name is found, without constructing a full [`DirPageIndex`]
    /// or cloning unrelated entries into the sorted in-memory index.
    pub fn lookup_in_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        name: &[u8],
    ) -> tidefs_local_object_store::Result<Option<(u64, u8, u64)>> {
        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            match store.get(key)? {
                Some(payload) => {
                    if let Some(page) = Self::dir_page_from_payload(&payload) {
                        for entry in &page.entries {
                            if entry.inode_id != 0 && entry.name == name {
                                return Ok(Some((
                                    entry.inode_id,
                                    entry.entry_type,
                                    entry.generation,
                                )));
                            }
                        }
                    }
                    page_num += 1;
                }
                None => break,
            }
        }
        Ok(None)
    }

    /// Count live directory entries directly from persisted pages.
    ///
    /// The returned count is capped at `max_entries`, so callers that only need
    /// to distinguish empty from non-empty directories can keep retained memory
    /// bounded and stop scanning as soon as the answer is known.
    pub fn live_entry_count_in_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        max_entries: usize,
    ) -> tidefs_local_object_store::Result<Option<usize>> {
        let mut found_any = false;
        let mut count = 0usize;
        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            match store.get(key)? {
                Some(payload) => {
                    found_any = true;
                    if let Some(page) = Self::dir_page_from_payload(&payload) {
                        for entry in &page.entries {
                            if entry.inode_id == 0 {
                                continue;
                            }
                            count = count.saturating_add(1);
                            if count >= max_entries {
                                return Ok(Some(count));
                            }
                        }
                    }
                    page_num += 1;
                }
                None => break,
            }
        }

        if found_any {
            Ok(Some(count))
        } else {
            Ok(None)
        }
    }

    /// Return a name-sorted entry window directly from persisted pages.
    ///
    /// The scan reads directory pages in sequence but keeps only the requested
    /// sorted window in memory. It is therefore bounded by `max_entries` rather
    /// than by the full directory entry count. `start_name` is exclusive,
    /// matching [`range_scan`](Self::range_scan).
    pub fn range_scan_in_store(
        store: &LocalObjectStore,
        dir_ino: u64,
        start_name: &[u8],
        max_entries: usize,
    ) -> tidefs_local_object_store::Result<Vec<(Vec<u8>, u64, u8, u64, u64)>> {
        let mut entries: Vec<(Vec<u8>, u64, u8, u64, u64)> = Vec::new();
        if max_entries == 0 {
            return Ok(entries);
        }

        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            match store.get(key)? {
                Some(payload) => {
                    if let Some(page) = Self::dir_page_from_payload(&payload) {
                        for entry in &page.entries {
                            if entry.inode_id == 0 {
                                continue;
                            }
                            if !start_name.is_empty() && entry.name.as_slice() <= start_name {
                                continue;
                            }
                            Self::insert_limited_sorted_entry(&mut entries, entry, max_entries);
                        }
                    }
                    page_num += 1;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    /// Visit live entries directly from persisted pages in page order.
    ///
    /// This retains only one decoded directory page at a time. It is intended
    /// for import/rebuild paths that need to inspect every persisted entry but
    /// do not need a mutable [`DirPageIndex`] or a sorted full-directory
    /// snapshot.
    pub fn for_each_in_store<F>(
        store: &LocalObjectStore,
        dir_ino: u64,
        mut visit: F,
    ) -> tidefs_local_object_store::Result<bool>
    where
        F: FnMut((Vec<u8>, u64, u8, u64, u64)),
    {
        let mut found_any = false;
        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            match store.get(key)? {
                Some(payload) => {
                    found_any = true;
                    if let Some(page) = Self::dir_page_from_payload(&payload) {
                        for entry in &page.entries {
                            if entry.inode_id != 0 {
                                visit(Self::entry_tuple(entry));
                            }
                        }
                    }
                    page_num += 1;
                }
                None => break,
            }
        }

        Ok(found_any)
    }

    pub fn load(
        store: &LocalObjectStore,
        dir_ino: u64,
    ) -> tidefs_local_object_store::Result<Option<Self>> {
        let mut pages: Vec<DirPage> = Vec::new();
        let mut found_any = false;

        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            match store.get(key)? {
                Some(payload) => {
                    found_any = true;
                    if let Some(page) = Self::dir_page_from_payload(&payload) {
                        pages.push(page);
                    }
                    page_num += 1;
                }
                None => break,
            }
        }

        if !found_any {
            return Ok(None);
        }

        pages.sort_by_key(|p| p.page_number);

        let mut entries: Vec<(Vec<u8>, u64, u8, u64, u64)> = Vec::new();
        for page in &pages {
            for entry in &page.entries {
                if entry.inode_id == 0 {
                    continue;
                }
                entries.push((
                    entry.name.clone(),
                    entry.inode_id,
                    entry.entry_type,
                    entry.generation,
                    entry.offset,
                ));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let next_offset = entries
            .iter()
            .map(|(_, _, _, _, offset)| offset + 1)
            .max()
            .unwrap_or(0);

        Ok(Some(DirPageIndex {
            dir_ino,
            next_offset,
            pages,
            dirty: false,
            dirty_pages: Vec::new(),
            entries,
            replicas: Mutex::new(Vec::new()),
        }))
    }

    /// Load directory pages with replica failover.
    ///
    /// Reads pages sequentially from `primary`. When a page is missing
    /// from the primary, each store in `replicas` is tried in order.
    /// Pages read from replicas are returned in a separate list so the
    /// caller can repair the primary.
    pub fn load_with_replicas(
        primary: &LocalObjectStore,
        replicas: &[LocalObjectStore],
        dir_ino: u64,
    ) -> tidefs_local_object_store::Result<(Option<Self>, ReplicaPagePayloads)> {
        let mut pages: Vec<DirPage> = Vec::new();
        let mut found_any = false;
        let mut repaired_pages: Vec<(u32, Vec<u8>)> = Vec::new();

        let mut page_num: u32 = 0;
        loop {
            let key = format::dir_page_key(dir_ino, page_num);
            let (payload, from_replica) = match primary.get(key)? {
                Some(p) => (p, false),
                None => {
                    let replica_refs: Vec<&LocalObjectStore> = replicas.iter().collect();
                    match replicated_get(primary, &replica_refs, &key)? {
                        ReplicatedReadResult::Primary(data) => (data, false),
                        ReplicatedReadResult::Replica(data, _) => {
                            repaired_pages.push((page_num, data.clone()));
                            (data, true)
                        }
                        ReplicatedReadResult::Unavailable => break,
                    }
                }
            };

            found_any = true;
            if let Some(page) = Self::dir_page_from_payload(&payload) {
                pages.push(page);
            }
            page_num += 1;
            let _ = from_replica;
        }

        if !found_any {
            return Ok((None, repaired_pages));
        }

        pages.sort_by_key(|p| p.page_number);

        let mut entries: Vec<(Vec<u8>, u64, u8, u64, u64)> = Vec::new();
        for page in &pages {
            for entry in &page.entries {
                if entry.inode_id == 0 {
                    continue;
                }
                entries.push((
                    entry.name.clone(),
                    entry.inode_id,
                    entry.entry_type,
                    entry.generation,
                    entry.offset,
                ));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let next_offset = entries
            .iter()
            .map(|(_, _, _, _, offset)| offset + 1)
            .max()
            .unwrap_or(0);

        Ok((
            Some(DirPageIndex {
                dir_ino,
                next_offset,
                pages,
                dirty: false,
                dirty_pages: Vec::new(),
                entries,
                replicas: Mutex::new(Vec::new()),
            }),
            repaired_pages,
        ))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    #[must_use]
    pub fn dir_ino(&self) -> u64 {
        self.dir_ino
    }
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<(u64, u8, u64)> {
        match self.entries.binary_search_by(|e| e.0.as_slice().cmp(name)) {
            Ok(idx) => {
                let (_, ino, ty, gen, _) = &self.entries[idx];
                Some((*ino, *ty, *gen))
            }
            Err(_) => None,
        }
    }

    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.lookup(name).is_some()
    }

    pub fn insert(
        &mut self,
        name: &[u8],
        inode_id: u64,
        entry_type: u8,
        generation: u64,
    ) -> Result<u64, DirPageIndexError> {
        if self.contains(name) {
            return Err(DirPageIndexError::EntryAlreadyExists);
        }
        let offset = self.next_offset;
        self.next_offset += 1;

        let entry = DirEntry {
            name_len: name.len() as u8,
            inode_id,
            entry_type,
            generation,
            offset,
            name: name.to_vec(),
        };

        let encoded_len = entry.encoded_len();

        let need_new_page = !self.pages.last().is_some_and(|p| p.can_fit(encoded_len));
        let page_num = if need_new_page {
            self.pages.len() as u32
        } else {
            self.pages.last().unwrap().page_number
        };

        if need_new_page {
            let mut new_page = DirPage::new(page_num);
            new_page.entries.push(entry);
            new_page.entry_count = 1;
            self.pages.push(new_page);
        } else {
            let last_idx = self.pages.len() - 1;
            self.pages[last_idx].entries.push(entry);
            self.pages[last_idx].entry_count += 1;
        }
        self.mark_page_dirty(page_num);

        let pos = self
            .entries
            .binary_search_by(|e| e.0.as_slice().cmp(name))
            .unwrap_err();
        self.entries.insert(
            pos,
            (name.to_vec(), inode_id, entry_type, generation, offset),
        );
        self.dirty = true;
        Ok(offset)
    }

    pub fn remove(&mut self, name: &[u8]) -> Result<bool, DirPageIndexError> {
        let idx = match self.entries.binary_search_by(|e| e.0.as_slice().cmp(name)) {
            Ok(i) => i,
            Err(_) => return Ok(false),
        };

        let (_, inode_id, _, _, _) = self.entries[idx];

        let mut found = false;
        let mut dirty_page: Option<u32> = None;
        for page in &mut self.pages {
            for entry in &mut page.entries {
                if entry.name == name && entry.inode_id == inode_id {
                    entry.inode_id = 0;
                    page.set_has_tombstones(true);
                    dirty_page = Some(page.page_number);
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        if let Some(pn) = dirty_page {
            self.mark_page_dirty(pn);
        }

        if found {
            self.entries.remove(idx);
            self.dirty = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[must_use]
    pub fn list(&self) -> Vec<(Vec<u8>, u64, u8, u64, u64)> {
        self.entries.clone()
    }

    #[must_use]
    pub fn entries_from_sorted_index(
        &self,
        start: usize,
        max_entries: usize,
    ) -> Vec<(Vec<u8>, u64, u8, u64, u64)> {
        if max_entries == 0 || start >= self.entries.len() {
            return Vec::new();
        }
        let end = start.saturating_add(max_entries).min(self.entries.len());
        self.entries[start..end].to_vec()
    }

    #[must_use]
    pub fn range_scan(
        &self,
        start_name: &[u8],
        max_entries: usize,
    ) -> Vec<(Vec<u8>, u64, u8, u64, u64)> {
        let start_idx = if start_name.is_empty() {
            0
        } else {
            match self
                .entries
                .binary_search_by(|e| e.0.as_slice().cmp(start_name))
            {
                Ok(idx) => idx + 1,
                Err(idx) => idx,
            }
        };
        if start_idx >= self.entries.len() {
            return Vec::new();
        }
        let end = start_idx
            .saturating_add(max_entries)
            .min(self.entries.len());
        self.entries[start_idx..end].to_vec()
    }

    pub fn flush(&mut self, store: &mut LocalObjectStore) -> tidefs_local_object_store::Result<()> {
        for &page_num in &self.dirty_pages {
            if let Some(page) = self.pages.get(page_num as usize) {
                let key = format::dir_page_key(self.dir_ino, page_num);
                let buf = page.encode();
                store.put(key, &buf)?;
                // Replicate to all configured replica stores
                {
                    let mut guard = self.replicas.lock().unwrap();
                    if !guard.is_empty() {
                        let mut replica_refs: Vec<&mut LocalObjectStore> =
                            guard.iter_mut().collect();
                        replicated_put(store, &mut replica_refs, &key, &buf)?;
                    }
                }
            }
        }
        self.dirty_pages.clear();
        self.dirty = false;
        Ok(())
    }

    pub fn sync(&mut self, store: &mut LocalObjectStore) -> tidefs_local_object_store::Result<()> {
        // Flush pages to primary + replicas (handled inside flush)
        for &page_num in &self.dirty_pages {
            if let Some(page) = self.pages.get(page_num as usize) {
                let key = format::dir_page_key(self.dir_ino, page_num);
                let buf = page.encode();
                store.put(key, &buf)?;
                {
                    let mut guard = self.replicas.lock().unwrap();
                    if !guard.is_empty() {
                        let mut replica_refs: Vec<&mut LocalObjectStore> =
                            guard.iter_mut().collect();
                        replicated_put(store, &mut replica_refs, &key, &buf)?;
                    }
                }
            }
        }
        self.dirty_pages.clear();
        self.dirty = false;
        store.sync_all()
    }

    fn mark_page_dirty(&mut self, page_num: u32) {
        if !self.dirty_pages.contains(&page_num) {
            self.dirty_pages.push(page_num);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store() -> (tempfile::TempDir, LocalObjectStore) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = LocalObjectStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    fn make_idx(ino: u64) -> DirPageIndex {
        DirPageIndex::new(ino)
    }

    use crate::format::{DIR_ENTRY_HEADER_LEN, DIR_PAGE_ENTRIES_AREA, DT_DIR};

    #[test]
    fn new_empty_dirty() {
        let idx = make_idx(1);
        assert!(idx.is_empty());
        assert!(idx.is_dirty());
        assert_eq!(idx.page_count(), 1);
    }
    #[test]
    fn insert_lookup() {
        let mut idx = make_idx(1);
        idx.insert(b"h", 42, DT_DIR, 1).unwrap();
        let (ino, ty, gen) = idx.lookup(b"h").unwrap();
        assert_eq!((ino, ty, gen), (42, DT_DIR, 1));
    }
    #[test]
    fn insert_dup_rejected() {
        let mut idx = make_idx(1);
        idx.insert(b"d", 1, DT_DIR, 0).unwrap();
        assert_eq!(
            idx.insert(b"d", 2, DT_DIR, 0),
            Err(DirPageIndexError::EntryAlreadyExists)
        );
    }
    #[test]
    fn lookup_missing() {
        assert!(make_idx(1).lookup(b"x").is_none());
    }
    #[test]
    fn contains_works() {
        let mut idx = make_idx(1);
        assert!(!idx.contains(b"x"));
        idx.insert(b"x", 1, DT_DIR, 0).unwrap();
        assert!(idx.contains(b"x"));
    }
    #[test]
    fn remove_existing() {
        let mut idx = make_idx(1);
        idx.insert(b"a", 10, DT_DIR, 1).unwrap();
        idx.insert(b"b", 20, DT_DIR, 2).unwrap();
        assert!(idx.remove(b"a").unwrap());
        assert_eq!(idx.len(), 1);
    }
    #[test]
    fn remove_nonexistent() {
        let mut idx = make_idx(1);
        assert!(!idx.remove(b"x").unwrap());
    }
    #[test]
    fn remove_reinsert() {
        let mut idx = make_idx(1);
        idx.insert(b"e", 100, DT_DIR, 1).unwrap();
        idx.remove(b"e").unwrap();
        let o = idx.insert(b"e", 200, DT_DIR, 2).unwrap();
        assert_eq!(o, 1);
    }
    #[test]
    fn offsets_monotonic() {
        let mut idx = make_idx(1);
        assert_eq!(idx.insert(b"a", 1, DT_DIR, 0).unwrap(), 0);
        assert_eq!(idx.insert(b"b", 2, DT_DIR, 0).unwrap(), 1);
        assert_eq!(idx.insert(b"c", 3, DT_DIR, 0).unwrap(), 2);
    }
    #[test]
    fn offsets_not_reused() {
        let mut idx = make_idx(1);
        idx.insert(b"a", 1, DT_DIR, 0).unwrap();
        idx.insert(b"b", 2, DT_DIR, 0).unwrap();
        idx.remove(b"a").unwrap();
        assert_eq!(idx.insert(b"c", 3, DT_DIR, 0).unwrap(), 2);
    }
    #[test]
    fn page_split() {
        let mut idx = make_idx(1);
        let es = DIR_ENTRY_HEADER_LEN + 4;
        let pp = DIR_PAGE_ENTRIES_AREA / es;
        for i in 0..pp {
            idx.insert(alloc::format!("{i:04}").as_bytes(), i as u64, DT_DIR, 0)
                .unwrap();
        }
        assert_eq!(idx.page_count(), 1);
        idx.insert(b"OVER", 999, DT_DIR, 0).unwrap();
        assert_eq!(idx.page_count(), 2);
    }
    #[test]
    fn list_sorted() {
        let mut idx = make_idx(1);
        idx.insert(b"z", 26, DT_DIR, 0).unwrap();
        idx.insert(b"a", 1, DT_DIR, 0).unwrap();
        idx.insert(b"m", 13, DT_DIR, 0).unwrap();
        let e = idx.list();
        assert_eq!(e[0].0, b"a");
        assert_eq!(e[1].0, b"m");
        assert_eq!(e[2].0, b"z");
    }
    #[test]
    fn range_scan_exclusive() {
        let mut idx = make_idx(1);
        idx.insert(b"a", 1, DT_DIR, 0).unwrap();
        idx.insert(b"b", 2, DT_DIR, 0).unwrap();
        let r = idx.range_scan(b"a", 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, b"b");
    }
    #[test]
    fn range_scan_limit() {
        let mut idx = make_idx(1);
        for i in 0..5u64 {
            idx.insert(alloc::format!("e{i}").as_bytes(), i, DT_DIR, 0)
                .unwrap();
        }
        assert_eq!(idx.range_scan(b"", 3).len(), 3);
    }
    #[test]
    fn range_scan_empty_dir() {
        assert!(make_idx(1).range_scan(b"", 10).is_empty());
    }
    #[test]
    fn range_scan_past_end() {
        let mut idx = make_idx(1);
        idx.insert(b"z", 1, DT_DIR, 0).unwrap();
        assert!(idx.range_scan(b"z", 10).is_empty());
    }
    #[test]
    fn flush_load_empty() {
        let (_t, mut s) = open_store();
        let mut idx = make_idx(100);
        idx.flush(&mut s).unwrap();
        let l = DirPageIndex::load(&s, 100).unwrap().unwrap();
        assert!(l.is_empty());
    }
    #[test]
    fn flush_load_entries() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(200);
        idx.insert(b"z", 26, DT_DIR, 1).unwrap();
        idx.insert(b"a", 1, DT_DIR, 2).unwrap();
        idx.flush(&mut s).unwrap();
        let l = DirPageIndex::load(&s, 200).unwrap().unwrap();
        assert_eq!(l.len(), 2);
        let e = l.list();
        assert_eq!(e[0].0, b"a");
        assert_eq!(e[0].1, 1);
        assert_eq!(e[1].0, b"z");
        assert_eq!(e[1].1, 26);
    }

    #[test]
    fn for_each_in_store_visits_live_entries_without_loading_index() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(201);
        idx.insert(b"z", 26, DT_DIR, 1).unwrap();
        idx.insert(b"a", 1, DT_DIR, 2).unwrap();
        idx.insert(b"dead", 99, DT_DIR, 3).unwrap();
        idx.remove(b"dead").unwrap();
        idx.flush(&mut s).unwrap();

        let mut seen = Vec::new();
        let found = DirPageIndex::for_each_in_store(&s, 201, |entry| seen.push(entry)).unwrap();

        assert!(found);
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, b"a");
        assert_eq!(seen[0].1, 1);
        assert_eq!(seen[1].0, b"z");
        assert_eq!(seen[1].1, 26);
    }

    #[test]
    fn flush_load_offsets() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(1);
        let o0 = idx.insert(b"a", 1, DT_DIR, 0).unwrap();
        let o1 = idx.insert(b"b", 2, DT_DIR, 0).unwrap();
        idx.flush(&mut s).unwrap();
        let l = DirPageIndex::load(&s, 1).unwrap().unwrap();
        let e = l.list();
        assert_eq!(e[0].4, o0);
        assert_eq!(e[1].4, o1);
    }
    #[test]
    fn flush_load_after_remove() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(1);
        idx.insert(b"a", 10, DT_DIR, 0).unwrap();
        idx.insert(b"b", 20, DT_DIR, 0).unwrap();
        idx.remove(b"a").unwrap();
        idx.flush(&mut s).unwrap();
        let l = DirPageIndex::load(&s, 1).unwrap().unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.contains(b"b"));
    }
    #[test]
    fn lookup_in_store_finds_entry_without_loading_index() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(42);
        let entries_per_page = DIR_PAGE_ENTRIES_AREA / (DIR_ENTRY_HEADER_LEN + 6);
        let target_idx = entries_per_page + 3;

        idx.insert(b"gone", 9, DT_DIR, 0).unwrap();
        idx.remove(b"gone").unwrap();
        for i in 0..(entries_per_page + 8) {
            let name = alloc::format!("p{i:05}");
            idx.insert(name.as_bytes(), 1_000 + i as u64, DT_DIR, i as u64)
                .unwrap();
        }
        idx.flush(&mut s).unwrap();

        let target = alloc::format!("p{target_idx:05}");
        assert_eq!(
            DirPageIndex::lookup_in_store(&s, 42, target.as_bytes()).unwrap(),
            Some((1_000 + target_idx as u64, DT_DIR, target_idx as u64))
        );
        assert_eq!(
            DirPageIndex::lookup_in_store(&s, 42, b"missing").unwrap(),
            None
        );
        assert_eq!(
            DirPageIndex::lookup_in_store(&s, 42, b"gone").unwrap(),
            None
        );
    }
    #[test]
    fn range_scan_in_store_returns_sorted_window_across_pages() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(99);
        let entries_per_page = DIR_PAGE_ENTRIES_AREA / (DIR_ENTRY_HEADER_LEN + 6);

        for i in 0..entries_per_page {
            let name = alloc::format!("z{i:05}");
            idx.insert(name.as_bytes(), 10_000 + i as u64, DT_DIR, i as u64)
                .unwrap();
        }
        for i in 0..6 {
            let name = alloc::format!("a{i:05}");
            idx.insert(name.as_bytes(), 20_000 + i as u64, DT_DIR, i as u64)
                .unwrap();
        }
        idx.flush(&mut s).unwrap();

        let first = DirPageIndex::range_scan_in_store(&s, 99, b"", 3).unwrap();
        let first_names: Vec<Vec<u8>> = first.iter().map(|entry| entry.0.clone()).collect();
        assert_eq!(
            first_names,
            vec![b"a00000".to_vec(), b"a00001".to_vec(), b"a00002".to_vec()]
        );

        let after = DirPageIndex::range_scan_in_store(&s, 99, b"a00002", 4).unwrap();
        let after_names: Vec<Vec<u8>> = after.iter().map(|entry| entry.0.clone()).collect();
        assert_eq!(
            after_names,
            vec![
                b"a00003".to_vec(),
                b"a00004".to_vec(),
                b"a00005".to_vec(),
                b"z00000".to_vec(),
            ]
        );
        assert!(DirPageIndex::range_scan_in_store(&s, 99, b"", 0)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn load_nonexistent() {
        let (_t, s) = open_store();
        assert!(DirPageIndex::load(&s, 999).unwrap().is_none());
    }
    #[test]
    fn sync_works() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(1);
        idx.insert(b"t", 42, DT_DIR, 0).unwrap();
        idx.sync(&mut s).unwrap();
        assert!(!idx.is_dirty());
        assert!(DirPageIndex::load(&s, 1).unwrap().unwrap().contains(b"t"));
    }
    #[test]
    fn flush_overwrites() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(1);
        idx.insert(b"first", 1, DT_DIR, 0).unwrap();
        idx.flush(&mut s).unwrap();
        idx.insert(b"second", 2, DT_DIR, 0).unwrap();
        idx.remove(b"first").unwrap();
        idx.flush(&mut s).unwrap();
        let l = DirPageIndex::load(&s, 1).unwrap().unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.contains(b"second"));
    }
    #[test]
    fn dirty_tracking() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(1);
        assert!(idx.is_dirty());
        idx.flush(&mut s).unwrap();
        assert!(!idx.is_dirty());
        idx.insert(b"x", 1, DT_DIR, 0).unwrap();
        assert!(idx.is_dirty());
        idx.flush(&mut s).unwrap();
        assert!(!idx.is_dirty());
        idx.remove(b"x").unwrap();
        assert!(idx.is_dirty());
    }
    #[test]
    fn all_entry_types() {
        let mut idx = DirPageIndex::new(1);
        idx.insert(b"dir", 1, DT_DIR, 0).unwrap();
        idx.insert(b"file", 2, DT_DIR + 1, 0).unwrap();
        idx.insert(b"link", 3, DT_DIR + 2, 0).unwrap();
        assert_eq!(idx.lookup(b"dir").unwrap().1, DT_DIR);
    }
    #[test]
    fn empty_name() {
        let mut idx = DirPageIndex::new(1);
        idx.insert(b"", 10, DT_DIR, 0).unwrap();
        assert_eq!(idx.lookup(b"").unwrap(), (10, DT_DIR, 0));
    }
    #[test]
    fn max_name_len() {
        let mut idx = DirPageIndex::new(1);
        let n = alloc::vec![b'x'; 255];
        idx.insert(&n, 42, DT_DIR, 0).unwrap();
        assert!(idx.contains(&n));
    }
    #[test]
    fn load_preserves_dir_ino() {
        let (_t, mut s) = open_store();
        let mut idx = DirPageIndex::new(42);
        idx.insert(b"t", 10, DT_DIR, 0).unwrap();
        idx.flush(&mut s).unwrap();
        assert_eq!(DirPageIndex::load(&s, 42).unwrap().unwrap().dir_ino(), 42);
    }
}
