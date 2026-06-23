// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-mode root directory reader through KernelStorageIo.
//!
//! [`KernelRootDirReader`] reads the on-disk [`DirPage`] sequence for a
//! single directory through [`KernelStorageIo`], providing name lookup and
//! cookie-based entry iteration for kernel VFS `lookup` and `readdir`.
//!
//! This is the canonical kernel-readable directory contract for #6252
//! (mounted replay/readback integration). The reader consumes a sector
//! range — typically derived from the commited-root inode's directory
//! extent pointer — and resolves child names and lists directory entries
//! without userspace assistance.
//!
//! # On-disk layout
//!
//! A directory is stored as a contiguous sequence of 4 KiB [`DirPage`]
//! objects at `dir_start_sector`. Production read-only kernel paths use
//! [`KernelRootDirReader::lookup_in_storage`] and
//! [`KernelRootDirReader::readdir_in_storage`] to answer lookup/readdir
//! directly from [`KernelStorageIo`] without retaining all directory entries.
//! The legacy full-snapshot reader is compiled only for unit tests.
//!
//! # no_std
//!
//! This module is `no_std` compatible. It uses `alloc` for page buffers
//! and entry vectors but does not require `std`.

extern crate alloc;

use alloc::vec::Vec;

use crate::format::{self, DirPage, DIR_PAGE_SIZE};
use tidefs_kernel_storage_io::{KernelStorageIo, KernelStorageIoCapabilities};
use tidefs_types_polymorphic_directory_index_core::DirMicroEntry;
use tidefs_types_vfs_core::Errno;

// ── KernelRootDirError ────────────────────────────────────────────────────

/// Errors returned by [`KernelRootDirReader`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelRootDirError {
    /// A page had wrong magic bytes or failed to decode.
    CorruptPage { page_number: u32 },
    /// Entry count mismatched the number of decoded entries in a page.
    EntryCountMismatch {
        page_number: u32,
        declared: u16,
        decoded: u16,
    },
    /// The directory has no pages (empty sector range or all pages invalid).
    EmptyDirectory,
    /// An I/O error occurred reading from the storage backend.
    IoError,
    /// The cookie offset is past the end of the directory.
    CookieOutOfRange { cookie: u64 },
}

impl From<KernelRootDirError> for Errno {
    fn from(e: KernelRootDirError) -> Self {
        match e {
            KernelRootDirError::CorruptPage { .. }
            | KernelRootDirError::EntryCountMismatch { .. }
            | KernelRootDirError::IoError => Errno::EIO,
            KernelRootDirError::EmptyDirectory => Errno::ENOENT,
            KernelRootDirError::CookieOutOfRange { .. } => Errno::EINVAL,
        }
    }
}

// ── KernelDirEntry ────────────────────────────────────────────────────────

/// A directory entry decoded from on-disk format, carrying the position
/// cookie needed for readdir pagination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelDirEntry {
    /// Entry name (not NUL-terminated).
    pub name: alloc::vec::Vec<u8>,
    /// Target inode number.
    pub inode_id: u64,
    /// Entry type: `format::DT_DIR`, `format::DT_FILE`, or `format::DT_SYMLINK`.
    pub entry_type: u8,
    /// Inode generation counter.
    pub generation: u64,
    /// Monotonic directory offset (cookie) for telldir/seekdir.
    pub offset: u64,
}

impl KernelDirEntry {
    /// Convert to a [`DirMicroEntry`] for crate API compatibility.
    #[must_use]
    pub fn to_micro_entry(&self) -> DirMicroEntry {
        DirMicroEntry {
            name_len: self.name.len() as u32,
            inode_id: self.inode_id,
            generation: self.generation,
            kind: u32::from(self.entry_type),
            name: self.name.clone(),
        }
    }
}

// ── Page reader helpers ───────────────────────────────────────────────────

/// Read a single [`DirPage`] from the given sector offset.
fn read_page(
    io: &dyn KernelStorageIo,
    dir_start_sector: u64,
    page_number: u32,
) -> Result<Option<DirPage>, KernelRootDirError> {
    let ss = io.sector_size() as u64;
    let sectors_per_page = (DIR_PAGE_SIZE as u64).div_ceil(ss);
    let start_sector = dir_start_sector + (page_number as u64) * sectors_per_page;

    // Check bounds
    let end_sector = start_sector + sectors_per_page;
    if end_sector > io.capacity_sectors() {
        return Ok(None);
    }

    let mut buf = alloc::vec![0u8; sectors_per_page as usize * ss as usize];
    let _sectors_read = io
        .read_sectors(start_sector, &mut buf)
        .map_err(|_| KernelRootDirError::IoError)?;

    // Extract the 4096-byte page from the sector-aligned buffer.
    if buf.len() < DIR_PAGE_SIZE {
        return Ok(None);
    }

    let page_buf: &[u8; DIR_PAGE_SIZE] = buf[..DIR_PAGE_SIZE]
        .try_into()
        .map_err(|_| KernelRootDirError::CorruptPage { page_number })?;

    // Check magic before full decode
    if page_buf[0..4] != format::DIR_PAGE_MAGIC {
        // All-zero page means we've reached the end of the directory
        if page_buf.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        return Err(KernelRootDirError::CorruptPage { page_number });
    }

    let page = DirPage::decode(page_buf).ok_or(KernelRootDirError::CorruptPage { page_number })?;

    // Verify entry count matches
    if page.entry_count != page.entries.len() as u16 {
        return Err(KernelRootDirError::EntryCountMismatch {
            page_number,
            declared: page.entry_count,
            decoded: page.entries.len() as u16,
        });
    }

    Ok(Some(page))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanDecision {
    Continue,
    Stop,
}

fn max_pages_for_range(io: &dyn KernelStorageIo, dir_sector_count: u64) -> u32 {
    let ss = io.sector_size() as u64;
    let sectors_per_page = (DIR_PAGE_SIZE as u64).div_ceil(ss);
    if sectors_per_page == 0 {
        return 0;
    }
    (dir_sector_count / sectors_per_page).min(u64::from(u32::MAX)) as u32
}

fn scan_live_entries<F>(
    io: &dyn KernelStorageIo,
    dir_start_sector: u64,
    dir_sector_count: u64,
    mut visit: F,
) -> Result<bool, KernelRootDirError>
where
    F: FnMut(KernelDirEntry) -> ScanDecision,
{
    let max_pages = max_pages_for_range(io, dir_sector_count);
    let mut found_any_page = false;

    for page_num in 0..max_pages {
        match read_page(io, dir_start_sector, page_num)? {
            Some(page) => {
                found_any_page = true;
                for entry in page.entries {
                    if entry.inode_id == 0 {
                        continue;
                    }
                    let entry = KernelDirEntry {
                        name: entry.name,
                        inode_id: entry.inode_id,
                        entry_type: entry.entry_type,
                        generation: entry.generation,
                        offset: entry.offset,
                    };
                    if visit(entry) == ScanDecision::Stop {
                        return Ok(found_any_page);
                    }
                }
            }
            None => break,
        }
    }

    Ok(found_any_page)
}

enum ReaddirBoundary {
    Start,
    AfterName(Vec<u8>),
    FromName(Vec<u8>),
}

impl ReaddirBoundary {
    fn accepts(&self, name: &[u8]) -> bool {
        match self {
            Self::Start => true,
            Self::AfterName(boundary) => name > boundary.as_slice(),
            Self::FromName(boundary) => name >= boundary.as_slice(),
        }
    }
}

fn find_readdir_boundary(
    io: &dyn KernelStorageIo,
    dir_start_sector: u64,
    dir_sector_count: u64,
    cookie: u64,
) -> Result<ReaddirBoundary, KernelRootDirError> {
    if cookie == 0 {
        return Ok(ReaddirBoundary::Start);
    }

    let mut exact_name: Option<Vec<u8>> = None;
    let mut fallback_name: Option<Vec<u8>> = None;

    scan_live_entries(io, dir_start_sector, dir_sector_count, |entry| {
        if entry.offset == cookie {
            exact_name = Some(entry.name);
            return ScanDecision::Stop;
        }
        if entry.offset > cookie
            && fallback_name
                .as_ref()
                .is_none_or(|current| entry.name.as_slice() < current.as_slice())
        {
            fallback_name = Some(entry.name);
        }
        ScanDecision::Continue
    })?;

    if let Some(name) = exact_name {
        return Ok(ReaddirBoundary::AfterName(name));
    }
    if let Some(name) = fallback_name {
        return Ok(ReaddirBoundary::FromName(name));
    }
    Err(KernelRootDirError::CookieOutOfRange { cookie })
}

fn insert_sorted_candidate(
    candidates: &mut Vec<KernelDirEntry>,
    candidate: KernelDirEntry,
    max_candidates: usize,
) {
    if max_candidates == 0 {
        return;
    }
    let pos = match candidates.binary_search_by(|entry| entry.name.cmp(&candidate.name)) {
        Ok(pos) | Err(pos) => pos,
    };
    if pos >= max_candidates {
        return;
    }
    candidates.insert(pos, candidate);
    if candidates.len() > max_candidates {
        candidates.pop();
    }
}

// ── KernelRootDirReader ────────────────────────────────────────────────────

/// Namespace for kernel-mode directory helpers over [`KernelStorageIo`].
///
/// Production callers should use [`Self::lookup_in_storage`] and
/// [`Self::readdir_in_storage`]. The retained full-snapshot reader used by
/// legacy compatibility tests is available only under `cfg(test)`.
///
/// # Contract for #6252
///
/// The mounted replay/readback integration ([`#6252`]) consumes this reader
/// to resolve root-directory child names during `lookup` and to enumerate
/// entries during `readdir`. The sector range is provided by the committed-root
/// inode's directory extent pointer or the inode-table record's directory
/// locator field.
pub struct KernelRootDirReader {
    /// Sorted list of all live directory entries.
    #[cfg(test)]
    entries: Vec<KernelDirEntry>,
}

impl KernelRootDirReader {
    /// Create a new reader for a directory at the given sector range.
    ///
    /// Reads all directory pages from `dir_start_sector` through the range
    /// `dir_sector_count` (or until an all-zero page marks the end).
    /// Builds a name-sorted entry index in memory.
    ///
    /// Returns [`KernelRootDirError::EmptyDirectory`] if no pages or entries
    /// are found.
    #[cfg(test)]
    pub fn new(
        io: &dyn KernelStorageIo,
        dir_start_sector: u64,
        dir_sector_count: u64,
    ) -> Result<Self, KernelRootDirError> {
        let mut all_entries: Vec<KernelDirEntry> = Vec::new();
        let found_any = scan_live_entries(io, dir_start_sector, dir_sector_count, |entry| {
            all_entries.push(entry);
            ScanDecision::Continue
        })?;

        if !found_any || all_entries.is_empty() {
            return Err(KernelRootDirError::EmptyDirectory);
        }

        // Sort entries by name for binary-search lookup.
        // The offset field preserves stable positioning for readdir.
        all_entries.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(Self {
            entries: all_entries,
        })
    }

    /// Return the number of live entries in this directory.
    #[must_use]
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the directory is empty.
    #[must_use]
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Lookup ────────────────────────────────────────────────────────

    /// Look up a child entry directly from [`KernelStorageIo`].
    ///
    /// This helper scans the persisted directory pages and returns as soon as
    /// `name` is found. It does not construct or retain a full sorted entry
    /// vector.
    pub fn lookup_in_storage(
        io: &dyn KernelStorageIo,
        dir_start_sector: u64,
        dir_sector_count: u64,
        name: &[u8],
    ) -> Result<Option<DirMicroEntry>, KernelRootDirError> {
        let mut found = None;
        scan_live_entries(io, dir_start_sector, dir_sector_count, |entry| {
            if entry.name == name {
                found = Some(entry.to_micro_entry());
                return ScanDecision::Stop;
            }
            ScanDecision::Continue
        })?;
        Ok(found)
    }

    /// Look up a child entry by name.
    ///
    /// Returns the matching [`DirMicroEntry`] if found, or `None` if no
    /// entry with `name` exists in this directory.
    ///
    /// Entry-type constants match [`format::DT_DIR`], [`format::DT_FILE`],
    /// and [`format::DT_SYMLINK`].
    #[must_use]
    #[cfg(test)]
    pub fn lookup(&self, name: &[u8]) -> Option<DirMicroEntry> {
        match self
            .entries
            .binary_search_by(|e| e.name.as_slice().cmp(name))
        {
            Ok(idx) => Some(self.entries[idx].to_micro_entry()),
            Err(_) => None,
        }
    }

    /// Look up a child entry and return the full [`KernelDirEntry`] with
    /// the directory offset cookie for readdir positioning.
    #[must_use]
    #[cfg(test)]
    pub fn lookup_full(&self, name: &[u8]) -> Option<&KernelDirEntry> {
        match self
            .entries
            .binary_search_by(|e| e.name.as_slice().cmp(name))
        {
            Ok(idx) => Some(&self.entries[idx]),
            Err(_) => None,
        }
    }

    // ── Readdir ───────────────────────────────────────────────────────

    /// Read a bounded name-sorted directory window directly from storage.
    ///
    /// The method scans persisted pages through [`KernelStorageIo`] while
    /// retaining at most `max_entries + 1` candidate entries. That preserves
    /// the existing name-sorted readdir contract and next-cookie behavior
    /// without allocating memory proportional to the whole directory.
    pub fn readdir_in_storage(
        io: &dyn KernelStorageIo,
        dir_start_sector: u64,
        dir_sector_count: u64,
        cookie: u64,
        max_entries: usize,
    ) -> Result<(Vec<DirMicroEntry>, u64), KernelRootDirError> {
        if max_entries == 0 {
            return Ok((Vec::new(), cookie));
        }

        let boundary = find_readdir_boundary(io, dir_start_sector, dir_sector_count, cookie)?;
        let max_candidates = max_entries.saturating_add(1);
        let mut candidates: Vec<KernelDirEntry> = Vec::with_capacity(max_candidates.min(128));
        let mut found_live_entry = false;
        let found_any_page = scan_live_entries(io, dir_start_sector, dir_sector_count, |entry| {
            found_live_entry = true;
            if boundary.accepts(entry.name.as_slice()) {
                insert_sorted_candidate(&mut candidates, entry, max_candidates);
            }
            ScanDecision::Continue
        })?;

        if !found_any_page || !found_live_entry {
            return Err(KernelRootDirError::EmptyDirectory);
        }
        if candidates.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let has_more = candidates.len() > max_entries;
        if has_more {
            candidates.truncate(max_entries);
        }
        let next_cookie = if has_more {
            candidates.last().map(|entry| entry.offset).unwrap_or(0)
        } else {
            0
        };
        let entries = candidates
            .iter()
            .map(KernelDirEntry::to_micro_entry)
            .collect();
        Ok((entries, next_cookie))
    }

    /// Read directory entries starting from `cookie`.
    ///
    /// Returns up to `max_entries` entries and the cookie for the next
    /// entry (or `0` when all entries have been yielded). Entries are
    /// returned in name-sorted order, with the cookie matching the
    /// per-entry `offset` field for stable kernel-VFS position tracking.
    ///
    /// Pass `0` as `cookie` to begin iteration from the first entry.
    ///
    /// Returns [`KernelRootDirError::CookieOutOfRange`] when the cookie
    /// does not correspond to a valid entry position.
    #[cfg(test)]
    pub fn readdir(
        &self,
        cookie: u64,
        max_entries: usize,
    ) -> Result<(Vec<DirMicroEntry>, u64), KernelRootDirError> {
        if max_entries == 0 {
            return Ok((Vec::new(), cookie));
        }

        // Entries are sorted by name, not by offset. To find the start
        // position, we iterate to locate the entry with offset == cookie,
        // then start from the next entry. If cookie is 0, start from the
        // beginning.
        let start_idx = if cookie == 0 {
            0
        } else {
            match self.entries.iter().position(|e| e.offset == cookie) {
                Some(idx) => idx + 1, // start after the cookie entry
                None => {
                    // Cookie not found — find first entry after it
                    match self.entries.iter().position(|e| e.offset > cookie) {
                        Some(idx) => idx,
                        None => return Err(KernelRootDirError::CookieOutOfRange { cookie }),
                    }
                }
            }
        };

        let end_idx = (start_idx + max_entries).min(self.entries.len());
        let mut out: Vec<DirMicroEntry> = Vec::with_capacity(end_idx - start_idx);

        for idx in start_idx..end_idx {
            out.push(self.entries[idx].to_micro_entry());
        }

        let next_cookie = if end_idx < self.entries.len() {
            self.entries[end_idx - 1].offset
        } else {
            0 // end of directory
        };

        Ok((out, next_cookie))
    }

    /// Return the cookie for the first entry in the directory, or `0` if
    /// the directory is empty.
    #[must_use]
    #[cfg(test)]
    pub fn first_cookie(&self) -> u64 {
        self.entries.first().map(|e| e.offset).unwrap_or(0)
    }

    /// Return all entries in name-sorted order.
    #[must_use]
    #[cfg(test)]
    pub fn all_entries(&self) -> &[KernelDirEntry] {
        &self.entries
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use core::sync::atomic::{AtomicU32, Ordering};

    /// In-memory test backend implementing [`KernelStorageIo`].
    struct TestStorage {
        data: Vec<u8>,
        sector_size: u32,
        reads: AtomicU32,
    }

    impl TestStorage {
        fn new(size_sectors: u64, sector_size: u32) -> Self {
            let cap = (size_sectors as usize) * (sector_size as usize);
            Self {
                data: vec![0u8; cap],
                sector_size,
                reads: AtomicU32::new(0),
            }
        }

        fn write_page(&mut self, page_num: u32, page: &[u8; format::DIR_PAGE_SIZE]) {
            let ss = self.sector_size as u64;
            let sectors_per_page = (format::DIR_PAGE_SIZE as u64).div_ceil(ss);
            let start_sector = page_num as u64 * sectors_per_page;
            let offset = (start_sector as usize) * (self.sector_size as usize);
            let end = offset + page.len();
            self.data[offset..end].copy_from_slice(page.as_slice());
        }

        fn read_count(&self) -> u32 {
            self.reads.load(Ordering::Relaxed)
        }

        fn reset_read_count(&self) {
            self.reads.store(0, Ordering::Relaxed);
        }
    }

    impl KernelStorageIo for TestStorage {
        fn capabilities(&self) -> KernelStorageIoCapabilities {
            KernelStorageIoCapabilities {
                read: true,
                write: false,
                flush: true,
                discard: false,
                write_zeroes: false,
                zero_range: false,
                teardown: true,
                sector_size: self.sector_size,
                capacity_sectors: self.capacity_sectors(),
            }
        }

        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let ss = self.sector_size as u64;
            let start_byte = (start_sector * ss) as usize;
            let end_byte = start_byte + buf.len();
            if end_byte > self.data.len() {
                return Err(Errno::EINVAL);
            }
            buf.copy_from_slice(&self.data[start_byte..end_byte]);
            Ok((buf.len() as u64 / ss) as u32)
        }

        fn write_sectors(&self, _s: u64, _d: &[u8]) -> Result<u32, Errno> {
            Err(Errno::EIO)
        }
        fn flush(&self) -> Result<(), Errno> {
            Ok(())
        }
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
        fn capacity_sectors(&self) -> u64 {
            (self.data.len() / self.sector_size as usize) as u64
        }

        fn teardown(&self) -> Result<(), Errno> {
            Ok(())
        }
    }

    /// Build a DirPage with entries.
    fn make_page(page_number: u32, entries: &[(&[u8], u64, u8, u64)]) -> format::DirPage {
        let mut page = format::DirPage::new(page_number);
        let mut offset = (page_number as u64) * 1000;
        for &(name, inode_id, entry_type, generation) in entries {
            let e = format::DirEntry {
                name_len: name.len() as u8,
                inode_id,
                entry_type,
                generation,
                offset,
                name: name.to_vec(),
            };
            offset += 1;
            page.entries.push(e);
        }
        page.entry_count = page.entries.len() as u16;
        page
    }

    fn make_page_with_offsets(
        page_number: u32,
        entries: &[(&[u8], u64, u8, u64, u64)],
    ) -> format::DirPage {
        let mut page = format::DirPage::new(page_number);
        for &(name, inode_id, entry_type, generation, offset) in entries {
            page.entries.push(format::DirEntry {
                name_len: name.len() as u8,
                inode_id,
                entry_type,
                generation,
                offset,
                name: name.to_vec(),
            });
        }
        page.entry_count = page.entries.len() as u16;
        page
    }

    // ── Empty / error paths ──────────────────────────────────────────

    #[test]
    fn empty_directory_returns_error() {
        let storage = TestStorage::new(16, 512);
        assert!(matches!(
            KernelRootDirReader::new(&storage, 0, 16),
            Err(KernelRootDirError::EmptyDirectory)
        ));
    }

    #[test]
    fn all_zero_page_ends_reading() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(0, &make_page(0, &[(b"x", 10, format::DT_FILE, 1)]).encode());
        // Page 1 is all zeros
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();
        assert_eq!(reader.len(), 1);
    }

    // ── Lookup ───────────────────────────────────────────────────────

    #[test]
    fn single_entry_lookup_found() {
        let mut storage = TestStorage::new(8, 512);
        storage.write_page(
            0,
            &make_page(0, &[(b"hello", 10, format::DT_FILE, 1)]).encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 8).unwrap();
        let found = reader.lookup(b"hello").unwrap();
        assert_eq!(found.inode_id, 10);
        assert_eq!(found.kind, format::DT_FILE as u32);
    }

    #[test]
    fn single_entry_lookup_miss() {
        let mut storage = TestStorage::new(8, 512);
        storage.write_page(
            0,
            &make_page(0, &[(b"hello", 10, format::DT_FILE, 1)]).encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 8).unwrap();
        assert!(reader.lookup(b"world").is_none());
    }

    #[test]
    fn multiple_entries_lookup() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"alpha", 1, format::DT_FILE, 10),
                    (b"beta", 2, format::DT_DIR, 20),
                    (b"gamma", 3, format::DT_FILE, 30),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();
        assert_eq!(reader.len(), 3);
        assert_eq!(reader.lookup(b"beta").unwrap().kind, format::DT_DIR as u32);
        assert!(reader.lookup(b"delta").is_none());
    }

    #[test]
    fn multi_page_lookup() {
        let mut storage = TestStorage::new(32, 512);
        storage.write_page(
            0,
            &make_page(0, &[(b"aaa", 1, format::DT_FILE, 10)]).encode(),
        );
        storage.write_page(
            1,
            &make_page(1, &[(b"bbb", 2, format::DT_FILE, 20)]).encode(),
        );
        storage.write_page(
            2,
            &make_page(2, &[(b"ccc", 3, format::DT_DIR, 30)]).encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 32).unwrap();
        assert!(reader.lookup(b"aaa").is_some());
        assert!(reader.lookup(b"bbb").is_some());
        assert!(reader.lookup(b"ccc").is_some());
    }

    #[test]
    fn direct_lookup_stops_after_matching_page() {
        let mut storage = TestStorage::new(32, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"alpha", 1, format::DT_FILE, 10),
                    (b"target", 2, format::DT_DIR, 20),
                ],
            )
            .encode(),
        );
        storage.write_page(
            1,
            &make_page(1, &[(b"late", 3, format::DT_FILE, 30)]).encode(),
        );

        storage.reset_read_count();
        let found = KernelRootDirReader::lookup_in_storage(&storage, 0, 32, b"target")
            .unwrap()
            .expect("target entry");

        assert_eq!(found.inode_id, 2);
        assert_eq!(found.kind, format::DT_DIR as u32);
        assert_eq!(storage.read_count(), 1);
    }

    // ── Readdir ───────────────────────────────────────────────────────

    #[test]
    fn readdir_all() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"ccc", 3, format::DT_DIR, 30),
                    (b"aaa", 1, format::DT_FILE, 10),
                    (b"bbb", 2, format::DT_FILE, 20),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();
        let (entries, next) = reader.readdir(0, 10).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, b"aaa");
        assert_eq!(entries[1].name, b"bbb");
        assert_eq!(entries[2].name, b"ccc");
        assert_eq!(next, 0);
    }

    #[test]
    fn readdir_pagination() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"aaa", 1, format::DT_FILE, 10),
                    (b"bbb", 2, format::DT_FILE, 11),
                    (b"ccc", 3, format::DT_DIR, 12),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();

        let (b1, c1) = reader.readdir(0, 2).unwrap();
        assert_eq!(b1.len(), 2);
        assert_eq!(b1[0].name, b"aaa");
        assert_eq!(b1[1].name, b"bbb");

        let (b2, c2) = reader.readdir(c1, 10).unwrap();
        assert_eq!(b2.len(), 1);
        assert_eq!(b2[0].name, b"ccc");
        assert_eq!(c2, 0);
    }

    #[test]
    fn readdir_empty_max() {
        let mut storage = TestStorage::new(8, 512);
        storage.write_page(0, &make_page(0, &[(b"x", 1, format::DT_FILE, 10)]).encode());
        let reader = KernelRootDirReader::new(&storage, 0, 8).unwrap();
        let (entries, cookie) = reader.readdir(0, 0).unwrap();
        assert!(entries.is_empty());
        assert_eq!(cookie, 0);
    }

    #[test]
    fn readdir_bad_cookie() {
        let mut storage = TestStorage::new(8, 512);
        storage.write_page(0, &make_page(0, &[(b"x", 1, format::DT_FILE, 10)]).encode());
        let reader = KernelRootDirReader::new(&storage, 0, 8).unwrap();
        assert!(matches!(
            reader.readdir(9999, 10),
            Err(KernelRootDirError::CookieOutOfRange { .. })
        ));
    }

    #[test]
    fn readdir_continuity() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"aaa", 1, format::DT_FILE, 10),
                    (b"bbb", 2, format::DT_FILE, 11),
                    (b"ccc", 3, format::DT_DIR, 12),
                    (b"ddd", 4, format::DT_FILE, 13),
                    (b"eee", 5, format::DT_FILE, 14),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();

        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut cookie = 0u64;
        loop {
            let (batch, next) = reader.readdir(cookie, 2).unwrap();
            if batch.is_empty() && next == 0 {
                break;
            }
            for e in &batch {
                names.push(e.name.clone());
            }
            if next == 0 {
                break;
            }
            cookie = next;
        }
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], b"aaa");
        assert_eq!(names[4], b"eee");
    }

    #[test]
    fn direct_readdir_window_sorts_across_pages() {
        let mut storage = TestStorage::new(32, 512);
        storage.write_page(
            0,
            &make_page_with_offsets(
                0,
                &[
                    (b"mmm", 30, format::DT_FILE, 1, 30),
                    (b"zzz", 60, format::DT_FILE, 1, 60),
                ],
            )
            .encode(),
        );
        storage.write_page(
            1,
            &make_page_with_offsets(
                1,
                &[
                    (b"aaa", 10, format::DT_FILE, 1, 10),
                    (b"nnn", 40, format::DT_FILE, 1, 40),
                ],
            )
            .encode(),
        );
        storage.write_page(
            2,
            &make_page_with_offsets(
                2,
                &[
                    (b"bbb", 20, format::DT_FILE, 1, 20),
                    (b"yyy", 50, format::DT_FILE, 1, 50),
                ],
            )
            .encode(),
        );

        let (first, first_cookie) =
            KernelRootDirReader::readdir_in_storage(&storage, 0, 32, 0, 2).unwrap();
        assert_eq!(
            first.iter().map(|e| e.name.as_slice()).collect::<Vec<_>>(),
            [b"aaa".as_slice(), b"bbb".as_slice(),]
        );
        assert_eq!(first_cookie, 20);

        let (second, second_cookie) =
            KernelRootDirReader::readdir_in_storage(&storage, 0, 32, first_cookie, 3).unwrap();
        assert_eq!(
            second.iter().map(|e| e.name.as_slice()).collect::<Vec<_>>(),
            [b"mmm".as_slice(), b"nnn".as_slice(), b"yyy".as_slice(),]
        );
        assert_eq!(second_cookie, 50);

        let (third, third_cookie) =
            KernelRootDirReader::readdir_in_storage(&storage, 0, 32, second_cookie, 3).unwrap();
        assert_eq!(
            third.iter().map(|e| e.name.as_slice()).collect::<Vec<_>>(),
            [b"zzz".as_slice(),]
        );
        assert_eq!(third_cookie, 0);
    }

    // ── Corrupt / tombstone ──────────────────────────────────────────

    #[test]
    fn corrupt_wrong_magic() {
        let mut storage = TestStorage::new(8, 512);
        let mut buf = [0u8; format::DIR_PAGE_SIZE];
        buf[0..4].copy_from_slice(b"BADC");
        storage.write_page(0, &buf);
        assert!(matches!(
            KernelRootDirReader::new(&storage, 0, 8),
            Err(KernelRootDirError::CorruptPage { .. })
        ));
    }

    #[test]
    fn tombstoned_skipped() {
        let mut storage = TestStorage::new(16, 512);
        let mut page = make_page(0, &[(b"alive", 1, format::DT_FILE, 10)]);
        page.entries.push(format::DirEntry {
            name_len: 5,
            inode_id: 0,
            entry_type: format::DT_FILE,
            generation: 0,
            offset: 1001,
            name: b"ghost".to_vec(),
        });
        page.entry_count = page.entries.len() as u16;
        storage.write_page(0, &page.encode());
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();
        assert_eq!(reader.len(), 1);
        assert!(reader.lookup(b"alive").is_some());
        assert!(reader.lookup(b"ghost").is_none());
    }

    // ── Kind variants ────────────────────────────────────────────────

    #[test]
    fn kind_dir_and_symlink() {
        let mut storage = TestStorage::new(8, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"subdir", 5, format::DT_DIR, 1),
                    (b"link", 7, format::DT_SYMLINK, 2),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 8).unwrap();
        assert_eq!(
            reader.lookup(b"subdir").unwrap().kind,
            format::DT_DIR as u32
        );
        assert_eq!(
            reader.lookup(b"link").unwrap().kind,
            format::DT_SYMLINK as u32
        );
    }

    // ── Error to Errno conversion ────────────────────────────────────

    #[test]
    fn error_to_errno() {
        assert_eq!(
            Errno::from(KernelRootDirError::CorruptPage { page_number: 0 }),
            Errno::EIO
        );
        assert_eq!(
            Errno::from(KernelRootDirError::EmptyDirectory),
            Errno::ENOENT
        );
        assert_eq!(
            Errno::from(KernelRootDirError::CookieOutOfRange { cookie: 42 }),
            Errno::EINVAL
        );
        assert_eq!(Errno::from(KernelRootDirError::IoError), Errno::EIO);
    }

    // ── Accessors ────────────────────────────────────────────────────

    #[test]
    fn accessors_and_sorted() {
        let mut storage = TestStorage::new(16, 512);
        storage.write_page(
            0,
            &make_page(
                0,
                &[
                    (b"zzz", 3, format::DT_FILE, 30),
                    (b"aaa", 1, format::DT_FILE, 10),
                    (b"mmm", 2, format::DT_FILE, 20),
                ],
            )
            .encode(),
        );
        let reader = KernelRootDirReader::new(&storage, 0, 16).unwrap();
        let all = reader.all_entries();
        assert_eq!(all[0].name, b"aaa");
        assert_eq!(all[1].name, b"mmm");
        assert_eq!(all[2].name, b"zzz");
        assert_eq!(reader.first_cookie(), all[0].offset);
        assert!(!reader.is_empty());
    }

    // ── Large directory ──────────────────────────────────────────────

    #[test]
    fn large_directory_100_entries() {
        let mut storage = TestStorage::new(128, 512);
        let mut pages: Vec<format::DirPage> = Vec::new();
        let mut current = format::DirPage::new(0);
        for i in 0..100u64 {
            let name = format!("file_{i:03}");
            let e = format::DirEntry {
                name_len: name.len() as u8,
                inode_id: i + 1,
                entry_type: format::DT_FILE,
                generation: i,
                offset: 1000 + i,
                name: name.into_bytes(),
            };
            if !current.can_fit(e.encoded_len()) {
                current.entry_count = current.entries.len() as u16;
                pages.push(current);
                current = format::DirPage::new(pages.len() as u32);
            }
            current.entries.push(e);
        }
        if !current.entries.is_empty() {
            current.entry_count = current.entries.len() as u16;
            pages.push(current);
        }
        for (i, p) in pages.iter().enumerate() {
            storage.write_page(i as u32, &p.encode());
        }
        let reader = KernelRootDirReader::new(&storage, 0, 128).unwrap();
        assert_eq!(reader.len(), 100);
        let all = reader.all_entries();
        for i in 0..99 {
            assert!(all[i].name < all[i + 1].name);
        }
        assert!(reader.lookup(b"file_050").is_some());
        assert!(reader.lookup(b"nonexistent").is_none());
    }
}
