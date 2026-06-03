//! Kernel-mode extent map reader for VFS block translation.
//!
//! `ExtentMapKernelReader` traverses the on-disk extent map B-tree pages
//! through [`KernelStorageIo`], translating a logical file offset to a
//! physical block address for kernel VFS read and write dispatch.
//!
//! ## On-disk page format (4096 bytes)
//!
//! ```text
//! Page Header (54 bytes):
//!   magic:         [u8; 4]   "EXMP"
//!   page_kind:     u8        0=leaf, 1=internal
//!   flags:         u8        reserved
//!   entry_count:   u16 LE    number of entries (keys for internal)
//!   level:         u8        tree level (0=leaf, 1+=internal)
//!   checksum:      [u8; 32]  BLAKE3-256 of header[0..22] + body data
//!   reserved:      [u8; 7]   padding
//!
//! Leaf body:
//!   [entry_count] x ExtentMapEntryV2 (89-byte on-disk record)
//!
//! Internal body:
//!   child_count = entry_count + 1
//!   [child_count] x child_page_id: u64 LE
//!   [entry_count] x separator_key: u64 LE
//!
//! Padding: zero-fill to 4096 bytes
//! ```
//!
//! ## no_std
//!
//! This module is `no_std` compatible. It uses `alloc` for Vec
//! but does not depend on `std`. The `kernel` feature gates all
//! kernel-mode dependencies.

use alloc::vec::Vec;
use core::fmt;

use tidefs_kernel_storage_io::KernelStorageIo;
use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, LocatorId, EXTENT_MAP_DEFAULT_PAGE_SIZE, EXTENT_MAP_ENTRY_V2_SIZE,
    EXTENT_MAP_PAGE_HEADER_SIZE, EXTENT_MAP_PAGE_MAGIC,
};
use tidefs_types_vfs_core::Errno;

// ── Page format constants ────────────────────────────────────────────────

/// Magic bytes for extent map pages.
const PAGE_MAGIC: [u8; 4] = EXTENT_MAP_PAGE_MAGIC; // "EXMP"

/// Page kind: leaf node.
const PAGE_KIND_LEAF: u8 = 0;
/// Page kind: internal node.
const PAGE_KIND_INTERNAL: u8 = 1;

/// Offset within the 54-byte page header where the BLAKE3 checksum starts.
const PAGE_CHECKSUM_OFFSET: usize = 22;
/// Number of header bytes covered by the checksum (before the checksum field).
const PAGE_HASHED_HEADER_LEN: usize = 22;

// ── ExtentMapping ─────────────────────────────────────────────────────────

/// Result of an extent map lookup: physical block address and extent metadata.
///
/// Returned by [`ExtentMapKernelReader::lookup`] to inform kernel VFS
/// read and write dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentMapping {
    /// Physical block address (byte offset on the block device).
    pub phys_addr: u64,
    /// Length of this extent in bytes.
    pub length: u64,
    /// Logical offset of this extent within the file.
    pub logical_offset: u64,
    /// End of this extent within the file (logical_offset + length).
    pub logical_end: u64,
    /// Compression hint (0=none, 1-3=algorithm).
    pub compression: u8,
    /// Extent type: 0=DATA, 1=UNWRITTEN.
    pub extent_kind: u8,
    /// Locator ID for the physical storage object.
    pub locator_id: LocatorId,
    /// Whether the returned extent maps to a hole (no physical storage).
    pub is_hole: bool,
}

impl ExtentMapping {
    /// Create a hole mapping for the given range.
    #[must_use]
    pub fn hole(logical_offset: u64, length: u64) -> Self {
        Self {
            phys_addr: 0,
            length,
            logical_offset,
            logical_end: logical_offset.saturating_add(length),
            compression: 0,
            extent_kind: 0,
            locator_id: LocatorId::NONE,
            is_hole: true,
        }
    }

    /// Create a mapping from an extent map entry.
    #[must_use]
    pub fn from_entry(entry: &ExtentMapEntryV2) -> Self {
        Self {
            phys_addr: entry.locator_id.0,
            length: entry.length,
            logical_offset: entry.logical_offset,
            logical_end: entry.end_offset(),
            compression: entry.compression_hint(),
            extent_kind: entry.extent_kind,
            locator_id: entry.locator_id,
            is_hole: entry.extent_kind != ExtentMapEntryV2::KIND_DATA
                && entry.extent_kind != ExtentMapEntryV2::KIND_UNWRITTEN
                && entry.extent_kind != ExtentMapEntryV2::KIND_PENDING_DATA,
        }
    }
}

impl fmt::Display for ExtentMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_hole {
            write!(
                f,
                "ExtentMapping(hole logical={}..{})",
                self.logical_offset, self.logical_end
            )
        } else {
            write!(
                f,
                "ExtentMapping(phys={:#x} logical={}..{} len={} kind={})",
                self.phys_addr,
                self.logical_offset,
                self.logical_end,
                self.length,
                self.extent_kind
            )
        }
    }
}

// ── Page parser ───────────────────────────────────────────────────────────

/// Decoded extent map page header.
#[derive(Clone, Copy, Debug)]
struct PageHeader {
    page_kind: u8,
    entry_count: u16,
}

/// Errors returned by page parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageError {
    WrongMagic,
    UnknownPageKind,
    ChecksumMismatch,
    Truncated,
    EntryOverflow,
    /// Leaf entries are unsorted, overlapping, or have invalid extent_kind.
    CorruptOrdering,
}

impl From<PageError> for Errno {
    fn from(e: PageError) -> Self {
        match e {
            PageError::WrongMagic
            | PageError::UnknownPageKind
            | PageError::ChecksumMismatch
            | PageError::Truncated
            | PageError::EntryOverflow
            | PageError::CorruptOrdering => Errno::EIO,
        }
    }
}

/// Compute the byte range of the body data within a 4096-byte page.
///
/// Leaf: `data_start = 54`, `data_end = 54 + entry_count * 89`.
/// Internal: `data_start = 54`, `data_end = 54 + (2*entry_count + 1) * 8`.
fn body_range(page_kind: u8, entry_count: u16) -> Result<(usize, usize), PageError> {
    let data_start = EXTENT_MAP_PAGE_HEADER_SIZE;
    let body_len = match page_kind {
        PAGE_KIND_LEAF => (entry_count as usize)
            .checked_mul(EXTENT_MAP_ENTRY_V2_SIZE)
            .ok_or(PageError::EntryOverflow)?,
        PAGE_KIND_INTERNAL => {
            let child_count = (entry_count as usize)
                .checked_add(1)
                .ok_or(PageError::EntryOverflow)?;
            child_count
                .checked_add(entry_count as usize)
                .ok_or(PageError::EntryOverflow)?
                .checked_mul(8)
                .ok_or(PageError::EntryOverflow)?
        }
        _ => return Err(PageError::UnknownPageKind),
    };
    let data_end = data_start
        .checked_add(body_len)
        .ok_or(PageError::EntryOverflow)?;
    if data_end > EXTENT_MAP_DEFAULT_PAGE_SIZE {
        return Err(PageError::EntryOverflow);
    }
    Ok((data_start, data_end))
}

/// Parse and verify the page header and checksum.
fn parse_page_header(page_buf: &[u8]) -> Result<(PageHeader, usize, usize), PageError> {
    if page_buf.len() < EXTENT_MAP_DEFAULT_PAGE_SIZE {
        return Err(PageError::Truncated);
    }

    if page_buf[0..4] != PAGE_MAGIC {
        return Err(PageError::WrongMagic);
    }

    let page_kind = page_buf[4];
    if page_kind != PAGE_KIND_LEAF && page_kind != PAGE_KIND_INTERNAL {
        return Err(PageError::UnknownPageKind);
    }

    let entry_count = u16::from_le_bytes([page_buf[6], page_buf[7]]);

    let header = PageHeader {
        page_kind,
        entry_count,
    };
    let (data_start, data_end) = body_range(page_kind, entry_count)?;

    // Verify BLAKE3 checksum: header[0..22] + body data.
    let expected_checksum = &page_buf[PAGE_CHECKSUM_OFFSET..PAGE_CHECKSUM_OFFSET + 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&page_buf[..PAGE_HASHED_HEADER_LEN]);
    hasher.update(&page_buf[data_start..data_end]);
    let actual = hasher.finalize();

    if actual.as_bytes() != expected_checksum {
        return Err(PageError::ChecksumMismatch);
    }

    Ok((header, data_start, data_end))
}

/// Decode a single ExtentMapEntryV2 from 89-byte on-disk format.
fn decode_entry_v2(data: &[u8]) -> Result<ExtentMapEntryV2, PageError> {
    if data.len() < EXTENT_MAP_ENTRY_V2_SIZE {
        return Err(PageError::Truncated);
    }

    let logical_offset =
        u64::from_le_bytes(data[0..8].try_into().map_err(|_| PageError::Truncated)?);
    let length = u64::from_le_bytes(data[8..16].try_into().map_err(|_| PageError::Truncated)?);
    let extent_kind = data[16];
    let flags = data[17];
    let locator_id = LocatorId(u64::from_le_bytes(
        data[18..26].try_into().map_err(|_| PageError::Truncated)?,
    ));
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&data[26..58]);
    let birth_commit_group =
        u64::from_le_bytes(data[58..66].try_into().map_err(|_| PageError::Truncated)?);
    let mut reserved = [0u8; 15];
    reserved.copy_from_slice(&data[66..81]);
    // bytes 81..89 are padding

    Ok(ExtentMapEntryV2 {
        logical_offset,
        length,
        extent_kind,
        flags,
        locator_id,
        checksum,
        birth_commit_group,
        reserved,
    })
}

/// Parse leaf entries from body data.
fn parse_leaf_entries(
    page_buf: &[u8],
    data_start: usize,
    data_end: usize,
    expected_count: u16,
) -> Result<Vec<ExtentMapEntryV2>, PageError> {
    let entry_data = &page_buf[data_start..data_end];
    if entry_data.len() / EXTENT_MAP_ENTRY_V2_SIZE != expected_count as usize {
        return Err(PageError::Truncated);
    }
    let mut entries = Vec::with_capacity(expected_count as usize);
    for chunk in entry_data.chunks_exact(EXTENT_MAP_ENTRY_V2_SIZE) {
        entries.push(decode_entry_v2(chunk)?);
    }
    validate_leaf_entries(&entries)?;
    Ok(entries)
}

/// Validate leaf entries for ordering invariants before binary search.
///
/// Checks that entries are sorted by `logical_offset`, have positive length,
/// do not overlap, and have a recognized `extent_kind`.
fn validate_leaf_entries(entries: &[ExtentMapEntryV2]) -> Result<(), PageError> {
    let mut prev_end: Option<u64> = None;
    for entry in entries {
        // Positive length
        if entry.length == 0 {
            return Err(PageError::CorruptOrdering);
        }
        // Valid extent_kind
        if entry.extent_kind != ExtentMapEntryV2::KIND_DATA
            && entry.extent_kind != ExtentMapEntryV2::KIND_UNWRITTEN
            && entry.extent_kind != ExtentMapEntryV2::KIND_PENDING_DATA
        {
            return Err(PageError::CorruptOrdering);
        }
        // Monotonic ordering and no overlap
        if let Some(prev) = prev_end {
            if entry.logical_offset < prev {
                return Err(PageError::CorruptOrdering);
            }
        }
        prev_end = Some(entry.end_offset());
    }
    Ok(())
}

/// Parse internal page body into child page addresses and separator keys.
fn parse_internal_page(
    page_buf: &[u8],
    data_start: usize,
    data_end: usize,
    entry_count: u16,
) -> Result<(Vec<u64>, Vec<u64>), PageError> {
    let child_count = (entry_count as usize) + 1;
    let body = &page_buf[data_start..data_end];
    let expected_size = (child_count + entry_count as usize) * 8;
    if body.len() < expected_size {
        return Err(PageError::Truncated);
    }
    let mut pos = 0;
    let mut child_pages = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        child_pages.push(u64::from_le_bytes(
            body[pos..pos + 8]
                .try_into()
                .map_err(|_| PageError::Truncated)?,
        ));
        pos += 8;
    }
    let mut sep_keys = Vec::with_capacity(entry_count as usize);
    for _ in 0..entry_count as usize {
        sep_keys.push(u64::from_le_bytes(
            body[pos..pos + 8]
                .try_into()
                .map_err(|_| PageError::Truncated)?,
        ));
        pos += 8;
    }
    Ok((child_pages, sep_keys))
}

// ── ExtentMapKernelReader ──────────────────────────────────────────────────

/// Kernel-mode extent map reader that traverses on-disk B-tree pages
/// through [`KernelStorageIo`].
///
/// Translates logical file offsets to physical block addresses for
/// kernel VFS read and write dispatch.
pub struct ExtentMapKernelReader<'a> {
    io: &'a dyn KernelStorageIo,
    root_page_addr: u64,
    sector_shift: u32,
}

impl<'a> ExtentMapKernelReader<'a> {
    /// Create a new kernel-mode extent map reader.
    ///
    /// - `io`: Storage I/O handle for reading extent map pages.
    /// - `root_page_addr`: Physical byte address of the root page.
    /// - `sector_shift`: log2 of the sector size (9 for 512, 12 for 4096).
    #[must_use]
    pub fn new(io: &'a dyn KernelStorageIo, root_page_addr: u64, sector_shift: u32) -> Self {
        Self {
            io,
            root_page_addr,
            sector_shift,
        }
    }

    /// Look up the extent covering `logical_offset`.
    ///
    /// Returns an [`ExtentMapping`] with physical block address and extent
    /// metadata, or an [`Errno`] on I/O or format errors.
    ///
    /// If the offset falls in a hole, the returned mapping has
    /// `is_hole = true` and `phys_addr = 0`.
    pub fn lookup(&self, logical_offset: u64) -> Result<ExtentMapping, Errno> {
        let mut page_buf = [0u8; EXTENT_MAP_DEFAULT_PAGE_SIZE];
        self.lookup_in_page(self.root_page_addr, logical_offset, &mut page_buf)
    }

    fn lookup_in_page(
        &self,
        page_addr: u64,
        logical_offset: u64,
        page_buf: &mut [u8; EXTENT_MAP_DEFAULT_PAGE_SIZE],
    ) -> Result<ExtentMapping, Errno> {
        self.read_page(page_addr, page_buf)?;
        let (header, data_start, data_end) = parse_page_header(page_buf).map_err(Errno::from)?;

        match header.page_kind {
            PAGE_KIND_LEAF => self.lookup_in_leaf(
                page_buf,
                data_start,
                data_end,
                header.entry_count,
                logical_offset,
            ),
            PAGE_KIND_INTERNAL => {
                let mut scratch = [0u8; EXTENT_MAP_DEFAULT_PAGE_SIZE];
                self.lookup_in_internal(
                    page_buf,
                    data_start,
                    data_end,
                    header.entry_count,
                    logical_offset,
                    &mut scratch,
                )
            }
            _ => Err(Errno::EIO),
        }
    }

    fn lookup_in_leaf(
        &self,
        page_buf: &[u8],
        data_start: usize,
        data_end: usize,
        entry_count: u16,
        logical_offset: u64,
    ) -> Result<ExtentMapping, Errno> {
        let entries =
            parse_leaf_entries(page_buf, data_start, data_end, entry_count).map_err(Errno::from)?;

        if entries.is_empty() {
            return Ok(ExtentMapping::hole(
                logical_offset,
                u64::MAX - logical_offset,
            ));
        }

        match entries.binary_search_by(|e| {
            if e.end_offset() <= logical_offset {
                core::cmp::Ordering::Less
            } else if e.logical_offset > logical_offset {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => Ok(ExtentMapping::from_entry(&entries[idx])),
            Err(idx) => {
                // Gap (hole) between extents.
                // By binary search semantics, logical_offset is in the gap
                // after entries[idx-1].end_offset() and before entries[idx].logical_offset.
                let hole_end = if idx < entries.len() {
                    entries[idx].logical_offset
                } else {
                    u64::MAX
                };
                let hole_len = hole_end.saturating_sub(logical_offset);
                Ok(ExtentMapping::hole(logical_offset, hole_len))
            }
        }
    }

    fn lookup_in_internal(
        &self,
        page_buf: &[u8],
        data_start: usize,
        data_end: usize,
        entry_count: u16,
        logical_offset: u64,
        scratch: &mut [u8; EXTENT_MAP_DEFAULT_PAGE_SIZE],
    ) -> Result<ExtentMapping, Errno> {
        let (child_pages, sep_keys) =
            parse_internal_page(page_buf, data_start, data_end, entry_count)
                .map_err(Errno::from)?;

        if child_pages.is_empty() {
            return Err(Errno::EIO);
        }

        // sep_keys[i] is the min key of child_pages[i+1].
        let child_idx = match sep_keys.binary_search(&logical_offset) {
            Ok(idx) => idx + 1, // exact match → right child
            Err(idx) => idx,    // logical_offset < sep_keys[idx] → child idx
        };

        self.lookup_in_page(child_pages[child_idx], logical_offset, scratch)
    }

    fn read_page(
        &self,
        phys_addr: u64,
        page_buf: &mut [u8; EXTENT_MAP_DEFAULT_PAGE_SIZE],
    ) -> Result<(), Errno> {
        let start_sector = phys_addr >> self.sector_shift;
        let sectors_per_page = (EXTENT_MAP_DEFAULT_PAGE_SIZE as u64) >> self.sector_shift;
        if sectors_per_page == 0 {
            return Err(Errno::EINVAL);
        }
        let sectors_read = self
            .io
            .read_sectors(start_sector, page_buf.as_mut_slice())?;
        if (sectors_read as u64) < sectors_per_page {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use alloc::{collections, format, vec};

    use super::*;

    /// Build a valid leaf page buffer with entries and correct checksum.
    fn make_leaf_page(entries: &[ExtentMapEntryV2]) -> [u8; 4096] {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_LEAF;
        page[6..8].copy_from_slice(&(entries.len() as u16).to_le_bytes());

        let mut body_pos = 54;
        for e in entries {
            let buf = &mut page[body_pos..body_pos + 89];
            buf[0..8].copy_from_slice(&e.logical_offset.to_le_bytes());
            buf[8..16].copy_from_slice(&e.length.to_le_bytes());
            buf[16] = e.extent_kind;
            buf[17] = e.flags;
            buf[18..26].copy_from_slice(&e.locator_id.0.to_le_bytes());
            buf[26..58].copy_from_slice(&e.checksum);
            buf[58..66].copy_from_slice(&e.birth_commit_group.to_le_bytes());
            buf[66..81].copy_from_slice(&e.reserved);
            // buf[81..89] stays zero (padding)
            body_pos += 89;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&page[..22]);
        hasher.update(&page[54..body_pos]);
        let checksum = hasher.finalize();
        page[22..54].copy_from_slice(checksum.as_bytes());
        page
    }

    /// Build a valid internal page with child IDs and separator keys.
    fn make_internal_page(child_pages: &[u64], sep_keys: &[u64], level: u8) -> [u8; 4096] {
        assert_eq!(child_pages.len(), sep_keys.len() + 1);
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_INTERNAL;
        page[6..8].copy_from_slice(&(sep_keys.len() as u16).to_le_bytes());
        page[8] = level;

        let mut body_pos = 54;
        for &cp in child_pages {
            page[body_pos..body_pos + 8].copy_from_slice(&cp.to_le_bytes());
            body_pos += 8;
        }
        for &sk in sep_keys {
            page[body_pos..body_pos + 8].copy_from_slice(&sk.to_le_bytes());
            body_pos += 8;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&page[..22]);
        hasher.update(&page[54..body_pos]);
        let checksum = hasher.finalize();
        page[22..54].copy_from_slice(checksum.as_bytes());
        page
    }

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0xA5; 32], 1)
    }

    // ── Entry decode ──────────────────────────────────────────────────

    #[test]
    fn decode_entry_v2_data_round_trip() {
        let mut buf = vec![0u8; EXTENT_MAP_ENTRY_V2_SIZE];
        buf[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[16] = ExtentMapEntryV2::KIND_DATA;
        buf[18..26].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        buf[26..58].copy_from_slice(&[0xAB; 32]);
        buf[58..66].copy_from_slice(&42u64.to_le_bytes());

        let decoded = decode_entry_v2(&buf).unwrap();
        assert_eq!(decoded.logical_offset, 0x1000);
        assert_eq!(decoded.length, 0x2000);
        assert_eq!(decoded.extent_kind, ExtentMapEntryV2::KIND_DATA);
        assert_eq!(decoded.locator_id, LocatorId(0xDEAD_BEEF));
        assert_eq!(decoded.checksum, [0xAB; 32]);
        assert_eq!(decoded.birth_commit_group, 42);
    }

    #[test]
    fn decode_entry_v2_unwritten() {
        let mut buf = vec![0u8; EXTENT_MAP_ENTRY_V2_SIZE];
        buf[0..8].copy_from_slice(&4096u64.to_le_bytes());
        buf[8..16].copy_from_slice(&8192u64.to_le_bytes());
        buf[16] = ExtentMapEntryV2::KIND_UNWRITTEN;
        buf[58..66].copy_from_slice(&100u64.to_le_bytes());
        let decoded = decode_entry_v2(&buf).unwrap();
        assert!(decoded.is_unwritten());
    }

    #[test]
    fn decode_entry_v2_truncated() {
        assert!(decode_entry_v2(&[0u8; 40]).is_err());
    }

    // ── ExtentMapping ────────────────────────────────────────────────

    #[test]
    fn extent_mapping_hole() {
        let m = ExtentMapping::hole(4096, 8192);
        assert!(m.is_hole);
        assert_eq!(m.phys_addr, 0);
        assert_eq!(m.length, 8192);
        assert_eq!(m.logical_end, 12288);
    }

    #[test]
    fn extent_mapping_from_data_entry() {
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(0x1000), [0u8; 32], 1);
        let m = ExtentMapping::from_entry(&entry);
        assert!(!m.is_hole);
        assert_eq!(m.phys_addr, 0x1000);
        assert_eq!(m.length, 4096);
    }

    #[test]
    fn extent_mapping_display_hole_and_data() {
        let m = ExtentMapping::hole(0, 4096);
        assert!(format!("{m}").contains("hole"));
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(0x42), [0u8; 32], 0);
        let m2 = ExtentMapping::from_entry(&entry);
        assert!(format!("{m2}").contains("0x42"));
    }

    // ── Page header ──────────────────────────────────────────────────

    #[test]
    fn parse_page_header_leaf_empty() {
        let page = make_leaf_page(&[]);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        assert_eq!(hdr.page_kind, PAGE_KIND_LEAF);
        assert_eq!(hdr.entry_count, 0);
        assert_eq!(ds, 54);
        assert_eq!(de, 54);
    }

    #[test]
    fn parse_page_header_leaf_one_entry() {
        let page = make_leaf_page(&[data(0, 4096, 1)]);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        assert_eq!(hdr.page_kind, PAGE_KIND_LEAF);
        assert_eq!(hdr.entry_count, 1);
        assert_eq!(ds, 54);
        assert_eq!(de, 143);
    }

    #[test]
    fn parse_page_header_internal() {
        let page = make_internal_page(&[0x1000, 0x2000, 0x3000], &[0x4000, 0x8000], 1);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        assert_eq!(hdr.page_kind, PAGE_KIND_INTERNAL);
        assert_eq!(hdr.entry_count, 2);
        assert_eq!(ds, 54);
        assert_eq!(de, 94); // 54 + (3+2)*8 = 94
    }

    #[test]
    fn parse_page_header_wrong_magic() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::WrongMagic)
        ));
    }

    #[test]
    fn parse_page_header_unknown_kind() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = 0xFF;
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::UnknownPageKind)
        ));
    }

    #[test]
    fn parse_page_header_checksum_mismatch() {
        let mut page = make_leaf_page(&[data(0, 4096, 1)]);
        page[30] ^= 0xFF; // corrupt checksum
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::ChecksumMismatch)
        ));
    }

    #[test]
    fn parse_page_header_truncated() {
        assert!(matches!(
            parse_page_header(&[0u8; 100]),
            Err(PageError::Truncated)
        ));
    }

    #[test]
    fn parse_page_header_entry_overflow_leaf() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_LEAF;
        page[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::EntryOverflow)
        ));
    }

    #[test]
    fn parse_page_header_entry_overflow_internal() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_INTERNAL;
        // Large entry_count gives body exceeding page size
        page[6..8].copy_from_slice(&300u16.to_le_bytes());
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::EntryOverflow)
        ));
    }

    // ── PageError to Errno ──────────────────────────────────────────

    #[test]
    fn page_error_converts_to_eio() {
        assert_eq!(Errno::from(PageError::WrongMagic), Errno::EIO);
        assert_eq!(Errno::from(PageError::ChecksumMismatch), Errno::EIO);
        assert_eq!(Errno::from(PageError::Truncated), Errno::EIO);
        assert_eq!(Errno::from(PageError::EntryOverflow), Errno::EIO);
        assert_eq!(Errno::from(PageError::UnknownPageKind), Errno::EIO);
    }

    // ── Internal page parsing ────────────────────────────────────────

    #[test]
    fn parse_internal_page_zero_entries() {
        let page = make_internal_page(&[0xABCD], &[], 0);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        let (children, keys) = parse_internal_page(&page, ds, de, hdr.entry_count).unwrap();
        assert_eq!(children, vec![0xABCD]);
        assert!(keys.is_empty());
    }

    #[test]
    fn parse_internal_page_correct_child_key_count() {
        let page = make_internal_page(&[10, 20, 30, 40], &[100, 200, 300], 2);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        let (children, keys) = parse_internal_page(&page, ds, de, hdr.entry_count).unwrap();
        assert_eq!(children.len(), 4);
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn parse_internal_page_truncated_body_checksum_mismatch() {
        // Create a page with entry_count=5 but only 8 bytes of body in the
        // checksum range; body_range returns data_end=142 but we only hashed 8
        // bytes → checksum will be wrong.
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_INTERNAL;
        page[6..8].copy_from_slice(&5u16.to_le_bytes());
        let body_start = 54;
        page[body_start..body_start + 8].copy_from_slice(&0u64.to_le_bytes());

        let mut hasher = blake3::Hasher::new();
        hasher.update(&page[..22]);
        hasher.update(&page[body_start..body_start + 8]); // only 8 bytes
        let checksum = hasher.finalize();
        page[22..54].copy_from_slice(checksum.as_bytes());

        // body_range gives 54..142 but checksum was over 54..62 → mismatch.
        assert!(matches!(
            parse_page_header(&page),
            Err(PageError::ChecksumMismatch)
        ));
    }

    // ── Leaf entry parsing ──────────────────────────────────────────

    #[test]
    fn parse_leaf_entries_single() {
        let page = make_leaf_page(&[data(0x1000, 4096, 42)]);
        let (hdr, ds, de) = parse_page_header(&page).unwrap();
        let entries = parse_leaf_entries(&page, ds, de, hdr.entry_count).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].logical_offset, 0x1000);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[0].locator_id, LocatorId(42));
    }

    #[test]
    fn parse_leaf_entries_count_mismatch() {
        let page = make_leaf_page(&[data(0, 4096, 1)]);
        let (_, ds, de) = parse_page_header(&page).unwrap();
        assert!(parse_leaf_entries(&page, ds, de, 2).is_err());
    }

    #[test]
    fn parse_leaf_entries_empty() {
        let page = make_leaf_page(&[]);
        let entries = parse_leaf_entries(&page, 54, 54, 0).unwrap();
        assert!(entries.is_empty());
    }

    // ── Mock KernelStorageIo for lookup tests ──────────────────────────

    /// In-memory page store for testing `ExtentMapKernelReader`.
    ///
    /// Maps page addresses (byte offsets) to 4096-byte page buffers.
    struct MockStorageIo {
        pages: collections::BTreeMap<u64, [u8; EXTENT_MAP_DEFAULT_PAGE_SIZE]>,
        sector_size: u32,
        capacity_sectors: u64,
    }

    impl MockStorageIo {
        fn new(sector_size: u32) -> Self {
            Self {
                pages: collections::BTreeMap::new(),
                sector_size,
                capacity_sectors: u64::MAX,
            }
        }

        fn insert_page(&mut self, addr: u64, page: [u8; EXTENT_MAP_DEFAULT_PAGE_SIZE]) {
            self.pages.insert(addr, page);
        }
    }

    impl KernelStorageIo for MockStorageIo {
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let ss = self.sector_size as u64;
            if ss == 0 {
                return Err(Errno::EINVAL);
            }
            let byte_offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)?;
            if buf.len() % self.sector_size as usize != 0 {
                return Err(Errno::EINVAL);
            }
            let sectors_requested = (buf.len() / self.sector_size as usize) as u64;
            if start_sector + sectors_requested > self.capacity_sectors {
                return Err(Errno::EINVAL);
            }
            let mut copied: u32 = 0;
            for i in 0..sectors_requested {
                let page_addr = byte_offset + i * ss;
                if let Some(page) = self.pages.get(&page_addr) {
                    let sector_start = (i as usize) * self.sector_size as usize;
                    let sector_end = sector_start + self.sector_size as usize;
                    let copy_len = sector_end.min(buf.len());
                    buf[sector_start..copy_len].copy_from_slice(&page[..copy_len - sector_start]);
                } else {
                    // Unmapped region → zero-fill
                    let sector_start = (i as usize) * self.sector_size as usize;
                    let sector_end = sector_start + self.sector_size as usize;
                    let copy_len = sector_end.min(buf.len());
                    buf[sector_start..copy_len].fill(0);
                }
                copied += 1;
            }
            Ok(copied)
        }

        fn write_sectors(&self, _start_sector: u64, _data: &[u8]) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }

        fn flush(&self) -> Result<(), Errno> {
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            self.capacity_sectors
        }
    }

    fn unwritten(off: u64, len: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(off, len, 1)
    }

    // ── Leaf lookup integration tests ─────────────────────────────────

    #[test]
    fn lookup_data_extent_middle() {
        let leaf = make_leaf_page(&[
            data(0, 4096, 0x100),
            data(4096, 4096, 0x200),
            data(8192, 4096, 0x300),
        ]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(4096).unwrap();
        assert!(!m.is_hole);
        assert_eq!(m.phys_addr, 0x200);
        assert_eq!(m.logical_offset, 4096);
        assert_eq!(m.length, 4096);
        assert_eq!(m.logical_end, 8192);
        assert_eq!(m.extent_kind, ExtentMapEntryV2::KIND_DATA);
        assert!(m.locator_id.is_some());
    }

    #[test]
    fn lookup_data_extent_first() {
        let leaf = make_leaf_page(&[data(0, 4096, 0x42), data(4096, 4096, 0x43)]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(0).unwrap();
        assert!(!m.is_hole);
        assert_eq!(m.phys_addr, 0x42);
        assert_eq!(m.logical_offset, 0);
    }

    #[test]
    fn lookup_data_extent_last() {
        let leaf = make_leaf_page(&[
            data(0, 4096, 0x10),
            data(4096, 4096, 0x20),
            data(8192, 4096, 0x30),
        ]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(10000).unwrap();
        assert!(!m.is_hole);
        assert_eq!(m.phys_addr, 0x30);
        assert_eq!(m.logical_offset, 8192);
    }

    #[test]
    fn lookup_unwritten_extent() {
        let leaf = make_leaf_page(&[
            data(0, 4096, 0x10),
            unwritten(4096, 4096),
            data(8192, 4096, 0x20),
        ]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(5000).unwrap();
        assert!(!m.is_hole);
        assert_eq!(m.extent_kind, ExtentMapEntryV2::KIND_UNWRITTEN);
        assert_eq!(m.logical_offset, 4096);
        assert_eq!(m.length, 4096);
        assert!(m.locator_id.is_none());
        assert_eq!(m.phys_addr, 0);
    }

    #[test]
    fn lookup_hole_between_extents() {
        let leaf = make_leaf_page(&[
            data(0, 4096, 0x10),
            // hole at 4096..8192
            data(8192, 4096, 0x20),
        ]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(6000).unwrap();
        assert!(m.is_hole);
        assert_eq!(m.logical_offset, 6000);
        // hole ends at next extent start
        assert_eq!(m.logical_end, 8192);
        assert_eq!(m.length, 2192);
        assert_eq!(m.phys_addr, 0);
        assert!(m.locator_id.is_none());
    }

    #[test]
    fn lookup_hole_before_first_extent() {
        let leaf = make_leaf_page(&[data(4096, 4096, 0x10)]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(0).unwrap();
        assert!(m.is_hole);
        assert_eq!(m.logical_offset, 0);
        assert_eq!(m.logical_end, 4096);
        assert_eq!(m.length, 4096);
    }

    #[test]
    fn lookup_eof_beyond_last_extent() {
        let leaf = make_leaf_page(&[data(0, 4096, 0x10)]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(8192).unwrap();
        assert!(m.is_hole);
        assert_eq!(m.logical_offset, 8192);
        assert_eq!(m.logical_end, u64::MAX);
    }

    #[test]
    fn lookup_empty_leaf() {
        let leaf = make_leaf_page(&[]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let m = reader.lookup(0).unwrap();
        assert!(m.is_hole);
        assert_eq!(m.logical_end, u64::MAX);
    }

    // ── Internal-to-leaf B-tree traversal tests ───────────────────────

    #[test]
    fn lookup_internal_routes_to_correct_leaf() {
        // Build two leaf pages:
        // Leaf 0x1000: entries 0..4096
        // Leaf 0x2000: entries 4096..8192
        let leaf0 = make_leaf_page(&[data(0, 4096, 0xAAA)]);
        let leaf1 = make_leaf_page(&[data(4096, 4096, 0xBBB)]);

        // Internal page: children [0x1000, 0x2000], sep_keys [4096]
        let internal = make_internal_page(&[0x1000, 0x2000], &[4096], 1);

        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0x0000, internal); // root at 0
        mock.insert_page(0x1000, leaf0);
        mock.insert_page(0x2000, leaf1);

        let reader = ExtentMapKernelReader::new(&mock, 0x0000, 9);

        // Lookup in first leaf
        let m = reader.lookup(0).unwrap();
        assert_eq!(m.phys_addr, 0xAAA);

        // Lookup in second leaf
        let m = reader.lookup(4096).unwrap();
        assert_eq!(m.phys_addr, 0xBBB);

        // Lookup at separator boundary
        let m = reader.lookup(4096).unwrap();
        assert_eq!(m.phys_addr, 0xBBB);
    }

    #[test]
    fn lookup_internal_hole_near_boundary() {
        // Leaf0: 0..4096 DATA, Leaf1: 8192..12288 DATA
        // Hole: 4096..8192
        let leaf0 = make_leaf_page(&[data(0, 4096, 0xAAA)]);
        let leaf1 = make_leaf_page(&[data(8192, 4096, 0xBBB)]);
        let internal = make_internal_page(&[0x1000, 0x2000], &[4096], 1);

        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0x0000, internal);
        mock.insert_page(0x1000, leaf0);
        mock.insert_page(0x2000, leaf1);

        let reader = ExtentMapKernelReader::new(&mock, 0x0000, 9);

        let m = reader.lookup(6000).unwrap();
        assert!(m.is_hole);
        assert_eq!(m.logical_offset, 6000);
        // hole goes up to leaf1's first entry
        assert_eq!(m.logical_end, 8192);
    }

    #[test]
    fn lookup_deeper_internal_routes_to_leaf() {
        // Two-level B-tree:
        // Root internal (level 2), two child internal pages (level 1), four leaves
        let leaf00 = make_leaf_page(&[data(0, 4096, 0x111)]);
        let leaf01 = make_leaf_page(&[data(8192, 4096, 0x222)]);
        let leaf10 = make_leaf_page(&[data(16384, 4096, 0x333)]);
        let leaf11 = make_leaf_page(&[data(24576, 4096, 0x444)]);

        let internal0 = make_internal_page(&[0x1000, 0x2000], &[8192], 1); // children to leaf00, leaf01
        let internal1 = make_internal_page(&[0x3000, 0x4000], &[24576], 1); // children to leaf10, leaf11
        let root = make_internal_page(&[0x5000, 0x6000], &[16384], 2); // children to internal0, internal1

        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0x0000, root);
        mock.insert_page(0x5000, internal0);
        mock.insert_page(0x6000, internal1);
        mock.insert_page(0x1000, leaf00);
        mock.insert_page(0x2000, leaf01);
        mock.insert_page(0x3000, leaf10);
        mock.insert_page(0x4000, leaf11);

        let reader = ExtentMapKernelReader::new(&mock, 0x0000, 9);

        assert_eq!(reader.lookup(0).unwrap().phys_addr, 0x111);
        assert_eq!(reader.lookup(8192).unwrap().phys_addr, 0x222);
        assert_eq!(reader.lookup(16384).unwrap().phys_addr, 0x333);
        assert_eq!(reader.lookup(25000).unwrap().phys_addr, 0x444);
    }

    #[test]
    fn lookup_internal_exact_separator_routes_right() {
        // sep_key=4096, children [0x1000, 0x2000]
        // exact match on sep_key → right child (child_pages[1] = 0x2000)
        let leaf0 = make_leaf_page(&[data(0, 4096, 0xA)]);
        let leaf1 = make_leaf_page(&[data(4096, 4096, 0xB)]);
        let internal = make_internal_page(&[0x1000, 0x2000], &[4096], 1);

        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0x0000, internal);
        mock.insert_page(0x1000, leaf0);
        mock.insert_page(0x2000, leaf1);

        let reader = ExtentMapKernelReader::new(&mock, 0x0000, 9);
        let m = reader.lookup(4096).unwrap();
        assert_eq!(m.phys_addr, 0xB);
    }

    // ── Corrupt ordering validation tests ────────────────────────────

    #[test]
    fn validate_leaf_entries_empty() {
        assert!(validate_leaf_entries(&[]).is_ok());
    }

    #[test]
    fn validate_leaf_entries_single_data() {
        let entries = [data(0, 4096, 1)];
        assert!(validate_leaf_entries(&entries).is_ok());
    }

    #[test]
    fn validate_leaf_entries_single_unwritten() {
        let entries = [unwritten(0, 4096)];
        assert!(validate_leaf_entries(&entries).is_ok());
    }

    #[test]
    fn validate_leaf_entries_unknown_kind_err() {
        let mut entry = data(0, 4096, 1);
        entry.extent_kind = 0xFF;
        assert_eq!(
            validate_leaf_entries(&[entry]),
            Err(PageError::CorruptOrdering)
        );
    }

    #[test]
    fn validate_leaf_entries_zero_length_err() {
        let mut entry = data(0, 0, 1);
        entry.length = 0;
        assert_eq!(
            validate_leaf_entries(&[entry]),
            Err(PageError::CorruptOrdering)
        );
    }

    #[test]
    fn validate_leaf_entries_unsorted_err() {
        let entries = [data(8192, 4096, 1), data(0, 4096, 2)];
        assert_eq!(
            validate_leaf_entries(&entries),
            Err(PageError::CorruptOrdering)
        );
    }

    #[test]
    fn validate_leaf_entries_overlap_err() {
        let entries = [data(0, 8192, 1), data(4096, 4096, 2)];
        assert_eq!(
            validate_leaf_entries(&entries),
            Err(PageError::CorruptOrdering)
        );
    }

    #[test]
    fn validate_leaf_entries_exact_abut_ok() {
        let entries = [data(0, 4096, 1), data(4096, 4096, 2)];
        assert!(validate_leaf_entries(&entries).is_ok());
    }

    #[test]
    fn validate_leaf_entries_gap_ok() {
        let entries = [data(0, 4096, 1), data(12288, 4096, 2)];
        assert!(validate_leaf_entries(&entries).is_ok());
    }

    // ── Corrupt page in lookup path ──────────────────────────────────

    #[test]
    fn lookup_corrupt_ordering_in_leaf_returns_eio() {
        // Build a leaf with unsorted entries but valid checksum
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = PAGE_KIND_LEAF;
        page[6..8].copy_from_slice(&2u16.to_le_bytes());

        // Write entry 1 at offset 8192 (comes after entry 2 - wrong order)
        let entries = [data(8192, 4096, 0xAAA), data(0, 4096, 0xBBB)];
        let mut body_pos = 54;
        for e in &entries {
            let buf = &mut page[body_pos..body_pos + 89];
            buf[0..8].copy_from_slice(&e.logical_offset.to_le_bytes());
            buf[8..16].copy_from_slice(&e.length.to_le_bytes());
            buf[16] = e.extent_kind;
            buf[17] = e.flags;
            buf[18..26].copy_from_slice(&e.locator_id.0.to_le_bytes());
            buf[26..58].copy_from_slice(&e.checksum);
            buf[58..66].copy_from_slice(&e.birth_commit_group.to_le_bytes());
            buf[66..81].copy_from_slice(&e.reserved);
            body_pos += 89;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&page[..22]);
        hasher.update(&page[54..body_pos]);
        let checksum = hasher.finalize();
        page[22..54].copy_from_slice(checksum.as_bytes());

        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, page);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Errno::EIO);
    }

    #[test]
    fn lookup_corrupt_overlap_in_leaf_returns_eio() {
        // Overlapping entries: [0..8192] followed by [4096..8192]
        let entries = [data(0, 8192, 0xAAA), data(4096, 4096, 0xBBB)];
        let leaf = make_leaf_page(&entries);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Errno::EIO);
    }

    #[test]
    fn lookup_zero_length_entry_returns_eio() {
        let mut entry = data(0, 0, 1);
        entry.length = 0;
        let leaf = make_leaf_page(&[entry]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Errno::EIO);
    }

    #[test]
    fn lookup_unknown_extent_kind_returns_eio() {
        let mut entry = data(0, 4096, 1);
        entry.extent_kind = 0xFE;
        let leaf = make_leaf_page(&[entry]);
        let mut mock = MockStorageIo::new(512);
        mock.insert_page(0, leaf);
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(4096);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Errno::EIO);
    }

    // ── I/O error propagation ────────────────────────────────────────

    #[test]
    fn lookup_read_page_eio_propagates() {
        // Mock with no pages: any read returns zero-filled, but no EIO
        // Instead, test sector alignment failure
        let mock = MockStorageIo::new(0); // sector_size=0 → EINVAL
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(0);
        assert!(result.is_err());
    }

    #[test]
    fn lookup_page_addr_out_of_range_returns_err() {
        // Root page at addr beyond capacity
        let leaf = make_leaf_page(&[data(0, 4096, 0x10)]);
        let mut mock = MockStorageIo::new(512);
        mock.capacity_sectors = 1; // only 512 bytes total
        mock.insert_page(0, leaf); // root at 0 can't be read since capacity is tiny
        let reader = ExtentMapKernelReader::new(&mock, 0, 9);
        let result = reader.lookup(0);
        assert!(result.is_err());
    }
}
