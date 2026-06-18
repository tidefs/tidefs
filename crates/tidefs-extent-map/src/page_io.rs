// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page-level serialization with BLAKE3 checksums for V2/V3 B-tree extent maps.
//!
//! Each B-tree page is serialized as a 4096-byte unit:
//!
//! ```text
//! Page Header (54 bytes):
//!   magic:         [u8; 4]   "EXMP"
//!   page_type:     u8        0=leaf, 1=internal
//!   flags:         u8        reserved
//!   entry_count:   u16 LE    number of entries
//!   reserved:      [u8; 14]  padding
//!   page_checksum: [u8; 32]  BLAKE3 hash of (header[0..22] + entries)
//!
//! Entries: entry_count x 89 bytes (ExtentMapEntryV2 on-disk record)
//!
//! Padding: zero-fill to 4096 bytes
//! ```
//!
//! The BLAKE3 checksum covers the first 22 bytes of the header (magic,
//! page_type, flags, entry_count, reserved) plus all entry records.

use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, LocatorId, EXTENT_MAP_DEFAULT_PAGE_SIZE,
    EXTENT_MAP_ENTRY_V2_SIZE, EXTENT_MAP_PAGE_HEADER_SIZE, EXTENT_MAP_PAGE_MAGIC,
};

/// Page type discriminant for leaf pages.
pub const PAGE_TYPE_LEAF: u8 = 0;
/// Page type discriminant for internal pages.
pub const PAGE_TYPE_INTERNAL: u8 = 1;

/// Offset within page header where the BLAKE3 checksum begins.
const PAGE_CHECKSUM_OFFSET: usize = 22;
/// Number of bytes before the checksum that get hashed.
const PAGE_HASHED_HEADER_LEN: usize = 22;

/// Errors specific to page I/O operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageIoError {
    /// Magic mismatch during deserialization.
    WrongMagic,
    /// Unknown page type.
    UnknownPageType,
    /// BLAKE3 checksum verification failed.
    ChecksumMismatch,
    /// Entry count exceeds page capacity.
    PageOverflow,
    /// Invalid entry count for page type.
    InvalidEntryCount,
}

impl From<PageIoError> for ExtentMapError {
    fn from(e: PageIoError) -> Self {
        match e {
            PageIoError::ChecksumMismatch | PageIoError::WrongMagic => ExtentMapError::Corrupt,
            PageIoError::UnknownPageType | PageIoError::InvalidEntryCount => {
                ExtentMapError::Corrupt
            }
            PageIoError::PageOverflow => ExtentMapError::MapFull,
        }
    }
}

/// Compute the maximum number of entries that fit in a single page.
#[must_use]
pub const fn max_entries_per_page() -> usize {
    (EXTENT_MAP_DEFAULT_PAGE_SIZE - EXTENT_MAP_PAGE_HEADER_SIZE) / EXTENT_MAP_ENTRY_V2_SIZE
}

/// Write a single ExtentMapEntryV2 in 89-byte on-disk format.
///
/// The on-disk record is:
/// ```text
/// logical_offset:      u64 LE   (8 bytes)
/// length:              u64 LE   (8 bytes)
/// extent_kind:         u8       (1 byte)
/// flags:               u8       (1 byte)
/// locator_id:          u64 LE   (8 bytes)
/// checksum:            [u8; 32] (32 bytes)
/// birth_commit_group:  u64 LE   (8 bytes)
/// reserved:            [u8; 15] (15 bytes)
/// padding:             [u8; 8]  (8 bytes, always zero)
/// ```
/// Total: 89 bytes.
fn write_entry_page(
    writer: &mut impl std::io::Write,
    entry: &ExtentMapEntryV2,
) -> Result<(), ExtentMapError> {
    writer
        .write_all(&entry.logical_offset.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.length.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&[entry.extent_kind])
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&[entry.flags])
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.locator_id.0.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.checksum)
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.birth_commit_group.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.reserved)
        .map_err(|_| ExtentMapError::Corrupt)?;
    // Extra 8 bytes of padding to reach 89-byte on-disk record.
    writer
        .write_all(&[0u8; 8])
        .map_err(|_| ExtentMapError::Corrupt)?;
    Ok(())
}

/// Read a single ExtentMapEntryV2 from 89-byte on-disk format.
fn read_entry_page(reader: &mut impl std::io::Read) -> Result<ExtentMapEntryV2, ExtentMapError> {
    let mut buf8 = [0u8; 8];
    let mut checksum = [0u8; 32];
    let mut reserved = [0u8; 15];
    let mut padding = [0u8; 8];

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let logical_offset = u64::from_le_bytes(buf8);

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let length = u64::from_le_bytes(buf8);

    let mut kind_buf = [0u8; 1];
    reader
        .read_exact(&mut kind_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let extent_kind = kind_buf[0];

    let mut flags_buf = [0u8; 1];
    reader
        .read_exact(&mut flags_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let flags = flags_buf[0];

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let locator_id = LocatorId(u64::from_le_bytes(buf8));

    reader
        .read_exact(&mut checksum)
        .map_err(|_| ExtentMapError::Corrupt)?;

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let birth_commit_group = u64::from_le_bytes(buf8);

    reader
        .read_exact(&mut reserved)
        .map_err(|_| ExtentMapError::Corrupt)?;

    // Read and discard the 8-byte padding.
    reader
        .read_exact(&mut padding)
        .map_err(|_| ExtentMapError::Corrupt)?;

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

/// Serialize one leaf page to a writer.
///
/// Writes the 54-byte page header followed by `entries` in 89-byte
/// on-disk format, then pads to 4096 bytes. The BLAKE3 checksum
/// covers the first 22 bytes of the header plus all entry data.
pub fn serialize_leaf_page<W: std::io::Write>(
    writer: &mut W,
    entries: &[ExtentMapEntryV2],
) -> Result<(), ExtentMapError> {
    if entries.len() > max_entries_per_page() {
        return Err(PageIoError::PageOverflow.into());
    }

    // Build the page content in a buffer so we can hash it.
    let entry_count = entries.len() as u16;
    let mut header_buf = [0u8; EXTENT_MAP_PAGE_HEADER_SIZE];
    header_buf[0..4].copy_from_slice(&EXTENT_MAP_PAGE_MAGIC);
    header_buf[4] = PAGE_TYPE_LEAF;
    header_buf[5] = 0; // flags
    header_buf[6..8].copy_from_slice(&entry_count.to_le_bytes());
    // bytes 8..22 are reserved (zero)
    // bytes 22..54 are checksum (computed below)

    // Compute BLAKE3 checksum over header[0..22] + entries.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&header_buf[..PAGE_HASHED_HEADER_LEN]);

    // Serialize entries into a temp buffer to hash and write.
    let mut entries_buf = Vec::with_capacity(entries.len() * EXTENT_MAP_ENTRY_V2_SIZE);
    for entry in entries {
        write_entry_page(&mut entries_buf, entry)?;
    }
    hasher.update(&entries_buf);

    let checksum = hasher.finalize();
    header_buf[PAGE_CHECKSUM_OFFSET..PAGE_CHECKSUM_OFFSET + 32]
        .copy_from_slice(checksum.as_bytes());

    // Write header.
    writer
        .write_all(&header_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;
    // Write entries.
    writer
        .write_all(&entries_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;

    // Pad to page size.
    let data_len = EXTENT_MAP_PAGE_HEADER_SIZE + entries.len() * EXTENT_MAP_ENTRY_V2_SIZE;
    let pad_len = EXTENT_MAP_DEFAULT_PAGE_SIZE - data_len;
    if pad_len > 0 {
        let pad = vec![0u8; pad_len];
        writer
            .write_all(&pad)
            .map_err(|_| ExtentMapError::Corrupt)?;
    }

    Ok(())
}

/// Deserialize and verify a single leaf page from a reader.
///
/// Reads a 4096-byte page, verifies the BLAKE3 checksum, and returns
/// the entries. Returns an error if the checksum does not match.
pub fn deserialize_leaf_page<R: std::io::Read>(
    reader: &mut R,
) -> Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
    // Read the full page.
    let mut page_buf = vec![0u8; EXTENT_MAP_DEFAULT_PAGE_SIZE];
    reader
        .read_exact(&mut page_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;

    // Verify magic.
    if page_buf[0..4] != EXTENT_MAP_PAGE_MAGIC {
        return Err(PageIoError::WrongMagic.into());
    }

    let page_type = page_buf[4];
    if page_type != PAGE_TYPE_LEAF {
        return Err(PageIoError::UnknownPageType.into());
    }

    let entry_count = u16::from_le_bytes([page_buf[6], page_buf[7]]) as usize;

    // Verify checksum: hash header[0..22] + entry data.
    let data_start = EXTENT_MAP_PAGE_HEADER_SIZE;
    let data_end = data_start + entry_count * EXTENT_MAP_ENTRY_V2_SIZE;
    if data_end > EXTENT_MAP_DEFAULT_PAGE_SIZE {
        return Err(PageIoError::InvalidEntryCount.into());
    }

    let expected_checksum = &page_buf[PAGE_CHECKSUM_OFFSET..PAGE_CHECKSUM_OFFSET + 32];

    let mut hasher = blake3::Hasher::new();
    hasher.update(&page_buf[..PAGE_HASHED_HEADER_LEN]);
    hasher.update(&page_buf[data_start..data_end]);
    let actual_checksum = hasher.finalize();

    if actual_checksum.as_bytes() != expected_checksum {
        return Err(PageIoError::ChecksumMismatch.into());
    }

    // Deserialize entries.
    let mut entries = Vec::with_capacity(entry_count);
    let entry_data = &page_buf[data_start..data_end];
    let mut cursor = std::io::Cursor::new(entry_data);
    for _ in 0..entry_count {
        let entry = read_entry_page(&mut cursor)?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Partition entries into leaf pages, serializing each page.
///
/// Groups entries into pages of up to [`max_entries_per_page()`]
/// entries. Each page is serialized independently with its own
/// BLAKE3 checksum.
pub fn serialize_to_pages<W: std::io::Write>(
    writer: &mut W,
    entries: &[ExtentMapEntryV2],
) -> Result<(), ExtentMapError> {
    if entries.is_empty() {
        // Always write at least one page, even for empty maps, so the
        // deserializer sees exactly page_count pages.
        serialize_leaf_page(writer, &[])?;
        return Ok(());
    }
    let max_per_page = max_entries_per_page();
    for chunk in entries.chunks(max_per_page) {
        serialize_leaf_page(writer, chunk)?;
    }
    Ok(())
}

/// Deserialize all leaf pages from a reader into a flat entry vector.
///
/// Pages are read sequentially until the reader is exhausted.
/// Returns all entries from all pages in order.
pub fn deserialize_from_pages<R: std::io::Read>(
    reader: &mut R,
    page_count: usize,
) -> Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
    let mut all_entries = Vec::new();
    for _ in 0..page_count {
        let entries = deserialize_leaf_page(reader)?;
        all_entries.extend(entries);
    }
    Ok(all_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_extent_map_core::LocatorId;

    fn data_entry(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0xA5; 32], 1)
    }

    #[test]
    fn page_roundtrip_single_entry() {
        let entries = vec![data_entry(0, 4096, 1)];
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();
        assert_eq!(buf.len(), EXTENT_MAP_DEFAULT_PAGE_SIZE);

        let mut cursor = std::io::Cursor::new(&buf);
        let recovered = deserialize_leaf_page(&mut cursor).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].logical_offset, 0);
        assert_eq!(recovered[0].length, 4096);
        assert_eq!(recovered[0].locator_id, LocatorId(1));
    }

    #[test]
    fn page_roundtrip_full_page() {
        let max = max_entries_per_page();
        let entries: Vec<_> = (0..max)
            .map(|i| data_entry(i as u64 * 4096, 4096, i as u64 + 1))
            .collect();
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();
        assert_eq!(buf.len(), EXTENT_MAP_DEFAULT_PAGE_SIZE);

        let mut cursor = std::io::Cursor::new(&buf);
        let recovered = deserialize_leaf_page(&mut cursor).unwrap();
        assert_eq!(recovered.len(), max);
        for (i, e) in recovered.iter().enumerate() {
            assert_eq!(e.logical_offset, i as u64 * 4096);
            assert_eq!(e.length, 4096);
        }
    }

    #[test]
    fn page_roundtrip_empty() {
        let entries: Vec<ExtentMapEntryV2> = vec![];
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();
        assert_eq!(buf.len(), EXTENT_MAP_DEFAULT_PAGE_SIZE);

        let mut cursor = std::io::Cursor::new(&buf);
        let recovered = deserialize_leaf_page(&mut cursor).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn checksum_verification_detects_corruption() {
        let entries = vec![data_entry(0, 4096, 1)];
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();

        // Corrupt a byte in the entry data area.
        let corrupt_offset = EXTENT_MAP_PAGE_HEADER_SIZE + 5;
        buf[corrupt_offset] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(&buf);
        let err = deserialize_leaf_page(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn checksum_verification_detects_header_corruption() {
        let entries = vec![data_entry(0, 4096, 1)];
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();

        // Corrupt the entry_count byte.
        buf[6] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(&buf);
        let err = deserialize_leaf_page(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn wrong_magic_rejected() {
        let entries = vec![data_entry(0, 4096, 1)];
        let mut buf = Vec::new();
        serialize_leaf_page(&mut buf, &entries).unwrap();

        // Change magic.
        buf[0] = b'X';
        buf[1] = b'X';
        buf[2] = b'X';
        buf[3] = b'X';
        // Recompute checksum so it won't fail on checksum first.
        // Actually, wrong magic should be caught before checksum check.
        // Let's just corrupt magic and see.
        let mut cursor = std::io::Cursor::new(&buf);
        let err = deserialize_leaf_page(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn multi_page_roundtrip() {
        let max = max_entries_per_page();
        let total = max * 3 + 5; // 3 full pages + 1 partial
        let entries: Vec<_> = (0..total)
            .map(|i| data_entry(i as u64 * 4096, 4096, i as u64 + 1))
            .collect();

        let mut buf = Vec::new();
        serialize_to_pages(&mut buf, &entries).unwrap();
        // 4 pages * 4096 = 16384
        let expected_pages = 4;
        assert_eq!(buf.len(), expected_pages * EXTENT_MAP_DEFAULT_PAGE_SIZE);

        // Deserialize page by page for exact page count.
        let mut cursor = std::io::Cursor::new(&buf);
        let mut recovered = Vec::new();
        for _ in 0..expected_pages {
            let page_entries = deserialize_leaf_page(&mut cursor).unwrap();
            recovered.extend(page_entries);
        }
        assert_eq!(recovered.len(), total);
        for (i, e) in recovered.iter().enumerate() {
            assert_eq!(e.logical_offset, i as u64 * 4096);
            assert_eq!(e.length, 4096);
        }
    }

    #[test]
    fn page_overflow_rejected() {
        let max = max_entries_per_page();
        let entries: Vec<_> = (0..max + 1)
            .map(|i| data_entry(i as u64 * 4096, 4096, i as u64 + 1))
            .collect();
        let mut buf = Vec::new();
        let err = serialize_leaf_page(&mut buf, &entries).unwrap_err();
        assert_eq!(err, ExtentMapError::MapFull);
    }

    #[test]
    fn entry_page_89_byte_format_roundtrip() {
        let entry = ExtentMapEntryV2::new_data(
            0xDEAD_BEEF,
            0xCAFE_BABE,
            LocatorId(0x1234_5678_9ABC_DEF0),
            [0x42; 32],
            0xF00D_BABE,
        );
        let mut buf = Vec::new();
        write_entry_page(&mut buf, &entry).unwrap();
        assert_eq!(buf.len(), EXTENT_MAP_ENTRY_V2_SIZE); // 89 bytes

        let mut cursor = std::io::Cursor::new(&buf);
        let recovered = read_entry_page(&mut cursor).unwrap();
        assert_eq!(recovered.logical_offset, 0xDEAD_BEEF);
        assert_eq!(recovered.length, 0xCAFE_BABE);
        assert_eq!(recovered.locator_id, LocatorId(0x1234_5678_9ABC_DEF0));
        assert_eq!(recovered.checksum, [0x42; 32]);
        assert_eq!(recovered.birth_commit_group, 0xF00D_BABE);
    }
}
