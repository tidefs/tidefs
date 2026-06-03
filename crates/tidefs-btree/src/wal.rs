//! Append-only write-ahead log for B+tree page-level crash safety.
//!
//! Every page mutation is recorded as a WAL entry before the page is
//! written to its home location. On recovery, the WAL is replayed from
//! the last checkpoint to restore the tree to a consistent state.
//!
//! ## Entry format
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │ WalEntryHeader (16 bytes)                    │
//! │  magic:      [u8; 2]   0x57 0x4C  "WL"      │
//! │  operation:  u8        Write=0x01            │
//! │  reserved:   u8                             │
//! │  page_id:    u32 LE    logical page number   │
//! │  generation: u32 LE    monotonic sequence    │
//! │  page_len:   u32 LE    always 4096           │
//! ├──────────────────────────────────────────────┤
//! │ Page data (4096 bytes)                       │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! ## Recovery
//!
//! Replay reads entries sequentially, validates magic, and writes the
//! after-image page data into the page store. The last generation
//! number written becomes the starting generation for new WAL entries.

use crate::page::{BtreePage, PAGE_SIZE};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes that identify a valid WAL entry: "WL".
pub const WAL_ENTRY_MAGIC: [u8; 2] = [0x57, 0x4C];

/// Size of the fixed WAL entry header.
pub const WAL_ENTRY_HEADER_SIZE: usize = 16;

/// Total size of one WAL entry (header + page).
pub const WAL_ENTRY_SIZE: usize = WAL_ENTRY_HEADER_SIZE + PAGE_SIZE;

// ---------------------------------------------------------------------------
// WalOperation
// ---------------------------------------------------------------------------

/// Operation recorded in a WAL entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WalOperation {
    /// A page was written (insert, update, or delete that mutated the page).
    Write = 0x01,
}

impl WalOperation {
    /// Decode from a `u8` byte.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Write),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// WalEntryHeader
// ---------------------------------------------------------------------------

/// Fixed-size header prefixed to each WAL entry on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalEntryHeader {
    /// Magic bytes (must be [`WAL_ENTRY_MAGIC`]).
    pub magic: [u8; 2],
    /// Operation code.
    pub operation: u8,
    /// Reserved; must be zero.
    pub reserved: u8,
    /// Logical page identifier.
    pub page_id: u32,
    /// Monotonic generation number (WAL sequence).
    pub generation: u32,
    /// Length of the page data that follows; always [`PAGE_SIZE`].
    pub page_len: u32,
}

impl WalEntryHeader {
    /// Create a new header for writing a page.
    #[must_use]
    pub fn new_write(page_id: u32, generation: u32) -> Self {
        Self {
            magic: WAL_ENTRY_MAGIC,
            operation: WalOperation::Write as u8,
            reserved: 0,
            page_id,
            generation,
            page_len: PAGE_SIZE as u32,
        }
    }

    /// Returns `true` if the magic bytes match [`WAL_ENTRY_MAGIC`].
    #[must_use]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == WAL_ENTRY_MAGIC
    }

    /// Encode this header into `buf` (must be ≥ 16 bytes).
    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.magic);
        buf[2] = self.operation;
        buf[3] = self.reserved;
        buf[4..8].copy_from_slice(&self.page_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.generation.to_le_bytes());
        buf[12..16].copy_from_slice(&self.page_len.to_le_bytes());
    }

    /// Decode a header from `buf` (must be ≥ 16 bytes).
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        let mut magic = [0u8; 2];
        magic.copy_from_slice(&buf[0..2]);
        Self {
            magic,
            operation: buf[2],
            reserved: buf[3],
            page_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            generation: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            page_len: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        }
    }
}

// ---------------------------------------------------------------------------
// WalEntry
// ---------------------------------------------------------------------------

/// A complete WAL entry: header + full page image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalEntry {
    /// Entry header.
    pub header: WalEntryHeader,
    /// Full 4096-byte page image (the after-image).
    pub page: BtreePage,
}

impl WalEntry {
    /// Create a new WAL entry for a page write.
    #[must_use]
    pub fn new_write(page_id: u32, generation: u32, page: &BtreePage) -> Self {
        Self {
            header: WalEntryHeader::new_write(page_id, generation),
            page: *page,
        }
    }

    /// Serialize this entry into `buf` (must be ≥ [`WAL_ENTRY_SIZE`]).
    pub fn encode(&self, buf: &mut [u8]) {
        self.header.encode(&mut buf[..WAL_ENTRY_HEADER_SIZE]);
        buf[WAL_ENTRY_HEADER_SIZE..].copy_from_slice(&self.page);
    }

    /// Deserialize an entry from `buf` (must be ≥ [`WAL_ENTRY_SIZE`]).
    pub fn decode(buf: &[u8]) -> Result<Self, WalError> {
        if buf.len() < WAL_ENTRY_HEADER_SIZE {
            return Err(WalError::Truncated);
        }
        let header = WalEntryHeader::decode(&buf[..WAL_ENTRY_HEADER_SIZE]);
        if !header.is_valid_magic() {
            return Err(WalError::BadMagic { got: header.magic });
        }
        let page_len = header.page_len as usize;
        if page_len != PAGE_SIZE {
            return Err(WalError::BadPageLen(page_len));
        }
        let mut page = [0u8; PAGE_SIZE];
        let data_start = WAL_ENTRY_HEADER_SIZE;
        let data_end = data_start + PAGE_SIZE;
        if buf.len() < data_end {
            return Err(WalError::Truncated);
        }
        page.copy_from_slice(&buf[data_start..data_end]);
        Ok(Self { header, page })
    }
}

// ---------------------------------------------------------------------------
// WalWriter
// ---------------------------------------------------------------------------

/// Append-only WAL writer.
///
/// Produces a sequence of [`WalEntry`] records. The caller is
/// responsible for providing a durable append target (e.g. a file or
/// device region).
#[derive(Clone, Debug, Default)]
pub struct WalWriter {
    /// All entries appended so far, in order.
    entries: Vec<WalEntry>,
    /// Next generation number to assign.
    next_gen: u32,
}

impl WalWriter {
    /// Create an empty WAL writer starting at `initial_generation`.
    #[must_use]
    pub fn new(initial_generation: u32) -> Self {
        Self {
            entries: Vec::new(),
            next_gen: initial_generation,
        }
    }

    /// Number of entries written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The next generation number that will be assigned.
    #[must_use]
    pub fn next_generation(&self) -> u32 {
        self.next_gen
    }

    /// Append a page write entry.
    ///
    /// Returns the assigned generation number.
    pub fn append_write(&mut self, page_id: u32, page: &BtreePage) -> u32 {
        let gen = self.next_gen;
        self.entries.push(WalEntry::new_write(page_id, gen, page));
        self.next_gen = gen.wrapping_add(1);
        gen
    }

    /// Return a reference to all recorded entries.
    #[must_use]
    pub fn entries(&self) -> &[WalEntry] {
        &self.entries
    }

    /// Serialize all entries into a flat byte buffer.
    #[must_use]
    pub fn serialize_all(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.entries.len() * WAL_ENTRY_SIZE];
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i * WAL_ENTRY_SIZE;
            entry.encode(&mut buf[offset..offset + WAL_ENTRY_SIZE]);
        }
        buf
    }

    /// Clear all entries (e.g. after a checkpoint).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// WalError
// ---------------------------------------------------------------------------

/// Error returned by WAL operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalError {
    /// Magic bytes do not match [`WAL_ENTRY_MAGIC`].
    BadMagic { got: [u8; 2] },
    /// Page length field is wrong.
    BadPageLen(usize),
    /// Buffer ended prematurely.
    Truncated,
}

impl fmt::Display for WalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { got } => write!(f, "bad WAL entry magic: {got:02x?}"),
            Self::BadPageLen(n) => write!(f, "bad WAL page length: {n}, expected 4096"),
            Self::Truncated => f.write_str("truncated WAL entry"),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// Replay WAL entries from a byte buffer, returning the recovered pages
/// and the highest generation number seen.
///
/// Each entry is decoded and its page image is stored keyed by `page_id`.
/// Later entries for the same `page_id` overwrite earlier ones (last-writer-wins).
///
/// Returns `(page_map, max_generation)` where `page_map` maps `page_id`
/// to its latest page image.
pub fn replay_wal(data: &[u8]) -> Result<(Vec<(u32, BtreePage)>, u32), WalError> {
    let entry_size = WAL_ENTRY_SIZE;
    if data.is_empty() {
        return Ok((Vec::new(), 0));
    }
    if data.len() % entry_size != 0 {
        return Err(WalError::Truncated);
    }
    let mut pages: Vec<(u32, BtreePage)> = Vec::new();
    let mut max_gen: u32 = 0;
    let count = data.len() / entry_size;
    for i in 0..count {
        let offset = i * entry_size;
        let entry = WalEntry::decode(&data[offset..offset + entry_size])?;
        if entry.header.generation > max_gen {
            max_gen = entry.header.generation;
        }
        // Last-writer-wins: overwrite existing entry for same page_id.
        if let Some(existing) = pages
            .iter_mut()
            .find(|(pid, _)| *pid == entry.header.page_id)
        {
            existing.1 = entry.page;
        } else {
            pages.push((entry.header.page_id, entry.page));
        }
    }
    Ok((pages, max_gen))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{blank_page, PAGE_HEADER_SIZE};
    use alloc::format;

    fn make_test_page(marker: u8) -> BtreePage {
        let mut page = blank_page();
        page[PAGE_HEADER_SIZE] = marker;
        page[PAGE_HEADER_SIZE + 1] = marker.wrapping_add(1);
        page
    }

    // ── WalOperation discriminants ──────────────────────────────────

    #[test]
    fn wal_operation_round_trip() {
        assert_eq!(WalOperation::from_u8(0x01), Some(WalOperation::Write));
    }

    #[test]
    fn wal_operation_unknown_rejected() {
        assert_eq!(WalOperation::from_u8(0xFF), None);
    }

    // ── WalEntryHeader encode/decode round-trip ─────────────────────

    #[test]
    fn header_encode_decode_round_trip() {
        let original = WalEntryHeader::new_write(42, 7);
        let mut buf = [0u8; 16];
        original.encode(&mut buf);
        let decoded = WalEntryHeader::decode(&buf);
        assert_eq!(original, decoded);
    }

    #[test]
    fn header_is_valid_magic() {
        let h = WalEntryHeader::new_write(0, 0);
        assert!(h.is_valid_magic());
    }

    #[test]
    fn header_bad_magic_detected() {
        let mut h = WalEntryHeader::new_write(0, 0);
        h.magic = [0x00, 0x00];
        assert!(!h.is_valid_magic());
    }

    // ── WalEntry encode/decode round-trip ───────────────────────────

    #[test]
    fn entry_encode_decode_round_trip() {
        let page = make_test_page(0xAB);
        let entry = WalEntry::new_write(1, 100, &page);
        let mut buf = [0u8; WAL_ENTRY_SIZE];
        entry.encode(&mut buf);
        let decoded = WalEntry::decode(&buf).unwrap();
        assert_eq!(entry.header, decoded.header);
        assert_eq!(entry.page, decoded.page);
    }

    #[test]
    fn entry_bad_magic_rejected() {
        let page = make_test_page(0);
        let mut entry = WalEntry::new_write(1, 1, &page);
        entry.header.magic = [0xBA, 0xAD];
        let mut buf = [0u8; WAL_ENTRY_SIZE];
        entry.encode(&mut buf);
        assert!(matches!(
            WalEntry::decode(&buf),
            Err(WalError::BadMagic { .. })
        ));
    }

    #[test]
    fn entry_truncated_buffer() {
        let buf = [0u8; 10];
        assert!(matches!(WalEntry::decode(&buf), Err(WalError::Truncated)));
    }

    // ── WalWriter append ────────────────────────────────────────────

    #[test]
    fn writer_append_and_read_back() {
        let mut writer = WalWriter::new(0);
        let page1 = make_test_page(0x10);
        let page2 = make_test_page(0x20);

        let gen1 = writer.append_write(5, &page1);
        let gen2 = writer.append_write(5, &page2);

        assert_eq!(gen1, 0);
        assert_eq!(gen2, 1);
        assert_eq!(writer.len(), 2);
        assert_eq!(writer.entries()[0].header.page_id, 5);
        assert_eq!(writer.entries()[1].header.generation, 1);
    }

    #[test]
    fn writer_serialization_round_trip() {
        let mut writer = WalWriter::new(10);
        writer.append_write(1, &make_test_page(0xAA));
        writer.append_write(2, &make_test_page(0xBB));

        let data = writer.serialize_all();
        assert_eq!(data.len(), 2 * WAL_ENTRY_SIZE);

        // Decode each entry
        let e1 = WalEntry::decode(&data[..WAL_ENTRY_SIZE]).unwrap();
        let e2 = WalEntry::decode(&data[WAL_ENTRY_SIZE..]).unwrap();
        assert_eq!(e1.header.page_id, 1);
        assert_eq!(e2.header.page_id, 2);
        assert_eq!(e1.header.generation, 10);
        assert_eq!(e2.header.generation, 11);
    }

    #[test]
    fn writer_clear() {
        let mut writer = WalWriter::new(0);
        writer.append_write(1, &make_test_page(0x01));
        assert_eq!(writer.len(), 1);
        writer.clear();
        assert_eq!(writer.len(), 0);
        assert!(writer.is_empty());
        // Generation counter is not reset by clear (intentional: checkpoint
        // does not rewind the generation sequence).
        assert_eq!(writer.next_generation(), 1);
    }

    // ── Replay ──────────────────────────────────────────────────────

    #[test]
    fn replay_single_entry() {
        let mut writer = WalWriter::new(0);
        let page = make_test_page(0x42);
        writer.append_write(3, &page);
        let data = writer.serialize_all();

        let (pages, max_gen) = replay_wal(&data).unwrap();
        assert_eq!(max_gen, 0);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].0, 3);
        assert_eq!(pages[0].1, page);
    }

    #[test]
    fn replay_multiple_pages() {
        let mut writer = WalWriter::new(0);
        writer.append_write(1, &make_test_page(0x11));
        writer.append_write(2, &make_test_page(0x22));
        writer.append_write(3, &make_test_page(0x33));
        let data = writer.serialize_all();

        let (pages, max_gen) = replay_wal(&data).unwrap();
        assert_eq!(max_gen, 2);
        assert_eq!(pages.len(), 3);
        // pages appear in insertion order for unique page_ids
        assert_eq!(pages[0].0, 1);
        assert_eq!(pages[1].0, 2);
        assert_eq!(pages[2].0, 3);
    }

    #[test]
    fn replay_overwrite_same_page_id() {
        let mut writer = WalWriter::new(0);
        let page_v1 = make_test_page(0xAA);
        let page_v2 = make_test_page(0xBB);
        writer.append_write(7, &page_v1); // gen 0
        writer.append_write(9, &make_test_page(0xCC)); // gen 1, different page
        writer.append_write(7, &page_v2); // gen 2, overwrites gen 0

        let data = writer.serialize_all();
        let (pages, max_gen) = replay_wal(&data).unwrap();
        assert_eq!(max_gen, 2);
        assert_eq!(pages.len(), 2); // page 7 and page 9
        let page7 = pages.iter().find(|(pid, _)| *pid == 7).unwrap();
        assert_eq!(page7.1, page_v2); // v2 wins
    }

    #[test]
    fn replay_empty_data() {
        let (pages, max_gen) = replay_wal(&[]).unwrap();
        assert!(pages.is_empty());
        assert_eq!(max_gen, 0);
    }

    #[test]
    fn replay_truncated_data() {
        let mut writer = WalWriter::new(0);
        writer.append_write(1, &make_test_page(0x01));
        let full = writer.serialize_all();
        let truncated = &full[..full.len() - 10];
        assert!(matches!(replay_wal(truncated), Err(WalError::Truncated)));
    }

    #[test]
    fn replay_bad_magic_detected() {
        let mut writer = WalWriter::new(0);
        writer.append_write(1, &make_test_page(0x01));
        let mut data = writer.serialize_all();
        // Corrupt magic in the first entry
        data[0] = 0xFF;
        data[1] = 0xFF;
        assert!(matches!(replay_wal(&data), Err(WalError::BadMagic { .. })));
    }

    // ── Replay preserves data integrity ─────────────────────────────

    #[test]
    fn replay_preserves_full_page_content() {
        let mut page = blank_page();
        // Fill entire page body with known pattern
        for (i, byte) in page
            .iter_mut()
            .enumerate()
            .take(PAGE_SIZE)
            .skip(PAGE_HEADER_SIZE)
        {
            *byte = (i % 256) as u8;
        }
        let mut writer = WalWriter::new(0);
        writer.append_write(42, &page);
        let data = writer.serialize_all();

        let (pages, _) = replay_wal(&data).unwrap();
        assert_eq!(pages[0].1, page);
    }

    // ── Large WAL replay ────────────────────────────────────────────

    #[test]
    fn replay_large_wal() {
        let mut writer = WalWriter::new(0);
        for i in 0u32..50 {
            writer.append_write(i, &make_test_page(i as u8));
        }
        let data = writer.serialize_all();
        assert_eq!(data.len(), 50 * WAL_ENTRY_SIZE);

        let (pages, max_gen) = replay_wal(&data).unwrap();
        assert_eq!(max_gen, 49);
        assert_eq!(pages.len(), 50);
    }

    // ── WAL crash simulation ────────────────────────────────────────

    #[test]
    fn wal_crash_recovery_scenario() {
        // Simulate: write pages via WAL, "crash" (drop writer), replay.
        let mut writer = WalWriter::new(100);
        writer.append_write(10, &make_test_page(0x10));
        writer.append_write(11, &make_test_page(0x11));
        writer.append_write(12, &make_test_page(0x12));
        let wal_data = writer.serialize_all();

        // Crash: drop writer, re-read from WAL data.
        drop(writer);

        let (pages, max_gen) = replay_wal(&wal_data).unwrap();
        assert_eq!(max_gen, 102);
        assert_eq!(pages.len(), 3);

        // Resume writing from after the recovered generation.
        let mut writer2 = WalWriter::new(max_gen.wrapping_add(1));
        writer2.append_write(10, &make_test_page(0xAA)); // update page 10
        writer2.append_write(13, &make_test_page(0x13)); // new page

        let wal_data2 = writer2.serialize_all();
        let (pages2, max_gen2) = replay_wal(&wal_data2).unwrap();
        assert_eq!(max_gen2, 104);
        assert_eq!(pages2.len(), 2);
    }

    // ── Display impls ───────────────────────────────────────────────

    #[test]
    fn wal_error_display() {
        let e = WalError::BadMagic { got: [0xDE, 0xAD] };
        assert!(!format!("{e}").is_empty());

        let e = WalError::BadPageLen(1024);
        assert!(!format!("{e}").is_empty());

        let e = WalError::Truncated;
        assert!(!format!("{e}").is_empty());
    }
}
