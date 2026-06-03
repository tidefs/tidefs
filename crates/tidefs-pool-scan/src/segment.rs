//! Segment table enumeration for pool device scanning.
//!
//! Each TideFS device carries a *system area* (pointed to by the
//! [`PoolLabelV1::system_area_pointer`] field) that holds a segment table
//! and committed-root records.  This module reads the system area header,
//! enumerates the segment descriptors, and deduplicates them across
//! multiple devices.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use tidefs_types_pool_label_core::PoolLabelV1;

use crate::label::LabelReader;

// ---------------------------------------------------------------------------
// System area constants
// ---------------------------------------------------------------------------

/// Magic bytes for the TideFS system area ("VBSA").
pub const SYSTEM_AREA_MAGIC: [u8; 4] = *b"VBSA";

/// Current system area format version.
pub const SYSTEM_AREA_VERSION: u32 = 1;

/// Wire size of the system area header (magic + version + counts + checksum).
pub const SYSTEM_AREA_HEADER_SIZE: usize = 56;

/// Wire size of one segment table entry.
pub const SEGMENT_TABLE_ENTRY_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// SegmentState
// ---------------------------------------------------------------------------

/// Lifecycle state of a segment on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SegmentState {
    /// Segment is accepting writes.
    Active,
    /// Segment is complete and durable.
    Sealed,
    /// Segment has been garbage-collected / reclaimed.
    Obsolete,
}

impl SegmentState {
    /// Decode from a u8 wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Sealed),
            2 => Some(Self::Obsolete),
            _ => None,
        }
    }

    /// Encode to a u8 wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns true if this segment carries data that must be preserved
    /// (active or sealed, not obsolete).
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Sealed)
    }
}

impl std::fmt::Display for SegmentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("ACTIVE"),
            Self::Sealed => f.write_str("SEALED"),
            Self::Obsolete => f.write_str("OBSOLETE"),
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentDescriptor
// ---------------------------------------------------------------------------

/// Describes one segment on a device.
///
/// The descriptor carries enough information to locate the segment on disk
/// and determine its lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentDescriptor {
    /// Unique segment identifier (monotonically increasing).
    pub segment_id: u64,
    /// Byte offset of the segment from the start of the device.
    pub base_offset: u64,
    /// Total size of the segment in bytes.
    pub size_bytes: u64,
    /// Lifecycle state of the segment.
    pub state: SegmentState,
}

impl SegmentDescriptor {
    /// Create a new segment descriptor.
    #[must_use]
    pub const fn new(
        segment_id: u64,
        base_offset: u64,
        size_bytes: u64,
        state: SegmentState,
    ) -> Self {
        Self {
            segment_id,
            base_offset,
            size_bytes,
            state,
        }
    }

    /// Returns the end offset (base_offset + size_bytes).
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.base_offset + self.size_bytes
    }

    /// Returns true if this segment is live (active or sealed).
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.state.is_live()
    }
}

// ---------------------------------------------------------------------------
// SystemAreaHeader
// ---------------------------------------------------------------------------

/// Parsed system area header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemAreaHeader {
    /// Magic bytes (should equal [`SYSTEM_AREA_MAGIC`]).
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Number of segment table entries.
    pub segment_count: u32,
    /// Number of committed-root entries.
    pub committed_root_count: u32,
}

// ---------------------------------------------------------------------------
// SegmentTable
// ---------------------------------------------------------------------------

/// A collection of segment descriptors, deduplicated across devices.
///
/// Segment IDs are globally unique, so this table maps `segment_id ->
/// SegmentDescriptor`.
#[derive(Clone, Debug, Default)]
pub struct SegmentTable {
    entries: BTreeMap<u64, SegmentDescriptor>,
}

impl SegmentTable {
    /// Create an empty segment table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert a segment descriptor.  If a descriptor with the same
    /// segment ID already exists, it is replaced (last-write-wins).
    pub fn insert(&mut self, desc: SegmentDescriptor) {
        self.entries.insert(desc.segment_id, desc);
    }

    /// Return the number of segments in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an iterator over all segment descriptors, sorted by
    /// segment ID.
    pub fn iter(&self) -> impl Iterator<Item = &SegmentDescriptor> {
        self.entries.values()
    }

    /// Return only live (active or sealed) segments.
    #[must_use]
    pub fn live_segments(&self) -> Vec<&SegmentDescriptor> {
        self.entries.values().filter(|d| d.is_live()).collect()
    }

    /// Return the descriptor for a specific segment ID, if present.
    #[must_use]
    pub fn get(&self, segment_id: u64) -> Option<&SegmentDescriptor> {
        self.entries.get(&segment_id)
    }
}

impl IntoIterator for SegmentTable {
    type Item = (u64, SegmentDescriptor);
    type IntoIter = std::collections::btree_map::IntoIter<u64, SegmentDescriptor>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during segment table enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentScanError {
    /// The device has no valid pool label.
    NoLabel { device_path: std::path::PathBuf },
    /// The label's system_area_pointer is zero (no system area).
    NoSystemArea { device_path: std::path::PathBuf },
    /// The system area magic bytes do not match [`SYSTEM_AREA_MAGIC`].
    BadSystemAreaMagic {
        device_path: std::path::PathBuf,
        found: [u8; 4],
    },
    /// The system area checksum does not match (BLAKE3).
    SystemAreaChecksumMismatch { device_path: std::path::PathBuf },
    /// An I/O error occurred.
    Io {
        device_path: std::path::PathBuf,
        msg: String,
    },
}

impl std::fmt::Display for SegmentScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLabel { device_path } => {
                write!(f, "no label on {}", device_path.display())
            }
            Self::NoSystemArea { device_path } => {
                write!(f, "no system area on {}", device_path.display())
            }
            Self::BadSystemAreaMagic { device_path, found } => {
                write!(
                    f,
                    "bad system area magic on {}: expected {:?}, found {:?}",
                    device_path.display(),
                    std::str::from_utf8(&SYSTEM_AREA_MAGIC).unwrap_or("???"),
                    std::str::from_utf8(found).unwrap_or("???"),
                )
            }
            Self::SystemAreaChecksumMismatch { device_path } => {
                write!(
                    f,
                    "system area checksum mismatch on {}",
                    device_path.display()
                )
            }
            Self::Io { device_path, msg } => {
                write!(f, "I/O error on {}: {msg}", device_path.display())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// System area parsing
// ---------------------------------------------------------------------------

/// Parse the system area header from a byte buffer.
///
/// Returns `None` if the buffer is too small or the magic does not match.
fn parse_system_area_header(buf: &[u8]) -> Option<SystemAreaHeader> {
    if buf.len() < SYSTEM_AREA_HEADER_SIZE {
        return None;
    }

    let magic: [u8; 4] = buf[0..4].try_into().ok()?;
    if magic != SYSTEM_AREA_MAGIC {
        return None;
    }

    let version = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    if version != SYSTEM_AREA_VERSION {
        return None;
    }

    let segment_count = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let committed_root_count = u32::from_le_bytes(buf[12..16].try_into().ok()?);

    // Verify BLAKE3 checksum over bytes 0..24.
    let checksum_offset = 24;
    let checksum_end = checksum_offset + 32;
    if buf.len() < checksum_end {
        return None;
    }
    let stored: [u8; 32] = buf[checksum_offset..checksum_end].try_into().ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf[0..checksum_offset]);
    let computed = hasher.finalize();
    if computed.as_bytes() != &stored {
        return None;
    }

    Some(SystemAreaHeader {
        magic,
        version,
        segment_count,
        committed_root_count,
    })
}

/// Parse a segment table entry from a byte buffer at the given offset.
fn parse_segment_entry(buf: &[u8], offset: usize) -> Option<SegmentDescriptor> {
    let end = offset + SEGMENT_TABLE_ENTRY_SIZE;
    if buf.len() < end {
        return None;
    }

    let entry = &buf[offset..end];
    let segment_id = u64::from_le_bytes(entry[0..8].try_into().ok()?);
    let base_offset = u64::from_le_bytes(entry[8..16].try_into().ok()?);
    let size_bytes = u64::from_le_bytes(entry[16..24].try_into().ok()?);
    let state = SegmentState::from_u8(entry[24])?;

    // Verify per-entry BLAKE3 checksum.
    let stored: [u8; 32] = entry[32..64].try_into().ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&entry[0..32]);
    let computed = hasher.finalize();
    if computed.as_bytes() != &stored {
        return None;
    }

    Some(SegmentDescriptor::new(
        segment_id,
        base_offset,
        size_bytes,
        state,
    ))
}

// ---------------------------------------------------------------------------
// Segment table reader
// ---------------------------------------------------------------------------

/// Reads the system area from a device and enumerates its segment table.
pub struct SegmentTableReader;

impl SegmentTableReader {
    /// Read the segment table from a single device.
    ///
    /// Requires a valid pool label (to locate the system area).  Returns
    /// the parsed [`SegmentTable`] on success.
    pub fn read_from_device(
        device_path: &std::path::Path,
        label: &PoolLabelV1,
    ) -> Result<SegmentTable, SegmentScanError> {
        if label.system_area_pointer == 0 || label.system_area_size == 0 {
            return Err(SegmentScanError::NoSystemArea {
                device_path: device_path.to_path_buf(),
            });
        }

        let mut file = std::fs::File::open(device_path).map_err(|e| SegmentScanError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("open: {e}"),
        })?;

        let area_end = label
            .system_area_pointer
            .saturating_add(label.system_area_size);
        let read_size = (area_end as usize).min(label.system_area_size as usize);

        file.seek(SeekFrom::Start(label.system_area_pointer))
            .map_err(|e| SegmentScanError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("seek to system area: {e}"),
            })?;

        let mut buf = vec![0u8; read_size];
        file.read_exact(&mut buf)
            .map_err(|e| SegmentScanError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("read system area: {e}"),
            })?;

        let header = parse_system_area_header(&buf).ok_or_else(|| {
            let found: [u8; 4] = if buf.len() >= 4 {
                buf[0..4].try_into().unwrap_or([0u8; 4])
            } else {
                [0u8; 4]
            };
            if found != SYSTEM_AREA_MAGIC {
                SegmentScanError::BadSystemAreaMagic {
                    device_path: device_path.to_path_buf(),
                    found,
                }
            } else {
                SegmentScanError::SystemAreaChecksumMismatch {
                    device_path: device_path.to_path_buf(),
                }
            }
        })?;

        let entries_start = SYSTEM_AREA_HEADER_SIZE;
        let mut table = SegmentTable::new();

        for i in 0..header.segment_count as usize {
            let offset = entries_start + i * SEGMENT_TABLE_ENTRY_SIZE;
            if let Some(desc) = parse_segment_entry(&buf, offset) {
                table.insert(desc);
            }
        }

        Ok(table)
    }

    /// Read segment tables from all devices that have valid labels and
    /// merge them into a single deduplicated [`SegmentTable`].
    #[must_use]
    pub fn enumerate_all(
        labelled_devices: &[(std::path::PathBuf, PoolLabelV1)],
    ) -> (SegmentTable, Vec<SegmentScanError>) {
        let mut table = SegmentTable::new();
        let mut errors = Vec::new();

        for (device_path, label) in labelled_devices {
            match Self::read_from_device(device_path, label) {
                Ok(device_table) => {
                    for (_id, desc) in device_table {
                        table.insert(desc);
                    }
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        (table, errors)
    }

    /// Enumerate segments using a [`LabelReader`] to first obtain valid
    /// labels, then read each device's system area.
    #[must_use]
    pub fn enumerate_from_reader(reader: &LabelReader) -> (SegmentTable, Vec<SegmentScanError>) {
        let labelled: Vec<_> = reader.scan_valid_labels();
        Self::enumerate_all(&labelled)
    }
}

// ---------------------------------------------------------------------------
// Helpers: build a synthetic system area (for tests)
// ---------------------------------------------------------------------------

/// Build a synthetic system area buffer containing a header and segment
/// entries suitable for writing to a test device file.
///
/// Returns the filled buffer and its length.
#[must_use]
pub fn build_system_area(segments: &[SegmentDescriptor], committed_root_count: u32) -> Vec<u8> {
    let entry_count = segments.len() as u32;
    let committed_root_entry_size = 96; // reserved for committed-root entries
    let total_entries_size = entry_count as usize * SEGMENT_TABLE_ENTRY_SIZE
        + committed_root_count as usize * committed_root_entry_size;
    let total_size = SYSTEM_AREA_HEADER_SIZE + total_entries_size;
    let mut buf = vec![0u8; total_size];

    // Header.
    buf[0..4].copy_from_slice(&SYSTEM_AREA_MAGIC);
    buf[4..8].copy_from_slice(&SYSTEM_AREA_VERSION.to_le_bytes());
    buf[8..12].copy_from_slice(&entry_count.to_le_bytes());
    buf[12..16].copy_from_slice(&committed_root_count.to_le_bytes());

    // Segment entries.
    let entries_offset = SYSTEM_AREA_HEADER_SIZE;
    for (i, desc) in segments.iter().enumerate() {
        let off = entries_offset + i * SEGMENT_TABLE_ENTRY_SIZE;
        let entry = &mut buf[off..off + SEGMENT_TABLE_ENTRY_SIZE];
        entry[0..8].copy_from_slice(&desc.segment_id.to_le_bytes());
        entry[8..16].copy_from_slice(&desc.base_offset.to_le_bytes());
        entry[16..24].copy_from_slice(&desc.size_bytes.to_le_bytes());
        entry[24] = desc.state.to_u8();

        // BLAKE3 checksum over first 32 bytes.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry[0..32]);
        let digest = hasher.finalize();
        entry[32..64].copy_from_slice(digest.as_bytes());
    }

    // BLAKE3 checksum over header (bytes 0..24).
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf[0..24]);
    let digest = hasher.finalize();
    buf[24..56].copy_from_slice(digest.as_bytes());

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    use tempfile;

    fn make_sealed_label(pool_name: &str) -> PoolLabelV1 {
        let pool_guid = [0xABu8; 16];
        let device_guid = [0xCDu8; 16];
        let label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        seal_label(label).unwrap()
    }

    fn make_test_segments() -> Vec<SegmentDescriptor> {
        vec![
            SegmentDescriptor::new(0, 0x100000, 0x400000, SegmentState::Sealed),
            SegmentDescriptor::new(1, 0x500000, 0x400000, SegmentState::Active),
            SegmentDescriptor::new(2, 0x900000, 0x400000, SegmentState::Obsolete),
        ]
    }

    // -- SegmentState tests --

    #[test]
    fn segment_state_from_u8() {
        assert_eq!(SegmentState::from_u8(0), Some(SegmentState::Active));
        assert_eq!(SegmentState::from_u8(1), Some(SegmentState::Sealed));
        assert_eq!(SegmentState::from_u8(2), Some(SegmentState::Obsolete));
        assert_eq!(SegmentState::from_u8(99), None);
    }

    #[test]
    fn segment_state_is_live() {
        assert!(SegmentState::Active.is_live());
        assert!(SegmentState::Sealed.is_live());
        assert!(!SegmentState::Obsolete.is_live());
    }

    #[test]
    fn segment_state_display() {
        assert_eq!(format!("{}", SegmentState::Active), "ACTIVE");
        assert_eq!(format!("{}", SegmentState::Sealed), "SEALED");
        assert_eq!(format!("{}", SegmentState::Obsolete), "OBSOLETE");
    }

    // -- SegmentDescriptor tests --

    #[test]
    fn segment_descriptor_end_offset() {
        let desc = SegmentDescriptor::new(5, 1024, 2048, SegmentState::Sealed);
        assert_eq!(desc.end_offset(), 3072);
        assert!(desc.is_live());
    }

    // -- SegmentTable tests --

    #[test]
    fn segment_table_insert_and_get() {
        let mut table = SegmentTable::new();
        assert!(table.is_empty());

        let desc = SegmentDescriptor::new(1, 0, 1024, SegmentState::Active);
        table.insert(desc);
        assert_eq!(table.len(), 1);

        let found = table.get(1).unwrap();
        assert_eq!(found.segment_id, 1);
        assert_eq!(found.size_bytes, 1024);
    }

    #[test]
    fn segment_table_live_filter() {
        let mut table = SegmentTable::new();
        table.insert(SegmentDescriptor::new(0, 0, 100, SegmentState::Active));
        table.insert(SegmentDescriptor::new(1, 100, 200, SegmentState::Sealed));
        table.insert(SegmentDescriptor::new(2, 300, 400, SegmentState::Obsolete));

        let live = table.live_segments();
        assert_eq!(live.len(), 2);
        assert!(live.iter().all(|d| d.is_live()));
    }

    #[test]
    fn segment_table_dedup_last_wins() {
        let mut table = SegmentTable::new();
        table.insert(SegmentDescriptor::new(7, 0, 100, SegmentState::Active));
        table.insert(SegmentDescriptor::new(7, 500, 200, SegmentState::Sealed));

        let found = table.get(7).unwrap();
        assert_eq!(found.base_offset, 500);
        assert_eq!(found.state, SegmentState::Sealed);
    }

    // -- System area build/parse roundtrip --

    #[test]
    fn system_area_build_and_parse() {
        let segments = make_test_segments();
        let buf = build_system_area(&segments, 0);

        let header = parse_system_area_header(&buf).unwrap();
        assert_eq!(header.magic, SYSTEM_AREA_MAGIC);
        assert_eq!(header.version, SYSTEM_AREA_VERSION);
        assert_eq!(header.segment_count, 3);
        assert_eq!(header.committed_root_count, 0);

        // Parse each segment entry.
        let entries_offset = SYSTEM_AREA_HEADER_SIZE;
        let parsed: Vec<_> = (0..3)
            .filter_map(|i| {
                parse_segment_entry(&buf, entries_offset + i * SEGMENT_TABLE_ENTRY_SIZE)
            })
            .collect();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].segment_id, 0);
        assert_eq!(parsed[0].state, SegmentState::Sealed);
        assert_eq!(parsed[1].segment_id, 1);
        assert_eq!(parsed[1].state, SegmentState::Active);
        assert_eq!(parsed[2].segment_id, 2);
        assert_eq!(parsed[2].state, SegmentState::Obsolete);
    }

    // -- Bad magic rejection --

    #[test]
    fn system_area_bad_magic() {
        let segments = make_test_segments();
        let mut buf = build_system_area(&segments, 0);
        buf[0] = b'X';
        assert!(parse_system_area_header(&buf).is_none());
    }

    // -- Checksum corruption detection --

    #[test]
    fn system_area_corrupted_checksum() {
        let segments = make_test_segments();
        let mut buf = build_system_area(&segments, 0);
        // Corrupt a byte in the header (before the checksum).
        buf[10] ^= 0xFF;
        assert!(parse_system_area_header(&buf).is_none());
    }

    #[test]
    fn segment_entry_corrupted_checksum() {
        let segments = make_test_segments();
        let buf = build_system_area(&segments, 0);
        let entries_offset = SYSTEM_AREA_HEADER_SIZE;

        // Valid entry.
        assert!(parse_segment_entry(&buf, entries_offset).is_some());

        // Corrupt entry.
        let mut bad_buf = buf.clone();
        bad_buf[entries_offset + 10] ^= 0xFF;
        assert!(parse_segment_entry(&bad_buf, entries_offset).is_none());
    }

    // -- Device integration test --

    #[test]
    fn read_segment_table_from_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("segdev");

        let segments = make_test_segments();
        let system_area_buf = build_system_area(&segments, 0);

        // Build a pool label that points to the system area.
        let system_area_offset = 4096u64; // 4 KiB in
        let system_area_size = system_area_buf.len() as u64;
        let pool_guid = [0x55u8; 16];
        let device_guid = [0x66u8; 16];
        let mut label = PoolLabelV1::new(pool_guid, device_guid, "segpool");
        label.system_area_pointer = system_area_offset;
        label.system_area_size = system_area_size;
        let label = seal_label(label).unwrap();

        // Write label at offset 0, system area at offset 4096.
        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut label_buf).unwrap();

        let mut file = std::fs::File::create(&dev_path).unwrap();
        file.write_all(&label_buf).unwrap();

        // Pad to system_area_offset.
        let current = file.stream_position().unwrap();
        if current < system_area_offset {
            let pad = vec![0u8; (system_area_offset - current) as usize];
            file.write_all(&pad).unwrap();
        }
        file.write_all(&system_area_buf).unwrap();

        let table = SegmentTableReader::read_from_device(&dev_path, &label).unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(table.get(0).unwrap().state, SegmentState::Sealed);
        assert_eq!(table.get(1).unwrap().state, SegmentState::Active);
        assert_eq!(table.get(2).unwrap().state, SegmentState::Obsolete);
    }

    #[test]
    fn read_segment_table_no_system_area() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("nosys");

        let mut label = make_sealed_label("nosyspool");
        label.system_area_pointer = 0;
        label.system_area_size = 0;
        let label = seal_label(label).unwrap();

        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut label_buf).unwrap();
        std::fs::write(&dev_path, label_buf).unwrap();

        let result = SegmentTableReader::read_from_device(&dev_path, &label);
        assert!(matches!(result, Err(SegmentScanError::NoSystemArea { .. })));
    }

    #[test]
    fn enumerate_all_multiple_devices() {
        let dir = tempfile::tempdir().unwrap();

        // Device A: segments 0, 1.
        let dev_a = dir.path().join("devA");
        let seg_a = vec![
            SegmentDescriptor::new(0, 0x100000, 0x100000, SegmentState::Sealed),
            SegmentDescriptor::new(1, 0x200000, 0x100000, SegmentState::Active),
        ];
        let sys_a = build_system_area(&seg_a, 0);

        let pool_guid = [0xAAu8; 16];
        let mut label_a = PoolLabelV1::new(pool_guid, [0x01u8; 16], "enum");
        label_a.system_area_pointer = 4096;
        label_a.system_area_size = sys_a.len() as u64;
        let label_a = seal_label(label_a).unwrap();
        write_device_with_system_area(&dev_a, &label_a, &sys_a, 4096);

        // Device B: segments 2, and also segment 1 (same pool, same segment).
        let dev_b = dir.path().join("devB");
        let seg_b = vec![
            SegmentDescriptor::new(1, 0x200000, 0x100000, SegmentState::Active),
            SegmentDescriptor::new(2, 0x300000, 0x100000, SegmentState::Sealed),
        ];
        let sys_b = build_system_area(&seg_b, 0);

        let mut label_b = PoolLabelV1::new(pool_guid, [0x02u8; 16], "enum");
        label_b.system_area_pointer = 4096;
        label_b.system_area_size = sys_b.len() as u64;
        let label_b = seal_label(label_b).unwrap();
        write_device_with_system_area(&dev_b, &label_b, &sys_b, 4096);

        let labelled = vec![(dev_a.clone(), label_a), (dev_b.clone(), label_b)];

        let (table, errors) = SegmentTableReader::enumerate_all(&labelled);
        assert!(errors.is_empty());
        assert_eq!(table.len(), 3); // segments 0, 1, 2
        assert!(table.get(0).is_some());
        assert!(table.get(1).is_some());
        assert!(table.get(2).is_some());
    }

    fn write_device_with_system_area(
        path: &std::path::Path,
        label: &PoolLabelV1,
        sys_buf: &[u8],
        sys_offset: u64,
    ) {
        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut label_buf).unwrap();

        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&label_buf).unwrap();
        let current = file.stream_position().unwrap();
        if current < sys_offset {
            let pad = vec![0u8; (sys_offset - current) as usize];
            file.write_all(&pad).unwrap();
        }
        file.write_all(sys_buf).unwrap();
    }

    // -- SegmentScanError Display --

    #[test]
    fn segment_scan_error_display() {
        let err = SegmentScanError::NoLabel {
            device_path: PathBuf::from("/dev/sda"),
        };
        assert!(format!("{err}").contains("no label"));

        let err = SegmentScanError::BadSystemAreaMagic {
            device_path: PathBuf::from("/dev/sdb"),
            found: [0u8; 4],
        };
        assert!(format!("{err}").contains("bad system area magic"));
    }

    // -- enumerate_from_reader --

    #[test]
    fn enumerate_from_reader_integration() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0xBBu8; 16];

        let segments = vec![SegmentDescriptor::new(
            10,
            0x500000,
            0x200000,
            SegmentState::Sealed,
        )];
        let sys_buf = build_system_area(&segments, 0);

        let mut label = PoolLabelV1::new(pool_guid, [0x10u8; 16], "readerpool");
        label.system_area_pointer = 4096;
        label.system_area_size = sys_buf.len() as u64;
        let label = seal_label(label).unwrap();

        let dev_path = dir.path().join("readerdev");
        write_device_with_system_area(&dev_path, &label, &sys_buf, 4096);

        let cfg = crate::label::PoolScanConfig::new(vec![dev_path]);
        let reader = crate::label::LabelReader::new(cfg);
        let (table, errors) = SegmentTableReader::enumerate_from_reader(&reader);

        assert!(errors.is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(10).unwrap().segment_id, 10);
    }
}
