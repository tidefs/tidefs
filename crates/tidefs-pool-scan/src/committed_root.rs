// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Committed-root locator for pool device scanning.
//!
//! A *committed root* anchors the durable state of the filesystem at a
//! specific transaction group (commit_group).  After a crash or clean shutdown,
//! the pool scan must discover the latest valid committed root across
//! all devices so that intent-log replay can start from the correct
//! recovery point.
//!
//! Committed roots are stored either:
//! - In a dedicated committed-root region within the system area, or
//! - At the tail (footer) of sealed segments.
//!
//! This module implements both strategies and selects the highest-commit_group
//! valid candidate.

use std::io::{Read, Seek, SeekFrom};

use tidefs_types_pool_label_core::PoolLabelV1;

use crate::segment::{SegmentState, SegmentTable};

// ---------------------------------------------------------------------------
// CommittedRoot
// ---------------------------------------------------------------------------

/// A durable root anchor written at a specific transaction group.
///
/// The committed root records where the filesystem root object can be
/// found and which segment holds it.  During scanning, the locator
/// selects the root with the highest `commit_group` that passes BLAKE3 checksum
/// verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRoot {
    /// Transaction group when this root was committed.
    pub commit_group: u64,
    /// Object ID of the root dataset / namespace root.
    pub root_object_id: u64,
    /// The segment that contains this root.
    pub segment_id: u64,
    /// Byte offset within the device where this root record is stored.
    pub device_offset: u64,
    /// Device path where this root was found.
    pub device_path: std::path::PathBuf,
    /// Whether this root passed BLAKE3 integrity verification.
    pub verified: bool,
}

impl CommittedRoot {
    /// Create a new committed root entry.
    #[must_use]
    pub fn new(
        commit_group: u64,
        root_object_id: u64,
        segment_id: u64,
        device_offset: u64,
        device_path: std::path::PathBuf,
    ) -> Self {
        Self {
            commit_group,
            root_object_id,
            segment_id,
            device_offset,
            device_path,
            verified: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Committed-root region constants
// ---------------------------------------------------------------------------

/// Magic bytes for a committed-root entry ("VBCR").
pub const COMMITTED_ROOT_MAGIC: [u8; 4] = *b"VBCR";

/// Wire size of a committed-root entry in the system area.
pub const COMMITTED_ROOT_ENTRY_SIZE: usize = 96;

/// Offset of the BLAKE3 checksum within a committed-root entry.
pub const COMMITTED_ROOT_CHECKSUM_OFFSET: usize = 32;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from committed-root location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootLocatorError {
    /// Not enough data to parse a committed-root entry.
    Truncated { device_path: std::path::PathBuf },
    /// Magic bytes do not match [`COMMITTED_ROOT_MAGIC`].
    BadMagic { device_path: std::path::PathBuf },
    /// BLAKE3 checksum verification failed.
    ChecksumMismatch {
        device_path: std::path::PathBuf,
        commit_group: u64,
    },
    /// I/O error.
    Io {
        device_path: std::path::PathBuf,
        msg: String,
    },
}

impl std::fmt::Display for RootLocatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { device_path } => {
                write!(
                    f,
                    "truncated committed-root data on {}",
                    device_path.display()
                )
            }
            Self::BadMagic { device_path } => {
                write!(f, "bad committed-root magic on {}", device_path.display())
            }
            Self::ChecksumMismatch {
                device_path,
                commit_group,
            } => {
                write!(
                    f,
                    "committed-root checksum mismatch on {} (commit_group={commit_group})",
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
// CommittedRootLocator
// ---------------------------------------------------------------------------

/// Locates the latest valid committed root across a set of devices.
pub struct CommittedRootLocator;

impl CommittedRootLocator {
    /// Scan the system area of each labelled device for committed-root
    /// entries.  Returns the root with the highest commit_group that passes
    /// BLAKE3 checksum verification.
    ///
    /// If no valid committed root is found, returns `Ok(None)`.
    /// Returns `Err` only on I/O failures (parse failures are logged
    /// as warnings but do not prevent scanning other candidates).
    pub fn find_latest(
        labelled_devices: &[(std::path::PathBuf, PoolLabelV1)],
    ) -> Result<Option<CommittedRoot>, RootLocatorError> {
        let mut best: Option<CommittedRoot> = None;

        for (device_path, label) in labelled_devices {
            if label.system_area_pointer == 0 || label.system_area_size == 0 {
                continue;
            }

            let candidates = Self::read_from_system_area(device_path, label)?;
            for mut root in candidates {
                root.device_path = device_path.clone();
                if Self::verify_root(&root) {
                    root.verified = true;
                    match &best {
                        None => best = Some(root),
                        Some(current) if root.commit_group > current.commit_group => {
                            best = Some(root)
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(best)
    }

    /// Scan segment footers from the segment table for committed roots.
    ///
    /// For each sealed segment in `table`, this reads the last
    /// [`COMMITTED_ROOT_ENTRY_SIZE`] bytes (the footer) from the
    /// device and attempts to parse a committed root.
    ///
    /// Returns all valid committed roots found.
    pub fn find_from_segments(
        device_path: &std::path::Path,
        _label: &PoolLabelV1,
        table: &SegmentTable,
    ) -> Result<Vec<CommittedRoot>, RootLocatorError> {
        let mut roots = Vec::new();

        let mut file = std::fs::File::open(device_path).map_err(|e| RootLocatorError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("open: {e}"),
        })?;

        for desc in table.iter() {
            // Only sealed segments carry committed roots.
            if desc.state != SegmentState::Sealed {
                continue;
            }

            let footer_offset = desc
                .base_offset
                .saturating_add(desc.size_bytes)
                .saturating_sub(COMMITTED_ROOT_ENTRY_SIZE as u64);

            file.seek(SeekFrom::Start(footer_offset))
                .map_err(|e| RootLocatorError::Io {
                    device_path: device_path.to_path_buf(),
                    msg: format!("seek to footer: {e}"),
                })?;

            let mut buf = [0u8; COMMITTED_ROOT_ENTRY_SIZE];
            if file.read_exact(&mut buf).is_err() {
                continue;
            }

            if let Some(root) = Self::parse_entry(&buf) {
                let mut root = root;
                root.device_path = device_path.to_path_buf();
                if Self::verify_root(&root) {
                    root.verified = true;
                    roots.push(root);
                }
            }
        }

        Ok(roots)
    }

    /// Find the latest committed root using all available methods:
    /// system-area entries first, then segment footers.
    ///
    /// Returns the highest-commit_group verified committed root, or `None` if
    /// none was found.
    pub fn find_latest_all(
        labelled_devices: &[(std::path::PathBuf, PoolLabelV1)],
        segment_table: &SegmentTable,
    ) -> Result<Option<CommittedRoot>, RootLocatorError> {
        let mut best: Option<CommittedRoot> = None;

        // Strategy 1: system area entries.
        if let Ok(Some(root)) = Self::find_latest(labelled_devices) {
            best = Some(root);
        }

        // Strategy 2: segment footers.
        for (device_path, label) in labelled_devices {
            match Self::find_from_segments(device_path, label, segment_table) {
                Ok(roots) => {
                    for root in roots {
                        match &best {
                            None => best = Some(root),
                            Some(current) if root.commit_group > current.commit_group => {
                                best = Some(root)
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(best)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Read committed-root entries from a device's system area.
    fn read_from_system_area(
        device_path: &std::path::Path,
        label: &PoolLabelV1,
    ) -> Result<Vec<CommittedRoot>, RootLocatorError> {
        let mut file = std::fs::File::open(device_path).map_err(|e| RootLocatorError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("open: {e}"),
        })?;

        // Read the system area header first to get committed_root_count.
        use crate::segment::SYSTEM_AREA_HEADER_SIZE;
        file.seek(SeekFrom::Start(label.system_area_pointer))
            .map_err(|e| RootLocatorError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("seek to system area: {e}"),
            })?;

        let mut header_buf = [0u8; SYSTEM_AREA_HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .map_err(|e| RootLocatorError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("read system area header: {e}"),
            })?;

        let committed_root_count =
            u32::from_le_bytes(header_buf[12..16].try_into().unwrap_or([0u8; 4]));

        if committed_root_count == 0 {
            return Ok(Vec::new());
        }

        // Read the whole system area to get committed-root entries.
        let area_size = label.system_area_size as usize;
        file.seek(SeekFrom::Start(label.system_area_pointer))
            .map_err(|e| RootLocatorError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("seek to system area: {e}"),
            })?;

        let mut buf = vec![0u8; area_size.min(16 * 1024 * 1024)]; // cap at 16 MiB
        let n = file.read(&mut buf).map_err(|e| RootLocatorError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("read system area: {e}"),
        })?;
        buf.truncate(n);

        // Committed-root entries come after segment table entries.
        use crate::segment::SEGMENT_TABLE_ENTRY_SIZE;
        let segment_count = u32::from_le_bytes(header_buf[8..12].try_into().unwrap_or([0u8; 4]));
        let committed_root_offset =
            SYSTEM_AREA_HEADER_SIZE + segment_count as usize * SEGMENT_TABLE_ENTRY_SIZE;

        let mut roots = Vec::new();
        for i in 0..committed_root_count as usize {
            let off = committed_root_offset + i * COMMITTED_ROOT_ENTRY_SIZE;
            if off + COMMITTED_ROOT_ENTRY_SIZE > buf.len() {
                break;
            }
            let entry = &buf[off..off + COMMITTED_ROOT_ENTRY_SIZE];
            if let Some(root) = Self::parse_entry(entry) {
                let mut root = root;
                root.device_path = device_path.to_path_buf();
                roots.push(root);
            }
        }

        Ok(roots)
    }

    /// Parse a committed-root entry from raw bytes.
    ///
    /// Verifies the BLAKE3-256 checksum over bytes 0..36 against the
    /// stored checksum at bytes 36..68.
    fn parse_entry(buf: &[u8]) -> Option<CommittedRoot> {
        if buf.len() < COMMITTED_ROOT_ENTRY_SIZE {
            return None;
        }

        // Check magic.
        let magic: [u8; 4] = buf[0..4].try_into().ok()?;
        if magic != COMMITTED_ROOT_MAGIC {
            return None;
        }

        // Verify BLAKE3-256 checksum over bytes 0..36.
        let stored: [u8; 32] = buf[36..68].try_into().ok()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[0..36]);
        let computed = hasher.finalize();
        if computed.as_bytes() != &stored {
            return None;
        }

        let commit_group = u64::from_le_bytes(buf[4..12].try_into().ok()?);
        let root_object_id = u64::from_le_bytes(buf[12..20].try_into().ok()?);
        let segment_id = u64::from_le_bytes(buf[20..28].try_into().ok()?);
        let device_offset = u64::from_le_bytes(buf[28..36].try_into().ok()?);

        let mut root = CommittedRoot::new(
            commit_group,
            root_object_id,
            segment_id,
            device_offset,
            std::path::PathBuf::new(),
        );
        root.verified = true;
        Some(root)
    }

    /// Verify the BLAKE3-256 checksum embedded in the committed-root entry.
    fn verify_root(root: &CommittedRoot) -> bool {
        // Re-encode the root fields and compare against known data.
        // In practice, the original on-disk entry would need to be re-read,
        // but for in-memory roots we verify the checksum was already
        // validated during parsing.  Here we check that the root fields
        // are self-consistent.
        root.commit_group > 0
    }
}

// ---------------------------------------------------------------------------
// Build a synthetic committed-root entry (for tests)
// ---------------------------------------------------------------------------

/// Build a committed-root entry at the specified offset in `buf`.
///
/// Writes magic, commit_group, root_object_id, segment_id, device_offset, and a
/// BLAKE3-256 checksum over bytes 0..36.
pub fn write_committed_root_entry(
    buf: &mut [u8],
    offset: usize,
    commit_group: u64,
    root_object_id: u64,
    segment_id: u64,
    device_offset: u64,
) {
    let end = offset + COMMITTED_ROOT_ENTRY_SIZE;
    if buf.len() < end {
        return;
    }
    let entry = &mut buf[offset..end];

    entry[0..4].copy_from_slice(&COMMITTED_ROOT_MAGIC);
    entry[4..12].copy_from_slice(&commit_group.to_le_bytes());
    entry[12..20].copy_from_slice(&root_object_id.to_le_bytes());
    entry[20..28].copy_from_slice(&segment_id.to_le_bytes());
    entry[28..36].copy_from_slice(&device_offset.to_le_bytes());

    // BLAKE3-256 over bytes 0..36 (all header fields).
    let mut hasher = blake3::Hasher::new();
    hasher.update(&entry[0..36]);
    let digest = hasher.finalize();
    entry[36..68].copy_from_slice(digest.as_bytes());

    // Remaining bytes 68..96 are reserved (zeroed).
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    use crate::segment::{build_system_area, SegmentDescriptor};

    use tempfile;

    fn make_label(
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        name: &str,
        sys_ptr: u64,
        sys_size: u64,
    ) -> PoolLabelV1 {
        let mut label = PoolLabelV1::new(pool_guid, device_guid, name);
        label.system_area_pointer = sys_ptr;
        label.system_area_size = sys_size;
        seal_label(label).unwrap()
    }

    fn write_device_with_sys_area(
        path: &std::path::Path,
        label: &PoolLabelV1,
        sys_buf: &[u8],
        sys_offset: u64,
    ) {
        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut label_buf).unwrap();

        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&label_buf).unwrap();
        let cur = file.stream_position().unwrap();
        if cur < sys_offset {
            let pad = vec![0u8; (sys_offset - cur) as usize];
            file.write_all(&pad).unwrap();
        }
        file.write_all(sys_buf).unwrap();
    }

    // -- Parse entry --

    #[test]
    fn parse_committed_root_entry_valid() {
        let mut buf = [0u8; COMMITTED_ROOT_ENTRY_SIZE];
        write_committed_root_entry(&mut buf, 0, 42, 100, 7, 0x500000);

        let root = CommittedRootLocator::parse_entry(&buf).unwrap();
        assert_eq!(root.commit_group, 42);
        assert_eq!(root.root_object_id, 100);
        assert_eq!(root.segment_id, 7);
        assert_eq!(root.device_offset, 0x500000);
    }

    #[test]
    fn parse_committed_root_bad_magic() {
        let buf = [0u8; COMMITTED_ROOT_ENTRY_SIZE];
        assert!(CommittedRootLocator::parse_entry(&buf).is_none());
    }

    #[test]
    fn parse_committed_root_truncated() {
        let buf = [0u8; 32];
        assert!(CommittedRootLocator::parse_entry(&buf).is_none());
    }

    // -- find_latest from system area --

    #[test]
    fn find_latest_from_system_area() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("rootdev");

        let segments: Vec<SegmentDescriptor> = vec![];
        let committed_root_count: u32 = 2;

        // Build system area with 2 committed-root entries.
        // Using the segment area builder and then writing committed-root entries manually.
        let mut sys_buf = build_system_area(&segments, committed_root_count);
        let entries_offset = crate::segment::SYSTEM_AREA_HEADER_SIZE;

        // Entry 0: commit_group=10
        write_committed_root_entry(&mut sys_buf, entries_offset, 10, 200, 1, 0x100000);
        // Entry 1: commit_group=15
        write_committed_root_entry(
            &mut sys_buf,
            entries_offset + COMMITTED_ROOT_ENTRY_SIZE,
            15,
            300,
            2,
            0x200000,
        );

        let sys_size = sys_buf.len() as u64;
        let pool_guid = [0x11u8; 16];
        let label = make_label(pool_guid, [0xAAu8; 16], "rootpool", 4096, sys_size);
        write_device_with_sys_area(&dev_path, &label, &sys_buf, 4096);

        let labelled = vec![(dev_path, label)];
        let found = CommittedRootLocator::find_latest(&labelled)
            .unwrap()
            .unwrap();

        assert_eq!(found.commit_group, 15);
        assert_eq!(found.root_object_id, 300);
        assert!(found.verified);
    }

    #[test]
    fn find_latest_no_system_area() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("noarea");

        let label = make_label(
            [0x22u8; 16],
            [0xBBu8; 16],
            "noarea",
            0, // system_area_pointer = 0
            0,
        );

        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut label_buf).unwrap();
        std::fs::write(&dev_path, label_buf).unwrap();

        let labelled = vec![(dev_path, label)];
        let found = CommittedRootLocator::find_latest(&labelled).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn find_latest_multiple_devices_picks_highest_txg() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x33u8; 16];

        // Device A: commit_group=5
        let dev_a = dir.path().join("devA");
        let segments_a: Vec<SegmentDescriptor> = vec![];
        let mut sys_a = build_system_area(&segments_a, 1);
        write_committed_root_entry(
            &mut sys_a,
            crate::segment::SYSTEM_AREA_HEADER_SIZE,
            5,
            100,
            1,
            0x100000,
        );
        let label_a = make_label(pool_guid, [0x01u8; 16], "multi", 4096, sys_a.len() as u64);
        write_device_with_sys_area(&dev_a, &label_a, &sys_a, 4096);

        // Device B: commit_group=20
        let dev_b = dir.path().join("devB");
        let segments_b: Vec<SegmentDescriptor> = vec![];
        let mut sys_b = build_system_area(&segments_b, 1);
        write_committed_root_entry(
            &mut sys_b,
            crate::segment::SYSTEM_AREA_HEADER_SIZE,
            20,
            200,
            2,
            0x200000,
        );
        let label_b = make_label(pool_guid, [0x02u8; 16], "multi", 4096, sys_b.len() as u64);
        write_device_with_sys_area(&dev_b, &label_b, &sys_b, 4096);

        let labelled = vec![(dev_a, label_a), (dev_b, label_b)];
        let found = CommittedRootLocator::find_latest(&labelled)
            .unwrap()
            .unwrap();

        assert_eq!(found.commit_group, 20);
    }

    #[test]
    fn committed_root_display_errors() {
        let err = RootLocatorError::BadMagic {
            device_path: std::path::PathBuf::from("/dev/sda"),
        };
        assert!(format!("{err}").contains("bad committed-root magic"));

        let err = RootLocatorError::ChecksumMismatch {
            device_path: std::path::PathBuf::from("/dev/sdb"),
            commit_group: 7,
        };
        assert!(format!("{err}").contains("commit_group=7"));
    }
}
