//! Consolidated pool scan result.
//!
//! [`PoolScanResult`] aggregates the output of a full pool device scan:
//! pool identity, per-device metadata, a unified segment map, the latest
//! committed root, and any warnings encountered.

use std::path::PathBuf;

use tidefs_types_pool_label_core::{PoolLabelV1, PoolState};

use crate::committed_root::CommittedRoot;
use crate::segment::SegmentTable;

// ---------------------------------------------------------------------------
// DeviceScanInfo
// ---------------------------------------------------------------------------

/// Per-device metadata collected during a pool scan.
#[derive(Clone, Debug)]
pub struct DeviceScanInfo {
    /// Absolute path to the device node.
    pub device_path: PathBuf,
    /// Device GUID from the label.
    pub device_guid: Option<[u8; 16]>,
    /// Device index within the pool topology.
    pub device_index: Option<u32>,
    /// Whether the device carries a valid pool label.
    pub label_valid: bool,
    /// Human-readable label status.
    pub label_status: String,
    /// Segment count found on this device.
    pub segment_count: usize,
    /// Committed roots found on this device.
    pub committed_roots_found: usize,
}

impl DeviceScanInfo {
    /// Create a new entry with defaults.
    #[must_use]
    pub fn new(device_path: PathBuf) -> Self {
        Self {
            device_path,
            device_guid: None,
            device_index: None,
            label_valid: false,
            label_status: String::new(),
            segment_count: 0,
            committed_roots_found: 0,
        }
    }

    /// Populate fields from a parsed pool label.
    pub fn apply_label(&mut self, label: &PoolLabelV1) {
        self.device_guid = Some(label.device_guid);
        self.device_index = Some(label.device_index);
        self.label_valid = true;
        self.label_status = format!(
            "pool='{}' state={} index={}",
            label.pool_name_str(),
            label.pool_state,
            label.device_index
        );
    }
}

// ---------------------------------------------------------------------------
// PoolScanResult
// ---------------------------------------------------------------------------

/// Consolidated result of scanning all devices in a pool.
///
/// Produced by [`PoolScanner`] after label validation, pool membership
/// verification, segment table enumeration, and committed-root discovery.
#[derive(Clone, Debug)]
pub struct PoolScanResult {
    /// Pool GUID (identical across all member devices).
    pub pool_guid: [u8; 16],
    /// Human-readable pool name from the label.
    pub pool_name: String,
    /// Operational state of the pool.
    pub pool_state: PoolState,
    /// Total device count from the topology.
    pub device_count: u32,
    /// Per-device scan metadata.
    pub devices: Vec<DeviceScanInfo>,
    /// Unified segment map (deduplicated across devices).
    pub segments: SegmentTable,
    /// The latest valid committed root, if found.
    pub committed_root: Option<CommittedRoot>,
    /// Non-fatal warnings accumulated during the scan (e.g. missing
    /// devices, corrupted but recoverable labels, checksum mismatches
    /// on secondary label copies).
    pub warnings: Vec<String>,
}

impl PoolScanResult {
    /// Create an empty result with the given pool GUID.
    #[must_use]
    pub fn new(pool_guid: [u8; 16]) -> Self {
        Self {
            pool_guid,
            pool_name: String::new(),
            pool_state: PoolState::Active,
            device_count: 0,
            devices: Vec::new(),
            segments: SegmentTable::new(),
            committed_root: None,
            warnings: Vec::new(),
        }
    }

    /// Returns the total number of live segments across all devices.
    #[must_use]
    pub fn live_segment_count(&self) -> usize {
        self.segments.live_segments().len()
    }

    /// Returns the total number of segments in the unified table.
    #[must_use]
    pub fn total_segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns true if a valid committed root was found.
    #[must_use]
    pub fn has_committed_root(&self) -> bool {
        self.committed_root.is_some()
    }

    /// Returns true if at least one device had a valid label.
    #[must_use]
    pub fn has_valid_devices(&self) -> bool {
        self.devices.iter().any(|d| d.label_valid)
    }

    /// Returns the commit_group of the committed root, if any.
    #[must_use]
    pub fn committed_txg(&self) -> Option<u64> {
        self.committed_root.as_ref().map(|r| r.commit_group)
    }

    /// Append a warning message.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

// ---------------------------------------------------------------------------
// PoolScanner — top-level orchestrator
// ---------------------------------------------------------------------------

/// Scans a set of device paths and produces a [`PoolScanResult`].
///
/// The scanner:
/// 1. Reads pool labels from every device.
/// 2. Validates pool membership (common pool GUID).
/// 3. Enumerates segment tables from the system area of each device.
/// 4. Locates the latest valid committed root.
/// 5. Returns a consolidated [`PoolScanResult`].
pub struct PoolScanner;

impl PoolScanner {
    /// Run a full scan of all devices in `config` and produce a
    /// [`PoolScanResult`].
    ///
    /// Returns `Err` only when no valid pool labels are found at all.
    pub fn scan(
        config: &crate::label::PoolScanConfig,
    ) -> Result<PoolScanResult, crate::label::MembershipError> {
        use crate::label::{validate_pool_membership, LabelReader};

        let reader = LabelReader::new(config.clone());
        let pool_guid = validate_pool_membership(&reader)?;

        let mut result = PoolScanResult::new(pool_guid);

        // Gather device info from label scan.
        let all_results = reader.scan_all();
        for (device_path, outcome) in &all_results {
            let mut info = DeviceScanInfo::new(device_path.clone());
            match outcome {
                crate::label::LabelReadOutcome::Valid(label) => {
                    info.apply_label(label);
                    // Use the first valid label for pool-wide fields.
                    if result.pool_name.is_empty() {
                        result.pool_name = label.pool_name_str().to_string();
                    }
                    result.pool_state = label.pool_state;
                    result.device_count = result.device_count.max(label.device_count);
                }
                crate::label::LabelReadOutcome::Corrupted { reason, .. } => {
                    info.label_status = format!("corrupted: {reason}");
                    result.warn(format!(
                        "corrupted label on {}: {reason}",
                        device_path.display()
                    ));
                }
                crate::label::LabelReadOutcome::NoLabel => {
                    info.label_status = "no label".into();
                    result.warn(format!(
                        "device {} has no TideFS label",
                        device_path.display()
                    ));
                }
            }
            result.devices.push(info);
        }

        // Enumerate segment table.
        let labelled: Vec<_> = reader.scan_valid_labels();
        let (segments, segment_errors) =
            crate::segment::SegmentTableReader::enumerate_all(&labelled);

        for err in &segment_errors {
            result.warn(format!("segment scan error: {err}"));
        }

        // Record per-device segment counts.
        for (path, _label) in &labelled {
            for info in &mut result.devices {
                if &info.device_path == path {
                    // Count segments that came from this device's system area.
                    // (We can't easily attribute segments to devices after
                    // dedup, so we count all segments for labelled devices.)
                    info.segment_count = segments.len();
                }
            }
        }

        result.segments = segments;

        // Locate committed root.
        use crate::committed_root::CommittedRootLocator;
        match CommittedRootLocator::find_latest_all(&labelled, &result.segments) {
            Ok(Some(root)) => {
                // Count per-device committed roots.
                for (path, _label) in &labelled {
                    for info in &mut result.devices {
                        if &info.device_path == path {
                            info.committed_roots_found = 1;
                        }
                    }
                }
                result.committed_root = Some(root);
            }
            Ok(None) => {
                result.warn("no committed root found on any device");
            }
            Err(e) => {
                result.warn(format!("committed-root locator error: {e}"));
            }
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, Write};

    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    use crate::committed_root::write_committed_root_entry;
    use crate::segment::{build_system_area, SegmentDescriptor, SegmentState};

    use tempfile;

    struct LabelledDeviceSpec<'a> {
        name: &'a str,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &'a str,
        device_index: u32,
        device_count: u32,
        sys_ptr: u64,
        sys_buf: Option<&'a [u8]>,
    }

    /// Write a labelled device file with optional system area.
    fn write_labelled_device(dir: &tempfile::TempDir, spec: LabelledDeviceSpec<'_>) -> PathBuf {
        let path = dir.path().join(spec.name);
        let mut label = PoolLabelV1::new(spec.pool_guid, spec.device_guid, spec.pool_name);
        label.device_index = spec.device_index;
        label.device_count = spec.device_count;
        label.system_area_pointer = spec.sys_ptr;
        label.system_area_size = spec.sys_buf.map(|b| b.len() as u64).unwrap_or(0);
        let label = seal_label(label).unwrap();

        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut label_buf).unwrap();

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&label_buf).unwrap();

        if let Some(sys) = spec.sys_buf {
            let cur = file.stream_position().unwrap();
            if cur < spec.sys_ptr {
                let pad = vec![0u8; (spec.sys_ptr - cur) as usize];
                file.write_all(&pad).unwrap();
            }
            file.write_all(sys).unwrap();
        }

        path
    }

    // -- PoolScanResult tests --

    #[test]
    fn empty_result() {
        let result = PoolScanResult::new([0xABu8; 16]);
        assert_eq!(result.pool_guid, [0xABu8; 16]);
        assert!(result.pool_name.is_empty());
        assert!(!result.has_committed_root());
        assert!(!result.has_valid_devices());
        assert_eq!(result.live_segment_count(), 0);
        assert_eq!(result.committed_txg(), None);
    }

    #[test]
    fn result_with_root() {
        let mut result = PoolScanResult::new([0x11u8; 16]);
        let root = CommittedRoot::new(42, 100, 3, 0x500000, PathBuf::from("/dev/sda"));
        result.committed_root = Some(root);
        assert!(result.has_committed_root());
        assert_eq!(result.committed_txg(), Some(42));
    }

    // -- PoolScanner integration test: single device with segments + root --

    #[test]
    fn scan_single_device_with_segments_and_root() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x99u8; 16];

        let segments = vec![
            SegmentDescriptor::new(0, 0x100000, 0x400000, SegmentState::Sealed),
            SegmentDescriptor::new(1, 0x500000, 0x400000, SegmentState::Active),
        ];
        let mut sys_buf = build_system_area(&segments, 1);

        // Add a committed-root entry after the segment table entries.
        let root_offset = crate::segment::SYSTEM_AREA_HEADER_SIZE
            + segments.len() * crate::segment::SEGMENT_TABLE_ENTRY_SIZE;
        write_committed_root_entry(
            &mut sys_buf,
            root_offset,
            99,  // commit_group
            777, // root_object_id
            0,   // segment_id
            0x100000,
        );

        let dev = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "singledev",
                pool_guid,
                device_guid: [0x01u8; 16],
                pool_name: "singlepool",
                device_index: 0,
                device_count: 1,
                sys_ptr: 4096,
                sys_buf: Some(&sys_buf),
            },
        );

        let cfg = crate::label::PoolScanConfig::new(vec![dev]);
        let result = PoolScanner::scan(&cfg).unwrap();

        assert_eq!(result.pool_guid, pool_guid);
        assert_eq!(result.pool_name, "singlepool");
        assert!(result.has_valid_devices());
        assert_eq!(result.devices.len(), 1);
        assert!(result.devices[0].label_valid);
        assert_eq!(result.total_segment_count(), 2);
        assert_eq!(result.live_segment_count(), 2);
        assert!(result.has_committed_root());
        assert_eq!(result.committed_txg(), Some(99));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn scan_multi_device_pool() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x77u8; 16];

        let seg_a = vec![SegmentDescriptor::new(
            0,
            0x100000,
            0x200000,
            SegmentState::Sealed,
        )];
        let sys_a = build_system_area(&seg_a, 0);

        let seg_b = vec![
            SegmentDescriptor::new(1, 0x300000, 0x200000, SegmentState::Active),
            SegmentDescriptor::new(2, 0x500000, 0x200000, SegmentState::Sealed),
        ];
        let mut sys_b = build_system_area(&seg_b, 1);
        let root_offset_b = crate::segment::SYSTEM_AREA_HEADER_SIZE
            + seg_b.len() * crate::segment::SEGMENT_TABLE_ENTRY_SIZE;
        write_committed_root_entry(&mut sys_b, root_offset_b, 55, 888, 2, 0x500000);

        let dev_a = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "devA",
                pool_guid,
                device_guid: [0x01u8; 16],
                pool_name: "multipool",
                device_index: 0,
                device_count: 2,
                sys_ptr: 4096,
                sys_buf: Some(&sys_a),
            },
        );
        let dev_b = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "devB",
                pool_guid,
                device_guid: [0x02u8; 16],
                pool_name: "multipool",
                device_index: 1,
                device_count: 2,
                sys_ptr: 4096,
                sys_buf: Some(&sys_b),
            },
        );

        let cfg = crate::label::PoolScanConfig::new(vec![dev_a, dev_b]);
        let result = PoolScanner::scan(&cfg).unwrap();

        assert_eq!(result.pool_guid, pool_guid);
        assert_eq!(result.devices.len(), 2);
        assert!(result.devices.iter().all(|d| d.label_valid));
        assert_eq!(result.total_segment_count(), 3);
        assert!(result.has_committed_root());
        assert_eq!(result.committed_txg(), Some(55));
    }

    #[test]
    fn scan_warns_on_unlabeled_device() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x66u8; 16];

        let segments = vec![SegmentDescriptor::new(
            0,
            0x100000,
            0x200000,
            SegmentState::Sealed,
        )];
        let sys_buf = build_system_area(&segments, 0);

        let good = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "good",
                pool_guid,
                device_guid: [0x01u8; 16],
                pool_name: "warnpool",
                device_index: 0,
                device_count: 2,
                sys_ptr: 4096,
                sys_buf: Some(&sys_buf),
            },
        );

        // Unlabeled device.
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"not a TideFS device").unwrap();

        let cfg = crate::label::PoolScanConfig::new(vec![good, plain]);
        let result = PoolScanner::scan(&cfg).unwrap();

        assert_eq!(result.devices.len(), 2);
        assert!(result.devices[0].label_valid);
        assert!(!result.devices[1].label_valid);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn scan_fails_on_pool_guid_mismatch() {
        let dir = tempfile::tempdir().unwrap();

        let dev_a = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "devA",
                pool_guid: [0x11u8; 16],
                device_guid: [0x01u8; 16],
                pool_name: "poolA",
                device_index: 0,
                device_count: 1,
                sys_ptr: 0,
                sys_buf: None,
            },
        );
        let dev_b = write_labelled_device(
            &dir,
            LabelledDeviceSpec {
                name: "devB",
                pool_guid: [0x22u8; 16],
                device_guid: [0x02u8; 16],
                pool_name: "poolB",
                device_index: 0,
                device_count: 1,
                sys_ptr: 0,
                sys_buf: None,
            },
        );

        let cfg = crate::label::PoolScanConfig::new(vec![dev_a, dev_b]);
        let result = PoolScanner::scan(&cfg);

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::label::MembershipError::PoolGuidMismatch { .. } => {}
            other => panic!("expected PoolGuidMismatch, got {other:?}"),
        }
    }
}
