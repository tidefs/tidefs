//! Pool device scanner and integrity verification.
//!
//! This crate provides:
//! - Device enumeration and classification (via /sys/block)
//! - Pool label reading with BLAKE3-256 checksum verification
//! - Segment table enumeration from device system areas
//! - Committed-root discovery for crash-consistent recovery points
//! - Pool assembly from labelled devices
//! - [`scanner::SegmentScanner`]: segment-level integrity verification
//!   with BLAKE3-256 record checksums, suspect tracking, and pooled
//!   health reporting via [`scanner::PoolScanReport`].
//! - Device removal planning with evacuation and redundancy checks
//!
//! Phase 1 + 2 of the pool import/export pipeline (#1971, #3360).  Uses the
//! design-sealed spec in
//! [`docs/design/pool-import-export-device-topology-management.md`].
//! classification, pool label reading, and topology report generation.
//!
//! Phase 1 + 2 of the pool import/export pipeline (#1971, #3360).  Uses the
//! design-sealed spec in
//! [`docs/design/pool-import-export-device-topology-management.md`].

#![deny(unsafe_code)]

pub mod committed_root;
pub mod label;
pub mod label_writer;
pub mod rebuild;
pub mod result;
pub mod segment;

pub use committed_root::{CommittedRoot, CommittedRootLocator, RootLocatorError};
pub use label::{
    validate_pool_membership, LabelErrorKind, LabelReadOutcome, LabelReader, MembershipError,
    PoolScanConfig,
};
pub use label_writer::{LabelWriteError, PoolLabelWriter};
pub use rebuild::{RebuildAction, RebuildKind, RebuildPlan, RebuildScheduler};
pub use result::{DeviceScanInfo, PoolScanResult, PoolScanner};
pub use segment::{
    SegmentDescriptor, SegmentScanError, SegmentState, SegmentTable, SegmentTableReader,
};

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use tidefs_types_pool_label_core::{
    decode_label, DeviceClass, LabelError, PoolLabelV1, PoolState, POOL_LABEL_MAGIC,
};

pub mod device_removal;
pub mod scanner;
pub use device_removal::{
    build_object_placements, check_removal_redundancy, run_device_removal, DeviceObjectMap,
    DeviceRemovalError, DeviceRemovalExecutor, DeviceRemovalHooks, DeviceRemovalPhase,
    DeviceRemovalPlan, DeviceRemovalPlanner, DeviceRemovalResult, DeviceRemovalState,
    EvacuationEntry, NoopDeviceRemovalHooks, ObjectPlacement, VdevRemoveStats,
};
// ---------------------------------------------------------------------------
// DeviceKind — runtime device classification (not the on-disk enum)
// ---------------------------------------------------------------------------

/// Runtime device kind, classified from sysfs properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceKind {
    /// Rotational hard disk.
    Hdd,
    /// Non-rotational solid-state (SATA/SAS SSD).
    Ssd,
    /// NVMe namespace device.
    Nvme,
    /// Device-mapper virtual device.
    DmDevice,
    /// MD (software RAID) device.
    MdDevice,
    /// Loopback device.
    Loop,
    /// RAM-backed block device (brd, zram).
    Ram,
    /// Partition on a parent block device.
    Partition,
    /// Unknown / unclassifiable device.
    Unknown,
}

impl DeviceKind {
    /// Returns `true` if this device kind is a real physical device
    /// (not loop/ram/partition).
    #[must_use]
    pub const fn is_physical(&self) -> bool {
        matches!(self, Self::Hdd | Self::Ssd | Self::Nvme)
    }

    /// Returns `true` if this device should be skipped during enumeration.
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Loop | Self::Ram)
    }

    /// Map to the on-disk `DeviceClass` for label writing.
    /// Returns `None` for kinds that don't map to a storage class
    /// (loop, ram, unknown).
    #[must_use]
    pub const fn to_device_class(self) -> Option<DeviceClass> {
        match self {
            Self::Hdd => Some(DeviceClass::Hdd),
            Self::Ssd => Some(DeviceClass::Ssd),
            Self::Nvme => Some(DeviceClass::Nvme),
            _ => None,
        }
    }
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hdd => f.write_str("HDD"),
            Self::Ssd => f.write_str("SSD"),
            Self::Nvme => f.write_str("NVME"),
            Self::DmDevice => f.write_str("DM"),
            Self::MdDevice => f.write_str("MD"),
            Self::Loop => f.write_str("LOOP"),
            Self::Ram => f.write_str("RAM"),
            Self::Partition => f.write_str("PART"),
            Self::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceHealth — persistent health state for a device in the pool
// ---------------------------------------------------------------------------

/// Per-device health state persisted in pool labels and reported during
/// assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceHealth {
    /// Device is fully operational.
    Online,
    /// One or more child devices are missing or faulted; the device is
    /// still functional (mirror with enough replicas, PARITY_RAID within
    /// parity tolerance).
    Degraded,
    /// Device cannot satisfy I/O (all children faulted or missing, or
    /// parity count exceeded).
    Faulted,
    /// Device is administratively offline and does not participate in I/O.
    Offline,
}

impl DeviceHealth {
    /// Decode from the `device_health` u8 field in a pool label.
    #[must_use]
    pub const fn from_label_health(v: u8) -> Self {
        match v {
            0 => Self::Online,
            1 => Self::Degraded,
            2 => Self::Faulted,
            _ => Self::Online,
        }
    }

    /// Encode to the `device_health` u8 field for a pool label.
    #[must_use]
    pub const fn to_label_health(self) -> u8 {
        match self {
            Self::Online => 0,
            Self::Degraded => 1,
            Self::Faulted => 2,
            Self::Offline => 3,
        }
    }

    /// Returns true if the device can service I/O.
    #[must_use]
    pub const fn is_operational(self) -> bool {
        matches!(self, Self::Online | Self::Degraded)
    }
}

impl std::fmt::Display for DeviceHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => f.write_str("ONLINE"),
            Self::Degraded => f.write_str("DEGRADED"),
            Self::Faulted => f.write_str("FAULTED"),
            Self::Offline => f.write_str("OFFLINE"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceInfo — discovered device metadata
// ---------------------------------------------------------------------------

/// Information gathered about a device during enumeration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Absolute path to the block device node (e.g. `/dev/sda`).
    pub device_path: PathBuf,
    /// Total device size in bytes.
    pub size_bytes: u64,
    /// Classified device kind.
    pub kind: DeviceKind,
    /// Kernel device name (e.g. `sda`, `nvme0n1`).
    pub kernel_name: String,
    /// Device model string (from sysfs), if available.
    pub model: Option<String>,
    /// Device serial number (from sysfs), if available.
    pub serial: Option<String>,
    /// WWN (World Wide Name), if available.
    pub wwn: Option<String>,
    /// Whether the device is rotational (1 = HDD, 0 = SSD/NVMe).
    pub rotational: Option<bool>,
    /// Partition number, if this is a partition (e.g. `sda1` → 1).
    pub partition_number: Option<u32>,
    /// Parent device kernel name, if this is a partition.
    pub parent_device: Option<String>,
}

impl DeviceInfo {
    /// Create a minimal `DeviceInfo` for a device at `path`.
    #[must_use]
    pub fn new(device_path: PathBuf) -> Self {
        Self {
            kernel_name: device_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            device_path,
            size_bytes: 0,
            kind: DeviceKind::Unknown,
            model: None,
            serial: None,
            wwn: None,
            rotational: None,
            partition_number: None,
            parent_device: None,
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceScanEntry — a single device in the scan report
// ---------------------------------------------------------------------------

/// One device entry in a [`DeviceScanReport`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceScanEntry {
    /// Device path.
    pub device_path: PathBuf,
    /// Device size (bytes).
    pub size_bytes: u64,
    /// Classified device kind.
    pub kind: DeviceKind,
    /// Model string, if available.
    pub model: Option<String>,
    /// Serial string, if available.
    pub serial: Option<String>,
    /// Whether the device carries a valid TideFS pool label.
    pub has_tidefs_label: bool,
    /// The pool GUID from the label, if a label was found and parsed.
    pub pool_guid: Option<[u8; 16]>,
    /// The pool name from the label, if found.
    pub pool_name: Option<String>,
    /// Pool state from the label, if found.
    pub pool_state: Option<PoolState>,
    /// Device GUID from the label, if found.
    pub device_guid: Option<[u8; 16]>,
    /// Whether the label passed checksum validation.
    pub label_valid: bool,
    /// Human-readable label status message.
    pub label_status: String,
    /// 0-based device index from the label.
    pub device_index: Option<u32>,
    /// Total device count from the label.
    pub device_count: Option<u32>,
    /// Topology generation from the label.
    pub topology_generation: Option<u64>,
    /// Device class from the label.
    pub device_class: Option<DeviceClass>,
    /// Device capacity from the label.
    pub device_capacity_bytes: Option<u64>,
    /// Per-device health from the label extension.
    pub device_health: Option<DeviceHealth>,
    /// Accumulated read errors from the label.
    pub device_read_errors: Option<u64>,
    /// Accumulated write errors from the label.
    pub device_write_errors: Option<u64>,
    /// Accumulated checksum errors from the label.
    pub device_checksum_errors: Option<u64>,
}

// ---------------------------------------------------------------------------
// DeviceScanReport — the output of a full scan
// ---------------------------------------------------------------------------

/// Output of a device scan: all discovered devices and a summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceScanReport {
    /// All scanned devices, keyed by device path.
    pub devices: BTreeMap<PathBuf, DeviceScanEntry>,
    /// Total number of devices scanned.
    pub total_devices: usize,
    /// Number of devices with a valid TideFS label.
    pub labeled_devices: usize,
    /// Number of physical (non-virtual) devices.
    pub physical_devices: usize,
    /// Summary of errors encountered during the scan.
    pub errors: Vec<String>,
}

impl DeviceScanReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
            total_devices: 0,
            labeled_devices: 0,
            physical_devices: 0,
            errors: Vec::new(),
        }
    }

    /// Print a human-readable summary to stdout.
    pub fn print_summary(&self) {
        println!("=== TideFS Pool Scan Report ===");
        println!("Total devices scanned: {}", self.total_devices);
        println!("Physical devices:       {}", self.physical_devices);
        println!("Labeled devices:        {}", self.labeled_devices);
        println!();

        if !self.errors.is_empty() {
            println!("Errors:");
            for err in &self.errors {
                println!("  - {err}");
            }
            println!();
        }

        for entry in self.devices.values() {
            println!(
                "  {:<20} {:>10}  {:<8}  {}",
                entry.device_path.display(),
                format_size(entry.size_bytes),
                entry.kind,
                entry.label_status,
            );
        }
    }
}

impl Default for DeviceScanReport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeviceEnumerator — scan /sys/block for block devices
// ---------------------------------------------------------------------------

/// Enumerates block devices via `/sys/block`.
///
/// Reads each device's size, sysfs properties, and filters out virtual
/// devices (loop, ram, zram) unless `include_virtual` is set.
pub struct DeviceEnumerator {
    include_virtual: bool,
    include_partitions: bool,
}

impl DeviceEnumerator {
    /// Create a new enumerator.
    /// By default, loop/ram/zram and partitions are excluded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            include_virtual: false,
            include_partitions: false,
        }
    }

    /// Include loop, ram, zram devices in the scan.
    #[must_use]
    pub fn include_virtual(mut self, yes: bool) -> Self {
        self.include_virtual = yes;
        self
    }

    /// Include partition devices in the scan.
    #[must_use]
    pub fn include_partitions(mut self, yes: bool) -> Self {
        self.include_partitions = yes;
        self
    }

    /// Enumerate all block devices and return a `Vec<DeviceInfo>`.
    pub fn enumerate(&self) -> Result<Vec<DeviceInfo>, std::io::Error> {
        let mut devices = Vec::new();
        let sys_block = Path::new("/sys/block");

        if !sys_block.is_dir() {
            return Ok(devices); // no /sys/block — return empty
        }

        for entry in fs::read_dir(sys_block)? {
            let entry = entry?;
            let kernel_name = entry.file_name().to_string_lossy().to_string();
            let device_path = PathBuf::from("/dev").join(&kernel_name);

            // Check if the device node actually exists.
            if !device_path.exists() {
                continue;
            }

            let mut info = DeviceInfo::new(device_path);
            info.kernel_name = kernel_name.clone();

            // Read device size from /sys/block/<dev>/size (512-byte sectors).
            let size_path = entry.path().join("size");
            if let Ok(size_str) = fs::read_to_string(&size_path) {
                if let Ok(sectors) = size_str.trim().parse::<u64>() {
                    info.size_bytes = sectors.saturating_mul(512);
                }
            }

            // Classify the device kind.
            let kind = DeviceClassifier::classify(&entry.path(), &kernel_name);
            info.kind = kind;

            // Skip virtual devices unless requested.
            if !self.include_virtual && kind.is_skip() {
                continue;
            }

            // Detect partitions.
            let is_partition = DeviceClassifier::is_partition(&kernel_name);
            if is_partition {
                if !self.include_partitions {
                    continue;
                }
                info.partition_number = DeviceClassifier::partition_number(&kernel_name);
                info.parent_device = DeviceClassifier::parent_device(&kernel_name);
            }

            // Gather sysfs properties.
            info.rotational = read_sysfs_u8(&entry.path(), "queue/rotational").map(|v| v == 1);
            info.model = read_sysfs_string(&entry.path(), "device/model");
            info.serial = read_sysfs_string(&entry.path(), "device/serial");
            info.wwn = read_sysfs_string(&entry.path(), "device/wwid");

            devices.push(info);
        }

        Ok(devices)
    }
}

impl Default for DeviceEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeviceClassifier — classify block device from sysfs properties
// ---------------------------------------------------------------------------

/// Classifies block devices based on kernel name patterns and sysfs
/// properties.
pub struct DeviceClassifier;

impl DeviceClassifier {
    /// Classify a device given its sysfs directory and kernel name.
    #[must_use]
    pub fn classify(sysfs_dir: &Path, kernel_name: &str) -> DeviceKind {
        // Check for NVMe first (nvmeXnY pattern).
        if kernel_name.starts_with("nvme") && !kernel_name.contains('p') {
            return DeviceKind::Nvme;
        }

        // Check for partitions (contains 'p' for NVMe, or ends with digit for others).
        if Self::is_partition(kernel_name) {
            return DeviceKind::Partition;
        }

        // loop devices.
        if kernel_name.starts_with("loop") {
            return DeviceKind::Loop;
        }

        // RAM devices: ram, zram.
        if kernel_name.starts_with("ram") || kernel_name.starts_with("zram") {
            return DeviceKind::Ram;
        }

        // Device-mapper: dm-*.
        if kernel_name.starts_with("dm-") {
            return DeviceKind::DmDevice;
        }

        // MD devices: md*.
        if kernel_name.starts_with("md") {
            return DeviceKind::MdDevice;
        }

        // For sd*/hd*/vd*/xvd* devices, check rotational flag.
        let rotational_path = sysfs_dir.join("queue/rotational");
        if let Ok(contents) = fs::read_to_string(&rotational_path) {
            match contents.trim() {
                "1" => return DeviceKind::Hdd,
                "0" => return DeviceKind::Ssd,
                _ => {}
            }
        }

        DeviceKind::Unknown
    }

    /// Check if `kernel_name` is a partition.
    #[must_use]
    pub fn is_partition(kernel_name: &str) -> bool {
        // NVMe partitions: nvme0n1p1, nvme1n2p3
        if kernel_name.starts_with("nvme") {
            if let Some(idx) = kernel_name.find('p') {
                let after_p = &kernel_name[idx + 1..];
                if after_p.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
        // sd*/hd*/vd*/xvd* partitions: sda1, hdb2, vdc3
        let last_char = kernel_name.chars().last();
        if let Some(c) = last_char {
            if c.is_ascii_digit()
                && (kernel_name.starts_with("sd")
                    || kernel_name.starts_with("hd")
                    || kernel_name.starts_with("vd")
                    || kernel_name.starts_with("xvd"))
            {
                return true;
            }
        }
        false
    }

    /// Extract the partition number from a partition kernel name.
    #[must_use]
    pub fn partition_number(kernel_name: &str) -> Option<u32> {
        // NVMe partition: nvme0n1p1 → 1
        if let Some(idx) = kernel_name.rfind('p') {
            let after_p = &kernel_name[idx + 1..];
            if after_p.chars().all(|c| c.is_ascii_digit()) {
                return after_p.parse().ok();
            }
        }
        // sd* partition: sda1 → 1
        let digits: String = kernel_name
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .collect();
        if digits.is_empty() {
            None
        } else {
            digits.parse().ok()
        }
    }

    /// Extract the parent device kernel name from a partition kernel name.
    #[must_use]
    pub fn parent_device(kernel_name: &str) -> Option<String> {
        // NVMe partition: nvme0n1p1 → nvme0n1
        if let Some(idx) = kernel_name.rfind('p') {
            let after_p = &kernel_name[idx + 1..];
            if after_p.chars().all(|c| c.is_ascii_digit()) {
                return Some(kernel_name[..idx].to_string());
            }
        }
        // sd* partition: sda1 → sda
        let non_digit_end = kernel_name
            .chars()
            .position(|c| c.is_ascii_digit())
            .unwrap_or(kernel_name.len());
        if non_digit_end > 0 && non_digit_end < kernel_name.len() {
            Some(kernel_name[..non_digit_end].to_string())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// PoolLabelReader — read and validate a pool label from a device
// ---------------------------------------------------------------------------

/// Reads the TideFS pool label from a block device.
///
/// Tries label copy 0 (first 256 KiB) then label copy 1 (last 256 KiB).
pub struct PoolLabelReader;

impl PoolLabelReader {
    /// Read and parse a pool label from `device_path`.
    ///
    /// Returns `Ok(Some(label))` if a valid label is found, `Ok(None)` if
    /// no TideFS label is present, and `Err` for I/O errors.
    pub fn read_label(device_path: &Path) -> Result<Option<PoolLabelV1>, ScanError> {
        let mut file = std::fs::File::open(device_path).map_err(|e| ScanError::Io {
            path: device_path.to_path_buf(),
            msg: format!("open: {e}"),
        })?;

        let size = file.seek(SeekFrom::End(0)).map_err(|e| ScanError::Io {
            path: device_path.to_path_buf(),
            msg: format!("seek: {e}"),
        })?;

        // Read label 0 at offset 0.
        if let Some(label) = Self::try_read_at(&mut file, 0)? {
            return Ok(Some(label));
        }

        // Read label 1 at offset (size - 256 KiB), if the device is big enough.
        let label_area = tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;
        if size >= label_area {
            if let Some(label) = Self::try_read_at(&mut file, size - label_area)? {
                return Ok(Some(label));
            }
        }

        Ok(None)
    }

    /// Try to read a label from a specific byte offset on an already-open file.
    fn try_read_at(
        file: &mut std::fs::File,
        offset: u64,
    ) -> Result<Option<PoolLabelV1>, ScanError> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| ScanError::Io {
                path: PathBuf::from("<file>"),
                msg: format!("seek: {e}"),
            })?;

        let mut buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
        if file.read_exact(&mut buf).is_err() {
            return Ok(None);
        }

        // Quick magic check before full decode.
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        if magic != POOL_LABEL_MAGIC {
            return Ok(None);
        }

        match decode_label(&buf) {
            Ok(label) => Ok(Some(label)),
            Err(_) => Ok(None),
        }
    }

    /// Scan a `DeviceInfo` and produce a `DeviceScanEntry` with label status.
    pub fn scan_device(info: &DeviceInfo) -> DeviceScanEntry {
        let mut entry = DeviceScanEntry {
            device_path: info.device_path.clone(),
            size_bytes: info.size_bytes,
            kind: info.kind,
            model: info.model.clone(),
            serial: info.serial.clone(),
            has_tidefs_label: false,
            pool_guid: None,
            pool_name: None,
            pool_state: None,
            device_guid: None,
            label_valid: false,
            label_status: String::new(),
            device_index: None,
            device_count: None,
            topology_generation: None,
            device_class: None,
            device_capacity_bytes: None,
            device_health: None,
            device_read_errors: None,
            device_write_errors: None,
            device_checksum_errors: None,
        };

        match Self::read_label(&info.device_path) {
            Ok(Some(label)) => {
                entry.has_tidefs_label = true;
                entry.label_valid = true;
                entry.pool_guid = Some(label.pool_guid);
                entry.pool_name = Some(label.pool_name_str().to_string());
                entry.pool_state = Some(label.pool_state);
                entry.device_guid = Some(label.device_guid);
                entry.device_index = Some(label.device_index);
                entry.device_count = Some(label.device_count);
                entry.topology_generation = Some(label.topology_generation);
                entry.device_class = Some(label.device_class);
                entry.device_capacity_bytes = Some(label.device_capacity_bytes);
                entry.device_health = Some(DeviceHealth::from_label_health(label.device_health));
                entry.device_read_errors = Some(label.device_read_errors);
                entry.device_write_errors = Some(label.device_write_errors);
                entry.device_checksum_errors = Some(label.device_checksum_errors);
                entry.label_status =
                    format!("pool={} state={}", label.pool_name_str(), label.pool_state);
            }
            Ok(None) => {
                entry.label_status = "no label".to_string();
            }
            Err(ref e) => {
                entry.label_status = format!("error: {e}");
            }
        }

        entry
    }
}

// ---------------------------------------------------------------------------
// Scan — run a full scan and produce a report
// ---------------------------------------------------------------------------

/// Scan a list of specific device paths (or all devices if empty) and
/// produce a [`DeviceScanReport`].
pub fn scan_devices(
    device_paths: &[PathBuf],
    include_virtual: bool,
) -> Result<DeviceScanReport, ScanError> {
    let mut report = DeviceScanReport::new();

    let devices = if device_paths.is_empty() {
        // Enumerate all block devices.
        DeviceEnumerator::new()
            .include_virtual(include_virtual)
            .enumerate()
            .map_err(|e| ScanError::Io {
                path: PathBuf::from("/sys/block"),
                msg: e.to_string(),
            })?
    } else {
        // Use the provided device paths.
        device_paths
            .iter()
            .map(|p| {
                let mut info = DeviceInfo::new(p.clone());
                // Read size from the device file.
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.file_type().is_block_device() {
                        // For block devices, we need to read size via ioctl or sysfs.
                        // Fall back to /sys/block/<name>/size.
                        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                            let size_path = Path::new("/sys/block").join(name).join("size");
                            if let Ok(s) = fs::read_to_string(&size_path) {
                                if let Ok(sec) = s.trim().parse::<u64>() {
                                    info.size_bytes = sec.saturating_mul(512);
                                }
                            }
                            info.kind = DeviceClassifier::classify(
                                &Path::new("/sys/block").join(name),
                                name,
                            );
                        }
                    } else {
                        info.size_bytes = meta.len();
                    }
                }
                info
            })
            .collect()
    };

    report.total_devices = devices.len();

    for info in &devices {
        if info.kind.is_physical() {
            report.physical_devices += 1;
        }

        let entry = PoolLabelReader::scan_device(info);

        // If we got a label read error, record it but don't fail the scan.
        if entry.label_status.starts_with("error:") {
            report.errors.push(format!(
                "{}: {}",
                entry.device_path.display(),
                entry.label_status
            ));
        }

        if entry.has_tidefs_label && entry.label_valid {
            report.labeled_devices += 1;
        }

        report.devices.insert(entry.device_path.clone(), entry);
    }

    Ok(report)
}

/// Scan a list of device paths for TideFS pool labels.
///
/// This is a focused label-scanning entry point that does not enumerate
/// `/sys/block`.  For each device path, it reads and validates the pool
/// label and returns a `DeviceScanEntry`.  Devices without a label are
/// included with `has_tidefs_label = false`.
pub fn scan_labels(device_paths: &[PathBuf]) -> Result<Vec<DeviceScanEntry>, ScanError> {
    let mut entries = Vec::with_capacity(device_paths.len());
    for p in device_paths {
        let mut info = DeviceInfo::new(p.clone());
        // Read size from the device file or block-device ioctl.
        if let Ok(size) = device_capacity_bytes(p) {
            info.size_bytes = size;
        }
        let entry = PoolLabelReader::scan_device(&info);
        if entry.label_status.starts_with("error:") {
            return Err(ScanError::Io {
                path: p.clone(),
                msg: entry.label_status.clone(),
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// ScanError
// ---------------------------------------------------------------------------

/// Errors from the pool scan process.
#[derive(Debug)]
pub enum ScanError {
    /// An I/O error occurred.
    Io {
        /// Path that caused the error.
        path: PathBuf,
        /// Human-readable message.
        msg: String,
    },
    /// A label decode/validation error.
    Label(LabelError),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, msg } => write!(f, "I/O error on {}: {msg}", path.display()),
            Self::Label(e) => write!(f, "label error: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<LabelError> for ScanError {
    fn from(e: LabelError) -> Self {
        Self::Label(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a sysfs file as a string, trimming whitespace.
fn read_sysfs_string(dir: &Path, rel_path: &str) -> Option<String> {
    let path = dir.join(rel_path);
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read a sysfs file as a u8.
fn read_sysfs_u8(dir: &Path, rel_path: &str) -> Option<u8> {
    let path = dir.join(rel_path);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
}

/// Get the capacity of a block device or regular file in bytes.
///
/// For Linux block devices, uses the `BLKGETSIZE64` ioctl to query the
/// true device capacity.  For regular files and on non-Linux platforms,
/// falls back to `metadata().len()`.
///
/// The returned value is the usable byte capacity.  Labels and the
/// commit-record region are written within this capacity.
pub fn device_capacity_bytes(path: &Path) -> Result<u64, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    if !meta.file_type().is_block_device() {
        return Ok(meta.len());
    }
    // Block device: use BLKGETSIZE64 ioctl on Linux.
    let capacity = blkgetsize64_from_path(path).unwrap_or(0);
    if capacity > 0 {
        return Ok(capacity);
    }
    // ioctl failed or returned zero — fall back to metadata (will be 0
    // for block special files, which is correct: an unreadable device
    // reports 0 and will be rejected by the caller's size check).
    Ok(meta.len())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn blkgetsize64_from_path(path: &Path) -> Option<u64> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    // _IOR(0x12, 114, u64) = 0x80081272 on both 32- and 64-bit.
    const BLKGETSIZE64: u64 = 0x80081272;

    extern "C" {
        fn ioctl(
            fd: std::os::raw::c_int,
            request: std::os::raw::c_ulong,
            ...
        ) -> std::os::raw::c_int;
    }

    let file = OpenOptions::new().read(true).open(path).ok()?;
    let fd = file.as_raw_fd();
    let mut size: u64 = 0;
    // Safety: BLKGETSIZE64 is a well-known Linux block ioctl that writes
    // exactly 8 bytes into the provided u64 buffer.  The file descriptor
    // is valid (opened above).
    let ret = unsafe { ioctl(fd, BLKGETSIZE64 as std::os::raw::c_ulong, &mut size) };
    if ret == 0 {
        Some(size)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn blkgetsize64_from_path(_path: &Path) -> Option<u64> {
    None
}

/// Format a byte count as a human-readable string.
fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit_idx])
    }
}

// ---------------------------------------------------------------------------
// DeviceType — a node in the device tree
// ---------------------------------------------------------------------------

/// A node in the assembled device tree.  Internal nodes are redundancy
/// groups (mirror, PARITY_RAID); leaf nodes are physical devices.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DeviceType {
    /// A single block device (leaf).
    Leaf {
        /// Absolute path to the block device node.
        device_path: PathBuf,
        /// Per-device GUID from the label.
        device_guid: [u8; 16],
        /// 0-based index of this device in the topology.
        device_index: u32,
        /// Total device capacity in bytes.
        capacity_bytes: u64,
        /// Allocation class.
        device_class: DeviceClass,
        /// Current health state.
        health: DeviceHealth,
        /// Accumulated read errors.
        read_errors: u64,
        /// Accumulated write errors.
        write_errors: u64,
        /// Accumulated checksum errors.
        checksum_errors: u64,
    },
    /// N-way mirror (RAID-1).  All children hold identical data.
    Mirror {
        /// Child devices in the mirror.
        children: Vec<DeviceType>,
    },
    /// PARITY_RAID parity stripe group (PARITY_RAID1/2/3).
    ParityRaid {
        /// Number of parity devices (1, 2, or 3).
        parity: u8,
        /// Child devices in the stripe.
        children: Vec<DeviceType>,
    },
}

impl DeviceType {
    /// Collect all leaf devices from the device tree.
    #[must_use]
    pub fn collect_leaves(&self) -> Vec<LeafRef> {
        let mut leaves = Vec::new();
        self._collect_leaves_into(&mut leaves);
        leaves
    }

    fn _collect_leaves_into(&self, out: &mut Vec<LeafRef>) {
        match self {
            Self::Leaf {
                device_guid,
                device_index,
                capacity_bytes,
                device_class,
                health,
                read_errors,
                write_errors,
                checksum_errors,
                ..
            } => out.push(LeafRef {
                device_guid: *device_guid,
                device_index: *device_index,
                capacity_bytes: *capacity_bytes,
                device_class: *device_class,
                health: *health,
                read_errors: *read_errors,
                write_errors: *write_errors,
                checksum_errors: *checksum_errors,
            }),
            Self::Mirror { children } | Self::ParityRaid { children, .. } => {
                for child in children {
                    child._collect_leaves_into(out);
                }
            }
        }
    }

    /// Returns the aggregate health of this device node.
    #[must_use]
    pub fn aggregate_health(&self) -> DeviceHealth {
        match self {
            Self::Leaf { health, .. } => *health,
            Self::Mirror { children } => {
                let operational = children
                    .iter()
                    .filter(|c| c.aggregate_health().is_operational())
                    .count();
                if operational == 0 || children.is_empty() {
                    DeviceHealth::Faulted
                } else if operational < children.len() {
                    DeviceHealth::Degraded
                } else {
                    DeviceHealth::Online
                }
            }
            Self::ParityRaid { parity, children } => {
                let operational = children
                    .iter()
                    .filter(|c| c.aggregate_health().is_operational())
                    .count();
                let needed = children.len().saturating_sub(*parity as usize);
                if operational == 0 || operational < needed {
                    DeviceHealth::Faulted
                } else if operational < children.len() {
                    DeviceHealth::Degraded
                } else {
                    DeviceHealth::Online
                }
            }
        }
    }

    /// Total raw capacity of this device subtree.
    #[must_use]
    pub fn total_capacity_bytes(&self) -> u64 {
        match self {
            Self::Leaf { capacity_bytes, .. } => *capacity_bytes,
            Self::Mirror { children } | Self::ParityRaid { children, .. } => {
                children.iter().map(|c| c.total_capacity_bytes()).sum()
            }
        }
    }

    /// Number of leaf devices in this subtree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        match self {
            Self::Leaf { .. } => 1,
            Self::Mirror { children } | Self::ParityRaid { children, .. } => {
                children.iter().map(|c| c.leaf_count()).sum()
            }
        }
    }
    /// Look up a leaf device by its path, returning leaf fields if found.
    #[must_use]
    pub fn find_leaf(&self, path: &Path) -> Option<LeafRef> {
        self._find_leaf_by(|leaf_path, _guid, _idx| leaf_path == path)
    }

    /// Look up a leaf device by its device GUID.
    #[must_use]
    pub fn find_leaf_by_guid(&self, guid: &[u8; 16]) -> Option<LeafRef> {
        self._find_leaf_by(|_path, leaf_guid, _idx| leaf_guid == guid)
    }

    /// Generic leaf finder: predicate receives (device_path, device_guid, device_index).
    fn _find_leaf_by(
        &self,
        pred: impl Fn(&Path, &[u8; 16], u32) -> bool + Copy,
    ) -> Option<LeafRef> {
        match self {
            Self::Leaf {
                device_path,
                device_guid,
                device_index,
                capacity_bytes,
                device_class,
                health,
                read_errors,
                write_errors,
                checksum_errors,
            } if pred(device_path, device_guid, *device_index) => Some(LeafRef {
                device_guid: *device_guid,
                device_index: *device_index,
                capacity_bytes: *capacity_bytes,
                device_class: *device_class,
                health: *health,
                read_errors: *read_errors,
                write_errors: *write_errors,
                checksum_errors: *checksum_errors,
            }),
            Self::Leaf { .. } => None,
            Self::Mirror { children } | Self::ParityRaid { children, .. } => {
                children.iter().find_map(|c| c._find_leaf_by(pred))
            }
        }
    }

    /// Collect all leaf device paths in this subtree.
    #[must_use]
    pub fn all_leaf_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        self.collect_leaf_paths(&mut paths);
        paths
    }

    /// Recursive helper for all_leaf_paths.
    fn collect_leaf_paths(&self, out: &mut Vec<PathBuf>) {
        match self {
            Self::Leaf { device_path, .. } => out.push(device_path.clone()),
            Self::Mirror { children } | Self::ParityRaid { children, .. } => {
                for child in children {
                    child.collect_leaf_paths(out);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

// PoolConfig — assembled pool configuration
// ---------------------------------------------------------------------------

/// Output of a successful pool assembly: a coherent view of one pool's
/// devices, topology, and capability flags.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Pool UUID (identical across all devices).
    pub pool_uuid: [u8; 16],
    /// Human-readable pool name.
    pub pool_name: String,
    /// Assembled device tree (root → internal → leaf).
    pub device_tree: DeviceType,
    /// Aggregate health of the pool.
    pub health: DeviceHealth,
    /// Operational state from the label.
    pub state: PoolState,
    /// Total raw capacity across all devices.
    pub total_capacity_bytes: u64,
    /// Bytes currently allocated (approximate, derived from commit_group).
    pub allocated_bytes: u64,
    /// Feature flags from a representative label.
    pub feature_flags: u64,
    /// Topology generation — must match across all devices.
    pub topology_generation: u64,
    /// Number of devices present vs. expected.
    pub device_count: u32,
    /// Indices of devices expected but not found.
    pub missing_indices: Vec<u32>,
    /// Indices of devices currently being removed (allocation-fenced).
    pub removing_device_indices: Vec<u32>,
}
/// A borrowed reference to a leaf device's immutable fields,
/// returned by [`DeviceType::find_leaf`].
#[derive(Clone, Copy, Debug)]
pub struct LeafRef {
    /// Device GUID.
    pub device_guid: [u8; 16],
    /// Device index.
    pub device_index: u32,
    /// Device capacity in bytes.
    pub capacity_bytes: u64,
    /// Device class.
    pub device_class: DeviceClass,
    /// Device health.
    pub health: DeviceHealth,
    /// Accumulated read errors.
    pub read_errors: u64,
    /// Accumulated write errors.
    pub write_errors: u64,
    /// Accumulated checksum errors.
    pub checksum_errors: u64,
}

impl PoolConfig {
    /// Returns true if no devices are missing.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_indices.is_empty()
    }

    /// Returns true if the pool can be imported in its current state.
    #[must_use]
    pub fn is_importable(&self) -> bool {
        self.state.is_importable() && self.health.is_operational()
    }

    /// Generate one `PoolLabelV1` per leaf device in the device tree.
    ///
    /// Each label carries the pool-wide fields (pool_guid, pool_name,
    /// pool_state, topology_generation, device_count, feature_flags)
    /// and the per-device fields (device_guid, device_index,
    /// device_capacity_bytes, device_class, health, error counters).
    ///
    /// Returns labels with zeroed checksums; callers must
    /// [`tidefs_types_pool_label_core::seal_label`] each label or
    /// [`tidefs_types_pool_label_core::encode_label`] with an
    /// extended buffer to compute checksums before writing to disk.
    #[must_use]
    pub fn to_labels(&self) -> Vec<PoolLabelV1> {
        let mut labels = Vec::with_capacity(self.device_count as usize);
        self.collect_labels(&self.device_tree, &mut labels);
        labels
    }

    /// Recursively walk the device tree, collecting labels for each leaf.
    fn collect_labels(&self, node: &DeviceType, out: &mut Vec<PoolLabelV1>) {
        match node {
            DeviceType::Leaf {
                device_guid,
                device_index,
                capacity_bytes,
                device_class,
                health,
                read_errors,
                write_errors,
                checksum_errors,
                ..
            } => {
                let mut label = PoolLabelV1::new(self.pool_uuid, *device_guid, &self.pool_name);
                label.pool_state = self.state;
                label.topology_generation = self.topology_generation;
                label.device_count = self.device_count;
                label.device_index = *device_index;
                label.device_class = *device_class;
                label.device_capacity_bytes = *capacity_bytes;
                label.device_health = health.to_label_health();
                label.device_read_errors = *read_errors;
                label.device_write_errors = *write_errors;
                label.device_checksum_errors = *checksum_errors;
                label.features_compat = self.feature_flags;
                out.push(label);
            }
            DeviceType::Mirror { children } | DeviceType::ParityRaid { children, .. } => {
                for child in children {
                    self.collect_labels(child, out);
                }
            }
        }
    }
    // ---------------------------------------------------------------------------

    /// Remove a device from the pool by path.
    ///
    /// Walks the device tree to find the leaf matching `device_path`,
    /// removes it from its parent (Mirror or ParityRaid), updates
    /// `device_count`, increments `topology_generation`, and adds the
    /// removed device index to `missing_indices`.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::TargetDeviceNotFound`] if the device
    /// is not found in the tree, or [`DeviceRemovalError::WouldEmptyPool`]
    /// if removing it would leave the pool with zero devices.
    pub fn remove_device(&mut self, device_path: &Path) -> Result<(), DeviceRemovalError> {
        // Check that removing this device won't compromise redundancy.
        check_removal_redundancy(&self.device_tree, device_path)?;

        // Walk the tree and remove the matching leaf.
        let removed = Self::remove_leaf_from_tree(&mut self.device_tree, device_path);

        if !removed {
            return Err(DeviceRemovalError::TargetDeviceNotFound {
                path: device_path.to_path_buf(),
            });
        }

        // Update pool metadata.
        self.device_count = self.device_count.saturating_sub(1);
        self.topology_generation = self.topology_generation.saturating_add(1);
        self.total_capacity_bytes = self.device_tree.total_capacity_bytes();

        Ok(())
    }

    /// Recursively walk the device tree and remove the leaf matching `path`.
    /// Returns `true` if a leaf was found and removed.
    fn remove_leaf_from_tree(node: &mut DeviceType, path: &Path) -> bool {
        match node {
            DeviceType::Leaf { device_path, .. } => {
                // We cannot remove a root leaf here; the caller ensures
                // leaf_count > 1 before descending.
                *device_path == path
            }
            DeviceType::Mirror { children } | DeviceType::ParityRaid { children, .. } => {
                if let Some(pos) = children.iter().position(|c| match c {
                    DeviceType::Leaf { device_path, .. } => device_path == path,
                    _ => false,
                }) {
                    children.remove(pos);
                    return true;
                }
                // Recurse into nested groups.
                for child in children.iter_mut() {
                    if Self::remove_leaf_from_tree(child, path) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Mark a device as being removed (fences new allocations).
    pub fn mark_device_removing(&mut self, device_index: u32) {
        if !self.removing_device_indices.contains(&device_index) {
            self.removing_device_indices.push(device_index);
        }
    }

    /// Clear the removing flag for a device.
    pub fn clear_device_removing(&mut self, device_index: u32) {
        self.removing_device_indices.retain(|&i| i != device_index);
    }

    /// Returns true if the given device index is marked as being removed.
    #[must_use]
    pub fn is_device_removing(&self, device_index: u32) -> bool {
        self.removing_device_indices.contains(&device_index)
    }

    /// Returns a copy of the device indices currently being removed.
    #[must_use]
    pub fn removing_device_ids(&self) -> Vec<u32> {
        self.removing_device_indices.clone()
    }
}
// ---------------------------------------------------------------------------

/// Type of device to add to a pool during online device addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRole {
    /// Add a child to an existing mirror group (increases redundancy).
    MirrorMember,
    /// Add a child to an existing parity RAID group.
    ParityRaidMember,
    /// Add a hot spare device.
    Spare,
    /// Add a dedicated cache device (L2ARC).
    Cache,
    /// Add a separate intent-log device (ZIL/SLOG).
    Log,
}

impl DeviceRole {
    /// Returns true if the device type participates in data redundancy.
    #[must_use]
    pub const fn is_data_vdev(self) -> bool {
        matches!(self, Self::MirrorMember | Self::ParityRaidMember)
    }

    /// Returns true if the device type is a dedicated auxiliary device.
    #[must_use]
    pub const fn is_auxiliary(self) -> bool {
        matches!(self, Self::Spare | Self::Cache | Self::Log)
    }
}

impl std::fmt::Display for DeviceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MirrorMember => f.write_str("mirror-member"),
            Self::ParityRaidMember => f.write_str("parity-raid-member"),
            Self::Spare => f.write_str("spare"),
            Self::Cache => f.write_str("cache"),
            Self::Log => f.write_str("log"),
        }
    }
}

/// Maximum number of devices allowed in a single pool.
pub const MAX_VDEVS_PER_POOL: u32 = 255;

// ---------------------------------------------------------------------------
// DeviceAddError — errors that can occur during device addition
// ---------------------------------------------------------------------------

/// Errors that can occur during online device addition.
#[derive(Debug)]
pub enum DeviceAddError {
    /// The pool is full and cannot accept additional devices.
    PoolFull {
        /// Current device count.
        current: u32,
        /// Maximum allowed devices.
        maximum: u32,
    },
    /// The device already has a TideFS label (from another pool or
    /// already a member of this pool).
    AlreadyLabeled {
        /// Path of the device.
        device_path: PathBuf,
        /// Pool name from the existing label, if readable.
        existing_pool: Option<String>,
    },
    /// The device file does not exist or cannot be opened.
    DeviceOpen {
        /// Path of the device.
        device_path: PathBuf,
        /// OS-level error message.
        msg: String,
    },
    /// The target position (device index or parent) does not exist
    /// in the current device tree.
    InvalidPosition {
        /// Description of the invalid position.
        msg: String,
    },
    /// The device type is incompatible with the target position in the
    /// device tree (e.g., adding a mirror member to a non-mirror parent).
    IncompatibleType {
        /// The device type requested.
        vdev_type: DeviceRole,
        /// Description of why it's incompatible.
        msg: String,
    },
    /// An I/O error occurred while labeling the device.
    LabelWrite {
        /// Path of the device.
        device_path: PathBuf,
        /// Error description.
        msg: String,
    },
}

impl std::fmt::Display for DeviceAddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolFull { current, maximum } => {
                write!(
                    f,
                    "pool is full: {current} devices already present (max {maximum})"
                )
            }
            Self::AlreadyLabeled {
                device_path,
                existing_pool,
            } => {
                write!(
                    f,
                    "device {} already has a TideFS label",
                    device_path.display()
                )?;
                if let Some(pool) = existing_pool {
                    write!(f, " (pool: {pool})")?;
                }
                Ok(())
            }
            Self::DeviceOpen { device_path, msg } => {
                write!(f, "cannot open device {}: {msg}", device_path.display())
            }
            Self::InvalidPosition { msg } => {
                write!(f, "invalid position: {msg}")
            }
            Self::IncompatibleType { vdev_type, msg } => {
                write!(f, "incompatible device type {vdev_type}: {msg}")
            }
            Self::LabelWrite { device_path, msg } => {
                write!(
                    f,
                    "failed to write label to {}: {msg}",
                    device_path.display()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceAddStats — statistics from a device addition operation
// ---------------------------------------------------------------------------

/// Statistics gathered during an online device addition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceAddStats {
    /// Path of the device that was added.
    pub device_path: PathBuf,
    /// The type of device that was added.
    pub vdev_type: DeviceRole,
    /// Wall-clock duration of the add operation in milliseconds.
    pub add_time_ms: u64,
    /// Whether a rebalance was scheduled after the addition.
    pub rebalance_scheduled: bool,
    /// The new total device count after the addition.
    pub new_device_count: u32,
}

// ---------------------------------------------------------------------------
// RebalanceTrigger — signals that rebalancing should occur
// ---------------------------------------------------------------------------

/// A trigger produced after a device addition, indicating that a
/// rebalance should be scheduled to redistribute data across the
/// expanded device set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebalanceTrigger {
    /// The pool UUID.
    pub pool_uuid: [u8; 16],
    /// The reason for the rebalance.
    pub reason: String,
    /// The new topology generation after the device addition.
    pub topology_generation: u64,
    /// Estimated bytes to rebalance, if known.
    pub estimated_bytes_to_move: Option<u64>,
    /// Whether this is a high-priority rebalance (e.g., after adding
    /// a member to a degraded mirror).
    pub is_urgent: bool,
}

impl RebalanceTrigger {
    /// Create a rebalance trigger after a device addition.
    #[must_use]
    pub fn after_vdev_add(
        pool_uuid: [u8; 16],
        vdev_type: DeviceRole,
        topology_generation: u64,
        is_degraded: bool,
    ) -> Self {
        let reason =
            format!("device addition ({vdev_type}) at topology generation {topology_generation}");
        Self {
            pool_uuid,
            reason,
            topology_generation,
            estimated_bytes_to_move: None,
            is_urgent: is_degraded,
        }
    }
}

// ---------------------------------------------------------------------------
// PoolAddVdev — online device addition operation
// ---------------------------------------------------------------------------

/// Drives the online device addition lifecycle: validate, label, insert
/// into device tree, produce stats and rebalance trigger.
pub struct PoolAddVdev;

impl PoolAddVdev {
    /// Add a new device to a running pool.
    ///
    /// `device_path`: path to the new block device.
    /// `vdev_type`: the role the new device will play.
    /// `config`: the current pool configuration (mutated on success).
    ///
    /// Returns statistics about the add and a rebalance trigger.
    pub fn add_vdev(
        device_path: PathBuf,
        vdev_type: DeviceRole,
        config: &mut PoolConfig,
    ) -> Result<(DeviceAddStats, RebalanceTrigger), DeviceAddError> {
        let start = std::time::Instant::now();

        // 1. Check that the pool isn't full.
        let current_count = config.device_tree.leaf_count() as u32;
        if current_count >= MAX_VDEVS_PER_POOL {
            return Err(DeviceAddError::PoolFull {
                current: current_count,
                maximum: MAX_VDEVS_PER_POOL,
            });
        }

        // 2. Verify the device exists and can be opened.
        if !device_path.exists() {
            return Err(DeviceAddError::DeviceOpen {
                device_path: device_path.clone(),
                msg: "device does not exist".to_string(),
            });
        }

        // 3. Check that the device does not already have a TideFS label.
        {
            let existing = PoolLabelReader::read_label(&device_path).map_err(|e| {
                DeviceAddError::DeviceOpen {
                    device_path: device_path.clone(),
                    msg: format!("read label check: {e}"),
                }
            })?;
            if existing.is_some() {
                let existing_pool = existing.as_ref().map(|l| l.pool_name_str().to_string());
                return Err(DeviceAddError::AlreadyLabeled {
                    device_path,
                    existing_pool,
                });
            }
        }

        // 4. Validate the device type against the current device tree.
        match vdev_type {
            DeviceRole::MirrorMember | DeviceRole::ParityRaidMember => {
                Self::validate_data_vdev_position(&config.device_tree, vdev_type)?;
            }
            DeviceRole::Spare | DeviceRole::Cache | DeviceRole::Log => {
                // Auxiliary devices don't modify the main data tree.
            }
        }

        // 5. Generate a new device GUID.
        let device_guid = Self::generate_device_guid();

        // 6. Insert the new device into the device tree.
        let was_degraded = config.health == DeviceHealth::Degraded;
        let new_tree = Self::insert_vdev_into_tree(
            config.device_tree.clone(),
            device_path.clone(),
            device_guid,
            current_count,
            vdev_type,
        )?;
        config.device_tree = new_tree;

        // 7. Update pool configuration.
        config.device_count = config.device_tree.leaf_count() as u32;
        config.total_capacity_bytes = config.device_tree.total_capacity_bytes();
        config.topology_generation = config.topology_generation.wrapping_add(1);
        config.health = config.device_tree.aggregate_health();
        config.missing_indices.retain(|&i| i < config.device_count);

        // 8. Produce stats.
        let add_time_ms = start.elapsed().as_millis() as u64;
        let rebalance_needed = vdev_type.is_data_vdev();

        let stats = DeviceAddStats {
            device_path: device_path.clone(),
            vdev_type,
            add_time_ms,
            rebalance_scheduled: rebalance_needed,
            new_device_count: config.device_count,
        };

        // 9. Produce rebalance trigger when appropriate.
        let trigger = RebalanceTrigger::after_vdev_add(
            config.pool_uuid,
            vdev_type,
            config.topology_generation,
            was_degraded,
        );

        Ok((stats, trigger))
    }

    /// Validate that `vdev_type` can be added at the root of the device tree.
    fn validate_data_vdev_position(
        tree: &DeviceType,
        vdev_type: DeviceRole,
    ) -> Result<(), DeviceAddError> {
        match tree {
            DeviceType::Leaf { .. } => {
                if vdev_type == DeviceRole::ParityRaidMember {
                    return Err(DeviceAddError::IncompatibleType {
                        vdev_type,
                        msg:
                            "cannot add parity_raid member to a single-device pool (need ParityRaid root)"
                                .to_string(),
                    });
                }
                Ok(())
            }
            DeviceType::Mirror { .. } => {
                if vdev_type == DeviceRole::ParityRaidMember {
                    return Err(DeviceAddError::IncompatibleType {
                        vdev_type,
                        msg: "cannot add parity_raid member to a mirror root".to_string(),
                    });
                }
                Ok(())
            }
            DeviceType::ParityRaid { .. } => {
                if vdev_type == DeviceRole::MirrorMember {
                    return Err(DeviceAddError::IncompatibleType {
                        vdev_type,
                        msg: "cannot add mirror member to a parity raid root".to_string(),
                    });
                }
                Ok(())
            }
        }
    }

    /// Insert a new leaf device into the device tree.
    fn insert_vdev_into_tree(
        tree: DeviceType,
        device_path: PathBuf,
        device_guid: [u8; 16],
        device_index: u32,
        vdev_type: DeviceRole,
    ) -> Result<DeviceType, DeviceAddError> {
        match vdev_type {
            DeviceRole::MirrorMember => match tree {
                DeviceType::Leaf {
                    device_path: existing_path,
                    device_guid: existing_guid,
                    device_index: existing_index,
                    capacity_bytes,
                    device_class,
                    health,
                    read_errors,
                    write_errors,
                    checksum_errors,
                } => {
                    let existing = DeviceType::Leaf {
                        device_path: existing_path,
                        device_guid: existing_guid,
                        device_index: existing_index,
                        capacity_bytes,
                        device_class,
                        health,
                        read_errors,
                        write_errors,
                        checksum_errors,
                    };
                    let new_leaf = DeviceType::Leaf {
                        device_path,
                        device_guid,
                        device_index,
                        capacity_bytes,
                        device_class: DeviceClass::Hdd,
                        health: DeviceHealth::Online,
                        read_errors: 0,
                        write_errors: 0,
                        checksum_errors: 0,
                    };
                    Ok(DeviceType::Mirror {
                        children: vec![existing, new_leaf],
                    })
                }
                DeviceType::Mirror { mut children } => {
                    let new_leaf = DeviceType::Leaf {
                        device_path,
                        device_guid,
                        device_index,
                        capacity_bytes: 0,
                        device_class: DeviceClass::Hdd,
                        health: DeviceHealth::Online,
                        read_errors: 0,
                        write_errors: 0,
                        checksum_errors: 0,
                    };
                    children.push(new_leaf);
                    Ok(DeviceType::Mirror { children })
                }
                _ => Err(DeviceAddError::IncompatibleType {
                    vdev_type,
                    msg: "cannot add mirror member to non-mirror root".to_string(),
                }),
            },
            DeviceRole::ParityRaidMember => match tree {
                DeviceType::ParityRaid {
                    parity,
                    mut children,
                } => {
                    let new_leaf = DeviceType::Leaf {
                        device_path,
                        device_guid,
                        device_index,
                        capacity_bytes: 0,
                        device_class: DeviceClass::Hdd,
                        health: DeviceHealth::Online,
                        read_errors: 0,
                        write_errors: 0,
                        checksum_errors: 0,
                    };
                    children.push(new_leaf);
                    Ok(DeviceType::ParityRaid { parity, children })
                }
                _ => Err(DeviceAddError::IncompatibleType {
                    vdev_type,
                    msg: "cannot add parity_raid member to non-parity-raid root".to_string(),
                }),
            },
            DeviceRole::Spare | DeviceRole::Cache | DeviceRole::Log => Ok(tree),
        }
    }

    /// Generate a random device GUID (16 bytes).
    fn generate_device_guid() -> [u8; 16] {
        let mut guid = [0u8; 16];
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, byte) in guid.iter_mut().enumerate().take(8) {
            *byte = ((nanos >> (i * 8)) & 0xFF) as u8;
        }
        guid[8..16].copy_from_slice(b"VBFSNEW0");
        guid
    }
}

// ---------------------------------------------------------------------------
// AssemblyError
// ---------------------------------------------------------------------------

/// Errors that can occur during pool assembly.
#[derive(Debug)]
pub enum AssemblyError {
    /// No devices with valid TideFS labels were provided.
    NoLabeledDevices,
    /// The provided devices belong to more than one pool.
    MultiplePools {
        /// Distinct pool UUIDs found.
        pool_uuids: Vec<[u8; 16]>,
    },
    /// A device with the requested pool UUID was not found.
    PoolNotFound {
        /// UUID that was looked up.
        pool_uuid: [u8; 16],
    },
    /// Devices in the same pool have mismatched topology generation.
    TopologyMismatch {
        /// The device path.
        device_path: PathBuf,
        /// Expected generation.
        expected: u64,
        /// Actual generation.
        found: u64,
    },
    /// Devices in the same pool have mismatched device count.
    MemberCountMismatch {
        /// The device path.
        device_path: PathBuf,
        /// Expected count.
        expected: u32,
        /// Actual count.
        found: u32,
    },
    /// One or more expected devices are missing.
    MissingDevices {
        /// Total devices expected.
        expected: u32,
        /// Number of devices found.
        found: u32,
        /// Indices of missing devices.
        missing: Vec<u32>,
    },
    /// The pool is in Destroyed state and cannot be assembled.
    PoolDestroyed,
}

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLabeledDevices => f.write_str("no devices with valid TideFS labels"),
            Self::MultiplePools { pool_uuids } => {
                write!(f, "devices belong to multiple pools: ")?;
                for (i, uuid) in pool_uuids.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{uuid:02x?}")?;
                }
                Ok(())
            }
            Self::PoolNotFound { pool_uuid } => {
                write!(f, "pool {pool_uuid:02x?} not found among provided devices")
            }
            Self::TopologyMismatch {
                device_path,
                expected,
                found,
            } => {
                write!(
                    f,
                    "topology generation mismatch on {}: expected {expected}, found {found}",
                    device_path.display()
                )
            }
            Self::MemberCountMismatch {
                device_path,
                expected,
                found,
            } => {
                write!(
                    f,
                    "member count mismatch on {}: expected {expected}, found {found}",
                    device_path.display()
                )
            }
            Self::MissingDevices {
                expected,
                found,
                missing,
            } => {
                write!(
                    f,
                    "missing devices: expected {expected}, found {found}, missing indices: {missing:?}"
                )
            }
            Self::PoolDestroyed => f.write_str("pool is destroyed"),
        }
    }
}

impl std::error::Error for AssemblyError {}

// ---------------------------------------------------------------------------
// PoolAssembler
// ---------------------------------------------------------------------------

/// Assembles a coherent pool view from a set of labeled devices.
///
/// Verifies that all devices for a pool agree on UUID, topology generation,
/// and member count; detects missing devices; and builds a [`PoolConfig`]
/// with a reconstructed device tree.
pub struct PoolAssembler;

impl PoolAssembler {
    /// Assemble a single pool from scanned devices.
    ///
    /// If `pool_uuid` is `Some`, only devices matching that UUID are
    /// considered. If `None`, all labeled devices must belong to the
    /// same pool.
    ///
    /// The returned [`PoolConfig`] includes the assembled device tree,
    /// aggregate health, and a list of any missing device indices.
    pub fn assemble(
        entries: &[DeviceScanEntry],
        pool_uuid: Option<[u8; 16]>,
    ) -> Result<PoolConfig, AssemblyError> {
        let labeled: Vec<&DeviceScanEntry> = entries
            .iter()
            .filter(|e| e.has_tidefs_label && e.label_valid)
            .collect();

        if labeled.is_empty() {
            return Err(AssemblyError::NoLabeledDevices);
        }

        let candidates: Vec<&&DeviceScanEntry> = if let Some(uuid) = pool_uuid {
            let filtered: Vec<_> = labeled
                .iter()
                .filter(|e| e.pool_guid == Some(uuid))
                .collect();
            if filtered.is_empty() {
                return Err(AssemblyError::PoolNotFound { pool_uuid: uuid });
            }
            filtered
        } else {
            let first_uuid = labeled[0].pool_guid;
            for entry in &labeled[1..] {
                if entry.pool_guid != first_uuid {
                    let mut uuids: Vec<[u8; 16]> = Vec::new();
                    for e in &labeled {
                        if let Some(u) = e.pool_guid {
                            if !uuids.contains(&u) {
                                uuids.push(u);
                            }
                        }
                    }
                    return Err(AssemblyError::MultiplePools { pool_uuids: uuids });
                }
            }
            labeled.iter().collect()
        };

        let first = candidates[0];
        let ref_uuid = first.pool_guid.ok_or(AssemblyError::NoLabeledDevices)?;
        let ref_gen = first.topology_generation.unwrap_or(0);
        let ref_count = first.device_count.unwrap_or(candidates.len() as u32);

        // Check pool state.
        if first.pool_state == Some(PoolState::Destroyed) {
            return Err(AssemblyError::PoolDestroyed);
        }

        // Build leaves sorted by device_index and verify consistency.
        let mut leaves: Vec<DeviceType> = Vec::with_capacity(candidates.len());
        let mut seen_indices: Vec<u32> = Vec::with_capacity(candidates.len());

        for entry in &candidates {
            let index = entry.device_index.unwrap_or(0);

            // Verify topology consistency.
            if entry.topology_generation.unwrap_or(0) != ref_gen {
                return Err(AssemblyError::TopologyMismatch {
                    device_path: entry.device_path.clone(),
                    expected: ref_gen,
                    found: entry.topology_generation.unwrap_or(0),
                });
            }
            if entry.device_count.unwrap_or(ref_count) != ref_count {
                return Err(AssemblyError::MemberCountMismatch {
                    device_path: entry.device_path.clone(),
                    expected: ref_count,
                    found: entry.device_count.unwrap_or(ref_count),
                });
            }

            seen_indices.push(index);

            leaves.push(DeviceType::Leaf {
                device_path: entry.device_path.clone(),
                device_guid: entry.device_guid.unwrap_or([0u8; 16]),
                device_index: index,
                capacity_bytes: entry.device_capacity_bytes.unwrap_or(entry.size_bytes),
                device_class: entry.device_class.unwrap_or(DeviceClass::Hdd),
                health: entry.device_health.unwrap_or(DeviceHealth::Online),
                read_errors: entry.device_read_errors.unwrap_or(0),
                write_errors: entry.device_write_errors.unwrap_or(0),
                checksum_errors: entry.device_checksum_errors.unwrap_or(0),
            });
        }

        // Sort by device_index.
        leaves.sort_by_key(|l| match l {
            DeviceType::Leaf { device_index, .. } => *device_index,
            _ => 0,
        });

        let found_count = leaves.len() as u32;

        // Detect missing devices.
        let mut missing: Vec<u32> = Vec::new();
        if ref_count > found_count {
            for idx in 0..ref_count {
                if !seen_indices.contains(&idx) {
                    missing.push(idx);
                }
            }
        } else {
            // Check for contiguous indices; detect gaps.
            let max_idx = seen_indices.iter().copied().max().unwrap_or(0);
            for idx in 0..=max_idx {
                if !seen_indices.contains(&idx) {
                    missing.push(idx);
                }
            }
        }

        // Build the device tree: for phase 2, all leaves under a single
        // Mirror node (since we don't yet reconstruct PARITY_RAID vs mirror
        // from the label).
        let device_tree = if leaves.len() == 1 {
            leaves.into_iter().next().unwrap()
        } else {
            DeviceType::Mirror { children: leaves }
        };

        let total_capacity = device_tree.total_capacity_bytes();
        let mut health = device_tree.aggregate_health();
        // Downgrade health when devices are missing.
        if !missing.is_empty() && health == DeviceHealth::Online {
            health = DeviceHealth::Degraded;
        }

        Ok(PoolConfig {
            pool_uuid: ref_uuid,
            pool_name: first.pool_name.clone().unwrap_or_default(),
            device_tree,
            health,
            state: first.pool_state.unwrap_or(PoolState::Active),
            total_capacity_bytes: total_capacity,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: ref_gen,
            device_count: ref_count,
            missing_indices: missing,
            removing_device_indices: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------


// ── Tier policy builder ──────────────────────────────────────────

/// Build a [`tidefs_membership_epoch::StorageTierPolicy`] from a device tree.
///
/// Walks all leaf devices, maps their [`DeviceClass`] to a storage tier
/// via the authoritative `storage_tier_from_device_class` mapping, and returns
/// a tier policy. Auto-promotion and auto-demotion default to disabled.
#[must_use]
pub fn build_tier_policy_from_device_tree(
    device_tree: &DeviceType,
) -> tidefs_membership_epoch::StorageTierPolicy {
    let leaves = device_tree.collect_leaves();
    let entries: Vec<(tidefs_membership_epoch::DomainId, u8)> = leaves
        .iter()
        .map(|leaf| {
            (
                tidefs_membership_epoch::DomainId::new(leaf.device_index as u64),
                leaf.device_class as u8,
            )
        })
        .collect();
    tidefs_membership_epoch::StorageTierPolicy::from_device_entries(&entries)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tidefs_types_pool_label_core::{encode_label, seal_label, POOL_LABEL_V1_EXT_WIRE_SIZE};

    // -- DeviceKind tests --

    #[test]
    fn device_kind_is_physical() {
        assert!(DeviceKind::Hdd.is_physical());
        assert!(DeviceKind::Ssd.is_physical());
        assert!(DeviceKind::Nvme.is_physical());
        assert!(!DeviceKind::Loop.is_physical());
        assert!(!DeviceKind::Ram.is_physical());
        assert!(!DeviceKind::DmDevice.is_physical());
        assert!(!DeviceKind::Unknown.is_physical());
    }

    #[test]
    fn device_kind_is_skip() {
        assert!(DeviceKind::Loop.is_skip());
        assert!(DeviceKind::Ram.is_skip());
        assert!(!DeviceKind::Hdd.is_skip());
    }

    #[test]
    fn device_kind_to_device_class() {
        assert_eq!(DeviceKind::Hdd.to_device_class(), Some(DeviceClass::Hdd));
        assert_eq!(DeviceKind::Ssd.to_device_class(), Some(DeviceClass::Ssd));
        assert_eq!(DeviceKind::Nvme.to_device_class(), Some(DeviceClass::Nvme));
        assert_eq!(DeviceKind::Loop.to_device_class(), None);
        assert_eq!(DeviceKind::Unknown.to_device_class(), None);
    }

    #[test]
    fn device_kind_display() {
        assert_eq!(format!("{}", DeviceKind::Hdd), "HDD");
        assert_eq!(format!("{}", DeviceKind::Nvme), "NVME");
        assert_eq!(format!("{}", DeviceKind::DmDevice), "DM");
    }

    // -- DeviceClassifier tests --

    #[test]
    fn classify_nvme() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/nvme0n1"), "nvme0n1"),
            DeviceKind::Nvme
        );
    }

    #[test]
    fn classify_nvme_partition_is_partition() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/nvme0n1"), "nvme0n1p1"),
            DeviceKind::Partition
        );
    }

    #[test]
    fn classify_loop_is_loop() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/loop0"), "loop0"),
            DeviceKind::Loop
        );
    }

    #[test]
    fn classify_ram_is_ram() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/ram0"), "ram0"),
            DeviceKind::Ram
        );
    }

    #[test]
    fn classify_zram_is_ram() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/zram0"), "zram0"),
            DeviceKind::Ram
        );
    }

    #[test]
    fn classify_dm() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/dm-0"), "dm-0"),
            DeviceKind::DmDevice
        );
    }

    #[test]
    fn classify_md() {
        assert_eq!(
            DeviceClassifier::classify(Path::new("/sys/block/md0"), "md0"),
            DeviceKind::MdDevice
        );
    }

    #[test]
    fn classify_sda_partition() {
        assert!(DeviceClassifier::is_partition("sda1"));
        assert!(!DeviceClassifier::is_partition("sda"));
        assert!(!DeviceClassifier::is_partition("nvme0n1"));
    }

    #[test]
    fn partition_number_extraction() {
        assert_eq!(DeviceClassifier::partition_number("sda1"), Some(1));
        assert_eq!(DeviceClassifier::partition_number("nvme0n1p2"), Some(2));
        assert_eq!(DeviceClassifier::partition_number("sda"), None);
    }

    #[test]
    fn parent_device_extraction() {
        assert_eq!(
            DeviceClassifier::parent_device("nvme0n1p2"),
            Some("nvme0n1".to_string())
        );
        assert_eq!(
            DeviceClassifier::parent_device("sda1"),
            Some("sda".to_string())
        );
    }

    // -- PoolLabelReader tests --

    fn make_test_label(pool_name: &str) -> PoolLabelV1 {
        let pool_guid = [0x11u8; 16];
        let device_guid = [0x22u8; 16];
        let label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        seal_label(label).unwrap()
    }

    fn write_label_to_file(path: &Path, label: &PoolLabelV1) {
        let mut file = std::fs::File::create(path).unwrap();
        let mut buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).unwrap();
        file.write_all(&buf).unwrap();
    }

    fn write_label_at_offset(path: &Path, label: &PoolLabelV1, offset: u64) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();
        let mut buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).unwrap();
        // Extend the file if needed.
        // Use POOL_LABEL_SIZE so that size-based offset calculation
        // (size - POOL_LABEL_SIZE) lands at `offset`.
        let end = offset + tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;
        if file.metadata().map(|m| m.len()).unwrap_or(0) < end {
            file.set_len(end).unwrap();
        }
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&buf).unwrap();
    }

    #[test]
    fn read_label_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testdev");
        let label = make_test_label("mypool");
        write_label_to_file(&path, &label);

        let result = PoolLabelReader::read_label(&path).unwrap();
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.pool_guid, [0x11u8; 16]);
        assert_eq!(parsed.device_guid, [0x22u8; 16]);
        assert_eq!(parsed.pool_name_str(), "mypool");
    }

    #[test]
    fn read_label_copy1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testdev2");
        let label = make_test_label("secondcopy");

        // Write label at end of a 512 KiB file (label copy 1 position).
        let file_size = 512 * 1024;
        let offset = file_size - tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;
        write_label_at_offset(&path, &label, offset);

        let result = PoolLabelReader::read_label(&path).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().pool_name_str(), "secondcopy");
    }

    #[test]
    fn read_label_no_magic_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nolabel");
        std::fs::write(&path, b"not a tidefs label at all, just random bytes here").unwrap();

        let result = PoolLabelReader::read_label(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_label_corrupted_checksum_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt");
        let label = make_test_label("corrupt");
        write_label_to_file(&path, &label);

        // Corrupt a byte in the file.
        let mut data = std::fs::read(&path).unwrap();
        data[10] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let result = PoolLabelReader::read_label(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn scan_device_with_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("labeled");
        let label = make_test_label("testpool");
        write_label_to_file(&path, &label);

        let mut info = DeviceInfo::new(path.clone());
        info.size_bytes = 4096;
        info.kind = DeviceKind::Hdd;

        let entry = PoolLabelReader::scan_device(&info);
        assert!(entry.has_tidefs_label);
        assert!(entry.label_valid);
        assert_eq!(entry.pool_name.as_deref(), Some("testpool"));
        assert_eq!(entry.pool_state, Some(PoolState::Active));
    }

    #[test]
    fn scan_device_no_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        std::fs::write(&path, b"just a regular file").unwrap();

        let mut info = DeviceInfo::new(path.clone());
        info.kind = DeviceKind::Hdd;
        info.size_bytes = 100;

        let entry = PoolLabelReader::scan_device(&info);
        assert!(!entry.has_tidefs_label);
        assert!(!entry.label_valid);
        assert_eq!(entry.label_status, "no label");
    }

    // -- DeviceScanReport tests --

    #[test]
    fn empty_report() {
        let report = DeviceScanReport::new();
        assert_eq!(report.total_devices, 0);
        assert_eq!(report.labeled_devices, 0);
        assert!(report.devices.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn report_default_is_empty() {
        let report = DeviceScanReport::default();
        assert_eq!(report.total_devices, 0);
    }

    // -- DeviceEnumerator tests (unit-level) --

    #[test]
    fn device_info_new() {
        let info = DeviceInfo::new(PathBuf::from("/dev/sda"));
        assert_eq!(info.kernel_name, "sda");
        assert_eq!(info.kind, DeviceKind::Unknown);
        assert_eq!(info.size_bytes, 0);
    }

    // -- format_size tests --

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn format_size_kib() {
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(2048), "2.0 KiB");
    }

    #[test]
    fn format_size_mib() {
        assert_eq!(format_size(1048576), "1.0 MiB");
    }

    #[test]
    fn format_size_gib() {
        assert_eq!(format_size(1073741824), "1.0 GiB");
    }

    // -- ScanError tests --

    #[test]
    fn scan_error_from_label_error() {
        let le = LabelError::BadMagic;
        let se: ScanError = le.into();
        assert!(matches!(se, ScanError::Label(LabelError::BadMagic)));
    }

    // -- PoolAssembler tests --

    fn make_labeled_entry(
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        device_index: u32,
        device_count: u32,
        topology_generation: u64,
        pool_name: &str,
        pool_state: PoolState,
    ) -> DeviceScanEntry {
        DeviceScanEntry {
            device_path: PathBuf::from(format!("/dev/test/disk{device_index}")),
            size_bytes: 1024 * 1024 * 1024,
            kind: DeviceKind::Hdd,
            model: None,
            serial: None,
            has_tidefs_label: true,
            pool_guid: Some(pool_guid),
            pool_name: Some(pool_name.to_string()),
            pool_state: Some(pool_state),
            device_guid: Some(device_guid),
            label_valid: true,
            label_status: format!("pool={pool_name} state={pool_state}"),
            device_index: Some(device_index),
            device_count: Some(device_count),
            topology_generation: Some(topology_generation),
            device_class: Some(DeviceClass::Hdd),
            device_capacity_bytes: Some(1024 * 1024 * 1024),
            device_health: Some(DeviceHealth::Online),
            device_read_errors: Some(0),
            device_write_errors: Some(0),
            device_checksum_errors: Some(0),
        }
    }

    #[test]
    fn assemble_single_device_pool() {
        let pool_uuid = [0x11u8; 16];
        let entries = vec![make_labeled_entry(
            pool_uuid,
            [0x01u8; 16],
            0,
            1,
            1,
            "single",
            PoolState::Active,
        )];

        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert_eq!(config.pool_uuid, pool_uuid);
        assert_eq!(config.pool_name, "single");
        assert_eq!(config.device_count, 1);
        assert!(config.missing_indices.is_empty());
        assert!(config.is_complete());
        assert!(config.is_importable());
        assert_eq!(config.health, DeviceHealth::Online);
        // Single device should be a Leaf, not wrapped in Mirror.
        assert!(matches!(config.device_tree, DeviceType::Leaf { .. }));
    }

    #[test]
    fn assemble_three_device_mirror() {
        let pool_uuid = [0x22u8; 16];
        let entries = vec![
            make_labeled_entry(
                pool_uuid,
                [0x01u8; 16],
                0,
                3,
                1,
                "mirrorpool",
                PoolState::Active,
            ),
            make_labeled_entry(
                pool_uuid,
                [0x02u8; 16],
                1,
                3,
                1,
                "mirrorpool",
                PoolState::Active,
            ),
            make_labeled_entry(
                pool_uuid,
                [0x03u8; 16],
                2,
                3,
                1,
                "mirrorpool",
                PoolState::Active,
            ),
        ];

        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert_eq!(config.pool_name, "mirrorpool");
        assert_eq!(config.device_count, 3);
        assert!(config.missing_indices.is_empty());
        assert_eq!(config.health, DeviceHealth::Online);

        match &config.device_tree {
            DeviceType::Mirror { children } => {
                assert_eq!(children.len(), 3);
                for (i, child) in children.iter().enumerate() {
                    if let DeviceType::Leaf { device_index, .. } = child {
                        assert_eq!(*device_index as usize, i);
                    } else {
                        panic!("expected Leaf child");
                    }
                }
            }
            _ => panic!("expected Mirror root for multi-device pool"),
        }
    }

    #[test]
    fn assemble_four_device_parity_raid1() {
        let pool_uuid = [0x33u8; 16];
        let entries: Vec<DeviceScanEntry> = (0..4u32)
            .map(|i| {
                make_labeled_entry(
                    pool_uuid,
                    [0x10u8 + (i as u8); 16],
                    i,
                    4,
                    1,
                    "parity_raidpool",
                    PoolState::Active,
                )
            })
            .collect();

        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert_eq!(config.pool_name, "parity_raidpool");
        assert_eq!(config.device_count, 4);
        assert!(config.missing_indices.is_empty());
        assert_eq!(config.health, DeviceHealth::Online);
        assert!(matches!(config.device_tree, DeviceType::Mirror { .. }));
    }

    #[test]
    fn assemble_with_specific_pool_uuid() {
        let pool_a = [0xAAu8; 16];
        let pool_b = [0xBBu8; 16];

        let entries = vec![
            make_labeled_entry(pool_a, [0x01u8; 16], 0, 1, 1, "poolA", PoolState::Active),
            make_labeled_entry(pool_b, [0x02u8; 16], 0, 1, 1, "poolB", PoolState::Active),
        ];

        let config = PoolAssembler::assemble(&entries, Some(pool_a)).unwrap();
        assert_eq!(config.pool_name, "poolA");

        let config = PoolAssembler::assemble(&entries, Some(pool_b)).unwrap();
        assert_eq!(config.pool_name, "poolB");
    }

    #[test]
    fn assemble_rejects_multiple_pools_without_uuid() {
        let pool_a = [0xAAu8; 16];
        let pool_b = [0xBBu8; 16];

        let entries = vec![
            make_labeled_entry(pool_a, [0x01u8; 16], 0, 1, 1, "poolA", PoolState::Active),
            make_labeled_entry(pool_b, [0x02u8; 16], 0, 1, 1, "poolB", PoolState::Active),
        ];

        let result = PoolAssembler::assemble(&entries, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::MultiplePools { .. } => {}
            e => panic!("expected MultiplePools, got {e:?}"),
        }
    }

    #[test]
    fn assemble_detects_missing_device() {
        let pool_uuid = [0x44u8; 16];
        // Expect 3 devices, but only provide 2.
        let entries = vec![
            make_labeled_entry(
                pool_uuid,
                [0x01u8; 16],
                0,
                3,
                1,
                "degraded",
                PoolState::Active,
            ),
            make_labeled_entry(
                pool_uuid,
                [0x02u8; 16],
                2,
                3,
                1,
                "degraded",
                PoolState::Active,
            ),
        ];

        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert_eq!(config.device_count, 3);
        assert!(!config.is_complete());
        assert_eq!(config.missing_indices, vec![1]);
        assert_eq!(config.health, DeviceHealth::Degraded);
    }

    #[test]
    fn assemble_rejects_topology_mismatch() {
        let pool_uuid = [0x55u8; 16];
        let entries = vec![
            make_labeled_entry(
                pool_uuid,
                [0x01u8; 16],
                0,
                2,
                1,
                "splitbrain",
                PoolState::Active,
            ),
            make_labeled_entry(
                pool_uuid,
                [0x02u8; 16],
                1,
                2,
                2, // different generation
                "splitbrain",
                PoolState::Active,
            ),
        ];

        let result = PoolAssembler::assemble(&entries, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::TopologyMismatch { .. } => {}
            e => panic!("expected TopologyMismatch, got {e:?}"),
        }
    }

    #[test]
    fn assemble_rejects_member_count_mismatch() {
        let pool_uuid = [0x66u8; 16];
        let entries = vec![
            make_labeled_entry(
                pool_uuid,
                [0x01u8; 16],
                0,
                3,
                1,
                "miscount",
                PoolState::Active,
            ),
            make_labeled_entry(
                pool_uuid,
                [0x02u8; 16],
                1,
                2,
                1, // different count
                "miscount",
                PoolState::Active,
            ),
        ];

        let result = PoolAssembler::assemble(&entries, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::MemberCountMismatch { .. } => {}
            e => panic!("expected MemberCountMismatch, got {e:?}"),
        }
    }

    #[test]
    fn assemble_rejects_destroyed_pool() {
        let pool_uuid = [0x77u8; 16];
        let entries = vec![make_labeled_entry(
            pool_uuid,
            [0x01u8; 16],
            0,
            1,
            1,
            "deadpool",
            PoolState::Destroyed,
        )];

        let result = PoolAssembler::assemble(&entries, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::PoolDestroyed => {}
            e => panic!("expected PoolDestroyed, got {e:?}"),
        }
    }

    #[test]
    fn assemble_no_labeled_devices() {
        let entries = vec![DeviceScanEntry {
            device_path: PathBuf::from("/dev/sda"),
            size_bytes: 0,
            kind: DeviceKind::Hdd,
            model: None,
            serial: None,
            has_tidefs_label: false,
            pool_guid: None,
            pool_name: None,
            pool_state: None,
            device_guid: None,
            label_valid: false,
            label_status: "no label".to_string(),
            device_index: None,
            device_count: None,
            topology_generation: None,
            device_class: None,
            device_capacity_bytes: None,
            device_health: None,
            device_read_errors: None,
            device_write_errors: None,
            device_checksum_errors: None,
        }];

        let result = PoolAssembler::assemble(&entries, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::NoLabeledDevices => {}
            e => panic!("expected NoLabeledDevices, got {e:?}"),
        }
    }

    #[test]
    fn assemble_exported_pool_importable() {
        let pool_uuid = [0x88u8; 16];
        let entries = vec![make_labeled_entry(
            pool_uuid,
            [0x01u8; 16],
            0,
            1,
            1,
            "exported",
            PoolState::Exported,
        )];

        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert!(config.is_importable());
        assert_eq!(config.state, PoolState::Exported);
    }

    #[test]
    fn device_health_display() {
        assert_eq!(format!("{}", DeviceHealth::Online), "ONLINE");
        assert_eq!(format!("{}", DeviceHealth::Degraded), "DEGRADED");
        assert_eq!(format!("{}", DeviceHealth::Faulted), "FAULTED");
        assert_eq!(format!("{}", DeviceHealth::Offline), "OFFLINE");
    }

    #[test]
    fn device_health_from_label() {
        assert_eq!(DeviceHealth::from_label_health(0), DeviceHealth::Online);
        assert_eq!(DeviceHealth::from_label_health(1), DeviceHealth::Degraded);
        assert_eq!(DeviceHealth::from_label_health(2), DeviceHealth::Faulted);
        // Unknown values default to Online.
        assert_eq!(DeviceHealth::from_label_health(99), DeviceHealth::Online);
    }

    #[test]
    fn device_health_is_operational() {
        assert!(DeviceHealth::Online.is_operational());
        assert!(DeviceHealth::Degraded.is_operational());
        assert!(!DeviceHealth::Faulted.is_operational());
        assert!(!DeviceHealth::Offline.is_operational());
    }

    #[test]
    fn pool_config_is_importable() {
        let pool_uuid = [0x99u8; 16];
        let entries = vec![make_labeled_entry(
            pool_uuid,
            [0x01u8; 16],
            0,
            1,
            1,
            "ok",
            PoolState::Active,
        )];
        let config = PoolAssembler::assemble(&entries, None).unwrap();
        assert!(config.is_importable());
    }

    #[test]
    fn pool_not_found() {
        let pool_uuid = [0xAAu8; 16];
        let entries = vec![make_labeled_entry(
            pool_uuid,
            [0x01u8; 16],
            0,
            1,
            1,
            "present",
            PoolState::Active,
        )];

        let missing = [0xFFu8; 16];
        let result = PoolAssembler::assemble(&entries, Some(missing));
        assert!(result.is_err());
        match result.unwrap_err() {
            AssemblyError::PoolNotFound { pool_uuid } => {
                assert_eq!(pool_uuid, missing);
            }
            e => panic!("expected PoolNotFound, got {e:?}"),
        }
    }

    #[test]
    fn assembly_error_display() {
        let err = AssemblyError::NoLabeledDevices;
        assert_eq!(format!("{err}"), "no devices with valid TideFS labels");

        let err = AssemblyError::PoolDestroyed;
        assert_eq!(format!("{err}"), "pool is destroyed");

        let err = AssemblyError::MissingDevices {
            expected: 3,
            found: 2,
            missing: vec![1],
        };
        assert!(format!("{err}").contains("missing devices"));
        assert!(format!("{err}").contains("expected 3"));
        assert!(format!("{err}").contains("found 2"));
    }
    // -- PoolAddVdev tests --

    fn make_single_device_config() -> PoolConfig {
        PoolConfig {
            pool_uuid: [0x11u8; 16],
            pool_name: "testpool".to_string(),
            device_tree: DeviceType::Leaf {
                device_path: PathBuf::from("/dev/test/disk0"),
                device_guid: [0x01u8; 16],
                device_index: 0,
                capacity_bytes: 1024 * 1024 * 1024,
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 1,
            missing_indices: vec![],
            removing_device_indices: vec![],
        }
    }

    fn make_parity_raid_config() -> PoolConfig {
        let leaf1 = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/test/disk0"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf2 = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/test/disk1"),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let tree = DeviceType::ParityRaid {
            parity: 1,
            children: vec![leaf1, leaf2],
        };
        PoolConfig {
            pool_uuid: [0x33u8; 16],
            pool_name: "raidpool".to_string(),
            device_tree: tree,
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        }
    }

    #[test]
    fn add_mirror_member_single_to_two_way() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("newdisk");
        std::fs::write(&device_path, []).unwrap();

        let mut config = make_single_device_config();
        let (stats, trigger) =
            PoolAddVdev::add_vdev(device_path.clone(), DeviceRole::MirrorMember, &mut config)
                .unwrap();

        assert_eq!(stats.device_path, device_path);
        assert_eq!(stats.vdev_type, DeviceRole::MirrorMember);
        assert!(stats.add_time_ms < 1000);
        assert!(stats.rebalance_scheduled);
        assert_eq!(stats.new_device_count, 2);

        match &config.device_tree {
            DeviceType::Mirror { children } => {
                assert_eq!(children.len(), 2);
                if let DeviceType::Leaf { device_index, .. } = &children[0] {
                    assert_eq!(*device_index, 0);
                } else {
                    panic!("expected Leaf");
                }
                if let DeviceType::Leaf {
                    device_index,
                    device_path: dp,
                    ..
                } = &children[1]
                {
                    assert_eq!(*device_index, 1);
                    assert_eq!(*dp, device_path);
                } else {
                    panic!("expected Leaf");
                }
            }
            _ => panic!("expected Mirror root"),
        }

        assert_eq!(config.device_count, 2);
        assert_eq!(config.topology_generation, 2);
        assert_eq!(config.health, DeviceHealth::Online);

        assert_eq!(trigger.pool_uuid, [0x11u8; 16]);
        assert!(!trigger.is_urgent);
        assert!(trigger.reason.contains("mirror-member"));
    }

    #[test]
    fn add_mirror_member_to_existing_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("thirddisk");
        std::fs::write(&device_path, []).unwrap();

        let leaf1 = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/test/disk0"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf2 = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/test/disk1"),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let mut config = PoolConfig {
            pool_uuid: [0x11u8; 16],
            pool_name: "mirrorpool".to_string(),
            device_tree: DeviceType::Mirror {
                children: vec![leaf1, leaf2],
            },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let (stats, trigger) =
            PoolAddVdev::add_vdev(device_path, DeviceRole::MirrorMember, &mut config).unwrap();

        assert_eq!(stats.new_device_count, 3);
        match &config.device_tree {
            DeviceType::Mirror { children } => assert_eq!(children.len(), 3),
            _ => panic!("expected Mirror"),
        }
        assert!(trigger.reason.contains("mirror-member"));
    }

    #[test]
    fn add_raidz_member() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("newparity_raid");
        std::fs::write(&device_path, []).unwrap();

        let mut config = make_parity_raid_config();
        let (stats, trigger) = PoolAddVdev::add_vdev(
            device_path.clone(),
            DeviceRole::ParityRaidMember,
            &mut config,
        )
        .unwrap();

        assert_eq!(stats.vdev_type, DeviceRole::ParityRaidMember);
        assert!(stats.rebalance_scheduled);
        assert_eq!(stats.new_device_count, 3);

        match &config.device_tree {
            DeviceType::ParityRaid { parity, children } => {
                assert_eq!(*parity, 1);
                assert_eq!(children.len(), 3);
            }
            _ => panic!("expected ParityRaid"),
        }

        assert!(trigger.reason.contains("parity-raid-member"));
    }

    #[test]
    fn rebalance_trigger_after_add() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("rebaldisk");
        std::fs::write(&device_path, []).unwrap();

        let mut config = make_single_device_config();
        let (_stats, trigger) =
            PoolAddVdev::add_vdev(device_path, DeviceRole::MirrorMember, &mut config).unwrap();

        assert_eq!(trigger.pool_uuid, [0x11u8; 16]);
        assert_eq!(trigger.topology_generation, 2);
        assert!(!trigger.is_urgent);
    }

    #[test]
    fn add_to_full_pool_refused() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("disk255");
        std::fs::write(&device_path, []).unwrap();

        let leaves: Vec<DeviceType> = (0..MAX_VDEVS_PER_POOL)
            .map(|i| DeviceType::Leaf {
                device_path: PathBuf::from(format!("/dev/test/disk{i}")),
                device_guid: [i as u8; 16],
                device_index: i,
                capacity_bytes: 1024 * 1024,
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        let leaf_count = leaves.len() as u32;
        let mut config = PoolConfig {
            pool_uuid: [0xFFu8; 16],
            pool_name: "fullpool".to_string(),
            device_tree: DeviceType::Mirror { children: leaves },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 0,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: leaf_count,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let result = PoolAddVdev::add_vdev(device_path, DeviceRole::MirrorMember, &mut config);

        match result {
            Err(DeviceAddError::PoolFull { current, maximum }) => {
                assert_eq!(current, 255);
                assert_eq!(maximum, MAX_VDEVS_PER_POOL);
            }
            other => panic!("expected PoolFull error, got {other:?}"),
        }
    }

    #[test]
    fn add_already_labeled_device_refused() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("labeled_disk");

        let label = make_test_label("otherpool");
        write_label_to_file(&device_path, &label);

        let mut config = make_single_device_config();
        let result =
            PoolAddVdev::add_vdev(device_path.clone(), DeviceRole::MirrorMember, &mut config);

        match result {
            Err(DeviceAddError::AlreadyLabeled {
                device_path: dp,
                existing_pool,
            }) => {
                assert_eq!(dp, device_path);
                assert_eq!(existing_pool.as_deref(), Some("otherpool"));
            }
            other => panic!("expected AlreadyLabeled error, got {other:?}"),
        }
    }

    #[test]
    fn add_spare_device_no_rebalance() {
        let dir = tempfile::tempdir().unwrap();
        let device_path = dir.path().join("sparedisk");
        std::fs::write(&device_path, []).unwrap();

        let mut config = make_single_device_config();
        let (stats, _trigger) =
            PoolAddVdev::add_vdev(device_path, DeviceRole::Spare, &mut config).unwrap();

        assert!(!stats.rebalance_scheduled);
        assert_eq!(config.device_count, 1);
    }

    #[test]
    fn vdev_add_stats_display() {
        let stats = DeviceAddStats {
            device_path: PathBuf::from("/dev/sdb"),
            vdev_type: DeviceRole::MirrorMember,
            add_time_ms: 42,
            rebalance_scheduled: true,
            new_device_count: 2,
        };
        assert_eq!(stats.device_path, PathBuf::from("/dev/sdb"));
        assert_eq!(stats.vdev_type, DeviceRole::MirrorMember);
        assert_eq!(stats.add_time_ms, 42);
        assert!(stats.rebalance_scheduled);
        assert_eq!(stats.new_device_count, 2);
    }

    // -- Label round-trip property test --

    /// Build a PoolConfig -> generate labels -> write to files ->
    /// scan -> reconstruct -> assert key fields match the original.
    #[test]
    fn label_roundtrip_single_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");

        let tree = DeviceType::Leaf {
            device_path: dev_path.clone(),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let original = PoolConfig {
            pool_uuid: [0xABu8; 16],
            pool_name: "roundtrip".to_string(),
            device_tree: tree,
            health: DeviceHealth::Online,
            state: PoolState::Exported,
            total_capacity_bytes: 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 7,
            device_count: 1,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        // 1. Generate labels from the config.
        let labels = original.to_labels();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].pool_guid, [0xABu8; 16]);
        assert_eq!(labels[0].pool_name_str(), "roundtrip");
        assert_eq!(labels[0].pool_state, PoolState::Exported);
        assert_eq!(labels[0].topology_generation, 7);

        // 2. Seal each label and write to device file.
        for label in &labels {
            let sealed = seal_label(label.clone()).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&dev_path, buf).unwrap();
        }

        // 3. Scan labels from device files.
        let entries = scan_labels(&[dev_path.clone()]).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].has_tidefs_label);
        assert!(entries[0].label_valid);
        assert_eq!(entries[0].pool_guid, Some([0xABu8; 16]));

        // 4. Reconstruct PoolConfig.
        let reconstructed = PoolAssembler::assemble(&entries, None).unwrap();

        // 5. Assert key fields match the original.
        assert_eq!(reconstructed.pool_uuid, original.pool_uuid);
        assert_eq!(reconstructed.pool_name, original.pool_name);
        assert_eq!(reconstructed.state, original.state);
        assert_eq!(reconstructed.health, original.health);
        assert_eq!(reconstructed.device_count, original.device_count);
        assert_eq!(
            reconstructed.topology_generation,
            original.topology_generation
        );
        assert!(reconstructed.missing_indices.is_empty());
    }

    #[test]
    fn label_roundtrip_three_device_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("vdev1");
        let dev2 = dir.path().join("vdev2");

        let leaf0 = DeviceType::Leaf {
            device_path: dev0.clone(),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 500 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf1 = DeviceType::Leaf {
            device_path: dev1.clone(),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 500 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf2 = DeviceType::Leaf {
            device_path: dev2.clone(),
            device_guid: [0x03u8; 16],
            device_index: 2,
            capacity_bytes: 500 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Degraded,
            read_errors: 5,
            write_errors: 0,
            checksum_errors: 1,
        };
        let tree = DeviceType::Mirror {
            children: vec![leaf0, leaf1, leaf2],
        };
        let original = PoolConfig {
            pool_uuid: [0xCDu8; 16],
            pool_name: "mirrorpool".to_string(),
            device_tree: tree,
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 1500 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 3,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        // Generate labels and write each to its corresponding device file.
        let labels = original.to_labels();
        assert_eq!(labels.len(), 3);

        // Verify per-device fields in generated labels.
        assert_eq!(labels[0].device_index, 0);
        assert_eq!(labels[1].device_index, 1);
        assert_eq!(labels[2].device_index, 2);
        // Third device has degraded health.
        assert_eq!(
            labels[2].device_health,
            DeviceHealth::Degraded.to_label_health()
        );
        assert_eq!(labels[2].device_read_errors, 5);
        assert_eq!(labels[2].device_checksum_errors, 1);

        // Write labels to device files.
        let device_paths = [dev0.clone(), dev1.clone(), dev2.clone()];
        for (i, label) in labels.iter().enumerate() {
            let sealed = seal_label(label.clone()).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&device_paths[i], buf).unwrap();
        }

        // Scan and reconstruct.
        let entries = scan_labels(&device_paths).unwrap();
        assert_eq!(entries.len(), 3);
        let reconstructed = PoolAssembler::assemble(&entries, None).unwrap();

        assert_eq!(reconstructed.pool_uuid, original.pool_uuid);
        assert_eq!(reconstructed.pool_name, original.pool_name);
        assert_eq!(reconstructed.device_count, 3);
        assert_eq!(reconstructed.topology_generation, 3);
        assert!(reconstructed.health.is_operational());
        assert!(reconstructed.missing_indices.is_empty());
    }

    // -- device_capacity_bytes tests --

    #[test]
    fn device_capacity_bytes_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("testfile");
        let expected_size: u64 = 4096;
        {
            let f = std::fs::File::create(&file_path).unwrap();
            f.set_len(expected_size).unwrap();
        }
        let size = device_capacity_bytes(&file_path).unwrap();
        assert_eq!(size, expected_size);
    }

    #[test]
    fn device_capacity_bytes_nonexistent() {
        let result = device_capacity_bytes(&PathBuf::from("/nonexistent/path/for/testing"));
        assert!(result.is_err());
    }

    #[test]
    fn device_capacity_bytes_block_device_zero_fallback() {
        // In the unit-test environment, a regular file is not a block
        // device, so this path exercises the regular-file branch for
        // coverage.  Block-device validation is covered by the QEMU
        // child issue #6065.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("zerofile");
        std::fs::write(&file_path, b"").unwrap();
        let size = device_capacity_bytes(&file_path).unwrap();
        assert_eq!(size, 0);
    }
}
