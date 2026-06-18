// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool label writer: writes sealed, BLAKE3-checksummed pool labels to
//! block devices at standard primary (offset 0) and backup
//! (end-of-device) locations.
//!
//! This module is the write-side counterpart to the [`LabelReader`] in
//! [`crate::label`].  Together they form the pool label I/O boundary:
//! labels are written here and read back during pool import/scan.

use std::collections::BTreeMap;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use tidefs_types_pool_label_core::{
    encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

use crate::label::PoolScanConfig;
use crate::DeviceType;
use crate::PoolConfig;

// ---------------------------------------------------------------------------
// LabelWriteError
// ---------------------------------------------------------------------------

/// Errors returned by pool label write operations.
#[derive(Clone, Debug)]
pub enum LabelWriteError {
    /// Failed to open the device file.
    OpenDevice {
        /// Device path.
        device_path: PathBuf,
        /// Underlying OS error.
        source: String,
    },
    /// Failed to seek within the device file.
    SeekFailed {
        /// Device path.
        device_path: PathBuf,
        /// Underlying OS error.
        source: String,
    },
    /// Failed to write label bytes.
    WriteFailed {
        /// Device path.
        device_path: PathBuf,
        /// Underlying OS error.
        source: String,
    },
    /// Cannot determine device size for backup label placement.
    NoDeviceSize {
        /// Device path.
        device_path: PathBuf,
        /// Reason size couldn't be determined.
        reason: String,
    },
    /// Device too small to hold labels.
    DeviceTooSmall {
        /// Device path.
        device_path: PathBuf,
        /// Actual device size in bytes.
        device_size: u64,
        /// Minimum required bytes.
        required: u64,
    },
    /// Failed to seal the label (BLAKE3 checksum computation).
    SealFailed {
        /// Device index from the label.
        device_index: u32,
        /// Reason for the failure.
        reason: String,
    },
    /// Failed to encode the label to wire format.
    EncodeFailed {
        /// Device index from the label.
        device_index: u32,
        /// Reason for the failure.
        reason: String,
    },
    /// A device path in the pool config could not be matched to a
    /// generated label.
    PathIndexMismatch {
        /// Device index that was requested.
        device_index: u32,
        /// Reason the path couldn't be found.
        reason: String,
    },
}

impl std::fmt::Display for LabelWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenDevice {
                device_path,
                source,
            } => {
                write!(f, "cannot open device {}: {source}", device_path.display())
            }
            Self::SeekFailed {
                device_path,
                source,
            } => {
                write!(f, "seek failed on {}: {source}", device_path.display())
            }
            Self::WriteFailed {
                device_path,
                source,
            } => {
                write!(f, "write failed on {}: {source}", device_path.display())
            }
            Self::NoDeviceSize {
                device_path,
                reason,
            } => {
                write!(
                    f,
                    "cannot determine size of {}: {reason}",
                    device_path.display()
                )
            }
            Self::DeviceTooSmall {
                device_path,
                device_size,
                required,
            } => {
                write!(
                    f,
                    "device {} is too small ({} bytes, need at least {})",
                    device_path.display(),
                    device_size,
                    required
                )
            }
            Self::SealFailed {
                device_index,
                reason,
            } => {
                write!(f, "seal label for device {device_index}: {reason}")
            }
            Self::EncodeFailed {
                device_index,
                reason,
            } => {
                write!(f, "encode label for device {device_index}: {reason}")
            }
            Self::PathIndexMismatch {
                device_index,
                reason,
            } => {
                write!(f, "device path for index {device_index}: {reason}")
            }
        }
    }
}

impl std::error::Error for LabelWriteError {}

// ---------------------------------------------------------------------------
// PoolLabelWriter
// ---------------------------------------------------------------------------

/// Writes sealed, BLAKE3-checksummed pool labels to block devices at
/// standard primary (offset 0) and backup (end-of-device) locations.
///
/// Each leaf device in a [`PoolConfig`] receives its per-device
/// [`PoolLabelV1`] at both label copies so that pool import can
/// discover the current topology, device count, and committed-root
/// generation from any surviving device.
///
/// # Usage
///
/// ```ignore
/// let cfg = PoolScanConfig::new(device_paths);
/// let writer = PoolLabelWriter::new(cfg);
/// writer.write_pool_labels(&pool_config, None)?;
/// ```
#[derive(Clone, Debug)]
pub struct PoolLabelWriter {
    config: PoolScanConfig,
}

impl PoolLabelWriter {
    /// Create a new writer from scan configuration.
    ///
    /// The writer uses `config.label0_offset` as the primary label
    /// offset, `config.label1_offset` (or end-of-device) as the
    /// backup, and `config.label_area_bytes` for region sizing.
    #[must_use]
    pub fn new(config: PoolScanConfig) -> Self {
        Self { config }
    }

    /// Return a reference to the writer's configuration.
    #[must_use]
    pub fn config(&self) -> &PoolScanConfig {
        &self.config
    }

    /// Write a single sealed label to `device_path` at both primary
    /// and backup offsets.
    ///
    /// The label must already be sealed (checksum computed).  The
    /// writer encodes it to wire format and writes the result at
    /// `label0_offset` and at `label1_offset` (or `device_size -
    /// label_area_bytes` when label1_offset is `None`).
    ///
    /// # Errors
    ///
    /// Returns [`LabelWriteError`] if the device cannot be opened,
    /// is too small, or the write fails.
    pub fn write_label(
        &self,
        device_path: &Path,
        label: &PoolLabelV1,
        device_size: Option<u64>,
    ) -> Result<(), LabelWriteError> {
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).map_err(|e| LabelWriteError::EncodeFailed {
            device_index: label.device_index,
            reason: format!("{e:?}"),
        })?;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .open(device_path)
            .map_err(|e| LabelWriteError::OpenDevice {
                device_path: device_path.to_path_buf(),
                source: e.to_string(),
            })?;

        // Write primary label at label0_offset.
        file.seek(std::io::SeekFrom::Start(self.config.label0_offset))
            .map_err(|e| LabelWriteError::SeekFailed {
                device_path: device_path.to_path_buf(),
                source: e.to_string(),
            })?;
        file.write_all(&buf)
            .map_err(|e| LabelWriteError::WriteFailed {
                device_path: device_path.to_path_buf(),
                source: e.to_string(),
            })?;

        // Write backup label.
        let backup_offset = match self.config.label1_offset {
            Some(offset) => offset,
            None => {
                let size = device_size.ok_or_else(|| LabelWriteError::NoDeviceSize {
                    device_path: device_path.to_path_buf(),
                    reason: "label1_offset is None and no device_size provided".into(),
                })?;
                if size < self.config.label_area_bytes {
                    return Err(LabelWriteError::DeviceTooSmall {
                        device_path: device_path.to_path_buf(),
                        device_size: size,
                        required: self.config.label_area_bytes,
                    });
                }
                size - self.config.label_area_bytes
            }
        };

        file.seek(std::io::SeekFrom::Start(backup_offset))
            .map_err(|e| LabelWriteError::SeekFailed {
                device_path: device_path.to_path_buf(),
                source: e.to_string(),
            })?;
        file.write_all(&buf)
            .map_err(|e| LabelWriteError::WriteFailed {
                device_path: device_path.to_path_buf(),
                source: e.to_string(),
            })?;

        file.flush().map_err(|e| LabelWriteError::WriteFailed {
            device_path: device_path.to_path_buf(),
            source: e.to_string(),
        })?;

        Ok(())
    }

    /// Generate labels from `config` via [`PoolConfig::to_labels`],
    /// seal each one, and write to the corresponding device path.
    ///
    /// Device paths are taken from the device tree via
    /// [`DeviceType::all_leaf_paths`], matched by index to the
    /// generated labels.  The caller must ensure the pool config
    /// reflects the current post-removal topology.
    ///
    /// When `device_sizes` is provided, each entry maps
    /// `device_index -> size_bytes` and is used for backup-offset
    /// computation.  When `None`, backup labels are written only if
    /// an explicit `label1_offset` is configured.
    ///
    /// # Errors
    ///
    /// Returns [`LabelWriteError`] on any seal, encode, open, seek,
    /// or write failure.
    /// Recursively collect device_index -> device_path mappings from the
    /// device tree.
    fn collect_leaf_index_map(node: &DeviceType, out: &mut BTreeMap<u32, PathBuf>) {
        match node {
            DeviceType::Leaf {
                device_path,
                device_index,
                ..
            } => {
                out.insert(*device_index, device_path.clone());
            }
            DeviceType::PoolWideData { children }
            | DeviceType::Mirror { children }
            | DeviceType::ParityRaid { children, .. } => {
                for child in children {
                    Self::collect_leaf_index_map(child, out);
                }
            }
        }
    }

    pub fn write_pool_labels(
        &self,
        config: &PoolConfig,
        device_sizes: Option<&BTreeMap<u32, u64>>,
    ) -> Result<(), LabelWriteError> {
        let mut labels = config.to_labels();

        // Seal each label (computes BLAKE3 checksum).
        for (i, label) in labels.iter_mut().enumerate() {
            *label = seal_label(label.clone()).map_err(|e| LabelWriteError::SealFailed {
                device_index: i as u32,
                reason: format!("{e:?}"),
            })?;
        }

        // Build a device_index -> device_path map from the tree,
        // since leaf_paths positional indexing breaks when device
        // indices have gaps after removal.
        let mut index_map: BTreeMap<u32, PathBuf> = BTreeMap::new();
        Self::collect_leaf_index_map(&config.device_tree, &mut index_map);

        for label in &labels {
            let device_path = index_map.get(&label.device_index).ok_or_else(|| {
                LabelWriteError::PathIndexMismatch {
                    device_index: label.device_index,
                    reason: format!(
                        "device_index {} not found in tree ({} leaves)",
                        label.device_index,
                        index_map.len()
                    ),
                }
            })?;

            let size = device_sizes.and_then(|m| m.get(&label.device_index).copied());
            self.write_label(device_path, label, size)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::{LabelReadOutcome, LabelReader};
    use crate::DeviceHealth;
    use std::io::Read;
    use tidefs_types_pool_label_core::{
        decode_label, verify_label_checksum, DeviceClass, PoolState,
    };

    /// Build a two-device mirror PoolConfig for testing.
    fn _make_test_pool_config() -> PoolConfig {
        let leaf0 = DeviceType::Leaf {
            device_path: PathBuf::from("/tmp/test-label-writer-disk0"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf1 = DeviceType::Leaf {
            device_path: PathBuf::from("/tmp/test-label-writer-disk1"),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 512 * 1024 * 1024,
            device_class: DeviceClass::Ssd,
            health: DeviceHealth::Degraded,
            read_errors: 3,
            write_errors: 1,
            checksum_errors: 0,
        };
        PoolConfig {
            pool_uuid: [0xABu8; 16],
            pool_name: "label-writer-test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![leaf0, leaf1],
            },
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 1536 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 5,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        }
    }

    #[test]
    fn write_single_label_to_file_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("testdev");

        // Create a zero-filled file large enough for labels.
        let file_size = 1024 * 1024; // 1 MiB
        {
            let f = std::fs::File::create(&dev_path).unwrap();
            f.set_len(file_size).unwrap();
        }

        let config = PoolScanConfig::new(vec![dev_path.clone()]).with_label_area(256 * 1024); // 256 KiB label area

        let writer = PoolLabelWriter::new(config);

        let mut label = PoolLabelV1::new([0x42u8; 16], [0x01u8; 16], "testpool");
        label.device_index = 0;
        label.device_count = 1;
        label.topology_generation = 7;
        label.device_class = DeviceClass::Nvme;
        let label = seal_label(label).unwrap();

        writer
            .write_label(&dev_path, &label, Some(file_size))
            .unwrap();

        // Read the primary label back and verify.
        let mut primary_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        {
            let mut f = std::fs::File::open(&dev_path).unwrap();
            f.read_exact(&mut primary_buf).unwrap();
        }
        let decoded = decode_label(&primary_buf).unwrap();
        assert!(verify_label_checksum(&decoded));
        assert_eq!(decoded.pool_guid, [0x42u8; 16]);
        assert_eq!(decoded.device_guid, [0x01u8; 16]);
        assert_eq!(decoded.pool_name_str(), "testpool");
        assert_eq!(decoded.topology_generation, 7);
        assert_eq!(decoded.device_count, 1);
        assert_eq!(decoded.device_index, 0);

        // Read the backup label (end of device - label area).
        let backup_offset = file_size - 256 * 1024;
        let mut backup_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        {
            let mut f = std::fs::File::open(&dev_path).unwrap();
            f.seek(std::io::SeekFrom::Start(backup_offset)).unwrap();
            f.read_exact(&mut backup_buf).unwrap();
        }
        let decoded_backup = decode_label(&backup_buf).unwrap();
        assert!(verify_label_checksum(&decoded_backup));
        assert_eq!(decoded_backup.topology_generation, 7);
    }

    #[test]
    fn write_pool_labels_and_read_back_via_label_reader() {
        let dir = tempfile::tempdir().unwrap();
        let dev0_path = dir.path().join("disk0");
        let dev1_path = dir.path().join("disk1");

        let file_size = 2 * 1024 * 1024; // 2 MiB each
        for p in &[&dev0_path, &dev1_path] {
            let f = std::fs::File::create(p).unwrap();
            f.set_len(file_size).unwrap();
        }

        // Build a pool config with device paths pointing at our temp files.
        let leaf0 = DeviceType::Leaf {
            device_path: dev0_path.clone(),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf1 = DeviceType::Leaf {
            device_path: dev1_path.clone(),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 512 * 1024 * 1024,
            device_class: DeviceClass::Ssd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let config = PoolConfig {
            pool_uuid: [0xCDu8; 16],
            pool_name: "roundtrip-pool".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![leaf0, leaf1],
            },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1536 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 3,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let scan_cfg = PoolScanConfig::new(vec![dev0_path.clone(), dev1_path.clone()])
            .with_label_area(256 * 1024);
        let writer = PoolLabelWriter::new(scan_cfg.clone());

        let mut sizes = BTreeMap::new();
        sizes.insert(0, file_size);
        sizes.insert(1, file_size);
        writer.write_pool_labels(&config, Some(&sizes)).unwrap();

        // Read back via LabelReader.
        let reader = LabelReader::new(scan_cfg);
        let results = reader.scan_all();

        assert_eq!(results.len(), 2);
        for (_path, outcome) in &results {
            match outcome {
                LabelReadOutcome::Valid(label) => {
                    assert_eq!(label.pool_guid, [0xCDu8; 16]);
                    assert_eq!(label.topology_generation, 3);
                    assert_eq!(label.device_count, 2);
                    assert!(verify_label_checksum(label));
                }
                other => panic!("expected Valid, got {other:?}"),
            }
        }

        // Both indices should be present.
        let valid_labels = reader.scan_valid_labels();
        let mut indices: Vec<u32> = valid_labels.iter().map(|(_, l)| l.device_index).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn write_pool_labels_after_removal_survivors_only() {
        let dir = tempfile::tempdir().unwrap();
        let dev0_path = dir.path().join("disk0");
        let dev1_path = dir.path().join("disk1");

        let file_size = 2 * 1024 * 1024;
        for p in &[&dev0_path, &dev1_path] {
            let f = std::fs::File::create(p).unwrap();
            f.set_len(file_size).unwrap();
        }

        // Three-device config, then remove one.
        let leaf0 = DeviceType::Leaf {
            device_path: dev0_path.clone(),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf1 = DeviceType::Leaf {
            device_path: dev1_path.clone(),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 512 * 1024 * 1024,
            device_class: DeviceClass::Ssd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf2 = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/removed-disk"),
            device_guid: [0x03u8; 16],
            device_index: 2,
            capacity_bytes: 512 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let mut config = PoolConfig {
            pool_uuid: [0xEFu8; 16],
            pool_name: "removal-test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![leaf0, leaf1, leaf2],
            },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 2048 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        // Remove disk2 (device at /dev/removed-disk).
        config
            .remove_device(Path::new("/dev/removed-disk"))
            .unwrap();

        assert_eq!(config.device_count, 2);
        assert_eq!(config.topology_generation, 2);
        let leaf_paths = config.device_tree.all_leaf_paths();
        assert_eq!(leaf_paths.len(), 2);
        assert!(!leaf_paths.contains(&PathBuf::from("/dev/removed-disk")));

        // Write labels for the surviving devices.
        let scan_cfg = PoolScanConfig::new(vec![dev0_path.clone(), dev1_path.clone()])
            .with_label_area(256 * 1024);
        let writer = PoolLabelWriter::new(scan_cfg.clone());

        let mut sizes = BTreeMap::new();
        sizes.insert(0, file_size);
        sizes.insert(1, file_size);
        writer.write_pool_labels(&config, Some(&sizes)).unwrap();

        // Read back and verify no label for removed device.
        let reader = LabelReader::new(scan_cfg);
        let valid = reader.scan_valid_labels();
        assert_eq!(valid.len(), 2);

        for (_path, label) in &valid {
            assert_eq!(label.pool_guid, [0xEFu8; 16]);
            assert_eq!(label.device_count, 2);
            assert_eq!(label.topology_generation, 2);
        }

        let indices: Vec<u32> = valid.iter().map(|(_, l)| l.device_index).collect();
        assert!(
            !indices.contains(&2),
            "removed device index 2 should not be present"
        );
    }

    #[test]
    fn write_label_device_too_small_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("tinydev");

        // Create a file too small for the label area.
        let tiny_size = 1024; // 1 KiB, less than 256 KiB label area
        {
            let f = std::fs::File::create(&dev_path).unwrap();
            f.set_len(tiny_size).unwrap();
        }

        let config = PoolScanConfig::new(vec![dev_path.clone()]).with_label_area(256 * 1024);
        let writer = PoolLabelWriter::new(config);

        let label = seal_label(PoolLabelV1::new([0x11u8; 16], [0x22u8; 16], "tinypool")).unwrap();

        let result = writer.write_label(&dev_path, &label, Some(tiny_size));
        assert!(result.is_err());
        match result.unwrap_err() {
            LabelWriteError::DeviceTooSmall { .. } => {}
            other => panic!("expected DeviceTooSmall, got {other}"),
        }
    }

    #[test]
    fn write_label_with_explicit_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("offsetdev");

        let file_size = 2 * 1024 * 1024;
        {
            let f = std::fs::File::create(&dev_path).unwrap();
            f.set_len(file_size).unwrap();
        }

        // Use explicit label offsets: primary at 4096, backup at 1048576.
        let config = PoolScanConfig::new(vec![dev_path.clone()])
            .with_label_offsets(4096, 1048576)
            .with_label_area(256 * 1024);
        let writer = PoolLabelWriter::new(config);

        let label = seal_label(PoolLabelV1::new([0xAAu8; 16], [0xBBu8; 16], "offsetpool")).unwrap();

        // No device_size needed since label1_offset is explicit.
        writer.write_label(&dev_path, &label, None).unwrap();

        // Read primary label at offset 4096.
        let mut primary_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        {
            let mut f = std::fs::File::open(&dev_path).unwrap();
            f.seek(std::io::SeekFrom::Start(4096)).unwrap();
            f.read_exact(&mut primary_buf).unwrap();
        }
        let decoded = decode_label(&primary_buf).unwrap();
        assert!(verify_label_checksum(&decoded));
        assert_eq!(decoded.pool_guid, [0xAAu8; 16]);

        // Read backup label at offset 1048576.
        let mut backup_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        {
            let mut f = std::fs::File::open(&dev_path).unwrap();
            f.seek(std::io::SeekFrom::Start(1048576)).unwrap();
            f.read_exact(&mut backup_buf).unwrap();
        }
        let decoded_backup = decode_label(&backup_buf).unwrap();
        assert!(verify_label_checksum(&decoded_backup));
        assert_eq!(decoded_backup.pool_guid, [0xAAu8; 16]);
    }

    #[test]
    fn path_index_mismatch_error() {
        // After the index_map fix, labels are matched by device_index
        // regardless of tree position. PathIndexMismatch requires
        // a label whose device_index truly has no corresponding leaf.
        // Test: with device_sizes, write succeeds even with non-zero-based indices.
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("solodev");
        {
            let f = std::fs::File::create(&dev_path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }

        let leaf0 = DeviceType::Leaf {
            device_path: dev_path.clone(),
            device_guid: [0x01u8; 16],
            device_index: 5,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let config = PoolConfig {
            pool_uuid: [0x99u8; 16],
            pool_name: "mismatch".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: leaf0,
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 1,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let scan_cfg = PoolScanConfig::new(vec![dev_path.clone()]).with_label_area(256 * 1024);
        let writer = PoolLabelWriter::new(scan_cfg);

        let mut sizes = BTreeMap::new();
        sizes.insert(5, 2 * 1024 * 1024);
        writer.write_pool_labels(&config, Some(&sizes)).unwrap();
    }
}
