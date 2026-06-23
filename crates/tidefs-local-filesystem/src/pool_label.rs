// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool label initialization: writes fresh `PoolLabelV1` superblocks to
//! block devices during pool creation. Counterpart to the pool-import

//! read path.
//!
//! # Label layout
//!
//! Each device receives two label copies:
//! - Label 0 at offset 0 (primary)
//! - Label 1 at offset `capacity - POOL_LABEL_SIZE` (secondary)
//!
//! Both copies are self-contained and independently verifiable.

#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(test)]
use std::path::{Path, PathBuf};

#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use tidefs_pool_scan::{DeviceHealth, DeviceType};
#[cfg(test)]
use tidefs_types_pool_label_core::{
    encode_label, features, seal_label, DeviceClass, LabelError, PoolLabelV1, PoolState,
    POOL_LABEL_MAGIC, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during pool label initialization.
#[derive(Debug)]
#[cfg(test)]
pub enum LabelInitError {
    /// I/O error on a device.
    Io {
        /// Device path that failed.
        device_path: PathBuf,
        /// Error message.
        msg: String,
    },
    /// Device already contains a recognizable TideFS pool label.
    ExistingLabel {
        /// Device path.
        device_path: PathBuf,
        /// Pool name found in the existing label.
        existing_pool_name: String,
    },
    /// Device is too small for label placement.
    DeviceTooSmall {
        /// Device path.
        device_path: PathBuf,
        /// Actual device size in bytes.
        size_bytes: u64,
    },
    /// Topology constraints violated.
    TopologyError {
        /// Human-readable description.
        msg: String,
    },
}

#[cfg(test)]
impl std::fmt::Display for LabelInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { device_path, msg } => {
                write!(f, "I/O error on {}: {msg}", device_path.display())
            }
            Self::ExistingLabel {
                device_path,
                existing_pool_name,
            } => {
                write!(
                    f,
                    "device {} already has a pool label (pool='{existing_pool_name}')",
                    device_path.display()
                )
            }
            Self::DeviceTooSmall {
                device_path,
                size_bytes,
            } => {
                write!(
                    f,
                    "device {} is too small ({} bytes); minimum {} bytes required",
                    device_path.display(),
                    size_bytes,
                    POOL_LABEL_SIZE * 2
                )
            }
            Self::TopologyError { msg } => {
                write!(f, "topology error: {msg}")
            }
        }
    }
}

#[cfg(test)]
impl From<LabelError> for LabelInitError {
    fn from(e: LabelError) -> Self {
        Self::TopologyError {
            msg: format!("label encoding error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PoolCreateResult
// ---------------------------------------------------------------------------

/// Result of a successful pool label initialization.
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct PoolCreateResult {
    /// Assigned pool GUID (shared across all devices).
    pub pool_guid: [u8; 16],
    /// Assigned pool name.
    pub pool_name: String,
    /// Labels generated for each leaf device.
    pub device_labels: Vec<(PathBuf, PoolLabelV1)>,
    #[allow(dead_code)] // INTENT: stored for pool topology inspection in tests
    /// The device tree topology written to labels.
    pub device_tree: DeviceType,
    /// Number of devices in the pool.
    pub device_count: u32,
    /// Topology generation (always 1 for a new pool).
    pub topology_generation: u64,
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Leaf collection from DeviceType
// ---------------------------------------------------------------------------

/// A flattened leaf device reference.
#[derive(Clone, Debug)]
#[cfg(test)]
struct LeafInfo {
    device_path: PathBuf,
    device_index: u32,
    capacity_bytes: u64,
    device_class: DeviceClass,
}

/// Walk the device tree and collect all leaf devices in index order.
#[cfg(test)]
fn collect_leaves(tree: &DeviceType) -> Vec<LeafInfo> {
    let mut out = Vec::new();
    collect_leaves_impl(tree, &mut out);
    out
}

#[cfg(test)]
fn collect_leaves_impl(node: &DeviceType, out: &mut Vec<LeafInfo>) {
    match node {
        DeviceType::Leaf {
            device_path,
            device_index,
            capacity_bytes,
            device_class,
            ..
        } => {
            out.push(LeafInfo {
                device_path: device_path.clone(),
                device_index: *device_index,
                capacity_bytes: *capacity_bytes,
                device_class: *device_class,
            });
        }
        DeviceType::PoolWideData { children }
        | DeviceType::Mirror { children }
        | DeviceType::ParityRaid { children, .. } => {
            for child in children {
                collect_leaves_impl(child, out);
            }
        }
    }
}

/// Validate topology constraints and return the number of leaf devices.
#[cfg(test)]
fn validate_topology(tree: &DeviceType) -> Result<usize, LabelInitError> {
    let leaves = collect_leaves(tree);
    let n = leaves.len();

    if n == 0 {
        return Err(LabelInitError::TopologyError {
            msg: "pool must have at least one leaf device".to_string(),
        });
    }

    match tree {
        DeviceType::Leaf { .. } => {
            if n != 1 {
                return Err(LabelInitError::TopologyError {
                    msg: "single-device topology must have exactly 1 leaf".to_string(),
                });
            }
        }
        DeviceType::PoolWideData { .. } => {
            if n < 1 {
                return Err(LabelInitError::TopologyError {
                    msg: "pool-wide data topology requires at least 1 device".to_string(),
                });
            }
        }
        DeviceType::Mirror { .. } => {
            if n < 2 {
                return Err(LabelInitError::TopologyError {
                    msg: format!("mirror topology requires at least 2 devices, got {n}"),
                });
            }
        }
        DeviceType::ParityRaid { parity, .. } => {
            let p = *parity as usize;
            if !(1..=3).contains(&p) {
                return Err(LabelInitError::TopologyError {
                    msg: format!("parity_raid parity must be 1, 2, or 3, got {p}"),
                });
            }
            // Minimum: parity + 2 data disks (e.g., 4-way parity_raid1 = 3 data + 1 parity)
            let min_devices = p + 2;
            if n < min_devices {
                return Err(LabelInitError::TopologyError {
                    msg: format!("parity_raid{p} requires at least {min_devices} devices, got {n}"),
                });
            }
        }
    }

    Ok(n)
}

// ---------------------------------------------------------------------------
// create_initial_labels
// ---------------------------------------------------------------------------

/// Build initial `PoolLabelV1` labels for every leaf device in `device_tree`.
///
/// Generates a fresh random pool GUID and per-device GUIDs.  All devices
/// are marked `ONLINE` with commit_group 0 and topology_generation 1.
#[cfg(test)]
pub fn create_initial_labels(
    device_tree: &DeviceType,
    pool_name: &str,
    feature_flags: u64,
) -> Result<PoolCreateResult, LabelInitError> {
    let leaf_count = validate_topology(device_tree)?;

    // Generate pool GUID (random 16 bytes = UUID v4-style).
    let mut pool_guid = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut pool_guid);

    // Collect leaves.
    let leaves = collect_leaves(device_tree);

    // Generate per-device labels.
    let mut device_labels: Vec<(PathBuf, PoolLabelV1)> = Vec::with_capacity(leaf_count);

    for leaf in &leaves {
        let mut device_guid = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut device_guid);

        let mut label = PoolLabelV1::new(pool_guid, device_guid, pool_name);

        // Populate topology fields.
        label.device_index = leaf.device_index;
        label.device_count = leaf_count as u32;
        label.topology_generation = 1;
        label.pool_state = PoolState::Active;
        label.commit_group = 0;
        label.label_commit_group = 0;

        // Device class and capacity.
        label.device_class = leaf.device_class;
        label.device_capacity_bytes = leaf.capacity_bytes;

        // System area not yet allocated.
        label.system_area_pointer = 0;
        label.system_area_size = 0;

        // Feature flags.
        label.features_incompat = features::POOL_LABEL_V1;
        label.features_ro_compat = 0;
        label.features_compat = feature_flags & !features::POOL_LABEL_V1;

        // Health: all devices start ONLINE.
        label.device_health = DeviceHealth::Online.to_label_health();
        label.device_read_errors = 0;
        label.device_write_errors = 0;
        label.device_checksum_errors = 0;

        // Seal the label (compute and embed checksum).
        let sealed = seal_label(label)?;

        device_labels.push((leaf.device_path.clone(), sealed));
    }

    Ok(PoolCreateResult {
        pool_guid,
        pool_name: pool_name.to_string(),
        device_labels,
        device_tree: device_tree.clone(),
        device_count: leaf_count as u32,
        topology_generation: 1,
    })
}

// ---------------------------------------------------------------------------
// write_label_to_device
// ---------------------------------------------------------------------------

/// Write a pool label to a block device at the primary (offset 0) and
/// secondary (offset `capacity - POOL_LABEL_SIZE`) positions.
///
/// Returns an error if the device already contains a recognizable TideFS
/// label, unless `force` is true.
#[cfg(test)]
pub fn write_label_to_device(
    device_path: &Path,
    label: &PoolLabelV1,
    capacity_bytes: u64,
    force: bool,
) -> Result<(), LabelInitError> {
    // Encode the label to wire format.
    let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    encode_label(label, &mut buf)?;

    // Pad to POOL_LABEL_SIZE so the on-disk area is full-size.
    let mut full_buf = vec![0u8; POOL_LABEL_SIZE];
    full_buf[..POOL_LABEL_V1_EXT_WIRE_SIZE].copy_from_slice(&buf);

    // Open the device for reading and writing.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)
        .map_err(|e| LabelInitError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("open: {e}"),
        })?;

    // Check device size.
    let actual_size = file
        .seek(SeekFrom::End(0))
        .map_err(|e| LabelInitError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("seek end: {e}"),
        })?;

    if actual_size < POOL_LABEL_SIZE as u64 * 2 {
        return Err(LabelInitError::DeviceTooSmall {
            device_path: device_path.to_path_buf(),
            size_bytes: actual_size,
        });
    }

    // Use the provided capacity_bytes if non-zero, otherwise use actual_size.
    let capacity = if capacity_bytes > 0 {
        capacity_bytes
    } else {
        actual_size
    };

    if capacity < POOL_LABEL_SIZE as u64 * 2 {
        return Err(LabelInitError::DeviceTooSmall {
            device_path: device_path.to_path_buf(),
            size_bytes: capacity,
        });
    }

    // Check for existing label unless force is set.
    if !force {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| LabelInitError::Io {
                device_path: device_path.to_path_buf(),
                msg: format!("seek: {e}"),
            })?;
        let mut probe = [0u8; 4];
        match file.read_exact(&mut probe) {
            Ok(()) if probe == POOL_LABEL_MAGIC => {
                // Read enough to get the pool name.
                let mut label_buf = vec![0u8; POOL_LABEL_SIZE];
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| LabelInitError::Io {
                        device_path: device_path.to_path_buf(),
                        msg: format!("seek: {e}"),
                    })?;
                file.read_exact(&mut label_buf)
                    .map_err(|e| LabelInitError::Io {
                        device_path: device_path.to_path_buf(),
                        msg: format!("read: {e}"),
                    })?;
                if let Ok(existing) = tidefs_types_pool_label_core::decode_label(&label_buf) {
                    return Err(LabelInitError::ExistingLabel {
                        device_path: device_path.to_path_buf(),
                        existing_pool_name: existing.pool_name_str().to_string(),
                    });
                }
                return Err(LabelInitError::ExistingLabel {
                    device_path: device_path.to_path_buf(),
                    existing_pool_name: "(unreadable)".to_string(),
                });
            }
            _ => {
                // No existing label found — proceed.
            }
        }
    }

    // Write primary label at offset 0.
    file.seek(SeekFrom::Start(0))
        .map_err(|e| LabelInitError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("seek: {e}"),
        })?;
    file.write_all(&full_buf).map_err(|e| LabelInitError::Io {
        device_path: device_path.to_path_buf(),
        msg: format!("write label 0: {e}"),
    })?;
    file.sync_all().map_err(|e| LabelInitError::Io {
        device_path: device_path.to_path_buf(),
        msg: format!("fsync label 0: {e}"),
    })?;

    // Write secondary label near end of device.
    let secondary_offset = capacity.saturating_sub(POOL_LABEL_SIZE as u64);
    file.seek(SeekFrom::Start(secondary_offset))
        .map_err(|e| LabelInitError::Io {
            device_path: device_path.to_path_buf(),
            msg: format!("seek secondary: {e}"),
        })?;
    file.write_all(&full_buf).map_err(|e| LabelInitError::Io {
        device_path: device_path.to_path_buf(),
        msg: format!("write label 1: {e}"),
    })?;
    file.sync_all().map_err(|e| LabelInitError::Io {
        device_path: device_path.to_path_buf(),
        msg: format!("fsync label 1: {e}"),
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// pool_create — orchestrate label initialization across all devices
// ---------------------------------------------------------------------------

/// Create a new pool by writing initial labels to all devices.
///
/// This is the primary entry point for pool creation.  It:
/// 1. Validates topology constraints.
/// 2. Generates random pool and device GUIDs.
/// 3. Creates sealed `PoolLabelV1` instances for each leaf device.
/// 4. Writes the labels to each device (primary + secondary copies).
/// 5. Returns a `PoolCreateResult` with the assigned UUIDs and topology.
#[cfg(test)]
pub fn pool_create(
    device_tree: &DeviceType,
    pool_name: &str,
    feature_flags: u64,
    force: bool,
) -> Result<PoolCreateResult, LabelInitError> {
    let result = create_initial_labels(device_tree, pool_name, feature_flags)?;

    for (device_path, label) in &result.device_labels {
        // Determine capacity from the device tree leaf.
        let capacity = get_leaf_capacity(device_tree, device_path);
        write_label_to_device(device_path, label, capacity, force)?;
    }

    Ok(result)
}

/// Look up the capacity_bytes for a leaf device path in the device tree.
#[cfg(test)]
fn get_leaf_capacity(tree: &DeviceType, device_path: &Path) -> u64 {
    let leaves = collect_leaves(tree);
    for leaf in &leaves {
        if leaf.device_path == device_path {
            return leaf.capacity_bytes;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;
    #[cfg(test)]
    use tidefs_types_pool_label_core::{decode_label, POOL_LABEL_SIZE};

    /// Build a single-device Leaf topology for testing.
    fn single_device_tree(path: &Path, capacity: u64) -> DeviceType {
        DeviceType::Leaf {
            device_path: path.to_path_buf(),
            device_guid: [0u8; 16],
            device_index: 0,
            capacity_bytes: capacity,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        }
    }

    /// Build a pool-wide data-member topology for testing.
    fn pool_wide_data_tree(paths: &[PathBuf], capacities: &[u64]) -> DeviceType {
        let children: Vec<DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| DeviceType::Leaf {
                device_path: p.clone(),
                device_guid: [0u8; 16],
                device_index: i as u32,
                capacity_bytes: capacities[i],
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        DeviceType::PoolWideData { children }
    }

    /// Build a parity_raid1 (single parity) topology.
    fn parity_raid1_tree(paths: &[PathBuf], capacities: &[u64]) -> DeviceType {
        let children: Vec<DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| DeviceType::Leaf {
                device_path: p.clone(),
                device_guid: [0u8; 16],
                device_index: i as u32,
                capacity_bytes: capacities[i],
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        DeviceType::ParityRaid {
            parity: 1,
            children,
        }
    }

    /// Create a file of `size` bytes filled with zeros.
    fn create_device_file(path: &Path, size: u64) {
        let f = File::create(path).unwrap();
        f.set_len(size).unwrap();
    }

    // -- create_initial_labels tests --

    #[test]
    fn single_device_stripe_creation() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");

        let tree = single_device_tree(&dev_path, 1024 * 1024);
        let result = create_initial_labels(&tree, "stripepool", 0).unwrap();

        assert_eq!(result.pool_name, "stripepool");
        assert_eq!(result.device_count, 1);
        assert_eq!(result.topology_generation, 1);
        assert_eq!(result.device_labels.len(), 1);

        let (path, label) = &result.device_labels[0];
        assert_eq!(*path, dev_path);
        assert_eq!(label.pool_name_str(), "stripepool");
        assert_eq!(label.device_index, 0);
        assert_eq!(label.device_count, 1);
        assert_eq!(label.pool_state, PoolState::Active);
        assert_eq!(label.device_health, 0); // ONLINE
        assert_eq!(label.commit_group, 0);
        assert_eq!(label.topology_generation, 1);
        // pool_guid should be non-zero (random).
        assert_ne!(label.pool_guid, [0u8; 16]);
        assert_ne!(label.device_guid, [0u8; 16]);
        // pool_guid must match result.
        assert_eq!(label.pool_guid, result.pool_guid);
    }

    #[test]
    fn two_way_mirror_creation() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..2)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = vec![1024 * 1024; 2];

        let tree = pool_wide_data_tree(&paths, &capacities);
        let result = create_initial_labels(&tree, "mirrorpool", 0).unwrap();

        assert_eq!(result.device_count, 2);
        assert_eq!(result.device_labels.len(), 2);

        // Both labels share the same pool_guid.
        let (_, label0) = &result.device_labels[0];
        let (_, label1) = &result.device_labels[1];
        assert_eq!(label0.pool_guid, label1.pool_guid);
        assert_eq!(label0.pool_name_str(), "mirrorpool");
        assert_eq!(label1.pool_name_str(), "mirrorpool");

        // Device indices are 0 and 1.
        assert_eq!(label0.device_index, 0);
        assert_eq!(label1.device_index, 1);

        // Device GUIDs differ.
        assert_ne!(label0.device_guid, label1.device_guid);

        // Both marked ONLINE.
        assert_eq!(label0.device_health, 0);
        assert_eq!(label1.device_health, 0);
    }

    #[test]
    fn parity_raid1_three_disk_creation() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = vec![1024 * 1024; 3];

        let tree = parity_raid1_tree(&paths, &capacities);
        let result = create_initial_labels(&tree, "parity_raidpool", 0).unwrap();

        assert_eq!(result.device_count, 3);
        assert_eq!(result.device_labels.len(), 3);

        // All labels share the same pool_guid.
        let pool_guid = result.device_labels[0].1.pool_guid;
        for (_, label) in &result.device_labels {
            assert_eq!(label.pool_guid, pool_guid);
        }
    }

    #[test]
    fn parity_raid1_minimum_device_check() {
        // 2 devices is too few for parity_raid1 (needs 3: 1 parity + 2 data).
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..2)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = vec![1024 * 1024; 2];
        let tree = parity_raid1_tree(&paths, &capacities);

        let result = create_initial_labels(&tree, "badparity_raid", 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabelInitError::TopologyError { msg } => {
                assert!(msg.contains("parity_raid1"));
                assert!(msg.contains("requires at least 3"));
            }
            e => panic!("expected TopologyError, got {e}"),
        }
    }

    #[test]
    fn mirror_minimum_device_check() {
        // 1 device is too few for mirror.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("device0");

        let tree = DeviceType::Mirror {
            children: vec![DeviceType::Leaf {
                device_path: path.clone(),
                device_guid: [0u8; 16],
                device_index: 0,
                capacity_bytes: 1024 * 1024,
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            }],
        };

        let result = create_initial_labels(&tree, "badmirror", 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabelInitError::TopologyError { msg } => {
                assert!(msg.contains("mirror"));
                assert!(msg.contains("at least 2"));
            }
            e => panic!("expected TopologyError, got {e}"),
        }
    }

    #[test]
    fn empty_pool_rejected() {
        let tree = DeviceType::Mirror { children: vec![] };
        let result = create_initial_labels(&tree, "empty", 0);
        assert!(result.is_err());
    }

    #[test]
    fn pool_guid_is_random() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let tree = single_device_tree(&dev_path, 1024 * 1024);

        let result1 = create_initial_labels(&tree, "pool1", 0).unwrap();
        let result2 = create_initial_labels(&tree, "pool2", 0).unwrap();

        // Two calls should produce different pool GUIDs.
        assert_ne!(result1.pool_guid, result2.pool_guid);
    }

    #[test]
    fn feature_flags_encoded() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let tree = single_device_tree(&dev_path, 1024 * 1024);

        let result = create_initial_labels(&tree, "featurepool", 0x42).unwrap();
        let (_, label) = &result.device_labels[0];

        // POOL_LABEL_V1 is always set in incompat flags.
        assert_eq!(label.features_incompat, features::POOL_LABEL_V1);
        // Compat flags should have the non-incompat bits.
        assert_eq!(label.features_compat, 0x42);
    }

    // -- write_label_to_device tests --

    #[test]
    fn write_and_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024; // 1 MiB

        create_device_file(&dev_path, capacity);

        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "roundtrip", 0).unwrap();
        let (_, label) = &result.device_labels[0];

        write_label_to_device(&dev_path, label, capacity, false).unwrap();

        // Read it back and verify.
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();

        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.pool_guid, label.pool_guid);
        assert_eq!(decoded.device_guid, label.device_guid);
        assert_eq!(decoded.pool_name_str(), "roundtrip");
        assert_eq!(decoded.pool_state, PoolState::Active);
        assert_eq!(decoded.checksum, label.checksum);
    }

    #[test]
    fn secondary_label_written_and_readable() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024; // 1 MiB

        create_device_file(&dev_path, capacity);

        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "secondary", 0).unwrap();
        let (_, label) = &result.device_labels[0];

        write_label_to_device(&dev_path, label, capacity, false).unwrap();

        // Read secondary copy.
        let mut file = File::open(&dev_path).unwrap();
        let secondary_offset = capacity - POOL_LABEL_SIZE as u64;
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.seek(SeekFrom::Start(secondary_offset)).unwrap();
        file.read_exact(&mut buf).unwrap();

        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.pool_name_str(), "secondary");
        assert_eq!(decoded.checksum, label.checksum);
    }

    #[test]
    fn existing_label_rejected() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;

        create_device_file(&dev_path, capacity);

        // Write a label first.
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "first", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();

        // Try to write again without force.
        let result2 = create_initial_labels(&tree, "second", 0).unwrap();
        let (_, label2) = &result2.device_labels[0];
        let err = write_label_to_device(&dev_path, label2, capacity, false).unwrap_err();
        match err {
            LabelInitError::ExistingLabel {
                existing_pool_name, ..
            } => {
                assert_eq!(existing_pool_name, "first");
            }
            e => panic!("expected ExistingLabel, got {e}"),
        }
    }

    #[test]
    fn force_overwrite_existing_label() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;

        create_device_file(&dev_path, capacity);

        // Write first label.
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "first", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();

        // Force overwrite with second label.
        let result2 = create_initial_labels(&tree, "second", 0).unwrap();
        let (_, label2) = &result2.device_labels[0];
        write_label_to_device(&dev_path, label2, capacity, true).unwrap();

        // Verify the second label is now on disk.
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.pool_name_str(), "second");
    }

    #[test]
    fn device_too_small_rejected() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 512; // Way too small

        create_device_file(&dev_path, capacity);

        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "small", 0).unwrap();
        let (_, label) = &result.device_labels[0];

        let err = write_label_to_device(&dev_path, label, capacity, false).unwrap_err();
        match err {
            LabelInitError::DeviceTooSmall { .. } => {}
            e => panic!("expected DeviceTooSmall, got {e}"),
        }
    }

    // -- pool_create integration tests --

    #[test]
    fn pool_create_single_device() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;

        create_device_file(&dev_path, capacity);

        let tree = single_device_tree(&dev_path, capacity);
        let result = pool_create(&tree, "integration", 0, false).unwrap();

        assert_eq!(result.pool_name, "integration");
        assert_eq!(result.device_count, 1);

        // Verify label was written.
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.pool_name_str(), "integration");
        assert_eq!(decoded.pool_guid, result.pool_guid);
    }

    #[test]
    fn pool_create_mirror() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..2)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = vec![1024 * 1024; 2];
        for (p, &c) in paths.iter().zip(&capacities) {
            create_device_file(p, c);
        }

        let tree = pool_wide_data_tree(&paths, &capacities);
        let result = pool_create(&tree, "mirrorint", 0, false).unwrap();

        assert_eq!(result.device_count, 2);

        // Both devices should have labels with the same pool GUID.
        let mut pool_guids = Vec::new();
        for p in &paths {
            let mut file = File::open(p).unwrap();
            let mut buf = vec![0u8; POOL_LABEL_SIZE];
            file.read_exact(&mut buf).unwrap();
            let decoded = decode_label(&buf).unwrap();
            pool_guids.push(decoded.pool_guid);
        }
        assert_eq!(pool_guids[0], pool_guids[1]);
        assert_eq!(pool_guids[0], result.pool_guid);
    }

    #[test]
    fn label_init_error_display() {
        let err = LabelInitError::TopologyError {
            msg: "bad stuff".to_string(),
        };
        assert!(format!("{err}").contains("bad stuff"));

        let err = LabelInitError::ExistingLabel {
            device_path: PathBuf::from("/dev/sda"),
            existing_pool_name: "oldpool".to_string(),
        };
        assert!(format!("{err}").contains("/dev/sda"));
        assert!(format!("{err}").contains("oldpool"));

        let err = LabelInitError::DeviceTooSmall {
            device_path: PathBuf::from("/dev/sdb"),
            size_bytes: 100,
        };
        let msg = format!("{err}");
        assert!(msg.contains("/dev/sdb"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn collect_leaves_flat() {
        let path = PathBuf::from("/dev/sda");
        let tree = DeviceType::Leaf {
            device_path: path.clone(),
            device_guid: [0u8; 16],
            device_index: 0,
            capacity_bytes: 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].device_path, path);
    }

    #[test]
    fn collect_leaves_nested_mirror() {
        let paths: Vec<_> = (0..3)
            .map(|i| PathBuf::from(format!("/dev/sd{}", (b'a' + i as u8) as char)))
            .collect();
        let children: Vec<DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| DeviceType::Leaf {
                device_path: p.clone(),
                device_guid: [0u8; 16],
                device_index: i as u32,
                capacity_bytes: 1024,
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        let tree = DeviceType::Mirror { children };
        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 3);
    }

    // -- Comprehensive round-trip tests --

    /// Verify every field of a written label survives the round-trip.
    #[test]
    fn roundtrip_all_fields_preserved() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 2 * 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "allfields", 0xAB).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.magic, label.magic);
        assert_eq!(decoded.version, label.version);
        assert_eq!(decoded.pool_guid, label.pool_guid);
        assert_eq!(decoded.device_guid, label.device_guid);
        assert_eq!(decoded.pool_name_len, label.pool_name_len);
        assert_eq!(decoded.pool_name, label.pool_name);
        assert_eq!(decoded.pool_state, label.pool_state);
        assert_eq!(decoded.commit_group, label.commit_group);
        assert_eq!(decoded.label_commit_group, label.label_commit_group);
        assert_eq!(decoded.device_index, label.device_index);
        assert_eq!(decoded.topology_generation, label.topology_generation);
        assert_eq!(decoded.device_count, label.device_count);
        assert_eq!(decoded.device_class, label.device_class);
        assert_eq!(decoded.device_capacity_bytes, label.device_capacity_bytes);
        assert_eq!(decoded.system_area_pointer, label.system_area_pointer);
        assert_eq!(decoded.system_area_size, label.system_area_size);
        assert_eq!(decoded.features_incompat, label.features_incompat);
        assert_eq!(decoded.features_ro_compat, label.features_ro_compat);
        assert_eq!(decoded.features_compat, label.features_compat);
        assert_eq!(decoded.device_health, label.device_health);
        assert_eq!(decoded.device_read_errors, label.device_read_errors);
        assert_eq!(decoded.device_write_errors, label.device_write_errors);
        assert_eq!(decoded.device_checksum_errors, label.device_checksum_errors);
        assert_eq!(decoded.checksum, label.checksum);
    }

    /// Verify pool_create round-trip preserves all fields.
    #[test]
    fn pool_create_roundtrip_all_fields() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 2 * 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = pool_create(&tree, "integration_full", 0x07, false).unwrap();
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        let (_, expected) = &result.device_labels[0];
        assert_eq!(decoded.pool_guid, expected.pool_guid);
        assert_eq!(decoded.device_guid, expected.device_guid);
        assert_eq!(decoded.pool_name_str(), "integration_full");
        assert_eq!(decoded.pool_state, PoolState::Active);
        assert_eq!(decoded.device_index, 0);
        assert_eq!(decoded.device_count, 1);
        assert_eq!(decoded.topology_generation, 1);
        assert_eq!(decoded.commit_group, 0);
        assert_eq!(decoded.label_commit_group, 0);
        assert_eq!(decoded.device_health, 0);
        assert_eq!(decoded.checksum, expected.checksum);
    }

    // -- Checksum mismatch tests --

    /// Flip body byte before checksum: decode must return ChecksumMismatch.
    #[test]
    fn checksum_mismatch_body_byte_flip() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "cksumtest", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&dev_path)
            .unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        match decode_label(&buf) {
            Err(LabelError::ChecksumMismatch) => {}
            Err(e) => panic!("expected ChecksumMismatch, got {e:?}"),
            Ok(_) => panic!("expected ChecksumMismatch, decoded successfully"),
        }
    }

    /// Flip byte in checksum field: decode must return ChecksumMismatch.
    #[test]
    fn checksum_mismatch_checksum_field_flip() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "cksumtest2", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&dev_path)
            .unwrap();
        file.seek(SeekFrom::Start(410)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(410)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        match decode_label(&buf) {
            Err(LabelError::ChecksumMismatch) => {}
            Err(e) => panic!("expected ChecksumMismatch, got {e:?}"),
            Ok(_) => panic!("expected ChecksumMismatch, decoded successfully"),
        }
    }

    /// Corrupt magic bytes: decode must return BadMagic (before checksum check).
    #[test]
    fn bad_magic_detected_before_checksum() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "magictest", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&dev_path)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"BADC").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        match decode_label(&buf) {
            Err(LabelError::BadMagic) => {}
            Err(e) => panic!("expected BadMagic, got {e:?}"),
            Ok(_) => panic!("expected BadMagic, decoded successfully"),
        }
    }

    // -- Secondary-label fallback tests --

    /// Corrupt primary copy; secondary must still decode correctly.
    #[test]
    fn secondary_label_fallback_on_primary_corruption() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "fallback", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&dev_path)
            .unwrap();
        file.seek(SeekFrom::Start(42)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(42)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        assert!(decode_label(&buf).is_err());
        let secondary_offset = capacity - POOL_LABEL_SIZE as u64;
        let mut file = File::open(&dev_path).unwrap();
        file.seek(SeekFrom::Start(secondary_offset)).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.pool_guid, label.pool_guid);
        assert_eq!(decoded.device_guid, label.device_guid);
        assert_eq!(decoded.pool_name_str(), "fallback");
        assert_eq!(decoded.pool_state, PoolState::Active);
        assert_eq!(decoded.checksum, label.checksum);
    }

    /// Corrupt both primary and secondary copies; both must fail.
    #[test]
    fn double_corruption_both_copies_fail() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "doublebad", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&dev_path)
            .unwrap();
        file.seek(SeekFrom::Start(80)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(80)).unwrap();
        file.write_all(&byte).unwrap();
        let secondary_offset = capacity - POOL_LABEL_SIZE as u64;
        file.seek(SeekFrom::Start(secondary_offset + 80)).unwrap();
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(secondary_offset + 80)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        assert!(decode_label(&buf).is_err());
        let mut file = File::open(&dev_path).unwrap();
        file.seek(SeekFrom::Start(secondary_offset)).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        assert!(decode_label(&buf).is_err());
    }

    // -- Force-overwrite tests --

    /// Force-overwrite must update both primary and secondary copies.
    #[test]
    fn force_overwrite_updates_both_copies() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result1 = create_initial_labels(&tree, "first", 0).unwrap();
        let (_, label1) = &result1.device_labels[0];
        write_label_to_device(&dev_path, label1, capacity, false).unwrap();
        let result2 = create_initial_labels(&tree, "second", 0).unwrap();
        let (_, label2) = &result2.device_labels[0];
        write_label_to_device(&dev_path, label2, capacity, true).unwrap();
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let primary = decode_label(&buf).unwrap();
        assert_eq!(primary.pool_name_str(), "second");
        assert_eq!(primary.pool_guid, result2.pool_guid);
        let secondary_offset = capacity - POOL_LABEL_SIZE as u64;
        let mut file = File::open(&dev_path).unwrap();
        file.seek(SeekFrom::Start(secondary_offset)).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let secondary = decode_label(&buf).unwrap();
        assert_eq!(secondary.pool_name_str(), "second");
        assert_eq!(secondary.pool_guid, result2.pool_guid);
    }

    // -- Invalid parity topology rejection --

    #[test]
    fn parity_raid_zero_parity_rejected() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = [1024 * 1024; 3];
        let children: Vec<DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| DeviceType::Leaf {
                device_path: p.clone(),
                device_guid: [0u8; 16],
                device_index: i as u32,
                capacity_bytes: capacities[i],
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        let tree = DeviceType::ParityRaid {
            parity: 0,
            children,
        };
        let result = create_initial_labels(&tree, "badparity", 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabelInitError::TopologyError { msg } => assert!(msg.contains("parity")),
            e => panic!("expected TopologyError, got {e}"),
        }
    }

    #[test]
    fn parity_raid_four_parity_rejected() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..6)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = [1024 * 1024; 6];
        let children: Vec<DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| DeviceType::Leaf {
                device_path: p.clone(),
                device_guid: [0u8; 16],
                device_index: i as u32,
                capacity_bytes: capacities[i],
                device_class: DeviceClass::Hdd,
                health: DeviceHealth::Online,
                read_errors: 0,
                write_errors: 0,
                checksum_errors: 0,
            })
            .collect();
        let tree = DeviceType::ParityRaid {
            parity: 4,
            children,
        };
        let result = create_initial_labels(&tree, "badparity4", 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            LabelInitError::TopologyError { msg } => assert!(msg.contains("parity")),
            e => panic!("expected TopologyError, got {e}"),
        }
    }

    // -- Multiple devices round-trip --

    #[test]
    fn mirror_multi_device_full_roundtrip() {
        let dir = TempDir::new().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|i| dir.path().join(format!("device{i}")))
            .collect();
        let capacities = vec![2 * 1024 * 1024; 3];
        for (p, &c) in paths.iter().zip(&capacities) {
            create_device_file(p, c);
        }
        let tree = pool_wide_data_tree(&paths, &capacities);
        let result = pool_create(&tree, "multi_mirror", 0, false).unwrap();
        assert_eq!(result.device_count, 3);
        for (i, (dev_path, label)) in result.device_labels.iter().enumerate() {
            let mut file = File::open(dev_path).unwrap();
            let mut buf = vec![0u8; POOL_LABEL_SIZE];
            file.read_exact(&mut buf).unwrap();
            let decoded = decode_label(&buf).unwrap();
            assert_eq!(decoded.pool_guid, label.pool_guid);
            assert_eq!(decoded.device_guid, label.device_guid);
            assert_eq!(decoded.device_index, i as u32);
            assert_eq!(decoded.device_count, 3);
            assert_eq!(decoded.pool_name_str(), "multi_mirror");
            assert_eq!(decoded.pool_state, PoolState::Active);
            assert_eq!(decoded.device_health, 0);
            assert_eq!(decoded.checksum, label.checksum);
        }
    }

    #[test]
    fn write_to_nonexistent_device() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 1024 * 1024;
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "noexist", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        let err = write_label_to_device(&dev_path, label, capacity, false).unwrap_err();
        match err {
            LabelInitError::Io { device_path, msg } => {
                assert_eq!(device_path, dev_path);
                assert!(msg.contains("open"));
            }
            e => panic!("expected Io error, got {e}"),
        }
    }

    #[test]
    fn minimum_capacity_accepted() {
        let dir = TempDir::new().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = (POOL_LABEL_SIZE * 2) as u64;
        create_device_file(&dev_path, capacity);
        let tree = single_device_tree(&dev_path, capacity);
        let result = create_initial_labels(&tree, "minsize", 0).unwrap();
        let (_, label) = &result.device_labels[0];
        write_label_to_device(&dev_path, label, capacity, false).unwrap();
        let mut file = File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let primary = decode_label(&buf).unwrap();
        assert_eq!(primary.pool_name_str(), "minsize");
        let secondary_offset = capacity - POOL_LABEL_SIZE as u64;
        let mut file = File::open(&dev_path).unwrap();
        file.seek(SeekFrom::Start(secondary_offset)).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        file.read_exact(&mut buf).unwrap();
        let secondary = decode_label(&buf).unwrap();
        assert_eq!(secondary.pool_name_str(), "minsize");
    }
}
