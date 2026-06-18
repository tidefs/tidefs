// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool creation: initialize byte-addressable pool devices with TideFS labels,
//! superblock data, and an initial committed root.
//!
//! This is the bootstrap path that writes the initial on-disk structures
//! needed to make a pool importable.  Each device receives dual-copy
//! BLAKE3-verified pool labels (at offset 0 and at the end of the device)
//! plus an initial committed-root region so that pool import can locate
//! a valid starting epoch.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tidefs_commit_group::{seal_commit_hash, CommitGroupId, RootPointer};
use tidefs_encryption::StoreKey;
use tidefs_pool_scan::PoolDeviceBacking;
use tidefs_types_pool_label_core::{
    decode_label, encode_label, encode_vcrl_ledger_into, pool_guid_to_uuid32, seal_label,
    vcrl_required_len, DeviceClass, LabelError, PoolLabelV1, PoolState, VcrlEntry, POOL_LABEL_SIZE,
};

use crate::committed_root::{
    encode_commit_record_region, CommittedRoot, ParsedCommitRecord, COMMIT_RECORD_REGION_MAX,
    COMMIT_RECORD_REGION_OFFSET,
};
use tidefs_auth::local_only::LocalOnlyGuard;

/// Pool-wide redundancy policy accepted by pool creation.
pub use tidefs_types_pool_label_core::PoolRedundancyPolicy as RedundancyPolicy;

const MIN_DEVICE_BYTES: u64 =
    (2 * POOL_LABEL_SIZE as u64) + COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX;
const INITIAL_ROOT_INO: u64 = 1;
const INITIAL_TXG: u64 = 1;
const INITIAL_SYSTEM_AREA_BLOCK_SIZE: u64 = 4096;
const INITIAL_SYSTEM_AREA_BLOCKS: u64 = 4;
const INITIAL_SYSTEM_AREA_SIZE: u64 = INITIAL_SYSTEM_AREA_BLOCK_SIZE * INITIAL_SYSTEM_AREA_BLOCKS;
const INITIAL_SYSTEM_AREA_OFFSET: u64 =
    COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX - INITIAL_SYSTEM_AREA_SIZE;

// ---------------------------------------------------------------------------
// PoolCreateConfig
// ---------------------------------------------------------------------------

/// Configuration for creating a new TideFS pool.
#[derive(Clone, Debug)]
pub struct PoolCreateConfig {
    /// Human-readable pool name (max 255 bytes UTF-8).
    pub pool_name: String,
    /// Pool GUID (UUID v4).  Auto-generated from `/dev/urandom` when `None`.
    pub pool_guid: Option<[u8; 16]>,
    /// Redundancy policy for the pool.
    pub redundancy: RedundancyPolicy,
    /// When `Some`, mark the pool as encrypted and use this key
    /// for all stored data.  The key must be obtained from a
    /// [`PoolEncryptionKeyLease`] issued via a [`PoolEncryptionSecretHandle`].
    ///
    /// When `None`, the pool is created unencrypted (plaintext).
    ///
    /// [`PoolEncryptionKeyLease`]: tidefs_encryption::PoolEncryptionKeyLease
    /// [`PoolEncryptionSecretHandle`]: tidefs_encryption::PoolEncryptionSecretHandle
    pub encryption_key: Option<StoreKey>,
    /// When true, set CLUSTER_POOL_INCOMPAT and CLUSTER_POOL_COMPAT feature
    /// flags so pool labels advertise clustered operation.
    pub clustered: bool,
}

// ---------------------------------------------------------------------------
// PoolCreateOutcome
// ---------------------------------------------------------------------------

/// Outcome of a successful pool creation.
#[derive(Clone, Debug)]
pub struct PoolCreateOutcome {
    /// Pool GUID assigned to the pool.
    pub pool_guid: [u8; 16],
    /// Pool name.
    pub pool_name: String,
    /// Number of devices in the pool.
    pub device_count: u32,
    /// Pool-wide redundancy policy persisted in every pool label.
    pub redundancy: RedundancyPolicy,
    /// Pool operational state after creation.
    pub state: PoolState,
    /// Whether the pool was created with per-object encryption enabled.
    pub encrypted: bool,
    /// Per-device GUIDs assigned during label creation (one per device).
    pub device_guids: Vec<[u8; 16]>,
    /// Explicit backing media accepted for each created device.
    pub device_backings: Vec<PoolDeviceBacking>,
    /// Hex key fingerprint (first 8 bytes of BLAKE3 keyed hash of the
    /// encryption key) for operator verification.  `None` when unencrypted.
    pub encryption_key_fingerprint: Option<String>,
    /// The initial committed root (epoch 1, empty dirty set).
    pub committed_root: CommittedRoot,
}

// ---------------------------------------------------------------------------
// CreateError
// ---------------------------------------------------------------------------

/// Errors that can occur during pool creation.
#[derive(Debug)]
pub enum CreateError {
    /// A device path could not be opened.
    DeviceOpen {
        /// Device path that failed to open.
        device_path: PathBuf,
        /// OS-level error description.
        msg: String,
    },
    /// Device is too small to hold a pool (needs room for two labels and
    /// the commit-record region).
    DeviceTooSmall {
        /// Device path.
        device_path: PathBuf,
        /// Capacity in bytes of the device.
        capacity_bytes: u64,
        /// Minimum required capacity in bytes.
        required_bytes: u64,
    },
    /// Device already has a valid pool label whose pool GUID differs from
    /// the one being created.
    DeviceAlreadyLabeled {
        /// Device path.
        device_path: PathBuf,
        /// Existing pool GUID found on the device.
        existing_pool_guid: [u8; 16],
    },
    /// An I/O error occurred during reads or writes.
    Io {
        /// Device path, if known.
        device_path: Option<PathBuf>,
        /// Error description.
        msg: String,
    },
    /// Label encoding or sealing error.
    Label(LabelError),
    /// No devices were specified.
    NoDevices,
    /// The requested redundancy policy cannot be satisfied by the device set.
    InvalidRedundancyPolicy {
        /// Requested policy.
        policy: RedundancyPolicy,
        /// Number of byte-addressable devices supplied.
        device_count: u32,
        /// Human-readable reason.
        reason: String,
    },
    /// Caller is not in a local process context -- privileged operation refused.
    NotLocal {
        operation: &'static str,
        reason: String,
    },
}

impl std::fmt::Display for CreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceOpen { device_path, msg } => {
                write!(f, "failed to open device {}: {msg}", device_path.display())
            }
            Self::DeviceTooSmall {
                device_path,
                capacity_bytes,
                required_bytes,
            } => {
                write!(
                    f,
                    "device {} is too small: {capacity_bytes} bytes, {required_bytes} required",
                    device_path.display()
                )
            }
            Self::DeviceAlreadyLabeled {
                device_path,
                existing_pool_guid,
            } => {
                write!(
                    f,
                    "device {} already labeled with pool {existing_pool_guid:02x?}",
                    device_path.display()
                )
            }
            Self::Io { device_path, msg } => {
                if let Some(p) = device_path {
                    write!(f, "I/O error on {}: {msg}", p.display())
                } else {
                    write!(f, "I/O error: {msg}")
                }
            }
            Self::Label(e) => write!(f, "label error: {e}"),
            Self::InvalidRedundancyPolicy {
                policy,
                device_count,
                reason,
            } => write!(
                f,
                "invalid redundancy policy {policy} for {device_count} device(s): {reason}"
            ),
            Self::NotLocal { operation, reason } => {
                write!(
                    f,
                    "privileged operation '{operation}' requires local execution: {reason}"
                )
            }
            Self::NoDevices => write!(f, "no devices specified for pool creation"),
        }
    }
}

impl From<tidefs_auth::local_only::LocalOnlyError> for CreateError {
    fn from(err: tidefs_auth::local_only::LocalOnlyError) -> Self {
        match err {
            tidefs_auth::local_only::LocalOnlyError::NotLocal { operation, reason } => {
                Self::NotLocal { operation, reason }
            }
            tidefs_auth::local_only::LocalOnlyError::NoProcessIdentity { operation } => {
                Self::NotLocal {
                    operation,
                    reason: "no local process identity".to_string(),
                }
            }
        }
    }
}
impl std::error::Error for CreateError {}

impl From<LabelError> for CreateError {
    fn from(e: LabelError) -> Self {
        Self::Label(e)
    }
}

// ---------------------------------------------------------------------------
// Internal: open-device handle
// ---------------------------------------------------------------------------

/// An open byte-addressable device path used during pool creation.
///
/// Production callers pass block devices. Development callers may pass regular
/// files. Directories and other special files are not pool devices.
struct CreationDevice {
    /// Absolute path to the device.
    device_path: PathBuf,
    /// 0-based device index.
    device_index: u32,
    /// Total capacity in bytes.
    capacity_bytes: u64,
    /// Explicit backing media classification.
    backing: PoolDeviceBacking,
    /// Opened read/write file handle.
    file: File,
}

impl CreationDevice {
    /// Open a pool device for creation. Fails if the path does not exist,
    /// is not a block device or regular file, or cannot be opened read/write.
    fn open(path: &Path, device_index: u32) -> Result<Self, CreateError> {
        let backing = tidefs_pool_scan::classify_pool_device_backing(path).map_err(|e| {
            CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("{e}"),
            }
        })?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("{e}"),
            })?;

        let capacity_bytes =
            tidefs_pool_scan::device_capacity_bytes(path).map_err(|e| CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("device capacity: {e}"),
            })?;

        // Reject devices that are too small.
        if capacity_bytes < MIN_DEVICE_BYTES {
            return Err(CreateError::DeviceTooSmall {
                device_path: path.to_path_buf(),
                capacity_bytes,
                required_bytes: MIN_DEVICE_BYTES,
            });
        }

        Ok(Self {
            device_path: path.to_path_buf(),
            device_index,
            capacity_bytes,
            backing,
            file,
        })
    }

    /// Flush stdio state and force the device/file contents to stable storage.
    fn flush_and_sync(&mut self, action: &'static str) -> Result<(), CreateError> {
        self.file.flush().map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("flush {action}: {e}"),
        })?;
        self.file.sync_all().map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("sync {action}: {e}"),
        })?;
        Ok(())
    }

    /// Read and decode a pool label at `offset`.
    fn read_label_at(&mut self, offset: u64) -> Result<PoolLabelV1, CreateError> {
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek: {e}"),
            })?;
        self.file
            .read_exact(&mut buf)
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("read at {offset}: {e}"),
            })?;

        decode_label(&buf).map_err(CreateError::Label)
    }

    /// Encode and write a sealed label at `offset`.
    fn write_label_at(&mut self, label: &PoolLabelV1, offset: u64) -> Result<(), CreateError> {
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        encode_label(label, &mut buf)?;

        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek: {e}"),
            })?;
        self.file.write_all(&buf).map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("write at {offset}: {e}"),
        })?;
        self.flush_and_sync("pool label")?;
        Ok(())
    }

    /// Write the commit-record region blob at the standard offset.
    fn write_commit_region(&mut self, region: &[u8]) -> Result<(), CreateError> {
        if region.len() > COMMIT_RECORD_REGION_MAX as usize {
            return Err(CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!(
                    "commit region too large: {} > {COMMIT_RECORD_REGION_MAX}",
                    region.len()
                ),
            });
        }

        self.file
            .seek(SeekFrom::Start(COMMIT_RECORD_REGION_OFFSET))
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek commit region: {e}"),
            })?;
        self.file.write_all(region).map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("write commit region: {e}"),
        })?;
        self.flush_and_sync("commit region")?;
        Ok(())
    }

    /// Write the kmod-readable committed-root ledger into the label-advertised
    /// system area. The initial image reserves four 4 KiB blocks so the
    /// mounted kernel path can later add duplicate VCRP pointer records and a
    /// VRBT committed-root block beside the VCRL ledger without overwriting the
    /// userspace VBCR commit-record region.
    fn write_system_area(&mut self, area: &[u8]) -> Result<(), CreateError> {
        if area.len() > INITIAL_SYSTEM_AREA_SIZE as usize {
            return Err(CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!(
                    "system area too large: {} > {INITIAL_SYSTEM_AREA_SIZE}",
                    area.len()
                ),
            });
        }

        let mut padded = vec![0u8; INITIAL_SYSTEM_AREA_SIZE as usize];
        padded[..area.len()].copy_from_slice(area);

        self.file
            .seek(SeekFrom::Start(INITIAL_SYSTEM_AREA_OFFSET))
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek system area: {e}"),
            })?;
        self.file.write_all(&padded).map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("write system area: {e}"),
        })?;
        self.flush_and_sync("system area")?;
        Ok(())
    }

    /// Zero the first 64 KiB of the data region (after the pool label).
    ///
    /// The data region starts at offset [`POOL_LABEL_SIZE`] and holds
    /// the object-store format header and record data.  Zeroing ensures
    /// that any stale format headers or records from a previous pool
    /// incarnation are cleared before first mount.
    fn zero_data_region_start(&mut self) -> Result<(), CreateError> {
        // Data region starts after the commit-record region:
        // COMMIT_RECORD_REGION_OFFSET (8 KiB) + COMMIT_RECORD_REGION_MAX (256 KiB) = 270336
        let data_start: u64 = COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX;
        let zero_len = 65536u64; // 64 KiB, enough for format header + first records
                                 // Clamp to device capacity to avoid writing past end of small devices.
        let len = zero_len.min(self.capacity_bytes.saturating_sub(data_start));
        if len == 0 {
            return Ok(());
        }
        let zeroes = vec![0u8; len as usize];
        self.file
            .seek(SeekFrom::Start(data_start))
            .map_err(|e| CreateError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek data region: {e}"),
            })?;
        self.file.write_all(&zeroes).map_err(|e| CreateError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("zero data region: {e}"),
        })?;
        self.flush_and_sync("data region zero")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PoolCreator
// ---------------------------------------------------------------------------

/// Creates TideFS pools on byte-addressable device paths.
///
/// This is the bootstrap path: it writes dual-copy BLAKE3-verified pool
/// labels to every device, initializes the superblock fields within the
/// labels, and writes an initial committed root so the pool is immediately
/// importable via [`crate::pool_import`].
///
/// # Example
///
/// ```ignore
/// use tidefs_pool_import::create::{PoolCreator, PoolCreateConfig, RedundancyPolicy};
///
/// let config = PoolCreateConfig {
///     pool_name: "mypool".into(),
///     pool_guid: None,
///     redundancy: RedundancyPolicy::replicated(1),
///     encryption_key: None,
/// };
/// let outcome = PoolCreator::create_pool(&["/dev/sda".into()], &config)?;
/// ```
pub struct PoolCreator;

impl PoolCreator {
    /// Create a new TideFS pool on the given block-device or regular-file paths.
    ///
    /// Writes dual-copy BLAKE3-verified pool labels (at offset 0 and at
    /// `capacity - POOL_LABEL_SIZE` on each device) and an initial
    /// committed-root region containing epoch 1 with no dirty objects.
    ///
    /// The pool is left in [`PoolState::Exported`] state so that a
    /// subsequent pool import will transition it to [`PoolState::Active`].
    ///
    /// # Errors
    ///
    /// Returns [`CreateError`] if any device is too small, already labeled
    /// with a conflicting pool GUID, missing, or experiences an I/O failure.
    pub fn create_pool(
        devices: &[PathBuf],
        config: &PoolCreateConfig,
    ) -> Result<PoolCreateOutcome, CreateError> {
        // Operator authorization boundary: pool create requires local execution.
        let _guard = LocalOnlyGuard::new("pool create")?;
        if devices.is_empty() {
            return Err(CreateError::NoDevices);
        }

        // Generate or use the provided pool GUID.
        let pool_guid = match config.pool_guid {
            Some(guid) => guid,
            None => filesystem_uuid().map_err(|e| CreateError::Io {
                device_path: None,
                msg: format!("generate pool GUID: {e}"),
            })?,
        };

        let device_count = devices.len() as u32;
        validate_redundancy_policy(config.redundancy, device_count)?;

        // Phase 1: open and validate every device.
        let mut handles: Vec<CreationDevice> = Vec::with_capacity(device_count as usize);
        for (i, path) in devices.iter().enumerate() {
            let mut handle = CreationDevice::open(path, i as u32)?;

            // Check for an existing label with a conflicting pool GUID.
            match handle.read_label_at(0) {
                Ok(existing) => {
                    if existing.pool_guid != pool_guid {
                        return Err(CreateError::DeviceAlreadyLabeled {
                            device_path: path.clone(),
                            existing_pool_guid: existing.pool_guid,
                        });
                    }
                    // Same pool GUID: device is already labeled for this
                    // pool — overwriting is safe (idempotent re-creation
                    // of a fresh pool).
                }
                Err(CreateError::Label(_)) => {
                    // No valid existing label — fine, we are creating one.
                }
                Err(e) => return Err(e),
            }

            handles.push(handle);
        }

        // Phase 2: build one label per device.
        let mut labels: Vec<PoolLabelV1> = Vec::with_capacity(device_count as usize);
        for handle in &handles {
            let device_guid = filesystem_uuid().map_err(|e| CreateError::Io {
                device_path: None,
                msg: format!("generate device GUID: {e}"),
            })?;

            let mut label = PoolLabelV1::new(pool_guid, device_guid, &config.pool_name);
            label.pool_state = PoolState::Exported;
            label.device_index = handle.device_index;
            label.device_count = device_count;
            label.topology_generation = 0;
            label.commit_group = INITIAL_TXG;
            label.label_commit_group = INITIAL_TXG;
            label.device_capacity_bytes = handle.capacity_bytes;
            label.system_area_pointer = INITIAL_SYSTEM_AREA_OFFSET;
            label.system_area_size = INITIAL_SYSTEM_AREA_SIZE;
            label.device_class = DeviceClass::Hdd;
            label.device_health = 0; // Online
            label.redundancy_policy = config.redundancy;
            label.features_incompat = tidefs_types_pool_label_core::features::POOL_LABEL_V1;
            label.features_compat = tidefs_types_pool_label_core::features::DEVICE_CLASS_AWARE;

            if config.clustered {
                label.set_clustered();
            }
            if config.encryption_key.is_some() {
                label.set_encrypted();
            }

            labels.push(label);
        }

        // Phase 3: seal labels with BLAKE3 and write dual copies.
        for (i, label) in labels.iter().enumerate() {
            let sealed = seal_label(label.clone())?;

            // Label 0 at offset 0.
            handles[i].write_label_at(&sealed, 0)?;

            // Label 1 near the end of the device.
            let label1_offset = handles[i]
                .capacity_bytes
                .saturating_sub(POOL_LABEL_SIZE as u64);
            handles[i].write_label_at(&sealed, label1_offset)?;
        }

        // Phase 4: create initial committed root (epoch 1, txg 1).
        let commitment_hash = seal_commit_hash(INITIAL_TXG, CommitGroupId(INITIAL_TXG), None, &[]);
        let root_pointer = RootPointer::new(CommitGroupId(INITIAL_TXG), 0);

        let record = ParsedCommitRecord {
            epoch_number: INITIAL_TXG,
            commit_group_id: INITIAL_TXG,
            commit_hash: commitment_hash,
            prior_epoch_hash: None,
            dirty_object_ids: vec![],
        };

        let region_bytes = encode_commit_record_region(&[record]);
        let vcrl_entry = VcrlEntry {
            root_ino: INITIAL_ROOT_INO,
            pool_uuid: pool_guid_to_uuid32(&pool_guid),
            txg: INITIAL_TXG,
        };
        let vcrl_len = vcrl_required_len(1).ok_or_else(|| CreateError::Io {
            device_path: None,
            msg: "compute initial VCRL length".to_string(),
        })?;
        let mut vcrl_bytes = vec![0u8; vcrl_len];
        encode_vcrl_ledger_into(&[vcrl_entry], &mut vcrl_bytes).map_err(|e| CreateError::Io {
            device_path: None,
            msg: format!("encode VCRL system area: {e:?}"),
        })?;

        // Write the userspace VBCR region and kmod-readable VCRL system area.
        for handle in &mut handles {
            handle.write_commit_region(&region_bytes)?;
            handle.write_system_area(&vcrl_bytes)?;
        }

        // Phase 5: zero the start of the data region on every device so
        // that stale format headers and records from previous pool
        // incarnations cannot be recovered by the object-store scan.
        for handle in &mut handles {
            handle.zero_data_region_start()?;
        }

        let committed_root = CommittedRoot::new(root_pointer, commitment_hash, INITIAL_TXG, 0);

        let device_guids: Vec<[u8; 16]> = labels.iter().map(|l| l.device_guid).collect();
        let device_backings: Vec<PoolDeviceBacking> = handles.iter().map(|h| h.backing).collect();

        Ok(PoolCreateOutcome {
            pool_guid,
            pool_name: config.pool_name.clone(),
            device_count,
            redundancy: config.redundancy,
            device_guids,
            device_backings,
            encrypted: config.encryption_key.is_some(),
            encryption_key_fingerprint: config.encryption_key.as_ref().map(|k| {
                let fp = blake3::keyed_hash(k.as_bytes(), b"tidefs-enc-fp");
                let mut hex = String::with_capacity(16);
                for b in &fp.as_bytes()[..8] {
                    use std::fmt::Write;
                    let _ = write!(hex, "{b:02x}");
                }
                hex
            }),
            state: PoolState::Exported,
            committed_root,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_redundancy_policy(
    policy: RedundancyPolicy,
    device_count: u32,
) -> Result<(), CreateError> {
    if !policy.is_well_formed() {
        let reason = match policy {
            RedundancyPolicy::Replicated { copies } if copies == 0 => {
                "replicated copies must be at least 1".to_string()
            }
            RedundancyPolicy::Erasure {
                data_shards,
                parity_shards,
            } if data_shards == 0 || parity_shards == 0 => {
                "erasure data and parity shards must both be at least 1".to_string()
            }
            _ => "policy is not well formed".to_string(),
        };
        return Err(CreateError::InvalidRedundancyPolicy {
            policy,
            device_count,
            reason,
        });
    }

    let required = policy.target_width() as u32;
    if required > device_count {
        return Err(CreateError::InvalidRedundancyPolicy {
            policy,
            device_count,
            reason: format!("requires at least {required} distinct device(s)"),
        });
    }

    Ok(())
}

/// Read 16 random bytes from `/dev/urandom`.
fn filesystem_uuid() -> Result<[u8; 16], std::io::Error> {
    let mut buf = [0u8; 16];
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use tidefs_types_pool_label_core::verify_label_checksum;

    /// Create a temporary file of `size` bytes and return its path.
    fn temp_device(dir: &TempDir, name: &str, size: u64) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.set_len(size).unwrap();
        f.flush().unwrap();
        path
    }

    /// Create a TempDir and a single temp device large enough for pool creation.
    fn setup_single_device(size: u64) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "device0", size);
        (dir, dev)
    }

    // -- basic creation tests --

    #[test]
    fn create_pool_single_device() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "testpool".into(),
            pool_guid: Some([0xABu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome.pool_name, "testpool");
        assert_eq!(outcome.pool_guid, [0xABu8; 16]);
        assert_eq!(outcome.device_count, 1);
        assert_eq!(
            outcome.device_backings,
            vec![PoolDeviceBacking::RegularFileDev]
        );
        assert_eq!(outcome.state, PoolState::Exported);
        assert!(outcome.committed_root.is_valid());
        assert_eq!(outcome.committed_root.epoch_number, 1);
    }

    #[test]
    fn create_pool_two_devices() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);

        let config = PoolCreateConfig {
            pool_name: "twodev".into(),
            pool_guid: Some([0xCDu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        let outcome = PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();
        assert_eq!(outcome.device_count, 2);
    }

    #[test]
    fn create_pool_auto_generated_guid() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "autoguid".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        // GUID must not be zero.
        assert_ne!(outcome.pool_guid, [0u8; 16]);
    }

    // -- label round-trip tests --

    #[test]
    fn labels_are_readable_after_creation() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "roundtrip".into(),
            pool_guid: Some([0xEFu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        // Re-open and read Label 0.
        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label0 = handle.read_label_at(0).unwrap();
        assert_eq!(label0.pool_guid, [0xEFu8; 16]);
        assert_eq!(label0.pool_name_str(), "roundtrip");
        assert_eq!(label0.pool_state, PoolState::Exported);
        assert_eq!(label0.device_count, 1);
        assert_eq!(label0.commit_group, INITIAL_TXG);
        assert_eq!(label0.label_commit_group, INITIAL_TXG);
        assert_eq!(label0.system_area_pointer, INITIAL_SYSTEM_AREA_OFFSET);
        assert_eq!(label0.system_area_size, INITIAL_SYSTEM_AREA_SIZE);
        assert!(verify_label_checksum(&label0));
    }

    #[test]
    fn create_pool_writes_kmod_readable_vcrl_system_area() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let pool_guid = [0x41u8; 16];
        let config = PoolCreateConfig {
            pool_name: "kmodroot".into(),
            pool_guid: Some(pool_guid),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        let mut area = vec![0u8; label.system_area_size as usize];
        handle
            .file
            .seek(SeekFrom::Start(label.system_area_pointer))
            .unwrap();
        handle.file.read_exact(&mut area).unwrap();

        assert_eq!(&area[0..4], &tidefs_types_pool_label_core::VCRL_MAGIC);
        assert_eq!(u32::from_le_bytes(area[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(area[8..12].try_into().unwrap()), 1);

        let entry_off = 12;
        assert_eq!(
            u64::from_le_bytes(area[entry_off..entry_off + 8].try_into().unwrap()),
            INITIAL_ROOT_INO
        );
        assert_eq!(
            &area[entry_off + 8..entry_off + 40],
            &pool_guid_to_uuid32(&pool_guid)
        );
        assert_eq!(
            u64::from_le_bytes(area[entry_off + 40..entry_off + 48].try_into().unwrap()),
            INITIAL_TXG
        );
        let digest: [u8; 32] = area[entry_off + 48..entry_off + 80].try_into().unwrap();
        assert_eq!(
            digest,
            tidefs_types_pool_label_core::compute_vcrl_entry_digest(
                INITIAL_ROOT_INO,
                &pool_guid_to_uuid32(&pool_guid),
                INITIAL_TXG
            )
        );

        let payload_end = 12 + 80;
        let stored_footer = &area[payload_end..payload_end + 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&area[..payload_end]);
        assert_eq!(stored_footer, hasher.finalize().as_bytes());
    }

    #[test]
    fn dual_copy_labels_at_both_offsets() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "dualcopy".into(),
            pool_guid: Some([0x11u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();

        // Label 0 at offset 0.
        let label0 = handle.read_label_at(0).unwrap();
        assert_eq!(label0.pool_guid, [0x11u8; 16]);
        assert!(verify_label_checksum(&label0));

        // Label 1 at capacity - POOL_LABEL_SIZE.
        let label1_offset = handle.capacity_bytes - POOL_LABEL_SIZE as u64;
        let label1 = handle.read_label_at(label1_offset).unwrap();
        assert_eq!(label1.pool_guid, [0x11u8; 16]);
        assert_eq!(label1.pool_name_str(), "dualcopy");
        assert!(verify_label_checksum(&label1));

        // Both labels must have identical content (except possibly checksum
        // — the checksum field itself is part of the hashed payload so
        // identical labels produce identical checksums).
        assert_eq!(label0.checksum, label1.checksum);
        assert_eq!(label0.magic, label1.magic);
        assert_eq!(label0.pool_guid, label1.pool_guid);
        assert_eq!(label0.device_guid, label1.device_guid);
    }

    #[test]
    fn dual_copy_recovery_when_label0_corrupted() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "recoverable".into(),
            pool_guid: Some([0x22u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();

        // Corrupt Label 0 by overwriting its first byte.
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        {
            use std::io::Read;
            handle.file.seek(SeekFrom::Start(0)).unwrap();
            handle.file.read_exact(&mut buf).unwrap();
        }
        buf[0] ^= 0xFF;
        handle.file.seek(SeekFrom::Start(0)).unwrap();
        handle.file.write_all(&buf).unwrap();
        handle.file.flush().unwrap();

        // Label 0 should now fail checksum.
        let result0 = handle.read_label_at(0);
        assert!(result0.is_err());

        // Label 1 should still be intact.
        let label1_offset = handle.capacity_bytes - POOL_LABEL_SIZE as u64;
        let label1 = handle.read_label_at(label1_offset).unwrap();
        assert_eq!(label1.pool_guid, [0x22u8; 16]);
        assert!(verify_label_checksum(&label1));
    }

    // -- committed-root tests --

    #[test]
    fn committed_root_present_after_creation() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "withroot".into(),
            pool_guid: Some([0x33u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert!(outcome.committed_root.is_valid());
        assert_eq!(outcome.committed_root.epoch_number, 1);
        assert_eq!(outcome.committed_root.root.commit_group_id.0, 1);
        assert_eq!(outcome.committed_root.dirty_object_count, 0);
    }

    #[test]
    fn committed_root_recoverable_from_disk() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "recoverroot".into(),
            pool_guid: Some([0x44u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        // Use the existing recovery function from committed_root.rs.
        let mut f = File::open(&dev).unwrap();
        let recovered = crate::committed_root::recover_committed_root_from_file(&mut f, None)
            .unwrap()
            .expect("committed root must be present after pool creation");

        assert_eq!(recovered.epoch_number, 1);
        assert_eq!(recovered.root.commit_group_id.0, 1);
        assert_eq!(recovered.dirty_object_count, 0);
        assert!(recovered.is_valid());
    }

    // -- error path tests --

    #[test]
    fn no_devices_error() {
        let config = PoolCreateConfig {
            pool_name: "empty".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[], &config);
        assert!(matches!(result, Err(CreateError::NoDevices)));
    }

    #[test]
    fn device_too_small_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // Create a file smaller than MIN_DEVICE_BYTES.
        let tiny = temp_device(&dir, "tiny", 1024);
        let config = PoolCreateConfig {
            pool_name: "tiny".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[tiny], &config);
        assert!(matches!(result, Err(CreateError::DeviceTooSmall { .. })));
    }

    #[test]
    fn device_already_labeled_with_different_pool() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config_a = PoolCreateConfig {
            pool_name: "pool_a".into(),
            pool_guid: Some([0xAAu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config_a).unwrap();

        // Try to create a different pool on the same device.
        let config_b = PoolCreateConfig {
            pool_name: "pool_b".into(),
            pool_guid: Some([0xBBu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[dev.clone()], &config_b);
        assert!(matches!(
            result,
            Err(CreateError::DeviceAlreadyLabeled { .. })
        ));
    }

    #[test]
    fn device_nonexistent() {
        let config = PoolCreateConfig {
            pool_name: "ghost".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result =
            PoolCreator::create_pool(&[PathBuf::from("/nonexistent/device/ghost")], &config);
        assert!(matches!(result, Err(CreateError::DeviceOpen { .. })));
    }

    #[test]
    fn directory_device_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = PoolCreateConfig {
            pool_name: "directory".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[dir.path().to_path_buf()], &config);
        match result {
            Err(CreateError::DeviceOpen { msg, .. }) => assert!(msg.contains("directory")),
            other => panic!("expected directory DeviceOpen error, got {other:?}"),
        }
    }

    #[test]
    fn exact_min_size_device_succeeds() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "exact".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[dev], &config);
        assert!(result.is_ok());
    }

    // -- label content tests --

    #[test]
    fn label_contains_device_capacity() {
        let size = MIN_DEVICE_BYTES + 4096;
        let (_dir, dev) = setup_single_device(size);
        let config = PoolCreateConfig {
            pool_name: "capacity".into(),
            pool_guid: Some([0xCCu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        assert_eq!(label.device_capacity_bytes, size);
    }

    #[test]
    fn label_device_index_correct() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);

        let config = PoolCreateConfig {
            pool_name: "indexed".into(),
            pool_guid: Some([0xDDu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();

        let mut h0 = CreationDevice::open(&dev0, 0).unwrap();
        let l0 = h0.read_label_at(0).unwrap();
        assert_eq!(l0.device_index, 0);
        assert_eq!(l0.device_count, 2);

        let mut h1 = CreationDevice::open(&dev1, 0).unwrap();
        let l1 = h1.read_label_at(0).unwrap();
        assert_eq!(l1.device_index, 1);
        assert_eq!(l1.device_count, 2);
    }

    #[test]
    fn replicated_policy_is_persisted_in_labels_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);

        let config = PoolCreateConfig {
            pool_name: "replicated".into(),
            pool_guid: Some([0xD0u8; 16]),
            redundancy: RedundancyPolicy::replicated(2),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();
        assert_eq!(outcome.redundancy, RedundancyPolicy::replicated(2));

        let mut h0 = CreationDevice::open(&dev0, 0).unwrap();
        let l0 = h0.read_label_at(0).unwrap();
        assert_eq!(l0.redundancy_policy, RedundancyPolicy::replicated(2));

        let mut h1 = CreationDevice::open(&dev1, 0).unwrap();
        let l1 = h1.read_label_at(0).unwrap();
        assert_eq!(l1.redundancy_policy, RedundancyPolicy::replicated(2));
    }

    #[test]
    fn erasure_policy_is_persisted_in_labels_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);
        let dev2 = temp_device(&dir, "dev2", MIN_DEVICE_BYTES);

        let config = PoolCreateConfig {
            pool_name: "erasure".into(),
            pool_guid: Some([0xD1u8; 16]),
            redundancy: RedundancyPolicy::erasure(2, 1),
            encryption_key: None,
            clustered: false,
        };
        let outcome =
            PoolCreator::create_pool(&[dev0.clone(), dev1.clone(), dev2.clone()], &config).unwrap();
        assert_eq!(outcome.redundancy, RedundancyPolicy::erasure(2, 1));

        for dev in [&dev0, &dev1, &dev2] {
            let mut handle = CreationDevice::open(dev, 0).unwrap();
            let label = handle.read_label_at(0).unwrap();
            assert_eq!(label.redundancy_policy, RedundancyPolicy::erasure(2, 1));
        }
    }

    #[test]
    fn replicated_policy_width_larger_than_device_count_is_rejected() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "too-wide".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(2),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[dev], &config);
        match result {
            Err(CreateError::InvalidRedundancyPolicy { reason, .. }) => {
                assert!(reason.contains("requires at least 2"));
            }
            other => panic!("expected InvalidRedundancyPolicy, got {other:?}"),
        }
    }

    #[test]
    fn erasure_policy_width_larger_than_device_count_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "too-wide-erasure".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::erasure(2, 1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&[dev0, dev1], &config);
        match result {
            Err(CreateError::InvalidRedundancyPolicy { reason, .. }) => {
                assert!(reason.contains("requires at least 3"));
            }
            other => panic!("expected InvalidRedundancyPolicy, got {other:?}"),
        }
    }

    #[test]
    fn labels_have_proper_feature_flags() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "features".into(),
            pool_guid: Some([0xEEu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        // features_incompat must include POOL_LABEL_V1 (0x01).
        assert_eq!(
            label.features_incompat & tidefs_types_pool_label_core::features::POOL_LABEL_V1,
            tidefs_types_pool_label_core::features::POOL_LABEL_V1
        );
        // features_compat must include DEVICE_CLASS_AWARE (0x01);
        // the encode path may also set DEVICE_HEALTH_STATE (0x80).
        assert_eq!(
            label.features_compat & tidefs_types_pool_label_core::features::DEVICE_CLASS_AWARE,
            tidefs_types_pool_label_core::features::DEVICE_CLASS_AWARE
        );
    }

    #[test]
    fn pool_state_is_exported_after_creation() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "exported".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome.state, PoolState::Exported);

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        assert_eq!(label.pool_state, PoolState::Exported);
    }

    // -- re-creation (idempotent) test --

    #[test]
    fn recreate_same_pool_is_allowed() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let guid = [0xFFu8; 16];
        let config = PoolCreateConfig {
            pool_name: "recreate".into(),
            pool_guid: Some(guid),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        // First creation succeeds.
        let outcome1 = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome1.pool_guid, guid);

        // Second creation with the same GUID succeeds (idempotent re-init).
        let outcome2 = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome2.pool_guid, guid);
    }

    // -- CreateError Display test --

    #[test]
    fn create_error_display() {
        let err = CreateError::NoDevices;
        assert!(format!("{err}").contains("no devices"));

        let err = CreateError::DeviceOpen {
            device_path: PathBuf::from("/dev/sda"),
            msg: "permission denied".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("/dev/sda"));
        assert!(s.contains("permission denied"));

        let err = CreateError::DeviceTooSmall {
            device_path: PathBuf::from("/dev/sdb"),
            capacity_bytes: 1000,
            required_bytes: 500000,
        };
        let s = format!("{err}");
        assert!(s.contains("/dev/sdb"));
        assert!(s.contains("1000"));
        assert!(s.contains("500000"));

        let err = CreateError::DeviceAlreadyLabeled {
            device_path: PathBuf::from("/dev/sdc"),
            existing_pool_guid: [0xABu8; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("/dev/sdc"));
        assert!(s.contains("already labeled"));
    }

    #[test]
    fn clustered_pool_labels_have_clustered_feature_flags() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "clustered".into(),
            pool_guid: Some([0x77u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: true,
        };
        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome.device_guids.len(), 1);
        assert_ne!(outcome.device_guids[0], [0u8; 16]);

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        assert!(label.is_clustered(), "clustered feature flags must be set");
    }

    #[test]
    fn non_clustered_pool_labels_missing_clustered_flags() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "nonclustered".into(),
            pool_guid: Some([0x88u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(outcome.device_guids.len(), 1);
        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        assert!(
            !label.is_clustered(),
            "clustered flags must not be set for non-clustered pool"
        );
    }

    #[test]
    fn outcome_device_guids_match_label_device_guids() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "guids".into(),
            pool_guid: Some([0x99u8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label = handle.read_label_at(0).unwrap();
        assert_eq!(
            outcome.device_guids[0], label.device_guid,
            "PoolCreateOutcome.device_guids must match label device_guid"
        );
    }
}
