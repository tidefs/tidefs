// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool creation: initialize byte-addressable pool devices with TideFS labels,
//! superblock data, and an initial committed root.
//!
//! This is the bootstrap path that writes the initial on-disk structures
//! needed to make a pool importable.  Each device receives dual-copy
//! BLAKE3-verified pool labels (at offset 0 and at the end of the device)
//! plus an initial committed-root region so that pool import can locate
//! a valid starting epoch.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{flock, FlockOperation};
use tidefs_commit_group::{
    seal_commit_hash, CommitGroupId, CommitGroupWriter, CommittedRootBlock, RootPointer,
};
use tidefs_encryption::StoreKey;
use tidefs_local_object_store::device_layout::{
    decode_device_layout_v1, encode_device_layout_v1, DeviceLayoutPolicy, DeviceLayoutV1,
    MIN_SEGMENT_SIZE_BYTES,
};
use tidefs_local_object_store::pool::{
    bootstrap_labelled_pool, preflight_labelled_pool_bootstrap, PoolBootstrapConfig,
    PoolBootstrapMember,
};
use tidefs_local_object_store::{
    DeviceBacking, EncryptionConfig as StoreEncryptionConfig, StoreEncryptionKey, StoreError,
};
use tidefs_pool_scan::PoolDeviceBacking;
use tidefs_types_pool_label_core::{
    decode_device_layout_v1_bytes, decode_label, encode_label_with_device_layout,
    encode_vcrl_ledger_into, pool_guid_to_uuid32, seal_label_with_device_layout, vcrl_required_len,
    DeviceClass, DeviceLayoutV1Bytes, LabelError, PoolLabelV1, PoolState, VcrlEntry,
    POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE, POOL_LABEL_SIZE,
    POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE,
};

use crate::committed_root::{
    encode_commit_record_region, CommittedRoot, ParsedCommitRecord, COMMIT_RECORD_REGION_MAX,
    COMMIT_RECORD_REGION_OFFSET,
};
use tidefs_auth::local_only::LocalOnlyGuard;

/// Pool-wide redundancy policy accepted by pool creation.
pub use tidefs_types_pool_label_core::PoolRedundancyPolicy as RedundancyPolicy;

const LABEL_AND_COMMIT_MIN_DEVICE_BYTES: u64 =
    (2 * POOL_LABEL_SIZE as u64) + COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX;
const STORE_MIN_DEVICE_BYTES: u64 =
    tidefs_local_object_store::LocalObjectStore::minimum_block_device_capacity();
const MIN_DEVICE_BYTES: u64 = if LABEL_AND_COMMIT_MIN_DEVICE_BYTES > STORE_MIN_DEVICE_BYTES {
    if LABEL_AND_COMMIT_MIN_DEVICE_BYTES > MIN_SEGMENT_SIZE_BYTES {
        LABEL_AND_COMMIT_MIN_DEVICE_BYTES
    } else {
        MIN_SEGMENT_SIZE_BYTES
    }
} else if STORE_MIN_DEVICE_BYTES > MIN_SEGMENT_SIZE_BYTES {
    STORE_MIN_DEVICE_BYTES
} else {
    MIN_SEGMENT_SIZE_BYTES
};
const INITIAL_ROOT_INO: u64 = 1;
const INITIAL_TXG: u64 = 1;
const INITIAL_SYSTEM_AREA_BLOCK_SIZE: u64 = 4096;
const INITIAL_SYSTEM_AREA_BLOCKS: u64 = 4;
const INITIAL_SYSTEM_AREA_SIZE: u64 = INITIAL_SYSTEM_AREA_BLOCK_SIZE * INITIAL_SYSTEM_AREA_BLOCKS;
const INITIAL_SYSTEM_AREA_OFFSET: u64 =
    COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX - INITIAL_SYSTEM_AREA_SIZE;
const INITIAL_STATE_AREA_OFFSET: u64 = INITIAL_SYSTEM_AREA_OFFSET + INITIAL_SYSTEM_AREA_SIZE;
const INITIAL_VCRP_RECORD_SIZE: usize = 96;
const INITIAL_VCRP_HEADER_SIZE: usize = 64;
const INITIAL_VCRP_HASH_OFFSET: usize = 64;

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
    /// Existing media cannot be proven to be blank or one exact fresh retry.
    AmbiguousMedia {
        /// Device path whose current state was refused.
        device_path: PathBuf,
        /// Exact reason the state is not safe to continue.
        reason: String,
    },
    /// Pool-owned object-store bootstrap rejected the media.
    Store(StoreError),
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
            Self::AmbiguousMedia {
                device_path,
                reason,
            } => write!(
                f,
                "refusing ambiguous pool-creation media {}: {reason}",
                device_path.display()
            ),
            Self::Store(error) => write!(f, "Pool object-store bootstrap failed: {error}"),
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

impl From<StoreError> for CreateError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
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
    /// Stable identity used to reject aliases of the same underlying media.
    media_identity: (u8, u64, u64),
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

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("{e}"),
            })?;

        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("device is already owned by another pool operation: {e}"),
            }
        })?;
        let capacity_bytes = file
            .seek(SeekFrom::End(0))
            .map_err(|e| CreateError::DeviceOpen {
                device_path: path.to_path_buf(),
                msg: format!("device capacity: {e}"),
            })?;
        let metadata = file.metadata().map_err(|e| CreateError::DeviceOpen {
            device_path: path.to_path_buf(),
            msg: format!("device identity: {e}"),
        })?;
        let media_identity = match backing {
            PoolDeviceBacking::BlockDevice => (1, metadata.rdev(), 0),
            PoolDeviceBacking::RegularFileDev => (2, metadata.dev(), metadata.ino()),
        };

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
            media_identity,
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
    #[cfg(test)]
    fn read_label_at(&mut self, offset: u64) -> Result<PoolLabelV1, CreateError> {
        let buf = self.read_label_bytes_at(offset)?;
        decode_label(&buf).map_err(CreateError::Label)
    }

    /// Read one complete fixed-offset label slot without interpreting it.
    fn read_label_bytes_at(&mut self, offset: u64) -> Result<Vec<u8>, CreateError> {
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

        Ok(buf)
    }

    /// Encode and write a sealed label at `offset`.
    fn write_label_at(
        &mut self,
        label: &PoolLabelV1,
        device_layout_v1: Option<&DeviceLayoutV1Bytes>,
        offset: u64,
    ) -> Result<(), CreateError> {
        // Only the current encoded header belongs to the label write. The
        // leading 256 KiB reservation overlaps fixed bootstrap root regions;
        // rewriting zero padding here would destroy those separately-owned
        // records during retry or final dual-label convergence.
        let mut buf = vec![0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
        encode_label_with_device_layout(label, device_layout_v1, &mut buf)?;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidCreationLabel {
    label: PoolLabelV1,
    layout_bytes: DeviceLayoutV1Bytes,
    layout: DeviceLayoutV1,
}

#[derive(Clone, Debug)]
enum CreationLabelState {
    Blank,
    Retry {
        valid: ValidCreationLabel,
        leading_blank: bool,
        trailing_blank: bool,
    },
}

fn ambiguous_media(
    device_path: &Path,
    reason: impl Into<String>,
) -> Result<CreationLabelState, CreateError> {
    Err(CreateError::AmbiguousMedia {
        device_path: device_path.to_path_buf(),
        reason: reason.into(),
    })
}

fn decode_creation_label_copy(
    device_path: &Path,
    copy_name: &'static str,
    raw: &[u8],
    label_owned_end: usize,
) -> Result<Option<ValidCreationLabel>, CreateError> {
    // The leading reservation overlaps fixed-region roots beginning at the
    // commit-record offset. Bytes before that boundary, and all bytes after
    // the trailing header, remain label-owned and must be blank for a fresh
    // retry.
    let header = &raw[..POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
    if raw[POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE..label_owned_end]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(CreateError::AmbiguousMedia {
            device_path: device_path.to_path_buf(),
            reason: format!("{copy_name} label has unexpected extension bytes"),
        });
    }
    if header.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let label = decode_label(raw).map_err(|error| CreateError::AmbiguousMedia {
        device_path: device_path.to_path_buf(),
        reason: format!("{copy_name} label is nonblank but invalid: {error}"),
    })?;
    let layout_bytes = decode_device_layout_v1_bytes(raw)
        .map_err(|error| CreateError::AmbiguousMedia {
            device_path: device_path.to_path_buf(),
            reason: format!("{copy_name} label DeviceLayoutV1 is invalid: {error}"),
        })?
        .ok_or_else(|| CreateError::AmbiguousMedia {
            device_path: device_path.to_path_buf(),
            reason: format!("{copy_name} label lacks DeviceLayoutV1 authority"),
        })?;
    let layout =
        decode_device_layout_v1(&layout_bytes).map_err(|error| CreateError::AmbiguousMedia {
            device_path: device_path.to_path_buf(),
            reason: format!("{copy_name} label DeviceLayoutV1 is corrupt: {error}"),
        })?;
    Ok(Some(ValidCreationLabel {
        label,
        layout_bytes,
        layout,
    }))
}

fn inspect_creation_labels(handle: &mut CreationDevice) -> Result<CreationLabelState, CreateError> {
    let leading_raw = handle.read_label_bytes_at(0)?;
    let trailing_offset = handle.capacity_bytes - POOL_LABEL_SIZE as u64;
    let trailing_raw = handle.read_label_bytes_at(trailing_offset)?;
    let leading = decode_creation_label_copy(
        &handle.device_path,
        "leading",
        &leading_raw,
        COMMIT_RECORD_REGION_OFFSET as usize,
    )?;
    let trailing = decode_creation_label_copy(
        &handle.device_path,
        "trailing",
        &trailing_raw,
        POOL_LABEL_SIZE,
    )?;

    match (leading, trailing) {
        (None, None) => Ok(CreationLabelState::Blank),
        (Some(valid), None) => Ok(CreationLabelState::Retry {
            valid,
            leading_blank: false,
            trailing_blank: true,
        }),
        (None, Some(valid)) => Ok(CreationLabelState::Retry {
            valid,
            leading_blank: true,
            trailing_blank: false,
        }),
        (Some(leading), Some(trailing)) if leading == trailing => Ok(CreationLabelState::Retry {
            valid: leading,
            leading_blank: false,
            trailing_blank: false,
        }),
        (Some(_), Some(_)) => {
            ambiguous_media(&handle.device_path, "leading and trailing labels conflict")
        }
    }
}

fn object_store_backing(backing: PoolDeviceBacking) -> DeviceBacking {
    match backing {
        PoolDeviceBacking::BlockDevice => DeviceBacking::BlockDevice,
        PoolDeviceBacking::RegularFileDev => DeviceBacking::RegularFileDev,
    }
}

fn canonical_creation_label(
    mut label: PoolLabelV1,
    layout_bytes: &DeviceLayoutV1Bytes,
) -> Result<PoolLabelV1, CreateError> {
    label = seal_label_with_device_layout(label, Some(layout_bytes))?;
    let mut encoded = vec![0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
    encode_label_with_device_layout(&label, Some(layout_bytes), &mut encoded)?;
    decode_label(&encoded).map_err(CreateError::Label)
}

fn store_encryption_config(config: &PoolCreateConfig) -> Option<StoreEncryptionConfig> {
    config.encryption_key.as_ref().map(|key| {
        StoreEncryptionConfig::new(
            StoreEncryptionKey::from_bytes(key.as_bytes())
                .expect("tidefs-encryption StoreKey is exactly 32 bytes"),
        )
    })
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

        let device_count = u32::try_from(devices.len()).map_err(|_| CreateError::Io {
            device_path: None,
            msg: "pool device count exceeds u32".to_string(),
        })?;
        validate_redundancy_policy(config.redundancy, device_count)?;

        // Phase 1: open every exact path and classify both label copies before
        // generating identity or mutating any media.
        let mut handles: Vec<CreationDevice> = Vec::with_capacity(device_count as usize);
        let mut label_states = Vec::with_capacity(device_count as usize);
        let mut seen_media = BTreeSet::new();
        for (i, path) in devices.iter().enumerate() {
            let mut handle = CreationDevice::open(path, i as u32)?;
            if !seen_media.insert(handle.media_identity) {
                return Err(CreateError::AmbiguousMedia {
                    device_path: path.clone(),
                    reason: "the same underlying device was supplied more than once".to_string(),
                });
            }
            label_states.push(inspect_creation_labels(&mut handle)?);
            handles.push(handle);
        }

        let existing_label =
            label_states
                .iter()
                .enumerate()
                .find_map(|(index, state)| match state {
                    CreationLabelState::Retry { valid, .. } => Some((index, &valid.label)),
                    CreationLabelState::Blank => None,
                });
        let pool_guid = if let Some((first_index, first)) = existing_label {
            if let Some(requested) = config.pool_guid {
                if requested != first.pool_guid {
                    return Err(CreateError::DeviceAlreadyLabeled {
                        device_path: handles[first_index].device_path.clone(),
                        existing_pool_guid: first.pool_guid,
                    });
                }
            }
            first.pool_guid
        } else {
            match config.pool_guid {
                Some(guid) => guid,
                None => filesystem_uuid().map_err(|e| CreateError::Io {
                    device_path: None,
                    msg: format!("generate pool GUID: {e}"),
                })?,
            }
        };

        // Phase 2: compute the exact intended label and layout for every
        // member, preserving all identity from a coherent retry.
        let mut labels: Vec<PoolLabelV1> = Vec::with_capacity(device_count as usize);
        let mut device_layouts: Vec<DeviceLayoutV1Bytes> =
            Vec::with_capacity(device_count as usize);
        for (handle, state) in handles.iter().zip(&label_states) {
            let device_guid = match state {
                CreationLabelState::Blank => filesystem_uuid().map_err(|e| CreateError::Io {
                    device_path: None,
                    msg: format!("generate device GUID: {e}"),
                })?,
                CreationLabelState::Retry { valid, .. } => valid.label.device_guid,
            };
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
            let layout = DeviceLayoutPolicy::Slice0Small
                .compute(handle.capacity_bytes)
                .map_err(|e| CreateError::Io {
                    device_path: Some(handle.device_path.clone()),
                    msg: format!("compute DeviceLayoutV1: {e}"),
                })?;
            let mut bytes = [0u8; POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
            encode_device_layout_v1(&layout, &mut bytes);
            let label = canonical_creation_label(label, &bytes)?;

            if let CreationLabelState::Retry { valid, .. } = state {
                if valid.label != label || valid.layout != layout || valid.layout_bytes != bytes {
                    return Err(CreateError::AmbiguousMedia {
                        device_path: handle.device_path.clone(),
                        reason: "existing label does not match the exact requested fresh topology"
                            .to_string(),
                    });
                }
            }
            labels.push(label);
            device_layouts.push(bytes);
        }

        let bootstrap_config = PoolBootstrapConfig {
            pool_guid,
            members: handles
                .iter()
                .zip(&labels)
                .zip(&device_layouts)
                .map(|((handle, label), device_layout_v1)| {
                    Ok(PoolBootstrapMember {
                        file: handle.file.try_clone().map_err(|e| CreateError::Io {
                            device_path: Some(handle.device_path.clone()),
                            msg: format!("retain bootstrap device handle: {e}"),
                        })?,
                        path: handle.device_path.clone(),
                        backing: object_store_backing(handle.backing),
                        device_index: handle.device_index,
                        capacity_bytes: handle.capacity_bytes,
                        device_guid: label.device_guid,
                        expected_label: label.clone(),
                        device_layout_v1: *device_layout_v1,
                        label_was_present: matches!(
                            label_states[handle.device_index as usize],
                            CreationLabelState::Retry { .. }
                        ),
                    })
                })
                .collect::<Result<Vec<_>, CreateError>>()?,
            encryption: store_encryption_config(config),
        };
        let bootstrap_admission = preflight_labelled_pool_bootstrap(bootstrap_config)?;

        // Phase 3: establish at least one valid topology label on each member.
        // A retry preserves an already-valid copy and fills only a blank peer;
        // it never overwrites a conflicting or corrupt copy.
        for (i, label) in labels.iter().enumerate() {
            let device_layout = &device_layouts[i];
            let label1_offset = handles[i]
                .capacity_bytes
                .saturating_sub(POOL_LABEL_SIZE as u64);
            match &label_states[i] {
                CreationLabelState::Blank => {
                    handles[i].write_label_at(label, Some(device_layout), 0)?;
                    handles[i].write_label_at(label, Some(device_layout), label1_offset)?;
                }
                CreationLabelState::Retry {
                    leading_blank,
                    trailing_blank,
                    ..
                } => {
                    if *leading_blank {
                        handles[i].write_label_at(label, Some(device_layout), 0)?;
                    }
                    if *trailing_blank {
                        handles[i].write_label_at(label, Some(device_layout), label1_offset)?;
                    }
                }
            }
        }

        // Phase 4: Pool owns the immutable Store identity and generation-zero
        // marker. It rereads every exact label before mutation and every Store
        // copy after sync.
        bootstrap_labelled_pool(bootstrap_admission)?;

        // Phase 5: create initial committed root (epoch 1, txg 1).
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
        let system_area = encode_initial_system_area(&pool_guid)?;

        // Write the userspace VBCR region and kmod-readable committed-root
        // system area: VCRL, duplicate VCRP pointer records, and VRBT.
        for handle in &mut handles {
            handle.write_commit_region(&region_bytes)?;
            handle.write_system_area(&system_area)?;
        }

        // Phase 6: converge both label copies only after Store bootstrap and
        // initial fixed-region roots are durable.
        for (i, label) in labels.iter().enumerate() {
            let device_layout = &device_layouts[i];
            let label1_offset = handles[i].capacity_bytes - POOL_LABEL_SIZE as u64;
            handles[i].write_label_at(label, Some(device_layout), 0)?;
            handles[i].write_label_at(label, Some(device_layout), label1_offset)?;
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

fn encode_initial_vcrp_pointer(
    sequence: u64,
    root_sector: u64,
    commit_group_id: CommitGroupId,
    root_hash: [u8; 32],
) -> [u8; INITIAL_VCRP_RECORD_SIZE] {
    let mut pointer = [0u8; INITIAL_VCRP_RECORD_SIZE];
    pointer[0..4].copy_from_slice(b"VCRP");
    pointer[4..8].copy_from_slice(&1u32.to_le_bytes());
    pointer[8..16].copy_from_slice(&sequence.to_le_bytes());
    pointer[16..24].copy_from_slice(&root_sector.to_le_bytes());
    pointer[24..32].copy_from_slice(&commit_group_id.0.to_le_bytes());
    pointer[32..64].copy_from_slice(&root_hash);
    let checksum: [u8; 32] = blake3::hash(&pointer[..INITIAL_VCRP_HEADER_SIZE]).into();
    pointer[INITIAL_VCRP_HASH_OFFSET..INITIAL_VCRP_RECORD_SIZE].copy_from_slice(&checksum);
    pointer
}

fn encode_initial_system_area(pool_guid: &[u8; 16]) -> Result<Vec<u8>, CreateError> {
    let vcrl_entry = VcrlEntry {
        root_ino: INITIAL_ROOT_INO,
        pool_uuid: pool_guid_to_uuid32(pool_guid),
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

    let committed_root = CommittedRootBlock::new(
        CommitGroupId(INITIAL_TXG),
        INITIAL_ROOT_INO,
        INITIAL_STATE_AREA_OFFSET,
        INITIAL_STATE_AREA_OFFSET,
        0,
    );
    let sealed_root = CommitGroupWriter::seal_root_block(committed_root);
    let root_bytes = sealed_root.to_bytes();
    let root_sector = (INITIAL_SYSTEM_AREA_OFFSET
        .saturating_add(3 * INITIAL_SYSTEM_AREA_BLOCK_SIZE))
        / INITIAL_SYSTEM_AREA_BLOCK_SIZE;
    let pointer = encode_initial_vcrp_pointer(
        INITIAL_TXG,
        root_sector,
        CommitGroupId(INITIAL_TXG),
        sealed_root.block_hash,
    );

    let mut area = vec![0u8; INITIAL_SYSTEM_AREA_SIZE as usize];
    area[..vcrl_bytes.len()].copy_from_slice(&vcrl_bytes);
    let pointer_a = INITIAL_SYSTEM_AREA_BLOCK_SIZE as usize;
    let pointer_b = 2 * INITIAL_SYSTEM_AREA_BLOCK_SIZE as usize;
    let root_off = 3 * INITIAL_SYSTEM_AREA_BLOCK_SIZE as usize;
    area[pointer_a..pointer_a + INITIAL_VCRP_RECORD_SIZE].copy_from_slice(&pointer);
    area[pointer_b..pointer_b + INITIAL_VCRP_RECORD_SIZE].copy_from_slice(&pointer);
    area[root_off..root_off + CommittedRootBlock::WIRE_SIZE].copy_from_slice(&root_bytes);
    Ok(area)
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
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::TempDir;
    use tidefs_local_object_store::device_layout::decode_device_layout_v1;
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

    fn read_raw_label_at(handle: &mut CreationDevice, offset: u64) -> Vec<u8> {
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        handle.file.seek(SeekFrom::Start(offset)).unwrap();
        handle.file.read_exact(&mut buf).unwrap();
        buf
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
    fn create_pool_writes_kmod_readable_committed_root_system_area() {
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

        let vrbt_off = (3 * INITIAL_SYSTEM_AREA_BLOCK_SIZE) as usize;
        let vrbt = CommittedRootBlock::from_bytes(
            &area[vrbt_off..vrbt_off + CommittedRootBlock::WIRE_SIZE],
        )
        .unwrap();
        assert!(CommitGroupWriter::verify_root_block(&vrbt));
        assert_eq!(vrbt.commit_group_id, CommitGroupId(INITIAL_TXG));
        assert_eq!(vrbt.namespace_root, INITIAL_ROOT_INO);
        assert_eq!(vrbt.inode_table_root, INITIAL_STATE_AREA_OFFSET);
        assert_eq!(vrbt.extent_map_root, INITIAL_STATE_AREA_OFFSET);
        assert_eq!(vrbt.intent_log_tail, 0);

        let root_sector = (INITIAL_SYSTEM_AREA_OFFSET + 3 * INITIAL_SYSTEM_AREA_BLOCK_SIZE)
            / INITIAL_SYSTEM_AREA_BLOCK_SIZE;
        for pointer_off in [
            INITIAL_SYSTEM_AREA_BLOCK_SIZE as usize,
            (2 * INITIAL_SYSTEM_AREA_BLOCK_SIZE) as usize,
        ] {
            let pointer = &area[pointer_off..pointer_off + INITIAL_VCRP_RECORD_SIZE];
            assert_eq!(&pointer[0..4], b"VCRP");
            assert_eq!(u32::from_le_bytes(pointer[4..8].try_into().unwrap()), 1);
            assert_eq!(
                u64::from_le_bytes(pointer[8..16].try_into().unwrap()),
                INITIAL_TXG
            );
            assert_eq!(
                u64::from_le_bytes(pointer[16..24].try_into().unwrap()),
                root_sector
            );
            assert_eq!(
                u64::from_le_bytes(pointer[24..32].try_into().unwrap()),
                INITIAL_TXG
            );
            assert_eq!(&pointer[32..64], &vrbt.block_hash);
            let pointer_hash: [u8; 32] = blake3::hash(&pointer[..INITIAL_VCRP_HEADER_SIZE]).into();
            assert_eq!(
                &pointer[INITIAL_VCRP_HASH_OFFSET..INITIAL_VCRP_RECORD_SIZE],
                &pointer_hash
            );
        }
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

    #[test]
    fn create_pool_bootstrap_refuses_second_creator_without_mutation() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let held = CreationDevice::open(&dev, 0).expect("hold first creator lock");
        let before = std::fs::read(&dev).expect("snapshot locked device");
        let config = PoolCreateConfig {
            pool_name: "second-creator".into(),
            pool_guid: Some([0xA6; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        match PoolCreator::create_pool(std::slice::from_ref(&dev), &config) {
            Err(CreateError::DeviceOpen { msg, .. }) => {
                assert!(msg.contains("already owned by another pool operation"));
            }
            other => panic!("expected competing creator refusal, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&dev).expect("reread locked device"),
            before,
            "competing creator changed media"
        );
        drop(held);
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
    fn create_pool_persists_device_layout_sidecar_in_dual_labels() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "layout-sidecar".into(),
            pool_guid: Some([0x4Cu8; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let label1_offset = handle.capacity_bytes - POOL_LABEL_SIZE as u64;
        for offset in [0, label1_offset] {
            let raw = read_raw_label_at(&mut handle, offset);
            let label = decode_label(&raw).unwrap();
            assert_ne!(
                label.features_compat & tidefs_types_pool_label_core::features::DEVICE_LAYOUT_V1,
                0
            );

            let layout_bytes = tidefs_types_pool_label_core::decode_device_layout_v1_bytes(&raw)
                .unwrap()
                .expect("layout sidecar");
            let layout = decode_device_layout_v1(&layout_bytes).unwrap();
            assert_eq!(layout.device_size_bytes, handle.capacity_bytes);
        }
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

    // -- strict fresh-bootstrap retry tests --

    #[test]
    fn create_pool_bootstrap_fresh_retry_adopts_generated_pool_and_device_guids() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "fresh-retry".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };

        let outcome1 = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        let outcome2 = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        assert_eq!(outcome2.pool_guid, outcome1.pool_guid);
        assert_eq!(outcome2.device_guids, outcome1.device_guids);
    }

    #[test]
    fn create_pool_bootstrap_accepts_valid_and_blank_interrupted_label_pair() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "label-retry".into(),
            pool_guid: Some([0xA1; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let first = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        // Simulate interruption while publishing the leading label header.
        // Fixed-root bytes elsewhere in the overlapping reservation remain.
        let mut file = OpenOptions::new().write(true).open(&dev).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&vec![0; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE])
            .unwrap();
        file.sync_all().unwrap();

        let retried = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        assert_eq!(retried.pool_guid, first.pool_guid);
        assert_eq!(retried.device_guids, first.device_guids);

        let mut handle = CreationDevice::open(&dev, 0).unwrap();
        let leading = handle.read_label_at(0).unwrap();
        let trailing = handle
            .read_label_at(handle.capacity_bytes - POOL_LABEL_SIZE as u64)
            .unwrap();
        assert_eq!(leading, trailing);
    }

    #[test]
    fn create_pool_bootstrap_converges_partially_labelled_member_set() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "member-label-retry".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let first = PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();

        let (leading, trailing) = {
            let mut member0 = CreationDevice::open(&dev0, 0).unwrap();
            let trailing_offset = member0.capacity_bytes - POOL_LABEL_SIZE as u64;
            (
                read_raw_label_at(&mut member0, 0),
                read_raw_label_at(&mut member0, trailing_offset),
            )
        };
        for path in [&dev0, &dev1] {
            let file = OpenOptions::new().write(true).open(path).unwrap();
            file.set_len(0).unwrap();
            file.set_len(MIN_DEVICE_BYTES).unwrap();
            file.sync_all().unwrap();
        }
        let mut member0 = OpenOptions::new().write(true).open(&dev0).unwrap();
        member0
            .write_all(&leading[..POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE])
            .unwrap();
        member0
            .seek(SeekFrom::Start(MIN_DEVICE_BYTES - POOL_LABEL_SIZE as u64))
            .unwrap();
        member0
            .write_all(&trailing[..POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE])
            .unwrap();
        member0.sync_all().unwrap();

        let retried = PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();
        assert_eq!(retried.pool_guid, first.pool_guid);
        assert_eq!(retried.device_guids[0], first.device_guids[0]);
        assert_ne!(retried.device_guids[1], [0; 16]);

        let converged = PoolCreator::create_pool(&[dev0, dev1], &config).unwrap();
        assert_eq!(converged.pool_guid, retried.pool_guid);
        assert_eq!(converged.device_guids, retried.device_guids);
    }

    #[test]
    fn create_pool_bootstrap_encrypted_fresh_retry_converges() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "encrypted-bootstrap".into(),
            pool_guid: None,
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: Some(StoreKey::generate()),
            clustered: false,
        };

        let first = PoolCreator::create_pool(&[dev.clone()], &config).unwrap();
        let retried = PoolCreator::create_pool(&[dev], &config).unwrap();

        assert!(retried.encrypted);
        assert_eq!(retried.pool_guid, first.pool_guid);
        assert_eq!(retried.device_guids, first.device_guids);
        assert_eq!(
            retried.encryption_key_fingerprint,
            first.encryption_key_fingerprint
        );
    }

    #[test]
    fn create_pool_bootstrap_refuses_used_same_guid_pool() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "used-pool".into(),
            pool_guid: Some([0xA2; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let pool_config = tidefs_local_object_store::PoolConfig {
            name: config.pool_name.clone(),
            root_path: _dir.path().join("metadata"),
            devices: vec![tidefs_local_object_store::DeviceConfig {
                path: dev.clone(),
                backing: tidefs_local_object_store::DeviceBacking::RegularFileDev,
                class: tidefs_local_object_store::DeviceClass::Data,
                media_class: Default::default(),
                kind: tidefs_local_object_store::DeviceKind::Block { path: dev.clone() },
                compression: None,
                encryption: None,
            }],
        };
        let mut pool_properties = tidefs_local_object_store::PoolProperties::default();
        pool_properties.redundancy_policy =
            tidefs_local_object_store::PoolRedundancyPolicy::replicated(1);
        let mut pool = tidefs_local_object_store::Pool::open(
            pool_config,
            pool_properties,
            &tidefs_local_object_store::StoreOptions::default(),
        )
        .unwrap();
        pool.put(
            tidefs_local_object_store::DeviceIoClass::Data,
            tidefs_local_object_store::ObjectKey::from_name(b"used-pool"),
            b"live payload",
        )
        .unwrap();
        pool.sync_all().unwrap();
        drop(pool);

        assert!(matches!(
            PoolCreator::create_pool(&[dev], &config),
            Err(CreateError::Store(StoreError::InvalidOptions { .. }))
        ));
    }

    #[test]
    fn create_pool_bootstrap_refuses_stale_label_extension_bytes() {
        let (_dir, dev) = setup_single_device(MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "stale-label-extension".into(),
            pool_guid: Some([0xA4; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev.clone()], &config).unwrap();

        let mut file = OpenOptions::new().write(true).open(&dev).unwrap();
        file.seek(SeekFrom::Start(
            MIN_DEVICE_BYTES - POOL_LABEL_SIZE as u64
                + POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE as u64,
        ))
        .unwrap();
        file.write_all(&[0xA5]).unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            PoolCreator::create_pool(&[dev], &config),
            Err(CreateError::AmbiguousMedia { reason, .. })
                if reason.contains("extension bytes")
        ));
    }

    #[test]
    fn create_pool_bootstrap_refuses_reordered_missing_and_extra_members() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = temp_device(&dir, "dev0", MIN_DEVICE_BYTES);
        let dev1 = temp_device(&dir, "dev1", MIN_DEVICE_BYTES);
        let dev2 = temp_device(&dir, "dev2", MIN_DEVICE_BYTES);
        let config = PoolCreateConfig {
            pool_name: "exact-topology".into(),
            pool_guid: Some([0xA3; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();

        for attempted in [
            vec![dev1.clone(), dev0.clone()],
            vec![dev0.clone()],
            vec![dev0, dev1, dev2],
        ] {
            assert!(matches!(
                PoolCreator::create_pool(&attempted, &config),
                Err(CreateError::AmbiguousMedia { .. })
            ));
        }
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
