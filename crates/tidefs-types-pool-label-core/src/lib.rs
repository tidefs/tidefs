#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! PoolLabelV1 on-device label type, PoolState/DeviceClass enums, and
//! BLAKE3-256 encode/decode with checksum verification.
//!
//! Implements the label format described in
//! [`docs/design/pool-import-export-device-topology-management.md`],
//! which is the canonical design-spec for pool import/export and online
//! device topology management.
//!
//! # Label layout
//!
//! Each device carries two copies of the label:
//! - Label 0 at offset 0 (first 256 KiB of device)
//! - Label 1 at offset `capacity - 256 KiB` (last 256 KiB of device)
//!
//! Each copy is self-contained and independently verifiable.

use core::fmt;

#[cfg(all(not(test), feature = "alloc"))]
extern crate alloc;

// ---------------------------------------------------------------------------
// Magic bytes
// ---------------------------------------------------------------------------

/// Magic bytes identifying a TideFS pool label.
pub const POOL_LABEL_MAGIC: [u8; 4] = *b"VBFS";

/// Size of each label copy on disk (256 KiB).
pub const POOL_LABEL_SIZE: usize = 256 * 1024;

/// Maximum pool name length in bytes (UTF-8).
pub const POOL_NAME_MAX: usize = 255;

// ---------------------------------------------------------------------------
// PoolState
// ---------------------------------------------------------------------------

/// Operational state of the pool recorded in each device label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PoolState {
    /// Pool is live and writable.
    Active = 0,
    /// Pool was cleanly exported; ready for import.
    Exported = 1,
    /// Pool has been administratively destroyed (terminal).
    Destroyed = 2,
}

impl PoolState {
    /// Decode from a u8 wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Exported),
            2 => Some(Self::Destroyed),
            _ => None,
        }
    }

    /// Encode to a u8 wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns true if the pool can be imported in this state.
    #[must_use]
    pub const fn is_importable(self) -> bool {
        matches!(self, Self::Active | Self::Exported)
    }
}

impl fmt::Display for PoolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("ACTIVE"),
            Self::Exported => f.write_str("EXPORTED"),
            Self::Destroyed => f.write_str("DESTROYED"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceClass
// ---------------------------------------------------------------------------

/// Device class for pool-level allocation routing (on-disk label variant).
///
/// Maps to ZFS allocation classes. Note: this is the on-disk label enum,
/// separate from the runtime `DeviceClass` in `tidefs-local-object-store`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DeviceClass {
    /// General-purpose HDD storage.
    Hdd = 0,
    /// Solid-state drive storage.
    Ssd = 1,
    /// NVMe flash storage.
    Nvme = 2,
    /// Separate fast intent-log device (LOG_DEVICE).
    LogDevice = 3,
    /// Read cache device (FlashTier).
    Cache = 4,
    /// Special allocation class (small files, dedup tables).
    Special = 5,
    /// Hot spare device — does not participate in normal I/O routing.
    Spare = 6,
}

impl DeviceClass {
    /// Decode from a u8 wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Hdd),
            1 => Some(Self::Ssd),
            2 => Some(Self::Nvme),
            3 => Some(Self::LogDevice),
            4 => Some(Self::Cache),
            5 => Some(Self::Special),
            6 => Some(Self::Spare),
            _ => None,
        }
    }

    /// Encode to a u8 wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns true if this is a data-bearing device class.
    #[must_use]
    pub const fn is_data_bearing(self) -> bool {
        matches!(self, Self::Hdd | Self::Ssd | Self::Nvme | Self::Special)
    }
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hdd => f.write_str("HDD"),
            Self::Ssd => f.write_str("SSD"),
            Self::Nvme => f.write_str("NVME"),
            Self::LogDevice => f.write_str("LOG_DEVICE"),
            Self::Cache => f.write_str("CACHE"),
            Self::Special => f.write_str("SPECIAL"),
            Self::Spare => f.write_str("SPARE"),
        }
    }
}

// ---------------------------------------------------------------------------
// Feature flag bit masks
// ---------------------------------------------------------------------------

/// Feature bit constants for `features_incompat` / `features_ro_compat` /
/// `features_compat` in PoolLabelV1.
pub mod features {
    /// Pool label format V1 (always set for this label version; incompat bit 0).
    pub const POOL_LABEL_V1: u64 = 1 << 0;
    /// Pool uses DeviceClass for allocation policy (compat bit 0).
    pub const DEVICE_CLASS_AWARE: u64 = 1 << 0;
    /// Pool supports hot-spare auto-replace (compat bit 1).
    pub const SPARE_POLICY_SUPPORTED: u64 = 1 << 1;
    /// Per-device health state (ONLINE/DEGRADED/FAULTED) and error counters are
    /// persisted in the label extension area.
    pub const DEVICE_HEALTH_STATE: u64 = 1 << 7;
    /// Pool uses per-object ChaCha20-Poly1305 encryption.
    /// When set, every object in the pool is transparently encrypted at rest.
    /// An importer or mounter must provide a valid sealing/lease secret;
    /// plaintext opens of encrypted pools must fail closed.
    pub const ENCRYPTION_INCOMPAT: u64 = 1 << 8;

    /// Pool is managed by cluster authority (multi-node, lease-fenced,
    /// membership-aware).  Stored in `features_incompat` so standalone
    /// importers refuse to open a clustered pool without cluster authority.
    /// Incompat bit 9.
    pub const CLUSTER_POOL_INCOMPAT: u64 = 1 << 9;

    /// Cluster-aware topology metadata is present in the label.
    /// Stored in `features_compat` — standalone importers can safely open
    /// the pool but will not participate in cluster operations.
    /// Compat bit 8.
    pub const CLUSTER_POOL_COMPAT: u64 = 1 << 8;
}

// ---------------------------------------------------------------------------
// PoolLabelV1
// ---------------------------------------------------------------------------

/// On-device self-describing pool label (version 1).
///
/// Each device in a pool carries this label at two locations for redundancy.
/// The label identifies the pool, device role, topology generation, and
/// recovery point (commit_group).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolLabelV1 {
    /// Magic bytes: `b"VBFS"`.
    pub magic: [u8; 4],
    /// Label format version (1).
    pub version: u32,
    /// Unique pool identifier (UUID v4).
    pub pool_guid: [u8; 16],
    /// Unique device identifier (UUID v4).
    pub device_guid: [u8; 16],
    /// Human-readable pool name (UTF-8, max 255 bytes).
    pub pool_name: [u8; POOL_NAME_MAX],
    /// Actual length of the pool name in `pool_name`.
    pub pool_name_len: u16,
    /// Operational state of the pool.
    pub pool_state: PoolState,
    /// Last committed commit_group on this device.
    pub commit_group: u64,
    /// CommitGroup when this label was last written.
    pub label_commit_group: u64,
    /// Device position in topology (0-based).
    pub device_index: u32,
    /// Incremented on each device add/remove.
    pub topology_generation: u64,
    /// Total devices in pool topology.
    pub device_count: u32,
    /// Allocation class of this device.
    pub device_class: DeviceClass,
    /// Total device capacity in bytes.
    pub device_capacity_bytes: u64,
    /// Byte offset to system area root.
    pub system_area_pointer: u64,
    /// Size of system area in bytes.
    pub system_area_size: u64,
    /// Bitmask: incompatible feature flags.
    pub features_incompat: u64,
    /// Bitmask: read-only-compatible feature flags.
    pub features_ro_compat: u64,
    /// Bitmask: compatible feature flags.
    pub features_compat: u64,
    /// Per-device health state: 0=Online, 1=Degraded, 2=Faulted.
    pub device_health: u8,
    /// Accumulated read I/O errors on this device.
    pub device_read_errors: u64,
    /// Accumulated write I/O errors on this device.
    pub device_write_errors: u64,
    /// Accumulated checksum errors on this device.
    pub device_checksum_errors: u64,
    /// BLAKE3-256 checksum of all preceding fields (zeroed for computation).
    pub checksum: [u8; 32],
}

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------
//
// Off  Size  Field
//   0    4   magic
//   4    4   version
//   8   16   pool_guid
//  24   16   device_guid
//  40    2   pool_name_len
//  42  255   pool_name (padded with zeros)
// 297    1   pool_state
// 298    8   commit_group
// 306    8   label_commit_group
// 314    4   device_index
// 318    8   topology_generation
// 326    4   device_count
// 330    1   device_class
// 331    8   device_capacity_bytes
// 339    8   system_area_pointer
// 347    8   system_area_size
// 355    8   features_incompat
// 363    8   features_ro_compat
// 371    8   features_compat
// 379    1   device_health
// 380    8   device_read_errors
// 388    8   device_write_errors
// 396    8   device_checksum_errors
// 404   32   checksum (BLAKE3-256)
// 436  end   (total: 436 bytes)

/// Total wire size of a PoolLabelV1 in bytes.
pub const POOL_LABEL_V1_WIRE_SIZE: usize = 411;

/// Extended wire size including device health fields.
pub const POOL_LABEL_V1_EXT_WIRE_SIZE: usize = 436;

/// Offset of the checksum field in the wire format.
/// Original checksum offset for labels without health extension.
pub const POOL_LABEL_V1_CHECKSUM_BASE_OFFSET: usize = 379;
pub const POOL_LABEL_V1_CHECKSUM_OFFSET: usize = 404;

// ---------------------------------------------------------------------------
// Label errors
// ---------------------------------------------------------------------------

/// Possible errors when decoding or validating a pool label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelError {
    /// Input buffer is too small to contain a complete label.
    BufferTooSmall,
    /// Magic bytes do not match [`POOL_LABEL_MAGIC`].
    BadMagic,
    /// Unrecognized label format version.
    UnsupportedVersion(u32),
    /// `PoolState` value out of range.
    BadPoolState(u8),
    /// `DeviceClass` value out of range.
    BadDeviceClass(u8),
    /// `pool_name_len` exceeds [`POOL_NAME_MAX`].
    NameTooLong,
    /// BLAKE3-256 checksum mismatch (label is corrupt).
    ChecksumMismatch,
    /// Cannot remove the last remaining device from a pool.
    LastDevice,
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("buffer too small for label"),
            Self::BadMagic => f.write_str("bad magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported label version {v}"),
            Self::BadPoolState(v) => write!(f, "bad pool state {v}"),
            Self::BadDeviceClass(v) => write!(f, "bad device class {v}"),
            Self::NameTooLong => f.write_str("pool name too long"),
            Self::ChecksumMismatch => f.write_str("checksum mismatch"),
            Self::LastDevice => f.write_str("cannot remove last device from pool"),
        }
    }
}

// ---------------------------------------------------------------------------
// CommittedRootState
// ---------------------------------------------------------------------------

/// Kernel-facing committed-root selection outcome.
///
/// After scanning pool device labels, the mount path uses this enum to
/// decide whether to accept a root, reject the device, or escalate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedRootState {
    /// A committed root was found and its self-hash is valid.
    Valid {
        /// Committed transaction group.
        txg: u64,
        /// Device index in the pool topology.
        device_index: u32,
    },

    /// The most-current committed root among all scanned devices (highest txg).
    Current {
        /// Highest committed transaction group across all devices.
        txg: u64,
        /// Device index that contributed the current root.
        device_index: u32,
    },

    /// A candidate committed-root entry had a self-hash mismatch.
    Corrupt {
        /// Device index where the corrupt entry was found.
        device_index: u32,
        /// The txg of the corrupt entry (may be suspect).
        txg: u64,
    },

    /// No committed-root entries were found (empty ledger or no valid label).
    Empty,
}

impl fmt::Display for CommittedRootState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid { txg, device_index } => {
                write!(f, "valid root txg={txg} dev={device_index}")
            }
            Self::Current { txg, device_index } => {
                write!(f, "current root txg={txg} dev={device_index}")
            }
            Self::Corrupt { device_index, txg } => {
                write!(f, "corrupt root txg={txg} dev={device_index}")
            }
            Self::Empty => write!(f, "empty committed-root ledger"),
        }
    }
}
// ---------------------------------------------------------------------------
// Encode / Decode
// ---------------------------------------------------------------------------

/// Encode a `PoolLabelV1` into `buf`, which must be at least
/// [`POOL_LABEL_V1_EXT_WIRE_SIZE`] bytes. The checksum field in `label` is
/// zeroed before hashing and then written out as the BLAKE3-256 of all other
/// fields.
/// Encode a `PoolLabelV1` into `buf`.  The buffer must be at least
/// [`POOL_LABEL_V1_WIRE_SIZE`] bytes.  When at least
/// [`POOL_LABEL_V1_EXT_WIRE_SIZE`] bytes are available, device health
/// fields are included at offsets 379–403 and the checksum covers
/// bytes 0–403.  Otherwise a backward-compatible 411-byte label is
/// written with checksum over bytes 0–378.
pub fn encode_label(label: &PoolLabelV1, buf: &mut [u8]) -> Result<(), LabelError> {
    if buf.len() < POOL_LABEL_V1_WIRE_SIZE {
        return Err(LabelError::BufferTooSmall);
    }
    let ext = buf.len() >= POOL_LABEL_V1_EXT_WIRE_SIZE;

    // Write fixed fields (little-endian).
    buf[0..4].copy_from_slice(&label.magic);
    buf[4..8].copy_from_slice(&label.version.to_le_bytes());
    buf[8..24].copy_from_slice(&label.pool_guid);
    buf[24..40].copy_from_slice(&label.device_guid);
    buf[40..42].copy_from_slice(&label.pool_name_len.to_le_bytes());
    buf[42..297].copy_from_slice(&label.pool_name);
    buf[297] = label.pool_state.to_u8();
    buf[298..306].copy_from_slice(&label.commit_group.to_le_bytes());
    buf[306..314].copy_from_slice(&label.label_commit_group.to_le_bytes());
    buf[314..318].copy_from_slice(&label.device_index.to_le_bytes());
    buf[318..326].copy_from_slice(&label.topology_generation.to_le_bytes());
    buf[326..330].copy_from_slice(&label.device_count.to_le_bytes());
    buf[330] = label.device_class.to_u8();
    buf[331..339].copy_from_slice(&label.device_capacity_bytes.to_le_bytes());
    buf[339..347].copy_from_slice(&label.system_area_pointer.to_le_bytes());
    buf[347..355].copy_from_slice(&label.system_area_size.to_le_bytes());
    buf[355..363].copy_from_slice(&label.features_incompat.to_le_bytes());
    buf[363..371].copy_from_slice(&label.features_ro_compat.to_le_bytes());
    let features_compat_wire = if ext {
        label.features_compat | features::DEVICE_HEALTH_STATE
    } else {
        label.features_compat
    };
    buf[371..379].copy_from_slice(&features_compat_wire.to_le_bytes());

    let cksum_off: usize;
    let cksum_end: usize;
    if ext {
        buf[379] = label.device_health;
        buf[380..388].copy_from_slice(&label.device_read_errors.to_le_bytes());
        buf[388..396].copy_from_slice(&label.device_write_errors.to_le_bytes());
        buf[396..404].copy_from_slice(&label.device_checksum_errors.to_le_bytes());
        cksum_off = 404;
        cksum_end = POOL_LABEL_V1_EXT_WIRE_SIZE;
    } else {
        cksum_off = POOL_LABEL_V1_CHECKSUM_BASE_OFFSET;
        cksum_end = POOL_LABEL_V1_WIRE_SIZE;
    }

    // Zero the checksum field, hash everything before it, then write.
    buf[cksum_off..cksum_end].fill(0);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf[0..cksum_off]);
    let digest = hasher.finalize();
    buf[cksum_off..cksum_end].copy_from_slice(digest.as_bytes());

    Ok(())
}

pub fn decode_label(buf: &[u8]) -> Result<PoolLabelV1, LabelError> {
    // Truncate to at most EXT_WIRE_SIZE bytes; callers may pass
    // the full label file which can be > 256 KiB.
    // Accept buffers >= WIRE_SIZE.  Callers may pass the full
    // label file (which can be > 256 KiB); we only look at the
    // first WIRE_SIZE or EXT_WIRE_SIZE bytes depending on the
    // feature flags read from the payload.
    if buf.len() < POOL_LABEL_V1_WIRE_SIZE {
        return Err(LabelError::BufferTooSmall);
    }

    // Verify magic.
    let magic: [u8; 4] = buf[0..4].try_into().unwrap();
    if magic != POOL_LABEL_MAGIC {
        return Err(LabelError::BadMagic);
    }

    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != 1 {
        return Err(LabelError::UnsupportedVersion(version));
    }

    let pool_guid: [u8; 16] = buf[8..24].try_into().unwrap();
    let device_guid: [u8; 16] = buf[24..40].try_into().unwrap();

    let pool_name_len = u16::from_le_bytes(buf[40..42].try_into().unwrap());
    if pool_name_len as usize > POOL_NAME_MAX {
        return Err(LabelError::NameTooLong);
    }

    let mut pool_name = [0u8; POOL_NAME_MAX];
    pool_name.copy_from_slice(&buf[42..297]);

    let pool_state = PoolState::from_u8(buf[297]).ok_or(LabelError::BadPoolState(buf[297]))?;
    let commit_group = u64::from_le_bytes(buf[298..306].try_into().unwrap());
    let label_commit_group = u64::from_le_bytes(buf[306..314].try_into().unwrap());
    let device_index = u32::from_le_bytes(buf[314..318].try_into().unwrap());
    let topology_generation = u64::from_le_bytes(buf[318..326].try_into().unwrap());
    let device_count = u32::from_le_bytes(buf[326..330].try_into().unwrap());
    let device_class =
        DeviceClass::from_u8(buf[330]).ok_or(LabelError::BadDeviceClass(buf[330]))?;
    let device_capacity_bytes = u64::from_le_bytes(buf[331..339].try_into().unwrap());
    let system_area_pointer = u64::from_le_bytes(buf[339..347].try_into().unwrap());
    let system_area_size = u64::from_le_bytes(buf[347..355].try_into().unwrap());
    let features_incompat = u64::from_le_bytes(buf[355..363].try_into().unwrap());
    let features_ro_compat = u64::from_le_bytes(buf[363..371].try_into().unwrap());
    let features_compat = u64::from_le_bytes(buf[371..379].try_into().unwrap());
    let has_health = features_compat & features::DEVICE_HEALTH_STATE != 0;
    // If health extension bit is set but the buffer is too short for the
    // extended label, reject early before slicing past the buffer.
    if has_health && buf.len() < POOL_LABEL_V1_EXT_WIRE_SIZE {
        return Err(LabelError::BufferTooSmall);
    }
    let (device_health, device_read_errors, device_write_errors, device_checksum_errors) =
        if has_health {
            (
                buf[379],
                u64::from_le_bytes(buf[380..388].try_into().unwrap()),
                u64::from_le_bytes(buf[388..396].try_into().unwrap()),
                u64::from_le_bytes(buf[396..404].try_into().unwrap()),
            )
        } else {
            (0, 0, 0, 0)
        };
    let checksum_offset = if has_health {
        POOL_LABEL_V1_CHECKSUM_OFFSET
    } else {
        POOL_LABEL_V1_CHECKSUM_BASE_OFFSET
    };
    let checksum_end = if has_health {
        POOL_LABEL_V1_EXT_WIRE_SIZE
    } else {
        POOL_LABEL_V1_WIRE_SIZE
    };
    let checksum: [u8; 32] = buf[checksum_offset..checksum_end].try_into().unwrap();

    // Verify checksum: hash everything before the checksum field.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf[0..checksum_offset]);
    let computed = hasher.finalize();
    if computed.as_bytes() != &checksum {
        return Err(LabelError::ChecksumMismatch);
    }

    Ok(PoolLabelV1 {
        magic,
        version,
        pool_guid,
        device_guid,
        pool_name,
        pool_name_len,
        pool_state,
        commit_group,
        label_commit_group,
        device_index,
        topology_generation,
        device_count,
        device_class,
        device_capacity_bytes,
        system_area_pointer,
        system_area_size,
        features_incompat,
        features_ro_compat,
        features_compat,
        device_health,
        device_read_errors,
        device_write_errors,
        device_checksum_errors,
        checksum,
    })
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Convenience: encode and compute a fresh checksum, returning the label with
/// an up-to-date checksum field.
pub fn seal_label(mut label: PoolLabelV1) -> Result<PoolLabelV1, LabelError> {
    let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    label.checksum = [0u8; 32];
    encode_label(&label, &mut buf)?;
    label
        .checksum
        .copy_from_slice(&buf[404..POOL_LABEL_V1_EXT_WIRE_SIZE]);
    Ok(label)
}

/// Verify a label's checksum in-place (without allocating a separate buffer).
pub fn verify_label_checksum(label: &PoolLabelV1) -> bool {
    let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    if encode_label(label, &mut buf).is_err() {
        return false;
    }
    buf[404..POOL_LABEL_V1_EXT_WIRE_SIZE] == label.checksum
}

impl PoolLabelV1 {
    /// Create a new label with default fields and zero checksum.
    /// Callers should populate fields then call [`seal_label`].
    #[must_use]
    pub fn new(pool_guid: [u8; 16], device_guid: [u8; 16], pool_name: &str) -> Self {
        let name_bytes = pool_name.as_bytes();
        let name_len = name_bytes.len().min(POOL_NAME_MAX);
        let mut name_buf = [0u8; POOL_NAME_MAX];
        name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);

        Self {
            magic: POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid,
            pool_name: name_buf,
            pool_name_len: name_len as u16,
            pool_state: PoolState::Active,
            commit_group: 0,
            label_commit_group: 0,
            device_index: 0,
            topology_generation: 0,
            device_count: 1,
            device_class: DeviceClass::Hdd,
            device_capacity_bytes: 0,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: 0,
            features_ro_compat: 0,
            features_compat: 0,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            checksum: [0u8; 32],
        }
    }

    /// Returns the pool name as a UTF-8 `&str`, truncating at
    /// `pool_name_len`. Returns an empty string for zero-length names.
    #[must_use]
    pub fn pool_name_str(&self) -> &str {
        let len = self.pool_name_len as usize;
        let slice = &self.pool_name[..len.min(POOL_NAME_MAX)];
        core::str::from_utf8(slice).unwrap_or("")
    }

    /// Returns true when the pool uses per-object encryption.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        (self.features_incompat & features::ENCRYPTION_INCOMPAT) != 0
    }

    /// Set the encryption flag on this label.
    ///
    /// Callers must re-seal the label via [`seal_label`] after calling this.
    pub fn set_encrypted(&mut self) {
        self.features_incompat |= features::ENCRYPTION_INCOMPAT;
    }

    /// Returns true when the pool is managed by cluster authority
    /// (multi-node, lease-fenced, membership-aware).
    ///
    /// When true, standalone importers must refuse to open the pool
    /// unless cluster authority is available.
    #[must_use]
    pub const fn is_clustered(&self) -> bool {
        (self.features_incompat & features::CLUSTER_POOL_INCOMPAT) != 0
    }

    /// Set the cluster-pool flag on this label.
    ///
    /// Callers must re-seal the label via [`seal_label`] after calling this.
    pub fn set_clustered(&mut self) {
        self.features_incompat |= features::CLUSTER_POOL_INCOMPAT;
    }
}

/// Remove a device from pool membership by updating the label on a
/// remaining device.
///
/// Decrements `device_count`, increments `topology_generation`, and
/// recomputes the BLAKE3 checksum.  The label is sealed via
/// [`seal_label`] before returning.
///
/// # Errors
///
/// Returns [`LabelError::LastDevice`] when `device_count <= 1`
/// (cannot remove the last remaining device from a pool).
pub fn remove_device_from_label(label: &PoolLabelV1) -> Result<PoolLabelV1, LabelError> {
    if label.device_count <= 1 {
        return Err(LabelError::LastDevice);
    }

    let mut updated = label.clone();
    updated.device_count = updated.device_count.saturating_sub(1);
    updated.topology_generation = updated.topology_generation.saturating_add(1);

    // Recompute checksum
    seal_label(updated)
}

/// Returns `true` when `label` represents a device that has been
/// removed from the pool (i.e., `pool_state` is [`PoolState::Destroyed`]).
#[must_use]
pub fn is_device_removed(label: &PoolLabelV1) -> bool {
    label.pool_state == PoolState::Destroyed
}

// ---------------------------------------------------------------------------
// VCRL committed-root ledger format (system area)
// ---------------------------------------------------------------------------

/// Magic bytes for the VCRL committed-root ledger ("VCRL").
pub const VCRL_MAGIC: [u8; 4] = *b"VCRL";

/// Current VCRL ledger format version.
pub const VCRL_VERSION: u32 = 1;

/// Header size: magic(4) + version(4) + entry_count(4).
pub const VCRL_HEADER_SIZE: usize = 12;

/// Size of a single ledger entry: root_ino(8) + pool_uuid(32) + txg(8) + digest(32).
pub const VCRL_ENTRY_SIZE: usize = 80;

/// Footer size: BLAKE3-256 checksum of header + entries.
pub const VCRL_FOOTER_SIZE: usize = 32;

/// Minimum ledger size (header + footer, zero entries).
pub const VCRL_MIN_SIZE: usize = VCRL_HEADER_SIZE + VCRL_FOOTER_SIZE;

/// BLAKE3 domain separator for committed-root anchor hashes.
/// Must match the kmod CommittedRootAnchor domain so that self-hashes verify.
pub const VCRL_DOMAIN: &str = "tidefs-kmod-posix-vfs-committed-root-v1";

/// Expand a 16-byte pool GUID into a 32-byte pool UUID (zero-extend).
#[must_use]
pub fn pool_guid_to_uuid32(guid: &[u8; 16]) -> [u8; 32] {
    let mut uuid = [0u8; 32];
    uuid[..16].copy_from_slice(guid);
    uuid
}

/// A committed-root ledger entry supplied by pool creation or root commit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcrlEntry {
    pub root_ino: u64,
    pub pool_uuid: [u8; 32],
    pub txg: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcrlEncodeError {
    EntryCountOverflow,
    BufferTooSmall { required: usize, provided: usize },
}

/// Compute the BLAKE3 entry digest for a VCRL ledger entry.
///
/// Domain: VCRL_DOMAIN. Input: root_ino || pool_uuid || txg (all LE).
#[must_use]
pub fn compute_vcrl_entry_digest(root_ino: u64, pool_uuid: &[u8; 32], txg: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VCRL_DOMAIN);
    hasher.update(&root_ino.to_le_bytes());
    hasher.update(pool_uuid);
    hasher.update(&txg.to_le_bytes());
    hasher.finalize().into()
}

#[must_use]
pub fn vcrl_required_len(entry_count: usize) -> Option<usize> {
    entry_count
        .checked_mul(VCRL_ENTRY_SIZE)
        .and_then(|entries| VCRL_HEADER_SIZE.checked_add(entries))
        .and_then(|without_footer| without_footer.checked_add(VCRL_FOOTER_SIZE))
}

/// Encode a set of entries into a caller-provided VCRL ledger buffer.
///
/// The caller supplies only root identity fields. This function computes every
/// per-entry digest and the final ledger checksum internally, so callers cannot
/// smuggle an unauthenticated digest into a pool image.
pub fn encode_vcrl_ledger_into(
    entries: &[VcrlEntry],
    buf: &mut [u8],
) -> Result<usize, VcrlEncodeError> {
    let count = u32::try_from(entries.len()).map_err(|_| VcrlEncodeError::EntryCountOverflow)?;
    let total = vcrl_required_len(entries.len()).ok_or(VcrlEncodeError::EntryCountOverflow)?;
    if buf.len() < total {
        return Err(VcrlEncodeError::BufferTooSmall {
            required: total,
            provided: buf.len(),
        });
    }

    // Header
    buf[0..4].copy_from_slice(&VCRL_MAGIC);
    buf[4..8].copy_from_slice(&VCRL_VERSION.to_le_bytes());
    buf[8..12].copy_from_slice(&count.to_le_bytes());

    // Entries
    for (i, entry) in entries.iter().enumerate() {
        let off = VCRL_HEADER_SIZE + i * VCRL_ENTRY_SIZE;
        buf[off..off + 8].copy_from_slice(&entry.root_ino.to_le_bytes());
        buf[off + 8..off + 40].copy_from_slice(&entry.pool_uuid);
        buf[off + 40..off + 48].copy_from_slice(&entry.txg.to_le_bytes());
        let digest = compute_vcrl_entry_digest(entry.root_ino, &entry.pool_uuid, entry.txg);
        buf[off + 48..off + 80].copy_from_slice(&digest);
    }

    // Footer checksum over header + entries.
    let entries_bytes = entries.len() * VCRL_ENTRY_SIZE;
    let payload_end = VCRL_HEADER_SIZE + entries_bytes;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf[..payload_end]);
    let checksum = hasher.finalize();
    buf[payload_end..payload_end + VCRL_FOOTER_SIZE].copy_from_slice(checksum.as_bytes());
    Ok(total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_label(name: &str) -> PoolLabelV1 {
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0xBBu8; 16];
        PoolLabelV1::new(pool_guid, device_guid, name)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let label = make_label("testpool");
        let sealed = seal_label(label).unwrap();

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();

        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.magic, POOL_LABEL_MAGIC);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.pool_guid, [0xAAu8; 16]);
        assert_eq!(decoded.device_guid, [0xBBu8; 16]);
        assert_eq!(decoded.pool_name_str(), "testpool");
        assert_eq!(decoded.pool_state, PoolState::Active);
        assert_eq!(decoded.checksum, sealed.checksum);
    }

    #[test]
    fn checksum_detects_corruption() {
        let label = make_label("corrupt");
        let sealed = seal_label(label).unwrap();

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();

        // Flip a byte in the payload area (pool_guid), before the checksum.
        buf[8] ^= 0x01;

        let result = decode_label(&buf);
        assert_eq!(result, Err(LabelError::ChecksumMismatch));
    }

    #[test]
    fn bad_magic_rejected() {
        let label = make_label("badmagic");
        let sealed = seal_label(label).unwrap();

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();

        buf[0] = b'X';
        assert_eq!(decode_label(&buf), Err(LabelError::BadMagic));
    }

    #[test]
    fn bad_version_rejected() {
        let label = make_label("badver");
        let sealed = seal_label(label).unwrap();

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();

        buf[4..8].copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(decode_label(&buf), Err(LabelError::UnsupportedVersion(42)));
    }

    #[test]
    fn pool_state_roundtrip() {
        for v in 0u8..=2u8 {
            let state = PoolState::from_u8(v).unwrap();
            assert_eq!(state.to_u8(), v);
        }
        assert!(PoolState::from_u8(3).is_none());
        assert!(PoolState::from_u8(255).is_none());
    }

    #[test]
    fn device_class_roundtrip() {
        for v in 0u8..=6u8 {
            let class = DeviceClass::from_u8(v).unwrap();
            assert_eq!(class.to_u8(), v);
        }
        assert!(DeviceClass::from_u8(7).is_none());
        assert!(DeviceClass::from_u8(255).is_none());
    }

    #[test]
    fn pool_name_truncation() {
        let long = "a".repeat(500);
        let label = make_label(&long);
        assert_eq!(label.pool_name_len as usize, 255);
        assert_eq!(label.pool_name_str().len(), 255);
    }

    #[test]
    fn verify_checksum_in_place() {
        let label = make_label("verify");
        let sealed = seal_label(label).unwrap();
        assert!(verify_label_checksum(&sealed));

        let mut corrupted = sealed.clone();
        corrupted.device_capacity_bytes ^= 1;
        assert!(!verify_label_checksum(&corrupted));
    }

    #[test]
    fn buffer_too_small() {
        let label = make_label("small");
        let mut buf = [0u8; 10];
        assert_eq!(
            encode_label(&label, &mut buf),
            Err(LabelError::BufferTooSmall)
        );
        assert_eq!(decode_label(&buf), Err(LabelError::BufferTooSmall));
    }

    #[test]
    fn is_importable() {
        assert!(PoolState::Active.is_importable());
        assert!(PoolState::Exported.is_importable());
        assert!(!PoolState::Destroyed.is_importable());
    }

    #[test]
    fn data_bearing_device_classes() {
        assert!(DeviceClass::Hdd.is_data_bearing());
        assert!(DeviceClass::Ssd.is_data_bearing());
        assert!(DeviceClass::Nvme.is_data_bearing());
        assert!(DeviceClass::Special.is_data_bearing());
        assert!(!DeviceClass::LogDevice.is_data_bearing());
        assert!(!DeviceClass::Cache.is_data_bearing());
    }

    // ── remove_device_from_label tests ──────────────────────────────

    fn make_test_label(device_count: u32, generation: u64) -> PoolLabelV1 {
        let mut label = make_label("testpool");
        label.device_count = device_count;
        label.topology_generation = generation;
        label
    }

    #[test]
    fn remove_device_decrements_count() {
        let label = make_test_label(3, 5);
        let updated = remove_device_from_label(&label).unwrap();
        assert_eq!(updated.device_count, 2);
        assert_eq!(updated.topology_generation, 6);
        assert_eq!(updated.pool_guid, label.pool_guid);
        assert_eq!(updated.pool_name_str(), label.pool_name_str());
    }

    #[test]
    fn remove_device_recomputes_checksum() {
        let label = make_test_label(2, 1);
        let updated = remove_device_from_label(&label).unwrap();
        // Checksum must differ from original since device_count and generation changed
        assert_ne!(updated.checksum, label.checksum);
        // Updated label must pass self-verification
        assert!(verify_label_checksum(&updated));
    }

    #[test]
    fn remove_device_last_device_is_error() {
        let label = make_test_label(1, 0);
        let result = remove_device_from_label(&label);
        assert_eq!(result, Err(LabelError::LastDevice));
    }

    #[test]
    fn remove_device_zero_device_count_is_error() {
        let mut label = make_label("empty");
        label.device_count = 0;
        let result = remove_device_from_label(&label);
        assert_eq!(result, Err(LabelError::LastDevice));
    }

    #[test]
    fn remove_device_preserves_original() {
        let label = make_test_label(4, 10);
        let original = label.clone();
        let _updated = remove_device_from_label(&label).unwrap();
        // Original label must be unchanged
        assert_eq!(label.device_count, original.device_count);
        assert_eq!(label.topology_generation, original.topology_generation);
    }

    #[test]
    fn remove_device_roundtrip_encode_decode() {
        let label = make_test_label(3, 7);
        let updated = remove_device_from_label(&label).unwrap();

        // Encode the updated label
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&updated, &mut buf).unwrap();

        // Decode back
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.device_count, 2);
        assert_eq!(decoded.topology_generation, 8);
        assert_eq!(decoded.checksum, updated.checksum);
    }

    #[test]
    fn remove_device_topology_generation_wraps() {
        let mut label = make_test_label(2, u64::MAX);
        // seal it so checksum matches pre-removal state
        label = seal_label(label).unwrap();
        let updated = remove_device_from_label(&label).unwrap();
        // saturating_add on u64::MAX wraps to u64::MAX; 0 would be wrapping_add
        // Using saturating_add means it stays at u64::MAX. This is acceptable.
        assert_eq!(updated.topology_generation, u64::MAX);
        assert_eq!(updated.device_count, 1);
    }

    #[test]
    fn remove_device_multiple_times() {
        let label = make_test_label(4, 0);
        let after1 = remove_device_from_label(&label).unwrap();
        assert_eq!(after1.device_count, 3);
        assert_eq!(after1.topology_generation, 1);

        let after2 = remove_device_from_label(&after1).unwrap();
        assert_eq!(after2.device_count, 2);
        assert_eq!(after2.topology_generation, 2);

        let after3 = remove_device_from_label(&after2).unwrap();
        assert_eq!(after3.device_count, 1);
        assert_eq!(after3.topology_generation, 3);

        // Cannot remove the last device
        assert_eq!(
            remove_device_from_label(&after3),
            Err(LabelError::LastDevice)
        );
    }

    #[test]
    fn remove_device_checksum_detects_tampering() {
        let label = make_test_label(3, 5);
        let mut updated = remove_device_from_label(&label).unwrap();
        // Tamper with device_count after sealing
        updated.device_count = 99;
        assert!(!verify_label_checksum(&updated));
    }

    #[test]
    fn last_device_error_display() {
        let err = LabelError::LastDevice;
        let s = format!("{err}");
        assert_eq!(s, "cannot remove last device from pool");
    }

    #[test]
    fn is_device_removed_false_for_active() {
        let label = make_test_label(3, 1);
        assert!(!is_device_removed(&label));
    }

    // ── CommittedRootState tests ──────────────────────────────────────

    #[test]
    fn committed_root_state_valid() {
        let s = CommittedRootState::Valid {
            txg: 42,
            device_index: 0,
        };
        assert!(matches!(
            s,
            CommittedRootState::Valid {
                txg: 42,
                device_index: 0
            }
        ));
    }

    #[test]
    fn committed_root_state_current() {
        let s = CommittedRootState::Current {
            txg: 100,
            device_index: 1,
        };
        match s {
            CommittedRootState::Current { txg, device_index } => {
                assert_eq!(txg, 100);
                assert_eq!(device_index, 1);
            }
            _ => panic!("expected Current"),
        }
    }

    #[test]
    fn committed_root_state_corrupt() {
        let s = CommittedRootState::Corrupt {
            device_index: 2,
            txg: 7,
        };
        match s {
            CommittedRootState::Corrupt { device_index, txg } => {
                assert_eq!(device_index, 2);
                assert_eq!(txg, 7);
            }
            _ => panic!("expected Corrupt"),
        }
    }

    #[test]
    fn committed_root_state_empty() {
        assert_eq!(CommittedRootState::Empty, CommittedRootState::Empty);
    }

    #[test]
    fn committed_root_state_display() {
        let s = format!(
            "{}",
            CommittedRootState::Valid {
                txg: 5,
                device_index: 0
            }
        );
        assert!(s.contains("txg=5"));
        let s = format!(
            "{}",
            CommittedRootState::Current {
                txg: 10,
                device_index: 1
            }
        );
        assert!(s.contains("current root"));
        let s = format!(
            "{}",
            CommittedRootState::Corrupt {
                device_index: 2,
                txg: 3
            }
        );
        assert!(s.contains("corrupt root"));
        let s = format!("{}", CommittedRootState::Empty);
        assert!(s.contains("empty"));
    }

    #[test]
    fn committed_root_state_clone_eq() {
        let a = CommittedRootState::Valid {
            txg: 1,
            device_index: 0,
        };
        let b = a;
        assert_eq!(a, b);
        let c = CommittedRootState::Valid {
            txg: 2,
            device_index: 0,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn vcrl_encoder_computes_entry_digest() {
        let entry = VcrlEntry {
            root_ino: 1,
            pool_uuid: [0x42; 32],
            txg: 7,
        };
        let mut buf = [0u8; VCRL_HEADER_SIZE + VCRL_ENTRY_SIZE + VCRL_FOOTER_SIZE];
        let written = encode_vcrl_ledger_into(&[entry.clone()], &mut buf).unwrap();
        assert_eq!(written, buf.len());
        assert_eq!(&buf[0..4], &VCRL_MAGIC);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 1);

        let stored_digest: [u8; 32] = buf[60..92].try_into().unwrap();
        assert_eq!(
            stored_digest,
            compute_vcrl_entry_digest(entry.root_ino, &entry.pool_uuid, entry.txg)
        );

        let mut footer_hasher = blake3::Hasher::new();
        footer_hasher.update(&buf[..VCRL_HEADER_SIZE + VCRL_ENTRY_SIZE]);
        assert_eq!(
            &buf[VCRL_HEADER_SIZE + VCRL_ENTRY_SIZE..written],
            footer_hasher.finalize().as_bytes()
        );
    }

    #[test]
    fn vcrl_encoder_requires_caller_buffer() {
        let entry = VcrlEntry {
            root_ino: 1,
            pool_uuid: [0x24; 32],
            txg: 1,
        };
        let mut short = [0u8; VCRL_MIN_SIZE];
        let err = encode_vcrl_ledger_into(&[entry], &mut short).unwrap_err();
        assert_eq!(
            err,
            VcrlEncodeError::BufferTooSmall {
                required: VCRL_HEADER_SIZE + VCRL_ENTRY_SIZE + VCRL_FOOTER_SIZE,
                provided: VCRL_MIN_SIZE,
            }
        );
    }

    // ── Wire format constant assertions ─────────────────────────────

    #[test]
    fn format_constants_match_411_436_layout() {
        assert_eq!(POOL_LABEL_MAGIC, *b"VBFS");
        assert_eq!(POOL_LABEL_V1_WIRE_SIZE, 411);
        assert_eq!(POOL_LABEL_V1_EXT_WIRE_SIZE, 436);
        assert_eq!(POOL_LABEL_V1_CHECKSUM_BASE_OFFSET, 379);
        assert_eq!(POOL_LABEL_V1_CHECKSUM_OFFSET, 404);
        assert_eq!(POOL_LABEL_SIZE, 262_144);
        assert_eq!(POOL_NAME_MAX, 255);

        // VCRL constants.
        assert_eq!(VCRL_MAGIC, *b"VCRL");
        assert_eq!(VCRL_VERSION, 1);
        assert_eq!(VCRL_HEADER_SIZE, 12);
        assert_eq!(VCRL_ENTRY_SIZE, 80);
        assert_eq!(VCRL_FOOTER_SIZE, 32);
        assert_eq!(VCRL_MIN_SIZE, 44);

        // Internal consistency: extended = base + health fields (25 bytes).
        assert_eq!(POOL_LABEL_V1_EXT_WIRE_SIZE, POOL_LABEL_V1_WIRE_SIZE + 25);
        assert_eq!(
            POOL_LABEL_V1_CHECKSUM_OFFSET,
            POOL_LABEL_V1_CHECKSUM_BASE_OFFSET + 25
        );
    }

    // ── Helpers for decode-rejection tests ──────────────────────────

    /// Encode a label into a fresh 436-byte buffer and return
    /// (buffer, checksum_offset, has_health).
    fn encode_valid_ext_label(name: &str) -> ([u8; POOL_LABEL_V1_EXT_WIRE_SIZE], usize, bool) {
        let label = make_label(name);
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        // The 436-byte buffer triggers the ext path in encode_label
        // which sets DEVICE_HEALTH_STATE in features_compat_wire.
        let has_health = u64::from_le_bytes(buf[371..379].try_into().unwrap())
            & features::DEVICE_HEALTH_STATE
            != 0;
        assert!(
            has_health,
            "EXT_WIRE_SIZE buffer should set DEVICE_HEALTH_STATE"
        );
        (buf, POOL_LABEL_V1_CHECKSUM_OFFSET, has_health)
    }

    /// Recompute the BLAKE3 checksum over buf[0..cksum_off] and write it
    /// into buf[cksum_off..cksum_off+32].
    fn rechecksum_buf(buf: &mut [u8], cksum_off: usize) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[0..cksum_off]);
        let digest = hasher.finalize();
        buf[cksum_off..cksum_off + 32].copy_from_slice(digest.as_bytes());
    }

    // ── Decode rejection: BadPoolState via corrupt buffer ───────────

    #[test]
    fn decode_rejects_bad_pool_state() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("badpool");
        buf[297] = 0xFF;
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::BadPoolState(0xFF)));
    }

    #[test]
    fn decode_rejects_bad_pool_state_boundary_3() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("boundary");
        buf[297] = 3; // valid range: 0..=2
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::BadPoolState(3)));
    }

    // ── Decode rejection: BadDeviceClass via corrupt buffer ─────────

    #[test]
    fn decode_rejects_bad_device_class() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("badclass");
        buf[330] = 0xFF;
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::BadDeviceClass(0xFF)));
    }

    #[test]
    fn decode_rejects_bad_device_class_boundary_7() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("classbound");
        buf[330] = 7; // valid range: 0..=6
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::BadDeviceClass(7)));
    }

    // ── Decode rejection: NameTooLong via corrupt buffer ────────────

    #[test]
    fn decode_rejects_name_too_long_300() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("okname");
        buf[40..42].copy_from_slice(&300u16.to_le_bytes());
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::NameTooLong));
    }

    #[test]
    fn decode_accepts_name_at_254() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("okname");
        buf[40..42].copy_from_slice(&254u16.to_le_bytes());
        rechecksum_buf(&mut buf, cksum_off);
        assert!(decode_label(&buf).is_ok());
    }

    #[test]
    fn decode_rejects_name_at_256() {
        let (mut buf, cksum_off, _) = encode_valid_ext_label("okname");
        buf[40..42].copy_from_slice(&256u16.to_le_bytes());
        rechecksum_buf(&mut buf, cksum_off);
        assert_eq!(decode_label(&buf), Err(LabelError::NameTooLong));
    }

    // ── Boundary tests: exact minimum / one-byte-short / health ext ─

    #[test]
    fn decode_exact_411_byte_buffer_succeeds() {
        let label = make_label("exact411");
        let sealed = seal_label(label).unwrap();
        let mut short_buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut short_buf).unwrap();
        let decoded = decode_label(&short_buf).unwrap();
        assert_eq!(decoded.magic, POOL_LABEL_MAGIC);
    }

    #[test]
    fn decode_410_byte_buffer_rejected() {
        let buf = [0u8; 410];
        assert_eq!(decode_label(&buf), Err(LabelError::BufferTooSmall));
    }

    #[test]
    fn decode_411_byte_buffer_with_health_flag_rejected() {
        let (ext_buf, _, _) = encode_valid_ext_label("healthtest");
        let mut short_buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        short_buf.copy_from_slice(&ext_buf[..POOL_LABEL_V1_WIRE_SIZE]);
        let mut fc = u64::from_le_bytes(short_buf[371..379].try_into().unwrap());
        fc |= features::DEVICE_HEALTH_STATE;
        short_buf[371..379].copy_from_slice(&fc.to_le_bytes());
        rechecksum_buf(&mut short_buf, POOL_LABEL_V1_CHECKSUM_BASE_OFFSET);
        assert_eq!(decode_label(&short_buf), Err(LabelError::BufferTooSmall));
    }

    #[test]
    fn decode_exact_436_byte_buffer_with_health_succeeds() {
        let (buf, _, _) = encode_valid_ext_label("exact436");
        let decoded = decode_label(&buf).unwrap();
        assert_eq!(decoded.magic, POOL_LABEL_MAGIC);
    }

    #[test]
    fn decode_435_byte_with_health_flag_rejected() {
        // encode_valid_ext_label returns a 436-byte buffer with health extension.
        // Truncating to 435 bytes with the health flag still set in
        // features_compat should trigger BufferTooSmall before the checksum
        // read, so no re-checksum is needed.
        let (full_buf, _, _) = encode_valid_ext_label("healthext435");
        let mut short = [0u8; 435];
        short.copy_from_slice(&full_buf[..435]);
        assert_eq!(decode_label(&short), Err(LabelError::BufferTooSmall));
    }

    // ── Zero-hash / committed-root rejection ────────────────────────

    #[test]
    fn zero_checksum_fails_verify_label_checksum() {
        let mut label = make_label("zerohash");
        label.checksum = [0u8; 32];
        assert!(
            !verify_label_checksum(&label),
            "label with zeroed checksum must not pass verification"
        );
    }

    #[test]
    fn zero_checksum_buffer_fails_decode_label() {
        let sealed = seal_label(make_label("zerohash2")).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        buf[POOL_LABEL_V1_CHECKSUM_OFFSET..POOL_LABEL_V1_CHECKSUM_OFFSET + 32].fill(0);
        assert_eq!(
            decode_label(&buf),
            Err(LabelError::ChecksumMismatch),
            "decode_label must reject buffer with zeroed checksum"
        );
    }

    // ── Consolidated negative-path table test ───────────────────────

    struct CorruptionCase {
        name: &'static str,
        offset: usize,
        value: u8,
        rechecksum: bool,
        expected: LabelError,
    }

    #[test]
    fn decode_negative_path_table() {
        let cases = [
            CorruptionCase {
                name: "bad magic byte 0",
                offset: 0,
                value: b'X',
                rechecksum: true,
                expected: LabelError::BadMagic,
            },
            CorruptionCase {
                name: "bad magic byte 3",
                offset: 3,
                value: 0xFF,
                rechecksum: true,
                expected: LabelError::BadMagic,
            },
            CorruptionCase {
                name: "unsupported version 42",
                offset: 4,
                value: 42,
                rechecksum: true,
                expected: LabelError::UnsupportedVersion(42),
            },
            CorruptionCase {
                name: "name too long 300",
                offset: 40,
                value: 44,
                rechecksum: true,
                expected: LabelError::NameTooLong,
            },
            CorruptionCase {
                name: "bad pool state 0xFF",
                offset: 297,
                value: 0xFF,
                rechecksum: true,
                expected: LabelError::BadPoolState(0xFF),
            },
            CorruptionCase {
                name: "bad device class 0xFF",
                offset: 330,
                value: 0xFF,
                rechecksum: true,
                expected: LabelError::BadDeviceClass(0xFF),
            },
            CorruptionCase {
                name: "checksum mismatch",
                offset: 8,
                value: 0x77,
                rechecksum: false,
                expected: LabelError::ChecksumMismatch,
            },
        ];

        for case in &cases {
            let (mut buf, cksum_off, _) = encode_valid_ext_label("tabletest");
            if case.offset == 40 {
                // Write u16 LE at offset 40: LSB=case.value, MSB=1
                buf[40] = case.value;
                buf[41] = 1;
            } else {
                buf[case.offset] = case.value;
            }
            if case.rechecksum {
                rechecksum_buf(&mut buf, cksum_off);
            }
            let result = decode_label(&buf);
            assert_eq!(
                result,
                Err(case.expected),
                "case '{}': expected {:?}, got {:?}",
                case.name,
                case.expected,
                result
            );
        }
    }

    // ── Post-seal checksum consistency ──────────────────────────────

    #[test]
    fn sealed_label_has_nonzero_unique_checksum() {
        let a = seal_label(make_label("a")).unwrap();
        let b = seal_label(make_label("b")).unwrap();
        assert_ne!(a.checksum, [0u8; 32]);
        assert_ne!(b.checksum, [0u8; 32]);
        assert_ne!(a.checksum, b.checksum);
        assert!(verify_label_checksum(&a));
        assert!(verify_label_checksum(&b));
    }

    // ── cluster feature flag tests ────────────────────────────────────

    #[test]
    fn is_clustered_false_by_default() {
        let label = make_label("standalone");
        assert!(!label.is_clustered());
    }

    #[test]
    fn set_clustered_makes_is_clustered_true() {
        let mut label = make_label("clustered");
        assert!(!label.is_clustered());
        label.set_clustered();
        assert!(label.is_clustered());
    }

    #[test]
    fn clustered_label_roundtrip_encode_decode() {
        let mut label = make_label("clust");
        label.set_clustered();
        let sealed = seal_label(label).unwrap();
        assert!(sealed.is_clustered());

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        let decoded = decode_label(&buf).unwrap();
        assert!(decoded.is_clustered());
        assert_eq!(decoded.pool_name_str(), "clust");
    }

    #[test]
    fn cluster_incompat_flag_preserved_after_seal() {
        let mut label = make_label("clust2");
        label.set_clustered();
        let sealed = seal_label(label).unwrap();
        assert!(sealed.features_incompat & features::CLUSTER_POOL_INCOMPAT != 0);
        assert!(verify_label_checksum(&sealed));
    }

    #[test]
    fn cluster_compat_flag_can_be_set() {
        let mut label = make_label("clustcompat");
        label.features_compat |= features::CLUSTER_POOL_COMPAT;
        let sealed = seal_label(label).unwrap();
        assert!(sealed.features_compat & features::CLUSTER_POOL_COMPAT != 0);
        assert!(verify_label_checksum(&sealed));
    }
}
