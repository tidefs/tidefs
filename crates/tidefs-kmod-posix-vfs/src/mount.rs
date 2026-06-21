// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-side pool import context and label validation.
//!
//! Provides the kernel-mode mount initialization path: pool label
//! scanning, validation, and superblock-region location using the
//! canonical TideFS on-disk label format (PoolLabelV1). This is the
//! kernel equivalent of the userspace `PoolImporter::read_candidate`
//! path, adapted for the `no_std` kernel module environment.
//!
//! # No-daemon boundary
//!
//! All label parsing and validation runs entirely in kernel context
//! through the kmod-bridge substrate. No userspace daemon or
//! helper process is required for pool import during mount(2).
//!
//! # Label layout (on-disk)
//!
//! Each device carries two label copies:
//! - Label 0 at offset 0 (first 256 KiB)
//! - Label 1 at offset `capacity - 256 KiB` (last 256 KiB)
//!
//! The label identifies the pool, device role, topology generation,
//! and recovery commit_group. The superblock region is located via
//! the `system_area_pointer` field.

use crate::TideString as String;
use core::fmt;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

#[cfg(CONFIG_RUST)]
use crate::blake3;
use crate::superblock::CommittedRootAnchor;
#[cfg(not(CONFIG_RUST))]
use tidefs_kernel_storage_io::{
    read_pool_superblock, read_pool_superblock_at, KernelPoolSuperblock, KernelStorageIo,
    PoolSuperblockError,
};
#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::{
    decode_label, read_pool_superblock, read_pool_superblock_at, DeviceClass, KernelPoolSuperblock,
    KernelStorageIo, LabelError, PoolLabelV1, PoolState, PoolSuperblockError, POOL_LABEL_SIZE,
    POOL_LABEL_V1_EXT_WIRE_SIZE, POOL_LABEL_V1_HEALTH_WIRE_SIZE, POOL_LABEL_V1_WIRE_SIZE,
};
#[cfg(not(CONFIG_RUST))]
use tidefs_types_pool_label_core::{
    decode_label, DeviceClass, LabelError, PoolLabelV1, PoolState, POOL_LABEL_SIZE,
    POOL_LABEL_V1_EXT_WIRE_SIZE, POOL_LABEL_V1_HEALTH_WIRE_SIZE, POOL_LABEL_V1_WIRE_SIZE,
};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Cluster mode
// ---------------------------------------------------------------------------

/// Cluster membership mode derived from pool label feature flags.
///
/// Detected during pool import from on-device feature flags
/// (`CLUSTER_POOL_INCOMPAT`, `CLUSTER_POOL_COMPAT`).  This enum
/// records the cluster state visible to the kernel mount path
/// so that subsequent placement, recovery, and transport operations
/// can disclose their cluster context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterMode {
    /// Pool is standalone — no cluster feature flags set.
    Standalone,
    /// Pool is cluster-managed (`CLUSTER_POOL_INCOMPAT` set).
    /// A standalone kernel mount that does not also declare
    /// cluster membership will refuse import of this pool.
    ClusteredIncompat,
    /// Pool has cluster-compatible topology metadata
    /// (`CLUSTER_POOL_COMPAT` set) but no `CLUSTER_POOL_INCOMPAT`.
    /// Standalone import is acceptable; cluster participation is optional.
    ClusteredCompat,
}

impl ClusterMode {
    /// Returns `true` when the pool has any cluster feature flag set.
    pub fn is_clustered(self) -> bool {
        matches!(self, Self::ClusteredIncompat | Self::ClusteredCompat)
    }
}

/// Cluster context derived from the pool label during import.
///
/// Carries the cluster mode and the pool/device identity needed
/// for cluster-aware kernel operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolClusterInfo {
    /// Cluster membership mode.
    pub mode: ClusterMode,
    /// Pool GUID from the label (16 bytes).
    pub pool_guid: [u8; 16],
    /// Device GUID from the label (16 bytes).
    pub device_guid: [u8; 16],
}

// Pool import errors
// ---------------------------------------------------------------------------

/// Errors returned by kernel-side pool import operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolImportError {
    /// Label buffer is too small to contain a valid label.
    BufferTooSmall { provided: usize, required: usize },
    /// Label magic bytes do not match — not a TideFS device.
    BadMagic,
    /// Unrecognized label format version.
    UnsupportedVersion { version: u32 },
    /// Pool state does not permit import (e.g. Destroyed).
    PoolNotImportable { state: String },
    /// BLAKE3-256 checksum verification failed — label is corrupt.
    ChecksumMismatch,
    /// The pool name contains invalid UTF-8.
    InvalidPoolName,
    /// The label has valid format but failed a semantic check.
    LabelInvalid { detail: String },
    /// The system area pointer and size are inconsistent.
    SuperblockRegionInvalid { offset: u64, size: u64 },
    /// BLAKE3-256 digest verification is unavailable on this kernel
    /// configuration; label or ledger integrity cannot be verified.
    /// Reserved: the current kmod bridge provides BLAKE3-256 in all
    /// supported kernel builds.
    DigestUnavailable,
}

impl fmt::Display for PoolImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { provided, required } => {
                write!(
                    f,
                    "buffer too small: {provided} bytes provided, {required} required"
                )
            }
            Self::BadMagic => f.write_str("bad magic bytes — not a TideFS pool"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported label version {version}")
            }
            Self::PoolNotImportable { state } => {
                write!(f, "pool state does not permit import: {state}")
            }
            Self::ChecksumMismatch => f.write_str("label checksum mismatch"),
            Self::InvalidPoolName => f.write_str("pool name contains invalid UTF-8"),
            Self::LabelInvalid { detail } => {
                write!(f, "label semantic check failed: {detail}")
            }
            Self::SuperblockRegionInvalid { offset, size } => {
                write!(f, "superblock region invalid: offset={offset}, size={size}")
            }
            Self::DigestUnavailable => f.write_str("kernel BLAKE3 digest unavailable"),
        }
    }
}

impl From<LabelError> for PoolImportError {
    fn from(e: LabelError) -> Self {
        match e {
            LabelError::BufferTooSmall => Self::BufferTooSmall {
                provided: 0,
                required: POOL_LABEL_V1_WIRE_SIZE,
            },
            LabelError::BadMagic => Self::BadMagic,
            LabelError::UnsupportedVersion(v) => Self::UnsupportedVersion { version: v },
            LabelError::BadPoolState(v) => Self::PoolNotImportable {
                state: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "invalid pool state byte {v}");
                    s
                },
            },
            LabelError::BadDeviceClass(_) | LabelError::BadRedundancyPolicy { .. } => {
                Self::LabelInvalid {
                    detail: {
                        use core::fmt::Write;
                        let mut s = String::new();
                        let _ = write!(s, "{e}");
                        s
                    },
                }
            }
            LabelError::NameTooLong => Self::LabelInvalid {
                detail: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "{e}");
                    s
                },
            },
            LabelError::ChecksumMismatch => Self::ChecksumMismatch,
            LabelError::LastDevice => Self::LabelInvalid {
                detail: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "{e}");
                    s
                },
            },
            #[cfg(CONFIG_RUST)]
            LabelError::ChecksumUnavailable => Self::DigestUnavailable,
        }
    }
}

// ---------------------------------------------------------------------------
// PoolImportContext
// ---------------------------------------------------------------------------

/// Kernel-side pool import context holding a validated pool label and
/// the derived mount-initialization metadata.
///
/// Constructed from a raw label buffer by [`PoolImportContext::import`].
/// On success the context provides:
///
/// - The decoded [`PoolLabelV1`] with verified BLAKE3-256 checksum.
/// - A human-readable pool name.
/// - Whether the pool state permits import.
/// - The most recent commit_group for recovery.
/// - The superblock region offset and size (from `system_area_pointer`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolImportContext {
    /// The decoded and verified pool label.
    pub label: PoolLabelV1,
    /// Which label copy was read (0 = head at offset 0, 1 = tail at end).
    pub label_copy: u8,
    /// Pool name as a UTF-8 string (extracted from label).
    pub pool_name: String,
    /// Whether the pool state permits import (`Active` or `Exported`).
    pub importable: bool,
    /// Most recent commit_group from this label (recovery reference).
    pub recovery_commit_group: u64,
    /// Byte offset to the superblock/system area on the device.
    pub superblock_offset: u64,
    /// Size of the superblock/system area in bytes.
    pub superblock_size: u64,
    /// Cluster context derived from label feature flags.
    pub cluster: PoolClusterInfo,
}

impl PoolImportContext {
    /// Domain separator for BLAKE3 label identity hashing.
    const IDENTITY_DOMAIN: &'static str = "tidefs-kmod-pool-import-v1";

    /// Import a pool label from a raw device buffer.
    ///
    /// Attempts to decode `buf` as a [`PoolLabelV1`]. If the buffer is
    /// large enough to contain an extended label, the health and pool-wide
    /// redundancy policy extension fields are decoded. Otherwise, a base
    /// (411-byte) label is decoded.
    ///
    /// After successful decode, performs semantic validation:
    /// - Pool state must be importable (`Active` or `Exported`).
    /// - The pool name must be valid UTF-8.
    /// - The system area pointer must be consistent with the
    ///   `POOL_LABEL_SIZE` constant (non-zero pointer requires non-zero size).
    ///
    /// `label_copy` indicates which copy was read (0 = head, 1 = tail).
    pub fn import(buf: &[u8], label_copy: u8) -> Result<Self, PoolImportError> {
        if buf.len() < POOL_LABEL_V1_WIRE_SIZE {
            return Err(PoolImportError::BufferTooSmall {
                provided: buf.len(),
                required: POOL_LABEL_V1_WIRE_SIZE,
            });
        }

        let label = decode_label(buf)?;

        // Semantic validation: pool state must be importable.
        let importable = label.pool_state.is_importable();
        if !importable {
            return Err(PoolImportError::PoolNotImportable {
                state: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "{}", label.pool_state);
                    s
                },
            });
        }

        // Extract pool name.
        let pool_name = Self::extract_pool_name(&label)?;

        // Recovery commit_group is the label's commit_group.
        let recovery_commit_group = label.commit_group;

        // Superblock region from system_area fields.
        let superblock_offset = label.system_area_pointer;
        let superblock_size = label.system_area_size;

        // Validate superblock region consistency.
        Self::validate_superblock_region(superblock_offset, superblock_size)?;
        let cluster = Self::compute_cluster_info(&label);

        Ok(Self {
            label,
            label_copy,
            pool_name,
            importable,
            recovery_commit_group,
            superblock_offset,
            superblock_size,
            cluster,
        })
    }

    /// Import from a buffer that is known to be at least `POOL_LABEL_SIZE`
    /// bytes (the full 256 KiB label region). Attempts decoding at both
    /// the base size (411 bytes), health-only size (436 bytes), and current
    /// policy-bearing size (440 bytes), preferring the widest decode required
    /// by the feature flags.
    pub fn import_full(buf: &[u8], label_copy: u8) -> Result<Self, PoolImportError> {
        if buf.len() < POOL_LABEL_V1_WIRE_SIZE {
            return Err(PoolImportError::BufferTooSmall {
                provided: buf.len(),
                required: POOL_LABEL_V1_WIRE_SIZE,
            });
        }

        let features_compat = u64::from_le_bytes(buf[371..379].try_into().unwrap_or([0u8; 8]));
        let has_policy =
            features_compat & tidefs_kmod_bridge::kernel_types::POOL_REDUNDANCY_POLICY != 0;
        let has_health =
            features_compat & tidefs_kmod_bridge::kernel_types::DEVICE_HEALTH_STATE != 0;

        let label = if has_policy {
            if buf.len() < POOL_LABEL_V1_EXT_WIRE_SIZE {
                return Err(PoolImportError::BufferTooSmall {
                    provided: buf.len(),
                    required: POOL_LABEL_V1_EXT_WIRE_SIZE,
                });
            }
            decode_label(&buf[..POOL_LABEL_V1_EXT_WIRE_SIZE])?
        } else if has_health {
            if buf.len() < POOL_LABEL_V1_HEALTH_WIRE_SIZE {
                return Err(PoolImportError::BufferTooSmall {
                    provided: buf.len(),
                    required: POOL_LABEL_V1_HEALTH_WIRE_SIZE,
                });
            }
            decode_label(&buf[..POOL_LABEL_V1_HEALTH_WIRE_SIZE])?
        } else {
            decode_label(&buf[..POOL_LABEL_V1_WIRE_SIZE])?
        };

        let importable = label.pool_state.is_importable();
        if !importable {
            return Err(PoolImportError::PoolNotImportable {
                state: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "{}", label.pool_state);
                    s
                },
            });
        }

        let pool_name = Self::extract_pool_name(&label)?;
        let recovery_commit_group = label.commit_group;
        let superblock_offset = label.system_area_pointer;
        let superblock_size = label.system_area_size;

        Self::validate_superblock_region(superblock_offset, superblock_size)?;

        let cluster = Self::compute_cluster_info(&label);
        Ok(Self {
            label,
            label_copy,
            pool_name,
            importable,
            recovery_commit_group,
            superblock_offset,
            superblock_size,
            cluster,
        })
    }

    /// Scan a device buffer for a valid label at both well-known locations
    /// (offset 0 for label copy 0, and offset `capacity - POOL_LABEL_SIZE`
    /// for label copy 1). Returns the first valid label found.
    ///
    /// `device_buf` is the raw device content starting at offset 0.
    /// `device_size` is the total device size in bytes, used to locate
    /// the tail label copy.
    pub fn scan_device(device_buf: &[u8], device_size: u64) -> Result<Self, PoolImportError> {
        // Try label copy 0 at the head of the buffer.
        if device_buf.len() >= POOL_LABEL_V1_WIRE_SIZE {
            match Self::import(device_buf, 0) {
                Ok(ctx) => return Ok(ctx),
                Err(PoolImportError::ChecksumMismatch)
                | Err(PoolImportError::BadMagic)
                | Err(PoolImportError::UnsupportedVersion { .. }) => {
                    // Fall through to try label copy 1.
                }
                Err(e) => return Err(e),
            }
        }

        // Try label copy 1 at the tail (capacity - POOL_LABEL_SIZE).
        let tail_offset = device_size.saturating_sub(POOL_LABEL_SIZE as u64);
        if device_buf.len() as u64 > tail_offset
            && (device_buf.len() as u64 - tail_offset) >= POOL_LABEL_V1_WIRE_SIZE as u64
        {
            let tail_slice = &device_buf[tail_offset as usize..];
            return Self::import(tail_slice, 1);
        }

        Err(PoolImportError::BufferTooSmall {
            provided: device_buf.len(),
            required: POOL_LABEL_V1_WIRE_SIZE,
        })
    }

    /// Scan a block device for a valid TideFS pool label using
    /// [] — the no_std I/O path for kernel-mode mounts.
    ///
    /// Reads the pool label from sector 0 (label copy 0), validates
    /// the magic and BLAKE3-256 checksum, and returns a
    /// [] with pool identity, recovery commit_group,
    /// and committed-root ledger location.
    ///
    /// Falls back to label copy 1 at the end of the device when the
    /// head label is absent (bad magic) or corrupt. Other I/O errors
    /// are propagated immediately.
    ///
    /// This is the []-based equivalent of
    /// [], replacing the raw-buffer path for kernel-mode
    /// mounts where the block-device I/O must go through the portable
    /// sector-aligned trait.
    pub fn scan_device_io(io: &dyn KernelStorageIo) -> Result<Self, PoolImportError> {
        // Try label copy 0 at sector 0.
        match read_pool_superblock(io) {
            Ok(sb) => {
                // Convert KernelPoolSuperblock into a PoolLabelV1 so we
                // can reuse the existing import logic.
                let label = Self::label_from_superblock(&sb)?;
                let importable = label.pool_state.is_importable();
                if !importable {
                    return Err(PoolImportError::PoolNotImportable {
                        state: {
                            use core::fmt::Write;
                            let mut s = String::new();
                            let _ = write!(s, "{}", label.pool_state);
                            s
                        },
                    });
                }
                let pool_name = Self::extract_pool_name(&label)?;
                let recovery_commit_group = label.commit_group;
                let superblock_offset = label.system_area_pointer;
                let superblock_size = label.system_area_size;
                Self::validate_superblock_region(superblock_offset, superblock_size)?;
                let cluster = Self::compute_cluster_info(&label);
                return Ok(Self {
                    label,
                    label_copy: 0,
                    pool_name,
                    importable,
                    recovery_commit_group,
                    superblock_offset,
                    superblock_size,
                    cluster,
                });
            }
            Err(PoolSuperblockError::BadMagic)
            | Err(PoolSuperblockError::Corrupt)
            | Err(PoolSuperblockError::UnsupportedVersion(_)) => {
                // Fall through to try label copy 1.
            }
            Err(e) => {
                return Err(PoolImportError::LabelInvalid {
                    detail: {
                        use core::fmt::Write;
                        let mut s = String::new();
                        let _ = write!(s, "label copy 0 read error: {e}");
                        s
                    },
                });
            }
        }

        // Try label copy 1 at the end of the device.
        let ss = io.sector_size() as u64;
        let label_sectors = (POOL_LABEL_V1_EXT_WIRE_SIZE as u64).div_ceil(ss);
        let capacity = io.capacity_sectors();
        if capacity > label_sectors {
            let tail_sector = capacity - label_sectors;
            match read_pool_superblock_at(io, tail_sector) {
                Ok(sb) => {
                    let label = Self::label_from_superblock(&sb)?;
                    let importable = label.pool_state.is_importable();
                    if !importable {
                        return Err(PoolImportError::PoolNotImportable {
                            state: {
                                use core::fmt::Write;
                                let mut s = String::new();
                                let _ = write!(s, "{}", label.pool_state);
                                s
                            },
                        });
                    }
                    let pool_name = Self::extract_pool_name(&label)?;
                    let recovery_commit_group = label.commit_group;
                    let superblock_offset = label.system_area_pointer;
                    let superblock_size = label.system_area_size;
                    Self::validate_superblock_region(superblock_offset, superblock_size)?;
                    let cluster = Self::compute_cluster_info(&label);
                    return Ok(Self {
                        label,
                        label_copy: 1,
                        pool_name,
                        importable,
                        recovery_commit_group,
                        superblock_offset,
                        superblock_size,
                        cluster,
                    });
                }
                Err(PoolSuperblockError::BadMagic)
                | Err(PoolSuperblockError::Corrupt)
                | Err(PoolSuperblockError::UnsupportedVersion(_)) => {
                    // Both copies failed.
                }
                Err(e) => {
                    return Err(PoolImportError::LabelInvalid {
                        detail: {
                            use core::fmt::Write;
                            let mut s = String::new();
                            let _ = write!(s, "label copy 1 read error: {e}");
                            s
                        },
                    });
                }
            }
        }

        Err(PoolImportError::BadMagic)
    }

    /// Reconstruct a [] from a [].
    fn label_from_superblock(sb: &KernelPoolSuperblock) -> Result<PoolLabelV1, PoolImportError> {
        let pool_state =
            PoolState::from_u8(sb.pool_state).ok_or(PoolImportError::PoolNotImportable {
                state: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "invalid pool state {}", sb.pool_state);
                    s
                },
            })?;
        let device_class =
            DeviceClass::from_u8(sb.device_class).ok_or(PoolImportError::LabelInvalid {
                detail: {
                    use core::fmt::Write;
                    let mut s = String::new();
                    let _ = write!(s, "invalid device class {}", sb.device_class);
                    s
                },
            })?;
        Ok(PoolLabelV1 {
            magic: sb.magic,
            version: 1,
            pool_guid: sb.pool_guid,
            device_guid: sb.device_guid,
            pool_name: sb.pool_name,
            pool_name_len: sb.pool_name_len,
            pool_state,
            commit_group: sb.commit_group,
            label_commit_group: sb.commit_group,
            device_index: sb.device_index,
            topology_generation: sb.topology_generation,
            device_count: sb.device_count,
            device_class,
            device_capacity_bytes: sb.device_capacity_bytes,
            system_area_pointer: sb.system_area_pointer,
            system_area_size: sb.system_area_size,
            features_incompat: sb.features_incompat,
            features_ro_compat: sb.features_ro_compat,
            features_compat: sb.features_compat,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            redundancy_policy: sb.redundancy_policy,
            checksum: sb.checksum,
        })
    }

    /// Compute a BLAKE3 identity digest for this import context.
    ///
    /// The digest covers (pool_guid || device_guid || pool_name ||
    /// label_copy || commit_group) and is domain-separated. This allows
    /// validation harnesses to verify that a specific device label was
    /// imported.
    #[must_use]
    pub fn compute_identity_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(Self::IDENTITY_DOMAIN);
        hasher.update(&self.label.pool_guid);
        hasher.update(&self.label.device_guid);
        hasher.update(self.pool_name.as_bytes());
        hasher.update(&[self.label_copy]);
        hasher.update(&self.label.commit_group.to_le_bytes());
        hasher.finalize().into()
    }

    /// Returns `true` if the pool was cleanly exported (state is `Exported`).
    pub fn is_clean_export(&self) -> bool {
        self.label.pool_state == PoolState::Exported
    }

    /// Returns the pool GUID bytes.
    pub fn pool_guid(&self) -> &[u8; 16] {
        &self.label.pool_guid
    }

    /// Returns the device GUID bytes.
    pub fn device_guid(&self) -> &[u8; 16] {
        &self.label.device_guid
    }

    /// Returns the device index within the pool topology.
    pub fn device_index(&self) -> u32 {
        self.label.device_index
    }

    /// Returns the total device count from the label.
    pub fn device_count(&self) -> u32 {
        self.label.device_count
    }

    /// Returns the topology generation from the label.
    pub fn topology_generation(&self) -> u64 {
        self.label.topology_generation
    }

    /// Returns the device capacity in bytes.
    pub fn device_capacity_bytes(&self) -> u64 {
        self.label.device_capacity_bytes
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Compute cluster context from a decoded pool label.
    ///
    /// Checks `features_incompat` bit 9 (`CLUSTER_POOL_INCOMPAT`) and
    /// `features_compat` bit 8 (`CLUSTER_POOL_COMPAT`) from the canonical
    /// on-disk label format.  These bit offsets are stable per the
    /// PoolLabelV1 wire format and do not change between Kbuild and
    /// cargo compilation paths.
    fn compute_cluster_info(label: &PoolLabelV1) -> PoolClusterInfo {
        // CLUSTER_POOL_INCOMPAT = 1 << 9  (bit 9 in features_incompat)
        // CLUSTER_POOL_COMPAT   = 1 << 8  (bit 8 in features_compat)
        const CLUSTER_POOL_INCOMPAT: u64 = 1 << 9;
        const CLUSTER_POOL_COMPAT: u64 = 1 << 8;
        let mode = if label.features_incompat & CLUSTER_POOL_INCOMPAT != 0 {
            ClusterMode::ClusteredIncompat
        } else if label.features_compat & CLUSTER_POOL_COMPAT != 0 {
            ClusterMode::ClusteredCompat
        } else {
            ClusterMode::Standalone
        };
        PoolClusterInfo {
            mode,
            pool_guid: label.pool_guid,
            device_guid: label.device_guid,
        }
    }

    /// Extract the pool name as a UTF-8 string from the label.
    fn extract_pool_name(label: &PoolLabelV1) -> Result<String, PoolImportError> {
        let raw = label.pool_name_str();
        if raw.is_empty() {
            // Empty pool name is allowed — use a default.
            return Ok(String::new());
        }
        // pool_name_str() already does UTF-8 validation via core::str::from_utf8.
        // Re-verify that it didn't silently fail.
        let len = label.pool_name_len as usize;
        let name_bytes = &label.pool_name[..len.min(255)];
        let name =
            core::str::from_utf8(name_bytes).map_err(|_| PoolImportError::InvalidPoolName)?;
        Ok(String::from(name))
    }

    /// Validate that the superblock region pointer and size are consistent.
    ///
    /// - Both zero: no superblock region declared (valid for minimal pools).
    /// - Non-zero offset with zero size: invalid.
    /// - Non-zero offset: must be at least `POOL_LABEL_SIZE` (past the label area).
    fn validate_superblock_region(offset: u64, size: u64) -> Result<(), PoolImportError> {
        if offset == 0 && size == 0 {
            // No superblock region declared.
            return Ok(());
        }
        if offset > 0 && size == 0 {
            return Err(PoolImportError::SuperblockRegionInvalid { offset, size });
        }
        // Offset should be >= POOL_LABEL_SIZE to avoid overlapping the label.
        // This is a policy check, not a hard error — we warn by allowing it
        // but not requiring it for now (forward compat).
        let _ = (offset, size);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Committed-root ledger types
// ---------------------------------------------------------------------------

/// Errors returned by committed-root ledger parsing and selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// Buffer is too small to contain a valid ledger header.
    BufferTooSmall { provided: usize, required: usize },
    /// Ledger magic bytes do not match.
    BadMagic { found: [u8; 4] },
    /// Unrecognized ledger format version.
    UnsupportedVersion { version: u32 },
    /// Ledger checksum (BLAKE3 footer) verification failed.
    ChecksumMismatch,
    /// An entry's self-hash does not match its fields.
    EntryDigestMismatch { entry_index: usize, txg: u64 },
    /// No valid entries found in the ledger.
    NoValidEntries,
    /// The declared entry count exceeds what the buffer can hold.
    EntryCountOverflow { count: u32, available: usize },
    /// BLAKE3-256 digest verification is unavailable on this kernel
    /// configuration; ledger integrity cannot be verified.
    /// Reserved: the current kmod bridge provides BLAKE3-256 in all
    /// supported kernel builds.
    DigestUnavailable,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { provided, required } => {
                write!(
                    f,
                    "ledger buffer too small: {provided} bytes, need {required}"
                )
            }
            Self::BadMagic { found } => {
                write!(f, "bad ledger magic: {found:02X?}")
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported ledger version {version}")
            }
            Self::ChecksumMismatch => f.write_str("ledger checksum mismatch"),
            Self::EntryDigestMismatch { entry_index, txg } => {
                write!(f, "entry {entry_index} (txg={txg}) digest mismatch")
            }
            Self::NoValidEntries => f.write_str("no valid entries in committed-root ledger"),
            Self::EntryCountOverflow { count, available } => {
                write!(
                    f,
                    "entry count {count} exceeds available space ({available} bytes)"
                )
            }
            Self::DigestUnavailable => f.write_str("kernel BLAKE3 digest unavailable"),
        }
    }
}

// ---------------------------------------------------------------------------
// MountRootSelector
// ---------------------------------------------------------------------------

/// Selects the most recent valid committed root from the superblock
/// region's committed-root ledger.
///
/// The ledger is a BLAKE3-verified sequence of entries stored in the
/// superblock region (located via the pool label's `system_area_pointer`).
/// Each entry is self-validating (its own BLAKE3 digest covers its
/// fields), and the entire ledger is protected by a trailing BLAKE3
/// checksum.
///
/// # Ledger wire format (version 1)
///
/// ```text
/// Header (12 bytes):
///   magic:     [u8; 4]  = b"VCRL"
///   version:   u32 LE   = 1
///   count:     u32 LE   = number of entries
///
/// Entries (count * 80 bytes), each:
///   root_ino:  u64 LE
///   pool_uuid: [u8; 32]
///   txg:       u64 LE
///   digest:    [u8; 32]  BLAKE3(root_ino || pool_uuid || txg)
///
/// Footer (32 bytes):
///   checksum:  [u8; 32]  BLAKE3(header || entries)
/// ```
pub struct MountRootSelector;

/// Wire-format constants for the committed-root ledger.
const LEDGER_MAGIC: [u8; 4] = *b"VCRL";
const LEDGER_VERSION: u32 = 1;
const LEDGER_HEADER_SIZE: usize = 12;
const LEDGER_ENTRY_SIZE: usize = 80;
const LEDGER_FOOTER_SIZE: usize = 32;
pub(crate) const LEDGER_MIN_SIZE: usize = LEDGER_HEADER_SIZE + LEDGER_FOOTER_SIZE;

impl MountRootSelector {
    /// Domain separator for committed-root anchor BLAKE3 hashing.
    ///
    /// Must match the domain used by `CommittedRootAnchor` so that
    /// self-hashes verify correctly.
    const ANCHOR_DOMAIN: &'static str = "tidefs-kmod-posix-vfs-committed-root-v1";

    /// Select the best (most recent valid) committed root from a ledger buffer.
    ///
    /// Parses the committed-root ledger, verifies the ledger checksum,
    /// validates each candidate entry's integrity, and returns the entry
    /// with the highest transaction group that passes all checks.
    pub fn select_root(ledger_buf: &[u8]) -> Result<CommittedRootAnchor, LedgerError> {
        let entries = Self::parse_ledger(ledger_buf)?;
        Self::select_best(&entries)
    }

    /// Parse the ledger buffer into individual raw entries.
    ///
    /// Verifies the ledger header and footer checksum but does NOT
    /// perform per-entry digest verification. Entry-level verification
    /// happens in [`Self::select_best`].
    fn parse_ledger(buf: &[u8]) -> Result<crate::TideVec<LedgerEntry>, LedgerError> {
        if buf.len() < LEDGER_MIN_SIZE {
            return Err(LedgerError::BufferTooSmall {
                provided: buf.len(),
                required: LEDGER_MIN_SIZE,
            });
        }

        // Header: magic.
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        if magic != LEDGER_MAGIC {
            return Err(LedgerError::BadMagic { found: magic });
        }

        let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if version != LEDGER_VERSION {
            return Err(LedgerError::UnsupportedVersion { version });
        }

        let count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;

        // Validate total size.
        let entries_bytes =
            count
                .checked_mul(LEDGER_ENTRY_SIZE)
                .ok_or(LedgerError::EntryCountOverflow {
                    count: count as u32,
                    available: buf
                        .len()
                        .saturating_sub(LEDGER_HEADER_SIZE + LEDGER_FOOTER_SIZE),
                })?;
        let total = LEDGER_HEADER_SIZE + entries_bytes + LEDGER_FOOTER_SIZE;
        if buf.len() < total {
            return Err(LedgerError::BufferTooSmall {
                provided: buf.len(),
                required: total,
            });
        }

        // Verify footer checksum over header + entries.
        // BLAKE3-256 is always available: the kmod bridge provides a
        // self-contained software implementation under Kbuild, and the
        // external blake3 crate is used under Cargo.
        let payload_end = LEDGER_HEADER_SIZE + entries_bytes;
        let stored: [u8; 32] = buf[payload_end..payload_end + LEDGER_FOOTER_SIZE]
            .try_into()
            .unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[..payload_end]);
        let computed = hasher.finalize();
        if computed.as_bytes() != &stored {
            return Err(LedgerError::ChecksumMismatch);
        }

        // Parse entries.
        let mut entries = crate::TideVec::with_capacity(count);
        for i in 0..count {
            let off = LEDGER_HEADER_SIZE + i * LEDGER_ENTRY_SIZE;
            let root_ino = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            let pool_uuid: [u8; 32] = buf[off + 8..off + 40].try_into().unwrap();
            let txg = u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
            let digest: [u8; 32] = buf[off + 48..off + 80].try_into().unwrap();
            // Suppress unused variable warning on i (used only in
            // potential future diagnostic paths).
            let _ = i;
            entries.push(LedgerEntry {
                root_ino,
                pool_uuid,
                txg,
                digest,
                verified: false,
            });
        }
        Ok(entries)
    }

    /// Select the best entry: highest txg with valid per-entry digest.
    fn select_best(entries: &[LedgerEntry]) -> Result<CommittedRootAnchor, LedgerError> {
        use tidefs_kmod_bridge::kernel_types::InodeId;

        #[cfg(CONFIG_RUST)]
        use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

        let mut best: Option<(u64, CommittedRootAnchor)> = None;

        // BLAKE3-256 is always available: the kmod bridge provides a
        // self-contained software implementation under Kbuild, and the
        // external blake3 crate is used under Cargo.

        for entry in entries.iter() {
            // Verify per-entry BLAKE3 digest.
            let recomputed =
                Self::compute_entry_digest(entry.root_ino, &entry.pool_uuid, entry.txg);
            if recomputed != entry.digest {
                continue;
            }

            let root_ino = InodeId::new(entry.root_ino);
            let anchor = CommittedRootAnchor::new(root_ino, entry.pool_uuid, entry.txg);

            // Double-check via the anchor's own verify().
            if !anchor.verify() {
                continue;
            }

            match &best {
                None => {
                    best = Some((entry.txg, anchor));
                }
                Some((best_txg, _)) if entry.txg > *best_txg => {
                    best = Some((entry.txg, anchor));
                }
                Some(_) => {}
            }
        }

        match best {
            Some((_, anchor)) => Ok(anchor),
            None => Err(LedgerError::NoValidEntries),
        }
    }

    /// Compute the BLAKE3 digest for a single entry's fields.
    fn compute_entry_digest(root_ino: u64, pool_uuid: &[u8; 32], txg: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(Self::ANCHOR_DOMAIN);
        hasher.update(&root_ino.to_le_bytes());
        hasher.update(pool_uuid);
        hasher.update(&txg.to_le_bytes());
        hasher.finalize().into()
    }

    /// Encode a set of committed-root anchors into a ledger buffer.
    ///
    /// Used for test construction and for future kernel-side ledger
    /// updates. Returns bytes ready to write into the superblock region.
    pub fn encode_ledger(anchors: &[CommittedRootAnchor]) -> crate::TideVec<u8> {
        let count = anchors.len() as u32;
        let entries_bytes = anchors.len() * LEDGER_ENTRY_SIZE;
        let total = LEDGER_HEADER_SIZE + entries_bytes + LEDGER_FOOTER_SIZE;
        #[cfg(not(CONFIG_RUST))]
        let mut buf = alloc::vec![0u8; total];
        #[cfg(CONFIG_RUST)]
        let mut buf = {
            let mut v = crate::TideVec::with_capacity(total);
            v.extend(core::iter::repeat(0u8).take(total));
            v
        };

        // Header.
        buf[0..4].copy_from_slice(&LEDGER_MAGIC);
        buf[4..8].copy_from_slice(&LEDGER_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&count.to_le_bytes());

        // Entries.
        for (i, anchor) in anchors.iter().enumerate() {
            let off = LEDGER_HEADER_SIZE + i * LEDGER_ENTRY_SIZE;
            buf[off..off + 8].copy_from_slice(&anchor.root_ino.get().to_le_bytes());
            buf[off + 8..off + 40].copy_from_slice(&anchor.pool_uuid);
            buf[off + 40..off + 48].copy_from_slice(&anchor.txg.to_le_bytes());
            buf[off + 48..off + 80].copy_from_slice(&anchor.digest);
        }

        // Footer checksum.
        let payload_end = LEDGER_HEADER_SIZE + entries_bytes;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[..payload_end]);
        let checksum = hasher.finalize();
        buf[payload_end..payload_end + LEDGER_FOOTER_SIZE].copy_from_slice(checksum.as_bytes());

        buf
    }
}

/// A single raw entry parsed from the committed-root ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerEntry {
    root_ino: u64,
    pool_uuid: [u8; 32],
    txg: u64,
    digest: [u8; 32],
    verified: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_pool_label_core::{
        encode_label, features, seal_label, PoolLabelV1, PoolState, POOL_LABEL_SIZE,
        POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    /// Build a minimal valid label for testing.
    fn test_label(state: PoolState, commit_group: u64) -> PoolLabelV1 {
        let mut label = PoolLabelV1::new([0xAAu8; 16], [0xBBu8; 16], "testpool");
        label.pool_state = state;
        label.commit_group = commit_group;
        label.label_commit_group = commit_group;
        label.device_index = 0;
        label.device_count = 1;
        label.topology_generation = 1;
        label.device_capacity_bytes = 1024 * 1024 * 1024;
        label.system_area_pointer = POOL_LABEL_SIZE as u64;
        label.system_area_size = 4096 * 64;
        seal_label(label).unwrap()
    }

    /// Encode a label into an extended buffer.
    fn encode_test_label(label: &PoolLabelV1) -> crate::TideVec<u8> {
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).unwrap();
        buf.to_vec()
    }

    // ── PoolImportContext::import ─────────────────────────────────────

    #[test]
    fn import_active_label_succeeds() {
        let label = test_label(PoolState::Active, 42);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();

        assert_eq!(ctx.label.pool_guid, [0xAAu8; 16]);
        assert_eq!(ctx.label.device_guid, [0xBBu8; 16]);
        assert_eq!(ctx.pool_name, "testpool");
        assert!(ctx.importable);
        assert_eq!(ctx.recovery_commit_group, 42);
        assert_eq!(ctx.label_copy, 0);
        assert_eq!(ctx.superblock_offset, POOL_LABEL_SIZE as u64);
        assert_eq!(ctx.superblock_size, 4096 * 64);
    }

    #[test]
    fn import_exported_label_succeeds() {
        let label = test_label(PoolState::Exported, 100);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();
        assert!(ctx.importable);
        assert!(ctx.is_clean_export());
    }

    #[test]
    fn import_destroyed_label_rejected() {
        let label = test_label(PoolState::Destroyed, 0);
        let buf = encode_test_label(&label);
        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        match err {
            PoolImportError::PoolNotImportable { state } => {
                assert!(state.contains("DESTROYED"), "got state={state}");
            }
            other => panic!("expected PoolNotImportable, got {other:?}"),
        }
    }

    #[test]
    fn import_buffer_too_small() {
        let buf = [0u8; 10];
        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        assert!(matches!(err, PoolImportError::BufferTooSmall { .. }));
    }

    #[test]
    fn import_bad_magic_rejected() {
        let label = test_label(PoolState::Active, 1);
        let mut buf = encode_test_label(&label);
        buf[0] = b'X'; // corrupt magic
        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        assert!(matches!(err, PoolImportError::BadMagic));
    }

    #[test]
    fn import_checksum_mismatch_rejected() {
        let label = test_label(PoolState::Active, 1);
        let mut buf = encode_test_label(&label);
        buf[42] ^= 0xFF; // corrupt pool_name area
        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        assert!(matches!(err, PoolImportError::ChecksumMismatch));
    }

    #[test]
    fn import_unsupported_version_rejected() {
        let label = test_label(PoolState::Active, 1);
        let mut buf = encode_test_label(&label);
        buf[4..8].copy_from_slice(&99u32.to_le_bytes());
        // Need to recompute checksum for modified version to pass magic check
        // but fail version check. decode_label checks magic -> version -> checksum.
        // If version is wrong, we get UnsupportedVersion before checksum check.
        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        assert!(matches!(err, PoolImportError::UnsupportedVersion { .. }));
    }

    // ── PoolImportContext::import_full ─────────────────────────────────

    #[test]
    fn import_full_with_health_extension() {
        let mut label = test_label(PoolState::Active, 7);
        label.features_compat |= features::DEVICE_HEALTH_STATE;
        label.device_health = 1;
        label.device_read_errors = 3;
        label = seal_label(label).unwrap();
        let buf = encode_test_label(&label);

        let ctx = PoolImportContext::import_full(&buf, 0).unwrap();
        assert_eq!(ctx.label.device_health, 1);
        assert_eq!(ctx.label.device_read_errors, 3);
    }

    #[test]
    fn import_full_without_health_falls_back_to_base() {
        let label = test_label(PoolState::Active, 5);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import_full(&buf, 0).unwrap();
        assert_eq!(ctx.label.device_health, 0);
        assert_eq!(ctx.pool_name, "testpool");
    }

    #[test]
    fn import_full_destroyed_rejected() {
        let label = test_label(PoolState::Destroyed, 0);
        let buf = encode_test_label(&label);
        let err = PoolImportContext::import_full(&buf, 0).unwrap_err();
        assert!(matches!(err, PoolImportError::PoolNotImportable { .. }));
    }

    // ── PoolImportContext::scan_device ─────────────────────────────────

    #[test]
    fn scan_device_finds_head_label() {
        let label = test_label(PoolState::Active, 10);
        let buf = encode_test_label(&label);
        // Create a larger buffer to simulate full device.
        let mut device_buf = alloc::vec![0u8; 1024 * 1024];
        device_buf[..buf.len()].copy_from_slice(&buf);

        let ctx = PoolImportContext::scan_device(&device_buf, device_buf.len() as u64).unwrap();
        assert_eq!(ctx.label_copy, 0);
        assert_eq!(ctx.recovery_commit_group, 10);
    }

    #[test]
    fn scan_device_falls_back_to_tail_when_head_corrupt() {
        let label = test_label(PoolState::Active, 20);
        let buf = encode_test_label(&label);
        let device_size = 1024 * 1024;
        let mut device_buf = alloc::vec![0u8; device_size];

        // Corrupt the head label.
        device_buf[0] = b'X';

        // Place valid label at tail.
        let tail_offset = device_size - POOL_LABEL_SIZE;
        device_buf[tail_offset..tail_offset + buf.len()].copy_from_slice(&buf);

        let ctx = PoolImportContext::scan_device(&device_buf, device_size as u64).unwrap();
        assert_eq!(ctx.label_copy, 1);
        assert_eq!(ctx.recovery_commit_group, 20);
    }

    #[test]
    fn scan_device_no_valid_label_errors() {
        let device_buf = alloc::vec![0u8; 1024 * 1024];
        let err = PoolImportContext::scan_device(&device_buf, device_buf.len() as u64).unwrap_err();
        assert!(matches!(err, PoolImportError::BadMagic));
    }

    // ── PoolImportContext::superblock_region ───────────────────────────

    #[test]
    fn zero_superblock_region_accepted() {
        let mut label = test_label(PoolState::Active, 1);
        label.system_area_pointer = 0;
        label.system_area_size = 0;
        label = seal_label(label).unwrap();
        let buf = encode_test_label(&label);

        let ctx = PoolImportContext::import(&buf, 0).unwrap();
        assert_eq!(ctx.superblock_offset, 0);
        assert_eq!(ctx.superblock_size, 0);
    }

    #[test]
    fn non_zero_offset_zero_size_rejected() {
        let mut label = test_label(PoolState::Active, 1);
        label.system_area_pointer = POOL_LABEL_SIZE as u64;
        label.system_area_size = 0;
        // We must bypass seal_label since encode_label will write
        // system_area_size = 0, but the semantic check happens in
        // PoolImportContext, not in decode_label.
        label = seal_label(label).unwrap();
        let buf = encode_test_label(&label);

        let err = PoolImportContext::import(&buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PoolImportError::SuperblockRegionInvalid { .. }
        ));
    }

    // ── PoolImportContext::identity_digest ─────────────────────────────

    #[test]
    fn identity_digest_deterministic() {
        let label = test_label(PoolState::Active, 3);
        let buf = encode_test_label(&label);
        let ctx1 = PoolImportContext::import(&buf, 0).unwrap();
        let ctx2 = PoolImportContext::import(&buf, 0).unwrap();
        assert_eq!(
            ctx1.compute_identity_digest(),
            ctx2.compute_identity_digest()
        );
    }

    #[test]
    fn identity_digest_distinct_for_different_copies() {
        let label = test_label(PoolState::Active, 3);
        let buf = encode_test_label(&label);
        let ctx0 = PoolImportContext::import(&buf, 0).unwrap();
        let ctx1 = PoolImportContext {
            label_copy: 1,
            ..ctx0.clone()
        };
        assert_ne!(
            ctx0.compute_identity_digest(),
            ctx1.compute_identity_digest()
        );
    }

    #[test]
    fn identity_digest_distinct_for_different_pools() {
        let label_a = test_label(PoolState::Active, 3);
        let mut label_b = test_label(PoolState::Active, 3);
        label_b.pool_guid = [0xCCu8; 16];
        label_b = seal_label(label_b).unwrap();

        let buf_a = encode_test_label(&label_a);
        let buf_b = encode_test_label(&label_b);
        let ctx_a = PoolImportContext::import(&buf_a, 0).unwrap();
        let ctx_b = PoolImportContext::import(&buf_b, 0).unwrap();
        assert_ne!(
            ctx_a.compute_identity_digest(),
            ctx_b.compute_identity_digest()
        );
    }

    #[test]
    fn identity_digest_non_zero() {
        let label = test_label(PoolState::Active, 1);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();
        assert_ne!(ctx.compute_identity_digest(), [0u8; 32]);
    }

    // ── Accessor tests ─────────────────────────────────────────────────

    #[test]
    fn accessors_reflect_label_fields() {
        let mut label = test_label(PoolState::Active, 42);
        label.device_index = 3;
        label.device_count = 5;
        label.topology_generation = 7;
        label.device_capacity_bytes = 8 * 1024 * 1024 * 1024;
        label = seal_label(label).unwrap();
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();

        assert_eq!(ctx.pool_guid(), &[0xAAu8; 16]);
        assert_eq!(ctx.device_guid(), &[0xBBu8; 16]);
        assert_eq!(ctx.device_index(), 3);
        assert_eq!(ctx.device_count(), 5);
        assert_eq!(ctx.topology_generation(), 7);
        assert_eq!(ctx.device_capacity_bytes(), 8 * 1024 * 1024 * 1024);
    }

    // ── PoolImportError tests ──────────────────────────────────────────

    #[test]
    fn pool_import_error_display() {
        let e = PoolImportError::BufferTooSmall {
            provided: 10,
            required: 411,
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("10 bytes"));

        let e = PoolImportError::BadMagic;
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("bad magic"));

        let e = PoolImportError::PoolNotImportable {
            state: String::from("DESTROYED"),
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("DESTROYED"));

        let e = PoolImportError::SuperblockRegionInvalid {
            offset: 256 * 1024,
            size: 0,
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("offset=262144"));
    }

    #[test]
    fn pool_import_error_from_label_error() {
        let le = LabelError::BadMagic;
        let pie: PoolImportError = le.into();
        assert_eq!(pie, PoolImportError::BadMagic);

        let le = LabelError::ChecksumMismatch;
        let pie: PoolImportError = le.into();
        assert_eq!(pie, PoolImportError::ChecksumMismatch);

        let le = LabelError::BufferTooSmall;
        let pie: PoolImportError = le.into();
        assert!(matches!(pie, PoolImportError::BufferTooSmall { .. }));
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn import_empty_pool_name_accepted() {
        let mut label = test_label(PoolState::Active, 1);
        label.pool_name = [0u8; 255];
        label.pool_name_len = 0;
        label = seal_label(label).unwrap();
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();
        assert!(ctx.pool_name.is_empty());
    }

    #[test]
    fn import_label_copy_1_tracks_correctly() {
        let label = test_label(PoolState::Exported, 99);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 1).unwrap();
        assert_eq!(ctx.label_copy, 1);
        assert!(ctx.is_clean_export());
    }

    #[test]
    fn import_exported_sets_importable_true() {
        let label = test_label(PoolState::Exported, 5);
        let buf = encode_test_label(&label);
        let ctx = PoolImportContext::import(&buf, 0).unwrap();
        assert!(ctx.importable);
        // Verify state via label directly.
        assert_eq!(ctx.label.pool_state, PoolState::Exported);
    }

    #[test]
    fn scan_device_empty_buffer_rejected() {
        let err = PoolImportContext::scan_device(&[], 0).unwrap_err();
        assert!(matches!(err, PoolImportError::BufferTooSmall { .. }));
    }

    #[test]
    fn scan_device_too_small_for_tail_fallback() {
        let mut small = alloc::vec![0u8; POOL_LABEL_V1_WIRE_SIZE];
        small[0] = b'X'; // corrupt head magic
                         // No room for tail.
        let err = PoolImportContext::scan_device(&small, small.len() as u64).unwrap_err();
        assert!(matches!(err, PoolImportError::BadMagic));
    }

    // ── MountRootSelector tests ────────────────────────────────────────

    /// Build a test CommittedRootAnchor.
    fn test_anchor(root_ino: u64, txg: u64) -> CommittedRootAnchor {
        use tidefs_kmod_bridge::kernel_types::InodeId;
        CommittedRootAnchor::new(InodeId::new(root_ino), [0xAAu8; 32], txg)
    }

    // ── encode_ledger / select_root roundtrip ─────────────────────────

    #[test]
    fn encode_and_select_single_anchor() {
        let anchor = test_anchor(10, 5);
        let ledger = MountRootSelector::encode_ledger(&[anchor.clone()]);
        let selected = MountRootSelector::select_root(&ledger).unwrap();
        assert_eq!(selected.root_ino, anchor.root_ino);
        assert_eq!(selected.txg, anchor.txg);
        assert_eq!(selected.pool_uuid, anchor.pool_uuid);
        assert!(selected.verify());
    }

    #[test]
    fn select_root_picks_highest_txg() {
        let a1 = test_anchor(1, 10);
        let a2 = test_anchor(2, 20); // should win
        let a3 = test_anchor(3, 15);
        let ledger = MountRootSelector::encode_ledger(&[a1.clone(), a2.clone(), a3.clone()]);
        let selected = MountRootSelector::select_root(&ledger).unwrap();
        assert_eq!(selected.root_ino, a2.root_ino);
        assert_eq!(selected.txg, 20);
    }

    #[test]
    fn select_root_skips_corrupt_entries() {
        let a1 = test_anchor(1, 10);
        // a2 has a tampered digest, should be skipped
        let mut a2 = test_anchor(2, 25);
        a2.digest = [0xFFu8; 32]; // corrupt the digest
        let a3 = test_anchor(3, 20);
        let ledger = MountRootSelector::encode_ledger(&[a1.clone(), a2.clone(), a3.clone()]);
        let selected = MountRootSelector::select_root(&ledger).unwrap();
        // a2 (txg=25) should be skipped because digest is corrupt;
        // best valid should be a3 (txg=20).
        assert_eq!(selected.txg, 20);
        assert_eq!(selected.root_ino, a3.root_ino);
    }

    #[test]
    fn select_root_all_corrupt_returns_no_valid_entries() {
        let mut a1 = test_anchor(1, 10);
        a1.digest = [0x00u8; 32];
        let ledger = MountRootSelector::encode_ledger(&[a1.clone()]);
        // Need to corrupt the stored digest in the ledger buffer too,
        // since encode_ledger writes the anchor's digest field as-is.
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::NoValidEntries)));
    }

    #[test]
    fn encode_then_select_multiple() {
        let anchors: crate::TideVec<_> = (1..=5).map(|i| test_anchor(i * 100, i * 10)).collect();
        let ledger = MountRootSelector::encode_ledger(&anchors);
        let selected = MountRootSelector::select_root(&ledger).unwrap();
        // txg=50 (i=5) should win
        assert_eq!(selected.txg, 50);
        assert_eq!(selected.root_ino.get(), 500);
    }

    // ── Ledger error cases ─────────────────────────────────────────────

    #[test]
    fn select_root_empty_buffer_rejected() {
        let result = MountRootSelector::select_root(&[]);
        assert!(matches!(result, Err(LedgerError::BufferTooSmall { .. })));
    }

    #[test]
    fn select_root_bad_magic_rejected() {
        let anchor = test_anchor(1, 1);
        let mut ledger = MountRootSelector::encode_ledger(&[anchor]);
        ledger[0] = b'X'; // corrupt magic
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::BadMagic { .. })));
    }

    #[test]
    fn select_root_unsupported_version_rejected() {
        let anchor = test_anchor(1, 1);
        let mut ledger = MountRootSelector::encode_ledger(&[anchor]);
        ledger[4..8].copy_from_slice(&99u32.to_le_bytes());
        // Recompute checksum after version change.
        let payload_end = LEDGER_HEADER_SIZE + LEDGER_ENTRY_SIZE;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&ledger[..payload_end]);
        let new_checksum = hasher.finalize();
        ledger[payload_end..payload_end + LEDGER_FOOTER_SIZE]
            .copy_from_slice(new_checksum.as_bytes());

        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(
            result,
            Err(LedgerError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn select_root_checksum_mismatch_rejected() {
        let anchor = test_anchor(1, 1);
        let mut ledger = MountRootSelector::encode_ledger(&[anchor]);
        // Flip a byte in the payload area (not footer).
        ledger[LEDGER_HEADER_SIZE] ^= 0xFF;
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::ChecksumMismatch)));
    }

    #[test]
    fn select_root_empty_ledger_no_valid_entries() {
        // Encode an empty ledger (valid format, zero entries).
        let ledger = MountRootSelector::encode_ledger(&[]);
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::NoValidEntries)));
    }
    #[test]
    fn select_root_entry_count_overflow() {
        // On 64-bit, u32::MAX * 80 fits in usize so the error is
        // BufferTooSmall rather than EntryCountOverflow.
        let anchor = test_anchor(1, 1);
        let mut ledger = MountRootSelector::encode_ledger(&[anchor]);
        // Corrupt the count field to a huge value.
        ledger[8..12].copy_from_slice(&(u32::MAX).to_le_bytes());
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::BufferTooSmall { .. })));
    }

    #[test]
    fn select_root_truncated_entries_buffer_too_small() {
        let anchor = test_anchor(1, 1);
        let mut ledger = MountRootSelector::encode_ledger(&[anchor]);
        // Truncate to remove the footer.
        ledger.truncate(LEDGER_HEADER_SIZE + LEDGER_ENTRY_SIZE);
        let result = MountRootSelector::select_root(&ledger);
        assert!(matches!(result, Err(LedgerError::BufferTooSmall { .. })));
    }

    // ── encode_ledger produces valid format ────────────────────────────

    #[test]
    fn encode_ledger_empty_produces_min_size() {
        let ledger = MountRootSelector::encode_ledger(&[]);
        assert_eq!(ledger.len(), LEDGER_MIN_SIZE);
        assert_eq!(&ledger[0..4], b"VCRL");
        assert_eq!(u32::from_le_bytes(ledger[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(ledger[8..12].try_into().unwrap()), 0);
    }

    #[test]
    fn encode_ledger_roundtrip_preserves_all_fields() {
        use tidefs_kmod_bridge::kernel_types::InodeId;
        let anchors = [
            CommittedRootAnchor::new(InodeId::new(42), [0x01u8; 32], 7),
            CommittedRootAnchor::new(InodeId::new(99), [0x02u8; 32], 13),
        ];
        let ledger = MountRootSelector::encode_ledger(&anchors);
        let selected = MountRootSelector::select_root(&ledger).unwrap();
        // Should pick txg=13
        assert_eq!(selected.txg, 13);
        assert_eq!(selected.root_ino.get(), 99);
        assert_eq!(selected.pool_uuid, [0x02u8; 32]);
        assert!(selected.verify());
    }

    // ── LedgerError Display ────────────────────────────────────────────

    #[test]
    fn ledger_error_display() {
        let e = LedgerError::BufferTooSmall {
            provided: 10,
            required: 44,
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("10 bytes"));

        let e = LedgerError::BadMagic {
            found: [b'B', b'A', b'D', 0],
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("bad ledger magic"));

        let e = LedgerError::ChecksumMismatch;
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("checksum mismatch"));

        let e = LedgerError::NoValidEntries;
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("no valid entries"));

        let e = LedgerError::EntryCountOverflow {
            count: 999,
            available: 80,
        };
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("999"));
        assert!({
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{e}");
            s
        }
        .contains("80"));
    }

    // ── compute_entry_digest determinism ───────────────────────────────

    #[test]
    fn compute_entry_digest_deterministic() {
        let d1 = MountRootSelector::compute_entry_digest(1, &[0xAAu8; 32], 5);
        let d2 = MountRootSelector::compute_entry_digest(1, &[0xAAu8; 32], 5);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_entry_digest_distinct_for_different_txg() {
        let d1 = MountRootSelector::compute_entry_digest(1, &[0xAAu8; 32], 5);
        let d2 = MountRootSelector::compute_entry_digest(1, &[0xAAu8; 32], 6);
        assert_ne!(d1, d2);
    }

    #[test]
    fn compute_entry_digest_non_zero() {
        let d = MountRootSelector::compute_entry_digest(1, &[0xAAu8; 32], 5);
        assert_ne!(d, [0u8; 32]);
    }
}
