//! Pool abstraction over a collection of devices.
//!
//! A `Pool` is the top-level storage container in TideFS, analogous to a ZFS
//! zpool. It manages one or more devices, routes I/O by device class, tracks
//! health and statistics, and supports online device add/remove.
//!
//! # I/O routing
//!
//! - `IoClass::Data` → pool-wide redundancy placement over eligible Data devices
//! - `IoClass::Metadata` → preferred media tier from `DeviceClass::Metadata`
//!   or `Special`, fallback `Data`, then pool-wide redundancy placement
//! - `IoClass::IntentLog` → `DeviceClass::IntentLog` (write-all), fallback `Data`
//! - `IoClass::ReadCache` → `DeviceClass::ReadCache`, fallback `Data`, then
//!   pool-wide redundancy placement

pub mod commit_group;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand;

use tidefs_types_pool_label_core::{
    self as pool_label, features, DeviceClass as LabelDeviceClass, PoolLabelV1, PoolState,
};

use crate::device::{
    Device, DeviceBacking, DeviceClass, DeviceConfig, DeviceImpl, DeviceKind, DeviceState,
    DeviceStats, DeviceStatus, IoClass,
};
use crate::device_health::{DeviceHealth, DeviceHealthState, DeviceHealthTransition};
use crate::device_layout::{
    DeviceClassPolicy, DeviceLayoutStats, DeviceMediaClass, WriteAllocator,
};
use crate::device_manager::{DeviceManager, SparePolicy};
use crate::io_scheduler::IoClass as SchedClass;
use crate::log_device::LogDeviceWriter;
use crate::{
    LocalObjectStore, ObjectKey, ObjectLocation, Result, ScrubStats, StoreError, StoreOptions,
    StoreRetentionCompactionReport, StoreStats, StoredObject,
};
use tidefs_block_allocator::{BlockAllocator, BlockId, TrimRequest};
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};
use tidefs_erasure_coding::{
    encode as encode_erasure_stripe, reconstruct as reconstruct_erasure_stripe, ErasureShard,
    ShardKind, StripeConfig,
};
use tidefs_placement_planner::{
    AllocationRequest, DeviceHealthCapacity, HashRingPlacementPlanner, PlacementDecision,
    PlacementPlanner,
};
use tidefs_space_accounting::{PoolCounters, StatfsResult};

// ---------------------------------------------------------------------------
// Pool configuration
// ---------------------------------------------------------------------------

/// Top-level pool configuration.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Human-readable pool name.
    pub name: String,
    /// Root directory for pool metadata.
    pub root_path: PathBuf,
    /// Devices that make up this pool.
    pub devices: Vec<DeviceConfig>,
}

/// Pool-wide redundancy policy applied at object/stripe allocation time.
///
/// This replaces user-visible fixed mirror/parity device groups as the active
/// pool allocation model: every allocation plans against the current eligible
/// device set and persists the selected targets in a placement receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolRedundancyPolicy {
    /// Store `copies` full replicas on distinct eligible pool devices.
    Replicated { copies: u8 },
    /// Store one erasure-coded stripe with `data_shards + parity_shards`
    /// physical shard targets.
    Erasure { data_shards: u8, parity_shards: u8 },
}

impl Default for PoolRedundancyPolicy {
    fn default() -> Self {
        Self::Replicated { copies: 1 }
    }
}

impl PoolRedundancyPolicy {
    /// Convenience constructor for replicated placement.
    #[must_use]
    pub const fn replicated(copies: u8) -> Self {
        Self::Replicated { copies }
    }

    /// Convenience constructor for erasure `(k,m)` placement.
    #[must_use]
    pub const fn erasure(data_shards: u8, parity_shards: u8) -> Self {
        Self::Erasure {
            data_shards,
            parity_shards,
        }
    }

    fn total_targets(self) -> Result<usize> {
        let required = match self {
            Self::Replicated { copies } => copies as usize,
            Self::Erasure {
                data_shards,
                parity_shards,
            } => (data_shards as usize).saturating_add(parity_shards as usize),
        };
        if required == 0 {
            Err(StoreError::InvalidOptions {
                reason: "pool redundancy policy requires at least one target",
            })
        } else {
            Ok(required)
        }
    }

    fn layout(self) -> Result<DurabilityLayoutV1> {
        let policy = match self {
            Self::Replicated { copies } => {
                DurabilityPolicy::mirror(copies).map_err(|_| StoreError::InvalidOptions {
                    reason: "replicated pool redundancy copies must be in 1..=32",
                })?
            }
            Self::Erasure {
                data_shards,
                parity_shards,
            } => DurabilityPolicy::erasure_style(data_shards, parity_shards).map_err(|_| {
                StoreError::InvalidOptions {
                    reason: "erasure pool redundancy shards must be nonzero and <=32",
                }
            })?,
        };
        Ok(DurabilityLayoutV1 { policy })
    }
}

/// Pool-level tunable properties (ZFS-heritage).
#[derive(Clone, Debug)]
pub struct PoolProperties {
    /// Ashift value for device block alignment (9 = 512B, 12 = 4K, etc.).
    pub ashift: u8,
    /// Whether to automatically expand when all devices grow.
    pub autoexpand: bool,
    /// Behaviour when a device fault is detected.
    pub failmode: FailMode,
    /// When `true` (default), freed blocks trigger an immediate
    /// TRIM/DISCARD to the backing device. When `false`, TRIM is
    /// deferred to a background batch pass via [`Pool::trim_free_space`].
    pub trim_on_delete: bool,
    /// Free-space watermark in bytes. Data writes that would reduce
    /// available capacity below this threshold are refused with
    /// `StoreError::NoSpace`.  Metadata and intent-log writes always
    /// bypass the gate so forward progress for reclaim, compaction,
    /// and allocator metadata remains possible.  Default 0 means the
    /// watermark is disabled, preserving existing behaviour.
    pub low_watermark_bytes: u64,
    /// Pool-wide redundancy policy used when allocating non-log objects.
    pub redundancy_policy: PoolRedundancyPolicy,
    /// Failure-domain level enforced by the placement planner.
    pub failure_domain_level: FailureDomainLevel,
}

impl Default for PoolProperties {
    fn default() -> Self {
        Self {
            ashift: 12,
            autoexpand: false,
            failmode: FailMode::Wait,
            trim_on_delete: true,
            low_watermark_bytes: 0,
            redundancy_policy: PoolRedundancyPolicy::default(),
            failure_domain_level: FailureDomainLevel::Device,
        }
    }
}

/// Pool-level failure-mode policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FailMode {
    /// Block I/O until the fault resolves.
    #[default]
    Wait,
    /// Continue I/O on healthy devices, report fault.
    Continue,
    /// Halt the pool entirely.
    Panic,
}

// ---------------------------------------------------------------------------
// Pool health
// ---------------------------------------------------------------------------

/// Computed pool health derived from device states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolHealth {
    /// All devices are online and healthy.
    Online,
    /// At least one device is degraded but no data is unavailable.
    Degraded,
    /// At least one non-redundant device is faulted — data loss possible.
    Faulted,
    /// Pool is administratively suspended.
    Suspended,
}

// ---------------------------------------------------------------------------
// Device replacement
// ---------------------------------------------------------------------------

/// State of an in-progress device replacement operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplacementState {
    /// Replacement is in progress: new device attached, data copy ongoing.
    InProgress {
        /// Bytes copied so far.
        bytes_copied: u64,
        /// Total bytes to copy (estimated).
        total_bytes: u64,
    },
    /// Data copy complete; old device awaiting detach.
    CopyComplete,
    /// Replacement was cancelled by the operator; old device preserved.
    Cancelled,
    /// Replacement failed due to an unrecoverable error.
    Failed { reason: String },
}

/// Tracks an in-progress or recently completed device replacement.
#[derive(Clone, Debug)]
pub struct DeviceReplacement {
    /// Path of the old device being replaced.
    pub old_path: PathBuf,
    /// Original configured media for the old device.
    pub old_config: DeviceConfig,
    /// Path of the new replacement device.
    pub new_path: PathBuf,
    /// Current replacement state.
    pub state: ReplacementState,
    /// Index of the device in the pool's device list during replacement.
    pub device_index: usize,
}

impl DeviceReplacement {
    /// Create a new replacement tracker.
    pub fn new(old_config: DeviceConfig, new_path: PathBuf, device_index: usize) -> Self {
        let old_path = old_config.path.clone();
        Self {
            old_path,
            old_config,
            new_path,
            state: ReplacementState::InProgress {
                bytes_copied: 0,
                total_bytes: 0,
            },
            device_index,
        }
    }

    /// Whether the replacement is active (not yet completed or finalised).
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            ReplacementState::InProgress { .. } | ReplacementState::CopyComplete
        )
    }

    /// Cancel an in-progress replacement, preserving the old device.
    pub fn cancel(&mut self) {
        self.state = ReplacementState::Cancelled;
    }
}

// ---------------------------------------------------------------------------
// Pool statistics
// ---------------------------------------------------------------------------

/// Aggregate pool-level statistics.
#[derive(Clone, Debug, Default)]
pub struct PoolStats {
    pub device_count: usize,
    pub total_objects: usize,
    pub total_bytes: u64,
    pub total_read_ops: u64,
    pub total_write_ops: u64,
    pub total_delete_ops: u64,
    pub per_device: Vec<DeviceStats>,
    /// Aggregate compression ratio across all compressed devices (1.0 = no
    /// compression or no compressed devices).
    pub compression_ratio: f64,
}

/// Pool capacity statistics for filesystem-level statfs integration.
///
/// Carries the capacity-oriented view of pool storage: total configured
/// capacity, live bytes (used), and remaining capacity. These feed into
/// FUSE `statfs` reply fields (`f_blocks`, `f_bfree`, `f_bavail`,
/// `f_files`, `f_ffree`) via the namespace → object-store routing path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolCapacityStats {
    /// Total raw capacity in bytes (segment_count * max_segment_bytes).
    pub total_capacity_bytes: u64,
    /// Live (used) bytes across all objects.
    pub used_bytes: u64,
    /// Available bytes (total - used, saturating at zero).
    pub available_bytes: u64,
    /// Total live object count.
    pub object_count: u64,
}

/// Role of a physical placement target within a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementTargetRole {
    /// Full replica or erasure data shard.
    Data,
    /// Erasure parity shard.
    Parity,
}

impl PlacementTargetRole {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Parity => 1,
        }
    }

    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Data),
            1 => Some(Self::Parity),
            _ => None,
        }
    }
}

/// A single physical target recorded in a placement receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementReceiptTarget {
    /// Device index when the receipt was issued.
    pub device_index: u32,
    /// Persistent device GUID from the pool label/device table.
    pub device_guid: [u8; 16],
    /// Replica or shard index within this logical object/stripe.
    pub shard_index: u16,
    /// Target role.
    pub role: PlacementTargetRole,
    /// BLAKE3 digest of the bytes stored on this target.
    pub stored_digest: [u8; 32],
}

/// Persisted object/stripe locator authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementReceipt {
    /// Logical object key being located.
    pub object_key: ObjectKey,
    /// Topology epoch used for new allocation.
    pub epoch: u64,
    /// Redundancy policy in force for this write.
    pub policy: PoolRedundancyPolicy,
    /// Failure-domain level requested by the pool.
    pub failure_domain_level: FailureDomainLevel,
    /// Logical payload length before replication/erasure padding.
    pub payload_len: u64,
    /// Erasure shard length, or 0 for replicated placement.
    pub shard_len: u32,
    /// BLAKE3 digest of the logical payload.
    pub payload_digest: [u8; 32],
    /// Physical targets selected by the placement planner.
    pub targets: Vec<PlacementReceiptTarget>,
}

const PLACEMENT_RECEIPT_MAGIC: &[u8; 8] = b"TFSPRC1\0";
const PLACEMENT_RECEIPT_CONTEXT: &str = "TideFS pool placement receipt object key v1";
const PLACEMENT_HASH_RING_VNODES_PER_GB: u64 = 16;

impl PlacementReceipt {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.targets.len() > u16::MAX as usize {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt target count exceeds wire format",
            });
        }
        let mut out = Vec::with_capacity(96 + self.targets.len() * 55);
        out.extend_from_slice(PLACEMENT_RECEIPT_MAGIC);
        out.extend_from_slice(&self.object_key.as_bytes32());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.push(self.failure_domain_level.discriminant());
        match self.policy {
            PoolRedundancyPolicy::Replicated { copies } => {
                out.push(0);
                out.push(copies);
                out.push(0);
            }
            PoolRedundancyPolicy::Erasure {
                data_shards,
                parity_shards,
            } => {
                out.push(1);
                out.push(data_shards);
                out.push(parity_shards);
            }
        }
        out.extend_from_slice(&self.payload_len.to_le_bytes());
        out.extend_from_slice(&self.shard_len.to_le_bytes());
        out.extend_from_slice(&self.payload_digest);
        out.extend_from_slice(&(self.targets.len() as u16).to_le_bytes());
        for target in &self.targets {
            out.extend_from_slice(&target.device_index.to_le_bytes());
            out.extend_from_slice(&target.device_guid);
            out.extend_from_slice(&target.shard_index.to_le_bytes());
            out.push(target.role.as_u8());
            out.extend_from_slice(&target.stored_digest);
        }
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        let mut cursor = ReceiptCursor::new(raw);
        if cursor.take(PLACEMENT_RECEIPT_MAGIC.len())? != PLACEMENT_RECEIPT_MAGIC {
            return None;
        }
        let object_key = ObjectKey::from_bytes32(cursor.array()?);
        let epoch = u64::from_le_bytes(cursor.array()?);
        let failure_domain_level = FailureDomainLevel::from_u8(cursor.u8()?)?;
        let policy_tag = cursor.u8()?;
        let first = cursor.u8()?;
        let second = cursor.u8()?;
        let policy = match policy_tag {
            0 => PoolRedundancyPolicy::Replicated { copies: first },
            1 => PoolRedundancyPolicy::Erasure {
                data_shards: first,
                parity_shards: second,
            },
            _ => return None,
        };
        let payload_len = u64::from_le_bytes(cursor.array()?);
        let shard_len = u32::from_le_bytes(cursor.array()?);
        let payload_digest = cursor.array()?;
        let target_count = u16::from_le_bytes(cursor.array()?) as usize;
        let mut targets = Vec::with_capacity(target_count);
        for _ in 0..target_count {
            let device_index = u32::from_le_bytes(cursor.array()?);
            let device_guid = cursor.array()?;
            let shard_index = u16::from_le_bytes(cursor.array()?);
            let role = PlacementTargetRole::from_u8(cursor.u8()?)?;
            let stored_digest = cursor.array()?;
            targets.push(PlacementReceiptTarget {
                device_index,
                device_guid,
                shard_index,
                role,
                stored_digest,
            });
        }
        if !cursor.is_finished() {
            return None;
        }
        Some(Self {
            object_key,
            epoch,
            policy,
            failure_domain_level,
            payload_len,
            shard_len,
            payload_digest,
            targets,
        })
    }
}

struct ReceiptCursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> ReceiptCursor<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let bytes = self.raw.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.raw.len()
    }
}

// ---------------------------------------------------------------------------
// IoClass → device index mapping
// ---------------------------------------------------------------------------

/// Maps each `IoClass` to the set of device indices that should serve it.
#[derive(Clone, Debug)]
struct ClassMap {
    data: Vec<usize>,
    metadata: Vec<usize>,
    intent_log: Vec<usize>,
    read_cache: Vec<usize>,
}

impl ClassMap {
    fn get(&self, class: IoClass) -> &[usize] {
        match class {
            IoClass::Data => &self.data,
            IoClass::Metadata => &self.metadata,
            IoClass::IntentLog => &self.intent_log,
            IoClass::ReadCache => &self.read_cache,
        }
    }
}

fn build_class_map(classes: &[DeviceClass]) -> ClassMap {
    let data: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, DeviceClass::Data))
        .map(|(i, _)| i)
        .collect();
    // Metadata prefers Metadata and Special, falls back to Data
    let metadata: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, DeviceClass::Metadata | DeviceClass::Special))
        .map(|(i, _)| i)
        .chain(data.iter().copied())
        .collect();
    // IntentLog prefers IntentLog, falls back to Data
    let intent_log: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, DeviceClass::IntentLog))
        .map(|(i, _)| i)
        .chain(data.iter().copied())
        .collect();
    // ReadCache prefers ReadCache, falls back to Data
    let read_cache: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, DeviceClass::ReadCache))
        .map(|(i, _)| i)
        .chain(data.iter().copied())
        .collect();

    ClassMap {
        data,
        metadata,
        intent_log,
        read_cache,
    }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// A TideFS storage pool, analogous to a ZFS zpool.
#[derive(Debug)]
pub struct Pool {
    config: PoolConfig,
    properties: PoolProperties,
    classes: Vec<DeviceClass>,
    devices: Vec<Device>,
    class_map: ClassMap,
    health: PoolHealth,
    /// Per-device physical media classes (NVMe, SSD, HDD, DM device).
    media_classes: Vec<DeviceMediaClass>,
    /// Device-class-aware write allocator retained for layout policy accounting
    /// and per-device scoring. Pool writes now persist placement receipts so
    /// reads and overwrites use recorded locator authority instead of
    /// recomputing against the current topology.
    write_allocator: WriteAllocator,
    /// Device class policy for I/O class preferences.
    device_class_policy: DeviceClassPolicy,
    /// Per-device layout statistics for observability.
    device_layout_stats: Vec<DeviceLayoutStats>,
    /// Optional separate intent-log device writer (LOG_DEVICE).
    log_device: Option<LogDeviceWriter>,
    /// Persistent pool identity (randomly generated on create).
    pool_guid: [u8; 16],
    /// Per-device GUIDs matching device order for label-based topology updates.
    device_guids: Vec<[u8; 16]>,
    /// Monotonic local placement epoch. Receipts bind reads to the epoch that
    /// selected their targets while later topology changes can steer new
    /// allocations elsewhere.
    placement_epoch: u64,
    /// Hot-spare activation policy.  Defaults to [`SparePolicy::Manual`].
    spare_policy: SparePolicy,
    /// Log of device health transitions for observability.
    health_transitions: Vec<DeviceHealthTransition>,
    /// Currently in-progress device replacement, if any.
    replacement: Option<DeviceReplacement>,
    /// Block allocator for free-space tracking and TRIM coordination.
    /// Initialised via [`set_allocator`].
    allocator: Option<BlockAllocator>,
    /// True when pool labels indicate per-object encryption is active
    /// but no encryption key was provided during open.  Locked pools
    /// refuse all data I/O with a clear error until the operator
    /// provides the correct key.
    ///
    /// This is the "locked dataset" state: the pool is importable and
    /// the committed-root chain is valid, but reads and writes are
    /// gated until the encryption key is supplied.
    locked: bool,
}

/// File written to pool root during device removal to enable
/// crash-safe resume on next pool open. Contains the path of the
/// device being removed.
const DEVICE_REMOVAL_MARKER_FILE: &str = ".tidefs_device_removal_pending";

/// Check for a pending device removal marker and resume evacuation if found.
fn resume_device_removal_if_pending(pool: &mut Pool) {
    let marker_path = pool.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
    if marker_path.exists() {
        if let Ok(encoded) = std::fs::read_to_string(&marker_path) {
            let target_path = PathBuf::from(encoded.trim());
            if target_path.exists() || pool.devices.iter().any(|d| d.root() == target_path) {
                let _ = pool.safe_remove_device(&target_path);
            }
            let _ = std::fs::remove_file(&marker_path);
        }
    }
}

impl Pool {
    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Build a WriteAllocator from the pool's devices and media classes.
    fn build_write_allocator(
        devices: &[Device],
        media_classes: &[DeviceMediaClass],
    ) -> WriteAllocator {
        let total_bytes: Vec<u64> = devices.iter().map(|d| d.store().capacity_bytes()).collect();
        WriteAllocator::new(media_classes.to_vec(), total_bytes)
    }

    /// Create a new pool from a configuration.
    ///
    /// Creates the root directory and initializes every device.
    pub fn create(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
        // Only create the root directory if it is a directory path.
        // Block-device-backed pools use the block device itself as the root;
        // the metadata directory is created separately by the caller.
        if !config.root_path.is_file() || config.root_path.is_dir() {
            fs::create_dir_all(&config.root_path).map_err(|e| StoreError::Io {
                operation: "pool_create_dir",
                path: config.root_path.clone(),
                source: e,
            })?;
        }

        // Generate a random pool GUID for persistent identity.
        let pool_guid: [u8; 16] = rand::random();
        let device_guids: Vec<[u8; 16]> =
            (0..config.devices.len()).map(|_| rand::random()).collect();

        let classes: Vec<DeviceClass> = config.devices.iter().map(|vc| vc.class).collect();
        let class_map = build_class_map(&classes);

        let devices = open_devices(&config.devices, options)?;

        // Build device-class-aware layout state.
        let media_classes: Vec<DeviceMediaClass> =
            config.devices.iter().map(|vc| vc.media_class).collect();
        let device_class_policy = DeviceClassPolicy::production();
        let device_layout_stats: Vec<DeviceLayoutStats> = media_classes
            .iter()
            .map(|mc| DeviceLayoutStats::with_segment_size(mc.default_segment_size()))
            .collect();
        let write_allocator = Self::build_write_allocator(&devices, &media_classes);
        let health = compute_health(&devices);

        // Open the log device writer if an IntentLog device is present.
        let log_device = open_log_device_for_devices(&config.devices)?;

        let mut pool = Self {
            config,
            properties,
            classes,
            devices,
            class_map,
            health,
            media_classes,
            write_allocator,
            device_class_policy,
            device_layout_stats,
            log_device,
            pool_guid,
            device_guids,
            placement_epoch: 1,
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            allocator: None,
            locked: false,
        };

        // Resume interrupted device removal if a pending marker exists.
        resume_device_removal_if_pending(&mut pool);

        Ok(pool)
    }

    /// Open an existing pool from its root directory.
    ///
    /// Reads PoolLabelV1 labels from each device root directory when present,
    /// validates pool identity (matching pool_guid across devices), and falls
    /// back to the legacy create-then-open path when labels are absent.
    pub fn open(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
        let mut pool_guid: Option<[u8; 16]> = None;
        let mut device_guids: Vec<[u8; 16]> = Vec::new();
        let mut label_health_states: Vec<(usize, u8, u64, u64, u64)> = Vec::new();
        let mut label_found = false;
        // Pool-level feature bitmasks captured from the first valid label
        // for post-import compatibility gating.
        let mut saved_features_incompat: u64 = 0;
        let mut saved_features_ro_compat: u64 = 0;
        let mut saved_features_valid = false;
        let mut label_is_encrypted = false;
        let mut topology_generation: Option<u64> = None;

        // Attempt to read a label from each configured device path.
        for vc in &config.devices {
            let device_root = device_root_path(vc);

            // Byte-addressable pool members have labels at fixed offset 0,
            // not in compatibility directory label files.
            let buf = if vc.backing.uses_fixed_offset_pool_labels() {
                match fs::File::open(&device_root) {
                    Ok(mut f) => {
                        use std::io::Read;
                        let mut raw = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
                        match f.read_exact(&mut raw) {
                            Ok(()) => raw,
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            } else {
                let label_path = label_file_path(&device_root);
                if !label_path.exists() {
                    continue;
                }
                fs::read(&label_path).map_err(|e| StoreError::Io {
                    operation: "pool_open_read_label",
                    path: label_path.clone(),
                    source: e,
                })?
            };
            label_found = true;
            // Only push device_guid on first-pass label reading (before decode).
            // We capture it after decode below.
            let label = pool_label::decode_label(&buf).map_err(|_| StoreError::InvalidOptions {
                reason: "pool label corrupt or unreadable",
            })?;
            device_guids.push(label.device_guid);
            topology_generation = Some(
                topology_generation
                    .unwrap_or(label.topology_generation)
                    .max(label.topology_generation),
            );
            if label.is_encrypted() {
                label_is_encrypted = true;
            }

            if !label.pool_state.is_importable() {
                return Err(StoreError::InvalidOptions {
                    reason: "pool state is not importable",
                });
            }

            match pool_guid {
                None => {
                    pool_guid = Some(label.pool_guid);
                    // Save pool feature bitmasks for compatibility gating.
                    saved_features_incompat = label.features_incompat;
                    saved_features_ro_compat = label.features_ro_compat;
                    saved_features_valid = true;
                }
                Some(existing) if existing != label.pool_guid => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pool GUID mismatch across devices",
                    });
                }
                Some(_) => {}
            }
            // Collect device health state for restoration after import.
            if label.features_compat & features::DEVICE_HEALTH_STATE != 0 {
                label_health_states.push((
                    label.device_index as usize,
                    label.device_health,
                    label.device_read_errors,
                    label.device_write_errors,
                    label.device_checksum_errors,
                ));
            }
        }

        if !label_found {
            // Legacy path: no labels present, create a fresh pool identity.
            return Self::create(config, properties, options);
        }

        // -- Pool feature compatibility gate ----------------------------------------
        //
        // Pool-level feature bitmasks (features_incompat / features_ro_compat /
        // features_compat) are checked against the current software version's
        // supported feature mask.  Unknown incompat bits refuse import; unknown
        // ro_compat bits warn (read-only enforcement is handled at the dataset
        // mount layer); unknown compat bits are silent.
        if saved_features_valid {
            // All pool-level feature bits understood by this software version.
            // When a new version adds pool-level feature bits, this mask must be
            // extended.
            const POOL_SUPPORTED_FEATURES_INCOMPAT: u64 =
                features::POOL_LABEL_V1 | features::ENCRYPTION_INCOMPAT;
            const POOL_SUPPORTED_FEATURES_RO_COMPAT: u64 = 0;

            let unsupported_incompat = saved_features_incompat & !POOL_SUPPORTED_FEATURES_INCOMPAT;
            if unsupported_incompat != 0 {
                return Err(StoreError::InvalidOptions {
                    reason: "pool import refused: unknown incompat pool feature bits",
                });
            }
            let unsupported_ro_compat =
                saved_features_ro_compat & !POOL_SUPPORTED_FEATURES_RO_COMPAT;
            if unsupported_ro_compat != 0 {
                eprintln!(
                    "warning: pool imported: unknown ro_compat pool feature bits 0x{unsupported_ro_compat:016x}"
                );
                // Note: Pool-level read-only enforcement for unknown ro_compat
                // bits is deferred to the dataset mount layer.
            }
        }
        // -- End pool feature compatibility gate ------------------------------------

        // Detect locked-dataset condition: labels say encrypted but
        // no encryption key was provided in the device configs.
        let encryption_provided = config.devices.iter().any(|vc| vc.encryption.is_some());
        let locked = label_is_encrypted && !encryption_provided;

        // Labels were found and validated — open the pool with the
        // recovered identity.
        let pg = pool_guid.unwrap();

        // root_path must be a directory for Pool::open to function
        // (it holds device subdirectories and label files).
        // Byte-addressable pools always use Pool::create/import by device
        // paths, not a directory root.
        if !config.root_path.is_dir() {
            let all_byte_addressable = config
                .devices
                .iter()
                .all(|vc| vc.backing.is_byte_addressable_pool_member());
            if !all_byte_addressable {
                return Err(StoreError::Io {
                    operation: "pool_open",
                    path: config.root_path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "pool root directory does not exist after label read",
                    ),
                });
            }
        }

        let classes: Vec<DeviceClass> = config.devices.iter().map(|vc| vc.class).collect();
        let class_map = build_class_map(&classes);
        let mut devices = open_devices(&config.devices, options)?;

        // Build device-class-aware layout state.
        let media_classes: Vec<DeviceMediaClass> =
            config.devices.iter().map(|vc| vc.media_class).collect();
        let device_class_policy = DeviceClassPolicy::production();
        let device_layout_stats: Vec<DeviceLayoutStats> = media_classes
            .iter()
            .map(|mc| DeviceLayoutStats::with_segment_size(mc.default_segment_size()))
            .collect();
        let write_allocator = Self::build_write_allocator(&devices, &media_classes);

        // Restore device health from imported label data.
        for (idx, health_byte, re, we, ce) in label_health_states {
            if let Some(device) = devices.get_mut(idx) {
                device.restore_health_from_label(health_byte, re, we, ce);
            }
        }
        let health = compute_health(&devices);

        // Open the log device writer if an IntentLog device is present.
        let log_device = open_log_device_for_devices(&config.devices)?;

        let mut pool = Self {
            config,
            properties,
            classes,
            devices,
            class_map,
            health,
            media_classes,
            write_allocator,
            device_class_policy,
            device_layout_stats,
            log_device,
            pool_guid: pg,
            device_guids,
            placement_epoch: topology_generation.unwrap_or(1).max(1),
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            allocator: None,
            locked,
        };

        // Resume interrupted device removal if a pending marker exists.
        resume_device_removal_if_pending(&mut pool);

        Ok(pool)
    }

    /// Export the pool: write PoolLabelV1 labels to every device root
    /// directory with `PoolState::Exported`.  After a successful export,
    /// the pool can be re-opened via [`Pool::open`] and the labels will
    /// be validated.
    pub fn export(&self) -> Result<()> {
        // Flush the log device before export.
        if let Some(ref log_device) = self.log_device {
            log_device.commit()?;
        }
        for (i, device) in self.devices.iter().enumerate() {
            let root = device.root().to_path_buf();
            fs::create_dir_all(&root).map_err(|e| StoreError::Io {
                operation: "pool_export_create_dir",
                path: root.clone(),
                source: e,
            })?;

            let label = self.build_label(i, device);

            let sealed = pool_label::seal_label(label).map_err(|_| StoreError::InvalidOptions {
                reason: "label seal failed",
            })?;

            let mut buf = [0u8; pool_label::POOL_LABEL_V1_EXT_WIRE_SIZE];
            pool_label::encode_label(&sealed, &mut buf).map_err(|_| {
                StoreError::InvalidOptions {
                    reason: "label encode failed",
                }
            })?;

            let lp = label_file_path(&root);
            let mut f = fs::File::create(&lp).map_err(|e| StoreError::Io {
                operation: "pool_export_write_label",
                path: lp.clone(),
                source: e,
            })?;
            f.write_all(&buf).map_err(|e| StoreError::Io {
                operation: "pool_export_write_label",
                path: lp,
                source: e,
            })?;
        }
        Ok(())
    }

    /// Returns `true` when the pool is in locked-dataset state.
    ///
    /// A locked pool has per-object encryption enabled in its device
    /// labels but was opened without an encryption key.  Reads and
    /// writes are refused until the correct key is supplied.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Return the persistent pool GUID.
    pub fn pool_guid(&self) -> [u8; 16] {
        self.pool_guid
    }

    /// Log of device health transitions since pool open.
    pub fn health_transitions(&self) -> &[DeviceHealthTransition] {
        &self.health_transitions
    }

    /// Number of health transitions recorded since pool creation.
    #[must_use]
    pub fn health_transition_count(&self) -> usize {
        self.health_transitions.len()
    }

    /// Per-device health states, indexed by device position.
    pub fn device_health_states(&self) -> Vec<(usize, DeviceHealthState)> {
        self.devices
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.health_state().map(|hs| (i, hs)))
            .collect()
    }

    /// Record device health transitions that have occurred since last I/O.
    /// Drain per-device health transition ring buffers and record
    /// [`DeviceHealthTransition`] events in the pool-level log.
    ///
    /// Call this after every I/O operation (put, get, delete, sync)
    /// to automatically capture health state changes.
    pub fn record_health_transitions(&mut self) {
        let pg_u64 = u64::from_le_bytes(self.pool_guid[..8].try_into().unwrap());
        let mut faulted_indices: Vec<usize> = Vec::new();
        for idx in 0..self.devices.len() {
            let drained = self.devices[idx].drain_health_transitions();
            for entry in drained {
                let reason = format!(
                    "device {idx}: {:?} error triggered {}-{} transition ({} window errors)",
                    entry.trigger, entry.from, entry.to, entry.window_errors,
                );
                self.health_transitions.push(DeviceHealthTransition::new(
                    idx as u64, pg_u64, entry.from, entry.to, reason,
                ));
                if entry.to == DeviceHealth::Faulted {
                    faulted_indices.push(idx);
                }
            }
        }
        // Check spare policy for any newly faulted devices.
        for idx in faulted_indices {
            self.check_spare_policy(idx);
        }
    }

    /// Recompute pool health from per-device DeviceHealth states.
    pub fn recompute_health_from_devices(&mut self) -> PoolHealth {
        let mut degraded = false;
        let mut faulted = false;
        for device in &self.devices {
            if let Some(hs) = device.health_state() {
                match hs.health {
                    DeviceHealth::Online => {}
                    DeviceHealth::Degraded => degraded = true,
                    DeviceHealth::Faulted => faulted = true,
                }
            }
        }
        let h = if faulted {
            PoolHealth::Faulted
        } else if degraded {
            PoolHealth::Degraded
        } else {
            PoolHealth::Online
        };
        self.health = h;
        h
    }

    /// Encode [`DeviceHealth`] as a u8 for the pool label wire format.
    /// 0=Online, 1=Degraded, 2=Faulted.
    fn device_health_for_label(hs: Option<DeviceHealthState>) -> u8 {
        match hs.map(|h| h.health) {
            Some(DeviceHealth::Online) | None => 0,
            Some(DeviceHealth::Degraded) => 1,
            Some(DeviceHealth::Faulted) => 2,
        }
    }

    /// Build a PoolLabelV1 for a single device.
    fn build_label(&self, device_index: usize, device: &Device) -> PoolLabelV1 {
        let device_guid: [u8; 16] = rand::random();

        let device_count = self.devices.len() as u32;

        PoolLabelV1 {
            pool_guid: self.pool_guid,
            device_guid,
            pool_name_len: self.config.name.len().min(255) as u16,
            pool_state: PoolState::Exported,
            device_index: device_index as u32,
            topology_generation: self.placement_epoch,
            device_count,
            device_class: runtime_class_to_label(self.classes.get(device_index).copied()),
            features_compat: features::DEVICE_HEALTH_STATE,
            features_incompat: {
                let mut flags = features::POOL_LABEL_V1;
                if self.devices.iter().any(|d| d.is_encrypted()) {
                    flags |= features::ENCRYPTION_INCOMPAT;
                }
                flags
            },
            device_health: Self::device_health_for_label(device.health_state()),
            device_read_errors: device.health_state().map_or(0, |hs| hs.total_read_errors),
            device_write_errors: device.health_state().map_or(0, |hs| hs.total_write_errors),
            device_checksum_errors: device
                .health_state()
                .map_or(0, |hs| hs.total_checksum_errors),
            ..PoolLabelV1::new(self.pool_guid, device_guid, &self.config.name)
        }
    }

    // ------------------------------------------------------------------
    // I/O: device-class-aware put / get / delete
    // ------------------------------------------------------------------

    /// Check whether a data write of `payload_len` bytes is admitted
    /// under the configured low-watermark policy.
    ///
    /// Returns `Ok(())` when the write is allowed or when the class is not
    /// `IoClass::Data` (metadata and intent-log always bypass the watermark).
    /// Returns `Err(StoreError::NoSpace)` when the write would push available
    /// capacity below the configured reserve.
    pub fn check_write_admission(&self, class: IoClass, payload_len: u64) -> Result<()> {
        if self.properties.low_watermark_bytes == 0 {
            // Watermark disabled; always admit.
            return Ok(());
        }
        if class != IoClass::Data {
            // Metadata and intent-log bypass the watermark gate so
            // reclaim, compaction, and allocator forward progress
            // remain possible even under space pressure.
            return Ok(());
        }
        let cap = self.pool_stats();
        let would_be_available = cap.available_bytes.saturating_sub(payload_len);
        if would_be_available < self.properties.low_watermark_bytes {
            return Err(StoreError::NoSpace);
        }
        Ok(())
    }

    fn usable_candidates(&self, indices: &[usize]) -> Vec<usize> {
        indices
            .iter()
            .copied()
            .filter(|idx| {
                let state = self.devices[*idx].status().state;
                state != DeviceState::Faulted && state != DeviceState::Removed
            })
            .collect()
    }

    fn placement_candidates(&self, class: IoClass, indices: &[usize]) -> Vec<usize> {
        self.placement_candidates_for_targets(class, indices, 1)
    }

    fn placement_candidates_for_targets(
        &self,
        class: IoClass,
        indices: &[usize],
        min_targets: usize,
    ) -> Vec<usize> {
        let usable = self.usable_candidates(indices);
        if class != IoClass::Metadata {
            return usable;
        }

        let allowed_preferences = if self.device_class_policy.metadata_allow_hdd {
            self.device_class_policy.metadata_preference.clone()
        } else {
            self.device_class_policy
                .metadata_preference
                .iter()
                .copied()
                .filter(|media_class| *media_class != DeviceMediaClass::Hdd)
                .collect()
        };

        for preferred in allowed_preferences {
            let preferred_tier: Vec<usize> = usable
                .iter()
                .copied()
                .filter(|idx| self.media_classes[*idx] == preferred)
                .collect();
            if preferred_tier.len() >= min_targets {
                return preferred_tier;
            }
        }

        usable
    }

    fn canonical_device_for_key(
        &self,
        class: IoClass,
        key: ObjectKey,
        indices: &[usize],
    ) -> Option<usize> {
        let candidates = self.placement_candidates(class, indices);
        if candidates.is_empty() {
            None
        } else {
            Some(pick_device(key, &candidates))
        }
    }

    fn read_order_for_key(&self, class: IoClass, key: ObjectKey, indices: &[usize]) -> Vec<usize> {
        let mut candidates = self.usable_candidates(indices);
        if class == IoClass::IntentLog {
            return candidates;
        }

        if let Some(canonical) = self.canonical_device_for_key(class, key, indices) {
            candidates.retain(|idx| *idx != canonical);
            candidates.insert(0, canonical);
        }
        candidates
    }

    fn record_device_write_result(
        &mut self,
        device_index: usize,
        payload_len: usize,
        result: &Result<StoredObject>,
    ) {
        if result.is_ok() {
            self.device_layout_stats[device_index].write_allocations += 1;
            self.device_layout_stats[device_index].bytes_written += payload_len as u64;
        } else {
            self.device_layout_stats[device_index].allocation_errors += 1;
        }
    }

    /// Current placement epoch used for new allocation receipts.
    #[must_use]
    pub fn placement_epoch(&self) -> u64 {
        self.placement_epoch
    }

    /// Pool-wide redundancy policy used for new non-log object allocation.
    #[must_use]
    pub fn redundancy_policy(&self) -> PoolRedundancyPolicy {
        self.properties.redundancy_policy
    }

    fn bump_placement_epoch(&mut self) {
        self.placement_epoch = self.placement_epoch.saturating_add(1).max(1);
    }

    fn placement_failure_domain(&self, candidate_count: usize) -> Result<FailureDomainV1> {
        let target_count =
            u8::try_from(candidate_count.clamp(1, 64)).map_err(|_| StoreError::InvalidOptions {
                reason: "candidate count exceeds placement failure-domain wire limit",
            })?;
        FailureDomainV1::new(self.properties.failure_domain_level, target_count).map_err(|_| {
            StoreError::InvalidOptions {
                reason: "invalid pool placement failure-domain policy",
            }
        })
    }

    fn device_guid_for_index(&self, idx: usize) -> [u8; 16] {
        self.device_guids.get(idx).copied().unwrap_or_else(|| {
            let mut fallback = [0u8; 16];
            fallback[..8].copy_from_slice(&(idx as u64).to_le_bytes());
            fallback
        })
    }

    fn device_id_for_index(&self, idx: usize) -> u64 {
        u64::from_le_bytes(self.device_guid_for_index(idx)[..8].try_into().unwrap())
    }

    fn device_index_for_device_id(&self, device_id: u64) -> Option<usize> {
        self.device_guids
            .iter()
            .position(|guid| u64::from_le_bytes(guid[..8].try_into().unwrap()) == device_id)
    }

    fn resolve_receipt_target(&self, target: &PlacementReceiptTarget) -> Option<usize> {
        if let Some(idx) = self
            .device_guids
            .iter()
            .position(|guid| *guid == target.device_guid)
        {
            return Some(idx);
        }

        let idx = target.device_index as usize;
        (idx < self.devices.len()).then_some(idx)
    }

    fn device_health_capacity_for_index(&self, idx: usize) -> DeviceHealthCapacity {
        let store = self.devices[idx].store();
        let total_bytes = store.capacity_bytes();
        let used_bytes = self.devices[idx].stats().live_bytes;
        let mut device = DeviceHealthCapacity::new(
            self.device_id_for_index(idx),
            self.device_id_for_index(idx),
            self.device_id_for_index(idx),
            total_bytes,
        );
        device.used_bytes = used_bytes;
        device.healthy = !matches!(
            self.devices[idx].status().state,
            DeviceState::Faulted | DeviceState::Removed
        );
        device
    }

    fn plan_pool_wide_placement(
        &self,
        class: IoClass,
        key: ObjectKey,
        payload_len: usize,
        indices: &[usize],
    ) -> Result<PlacementReceipt> {
        let required = self.properties.redundancy_policy.total_targets()?;
        let candidates = self.placement_candidates_for_targets(class, indices, required);
        if candidates.len() < required {
            return Err(StoreError::InvalidOptions {
                reason: "not enough eligible pool devices for redundancy policy",
            });
        }

        let layout = self.properties.redundancy_policy.layout()?;
        let failure_domain = self.placement_failure_domain(candidates.len())?;
        let devices: Vec<DeviceHealthCapacity> = candidates
            .iter()
            .copied()
            .map(|idx| self.device_health_capacity_for_index(idx))
            .collect();
        let (object_id, placement_key) = placement_key_pair(key);
        let request = AllocationRequest::new(object_id, payload_len as u64, placement_key);
        let planner =
            HashRingPlacementPlanner::new(PLACEMENT_HASH_RING_VNODES_PER_GB, self.placement_epoch);
        let decision = planner
            .plan_placement(&layout, &failure_domain, &devices, &request)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "pool-wide placement planner could not satisfy redundancy policy",
            })?;

        self.receipt_from_decision(key, payload_len, decision, &candidates)
    }

    fn receipt_from_decision(
        &self,
        key: ObjectKey,
        payload_len: usize,
        decision: PlacementDecision,
        candidates: &[usize],
    ) -> Result<PlacementReceipt> {
        let device_to_index: BTreeMap<u64, usize> = candidates
            .iter()
            .copied()
            .map(|idx| (self.device_id_for_index(idx), idx))
            .collect();
        let (data_shards, _parity_shards) = match self.properties.redundancy_policy {
            PoolRedundancyPolicy::Replicated { copies } => (copies, 0),
            PoolRedundancyPolicy::Erasure {
                data_shards,
                parity_shards,
            } => (data_shards, parity_shards),
        };
        let mut targets = Vec::with_capacity(decision.device_targets.len());
        for (slot, device_id) in decision.device_targets.iter().copied().enumerate() {
            let idx = device_to_index
                .get(&device_id)
                .copied()
                .or_else(|| self.device_index_for_device_id(device_id))
                .ok_or(StoreError::InvalidOptions {
                    reason: "placement planner selected unknown device",
                })?;
            let role = match self.properties.redundancy_policy {
                PoolRedundancyPolicy::Replicated { .. } => PlacementTargetRole::Data,
                PoolRedundancyPolicy::Erasure { .. } if slot < data_shards as usize => {
                    PlacementTargetRole::Data
                }
                PoolRedundancyPolicy::Erasure { .. } => PlacementTargetRole::Parity,
            };
            targets.push(PlacementReceiptTarget {
                device_index: idx as u32,
                device_guid: self.device_guid_for_index(idx),
                shard_index: slot as u16,
                role,
                stored_digest: [0u8; 32],
            });
        }

        Ok(PlacementReceipt {
            object_key: key,
            epoch: self.placement_epoch,
            policy: self.properties.redundancy_policy,
            failure_domain_level: self.properties.failure_domain_level,
            payload_len: payload_len as u64,
            shard_len: 0,
            payload_digest: [0u8; 32],
            targets,
        })
    }

    /// Return the persisted placement receipt for a key, if one exists.
    pub fn placement_receipt_for_key(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<PlacementReceipt>> {
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Ok(None);
        }
        self.load_placement_receipt(&indices, key)
    }

    fn load_placement_receipt(
        &self,
        indices: &[usize],
        key: ObjectKey,
    ) -> Result<Option<PlacementReceipt>> {
        let receipt_key = placement_receipt_object_key(key);
        let mut best: Option<PlacementReceipt> = None;
        for idx in self.usable_candidates(indices) {
            let raw = match self.devices[idx].get(receipt_key) {
                Ok(Some(raw)) => raw,
                Ok(None) | Err(_) => continue,
            };
            let Some(receipt) = PlacementReceipt::decode(&raw) else {
                continue;
            };
            if receipt.object_key != key {
                continue;
            }
            let replace = match best.as_ref() {
                Some(current) => receipt.epoch >= current.epoch,
                None => true,
            };
            if replace {
                best = Some(receipt);
            }
        }
        Ok(best)
    }

    fn write_placement_receipt(
        &mut self,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) -> Result<()> {
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        let encoded = receipt.encode()?;
        let mut wrote = false;
        let mut last_err = None;
        for idx in self.usable_candidates(indices) {
            match self.devices[idx].put(receipt_key, &encoded) {
                Ok(_) => wrote = true,
                Err(err) => last_err = Some(err),
            }
        }
        if wrote {
            Ok(())
        } else {
            Err(last_err.unwrap_or(StoreError::InvalidOptions {
                reason: "placement receipt could not be persisted",
            }))
        }
    }

    fn put_pool_wide(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        payload: &[u8],
        indices: &[usize],
    ) -> Result<StoredObject> {
        let mut receipt = self.plan_pool_wide_placement(class, key, payload.len(), indices)?;
        receipt.payload_digest = digest32(payload);

        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                self.put_replicated_with_receipt(key, payload, indices, &mut receipt)
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                self.put_erasure_with_receipt(key, payload, indices, &mut receipt)
            }
        }
    }

    fn put_replicated_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        indices: &[usize],
        receipt: &mut PlacementReceipt,
    ) -> Result<StoredObject> {
        let target_indices: Vec<(usize, usize)> = receipt
            .targets
            .iter()
            .enumerate()
            .filter_map(|(pos, target)| self.resolve_receipt_target(target).map(|idx| (pos, idx)))
            .collect();
        if target_indices.len() != receipt.targets.len() {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt references unavailable device",
            });
        }

        let mut written_indices = Vec::with_capacity(target_indices.len());
        let mut last_object = None;
        for (target_pos, idx) in target_indices {
            let result = self.devices[idx].put(key, payload);
            self.record_device_write_result(idx, payload.len(), &result);
            match result {
                Ok(object) => {
                    receipt.targets[target_pos].stored_digest = receipt.payload_digest;
                    written_indices.push(idx);
                    last_object = Some(object);
                }
                Err(err) => {
                    for rollback_idx in written_indices {
                        let _ = self.devices[rollback_idx].delete(key);
                    }
                    self.health = compute_health(&self.devices);
                    self.record_health_transitions();
                    return Err(err);
                }
            }
        }

        self.write_placement_receipt(indices, receipt)?;
        self.cleanup_stale_replicated_copies(key, indices, receipt);
        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        Ok(last_object.unwrap_or(StoredObject {
            key,
            sequence: 0,
            len: payload.len() as u64,
            checksum: crate::store::checksum64(payload),
        }))
    }

    fn put_erasure_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        indices: &[usize],
        receipt: &mut PlacementReceipt,
    ) -> Result<StoredObject> {
        let PoolRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } = receipt.policy
        else {
            return Err(StoreError::InvalidOptions {
                reason: "erasure write requested for non-erasure receipt",
            });
        };
        let shard_len = payload.len().div_ceil(data_shards as usize).max(1);
        let stripe_config = StripeConfig {
            data_shards: data_shards as usize,
            parity_shards: parity_shards as usize,
            shard_len,
        };
        let encoded =
            encode_erasure_stripe(&stripe_config, payload).ok_or(StoreError::InvalidOptions {
                reason: "erasure encoder rejected pool placement payload",
            })?;
        receipt.shard_len = shard_len as u32;

        let mut written = Vec::with_capacity(receipt.targets.len());
        for target_pos in 0..receipt.targets.len() {
            let shard_index = receipt.targets[target_pos].shard_index as usize;
            let Some(shard) = encoded
                .shards
                .iter()
                .find(|shard| shard.index == shard_index)
            else {
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement receipt missing encoded shard",
                });
            };
            let Some(idx) = self.resolve_receipt_target(&receipt.targets[target_pos]) else {
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement receipt references unavailable device",
                });
            };
            let shard_key = placement_shard_object_key(key, shard_index as u16);
            let result = self.devices[idx].put(shard_key, &shard.bytes);
            self.record_device_write_result(idx, shard.bytes.len(), &result);
            match result {
                Ok(_) => {
                    receipt.targets[target_pos].stored_digest = digest32(&shard.bytes);
                    written.push((idx, shard_key));
                }
                Err(err) => {
                    for (rollback_idx, rollback_key) in written {
                        let _ = self.devices[rollback_idx].delete(rollback_key);
                    }
                    self.health = compute_health(&self.devices);
                    self.record_health_transitions();
                    return Err(err);
                }
            }
        }

        self.write_placement_receipt(indices, receipt)?;
        self.cleanup_stale_erasure_shards(key, indices, receipt);
        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        Ok(StoredObject {
            key,
            sequence: 0,
            len: payload.len() as u64,
            checksum: crate::store::checksum64(payload),
        })
    }

    fn cleanup_stale_replicated_copies(
        &mut self,
        key: ObjectKey,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) {
        let target_indices: BTreeSet<usize> = receipt
            .targets
            .iter()
            .filter_map(|target| self.resolve_receipt_target(target))
            .collect();
        for idx in self.usable_candidates(indices) {
            if !target_indices.contains(&idx) {
                let _ = self.devices[idx].delete(key);
            }
        }
    }

    fn cleanup_stale_erasure_shards(
        &mut self,
        key: ObjectKey,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) {
        let target_by_index: BTreeMap<usize, u16> = receipt
            .targets
            .iter()
            .filter_map(|target| {
                self.resolve_receipt_target(target)
                    .map(|idx| (idx, target.shard_index))
            })
            .collect();
        for idx in self.usable_candidates(indices) {
            let keep_shard = target_by_index.get(&idx).copied();
            for shard_index in 0..receipt.targets.len() {
                let shard_key = placement_shard_object_key(key, shard_index as u16);
                if keep_shard != Some(shard_index as u16) {
                    let _ = self.devices[idx].delete(shard_key);
                }
            }
            let _ = self.devices[idx].delete(key);
        }
    }

    /// Store an object, routing by `class`.
    ///
    /// `IntentLog` retains write-all log semantics. All other classes allocate
    /// through the pool-wide redundancy policy and persist a placement receipt
    /// that becomes the read locator authority for this key.
    pub fn put(&mut self, class: IoClass, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        match class {
            IoClass::IntentLog => {
                // Write to all healthy intent-log devices (write-ahead-log
                // semantics).  Faulted devices are skipped; if every device
                // fails the operation returns the last error.  The
                // ClassMap fallback chain (IntentLog → Data) means the
                // indices already include Data devices after dedicated log
                // devices, so writes automatically fall back to data when
                // no log device is healthy.
                let mut last: Option<StoredObject> = None;
                let mut last_err: Option<StoreError> = None;
                for &idx in &indices {
                    let state = self.devices[idx].status().state;
                    if state == DeviceState::Faulted || state == DeviceState::Removed {
                        continue;
                    }
                    match self.devices[idx].put(key, payload) {
                        Ok(obj) => last = Some(obj),
                        Err(e) => {
                            last_err = Some(e);
                            // Continue to next device (fallback chain)
                            continue;
                        }
                    }
                }
                self.health = compute_health(&self.devices);
                self.record_health_transitions();
                match last {
                    Some(obj) => Ok(obj),
                    None => Err(last_err.unwrap_or(StoreError::InvalidOptions {
                        reason: "intent log: no healthy devices available",
                    })),
                }
            }
            IoClass::Metadata => self.put_pool_wide(class, key, payload, &indices),
            IoClass::Data => {
                self.check_write_admission(class, payload.len() as u64)?;
                self.put_pool_wide(class, key, payload, &indices)
            }
            IoClass::ReadCache => self.put_pool_wide(class, key, payload, &indices),
        }
    }

    /// Retrieve an object from its persisted placement receipt when present.
    pub fn get(&self, class: IoClass, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        if let Some(receipt) = self.load_placement_receipt(&indices, key)? {
            return self.get_with_receipt(&receipt);
        }

        for idx in self.read_order_for_key(class, key, &indices) {
            match self.devices[idx].get(key) {
                Ok(Some(data)) => return Ok(Some(data)),
                Ok(None) => continue,
                Err(e) => {
                    // Log the error but try other devices (e.g., mirrors with
                    // one bad member)
                    let _ = e;
                    continue;
                }
            }
        }
        Ok(None)
    }

    fn get_with_receipt(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => self.get_replicated_with_receipt(receipt),
            PoolRedundancyPolicy::Erasure { .. } => self.get_erasure_with_receipt(receipt),
        }
    }

    fn get_replicated_with_receipt(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        for target in &receipt.targets {
            let Some(idx) = self.resolve_receipt_target(target) else {
                continue;
            };
            match self.devices[idx].get(receipt.object_key) {
                Ok(Some(payload)) if digest32(&payload) == receipt.payload_digest => {
                    return Ok(Some(payload));
                }
                Ok(Some(_)) => continue,
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        Ok(None)
    }

    fn get_erasure_with_receipt(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        let PoolRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } = receipt.policy
        else {
            return Ok(None);
        };
        let shard_len =
            usize::try_from(receipt.shard_len).map_err(|_| StoreError::InvalidOptions {
                reason: "placement receipt shard length exceeds platform usize",
            })?;
        if shard_len == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "erasure placement receipt has zero shard length",
            });
        }
        let config = StripeConfig {
            data_shards: data_shards as usize,
            parity_shards: parity_shards as usize,
            shard_len,
        };
        let width = config.stripe_width();
        let mut available = vec![None; width];

        for target in &receipt.targets {
            let shard_index = target.shard_index as usize;
            if shard_index >= width {
                continue;
            }
            let Some(idx) = self.resolve_receipt_target(target) else {
                continue;
            };
            let shard_key = placement_shard_object_key(receipt.object_key, target.shard_index);
            let Some(bytes) = self.devices[idx].get(shard_key)? else {
                continue;
            };
            if digest32(&bytes) != target.stored_digest {
                continue;
            }
            let kind = match target.role {
                PlacementTargetRole::Data => ShardKind::Data,
                PlacementTargetRole::Parity => ShardKind::Parity,
            };
            available[shard_index] = Some(ErasureShard {
                index: shard_index,
                kind,
                bytes,
            });
        }

        let Some(mut reconstructed) = reconstruct_erasure_stripe(&config, &available, None) else {
            return Ok(None);
        };
        reconstructed.payload.truncate(receipt.payload_len as usize);
        if digest32(&reconstructed.payload) != receipt.payload_digest {
            return Ok(None);
        }
        Ok(Some(reconstructed.payload))
    }

    /// Delete an object from every device that can hold this I/O class.
    pub fn delete(&mut self, class: IoClass, key: ObjectKey) -> Result<bool> {
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        if let Some(receipt) = self.load_placement_receipt(&indices, key)? {
            let deleted = self.delete_with_receipt(&receipt, &indices)?;
            self.health = compute_health(&self.devices);
            self.record_health_transitions();
            return Ok(deleted);
        }

        let mut deleted = false;
        let mut attempted = false;
        let mut last_err = None;

        for idx in self.usable_candidates(&indices) {
            attempted = true;
            match self.devices[idx].delete(key) {
                Ok(was_present) => deleted |= was_present,
                Err(err) => last_err = Some(err),
            }
        }

        self.health = compute_health(&self.devices);
        self.record_health_transitions();

        if deleted {
            Ok(true)
        } else if attempted {
            if let Some(err) = last_err {
                Err(err)
            } else {
                Ok(false)
            }
        } else {
            Err(StoreError::InvalidOptions {
                reason: "delete: no healthy devices available",
            })
        }
    }

    fn delete_with_receipt(
        &mut self,
        receipt: &PlacementReceipt,
        indices: &[usize],
    ) -> Result<bool> {
        let mut deleted = false;
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                for idx in self.usable_candidates(indices) {
                    deleted |= self.devices[idx]
                        .delete(receipt.object_key)
                        .unwrap_or(false);
                }
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                for idx in self.usable_candidates(indices) {
                    for target in &receipt.targets {
                        let shard_key =
                            placement_shard_object_key(receipt.object_key, target.shard_index);
                        deleted |= self.devices[idx].delete(shard_key).unwrap_or(false);
                    }
                    deleted |= self.devices[idx]
                        .delete(receipt.object_key)
                        .unwrap_or(false);
                }
            }
        }

        let receipt_key = placement_receipt_object_key(receipt.object_key);
        for idx in self.usable_candidates(indices) {
            deleted |= self.devices[idx].delete(receipt_key).unwrap_or(false);
        }
        Ok(deleted)
    }

    fn retarget_replicated_receipt_after_evacuate(
        &mut self,
        key: ObjectKey,
        old_idx: usize,
        new_idx: usize,
        payload: &[u8],
    ) -> Result<()> {
        let indices: Vec<usize> = self.class_map.get(IoClass::Data).to_vec();
        let Some(mut receipt) = self.load_placement_receipt(&indices, key)? else {
            return Ok(());
        };
        if !matches!(receipt.policy, PoolRedundancyPolicy::Replicated { .. }) {
            return Ok(());
        }

        let new_guid = self.device_guid_for_index(new_idx);
        let digest = digest32(payload);
        let mut changed = false;
        for target in &mut receipt.targets {
            let target_idx = self
                .device_guids
                .iter()
                .position(|guid| *guid == target.device_guid)
                .unwrap_or(target.device_index as usize);
            if target_idx == old_idx {
                target.device_index = new_idx as u32;
                target.device_guid = new_guid;
                target.stored_digest = digest;
                changed = true;
            }
        }
        if changed {
            receipt.epoch = self.placement_epoch.saturating_add(1).max(1);
            self.write_placement_receipt(&indices, &receipt)?;
        }
        Ok(())
    }

    /// Flush all devices.
    pub fn sync_all(&mut self) -> Result<()> {
        for device in &mut self.devices {
            device.sync_all()?;
        }
        Ok(())
    }

    /// Lightweight data-only flush across all pool devices.
    ///
    /// Calls sync_data on each device instead of sync_all, providing
    /// fdatasync semantics for writeback-drain convergence without
    /// the full metadata commit overhead of sync_all.
    pub fn sync_data(&mut self) -> Result<()> {
        for device in &mut self.devices {
            device.sync_data()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Device management
    // ------------------------------------------------------------------

    /// Add a device to the running pool.
    pub fn add_device(&mut self, config: DeviceConfig, options: &StoreOptions) -> Result<()> {
        let config_for_record = config.clone();
        let mut dev_opts = options.clone();
        dev_opts.max_segment_bytes = config.media_class.default_segment_size();
        let device = open_single_device(&config, &dev_opts)?;
        self.classes.push(config.class);
        self.media_classes.push(config.media_class);
        self.devices.push(device);
        self.device_guids.push(rand::random());
        self.class_map = build_class_map(&self.classes);
        self.device_layout_stats
            .push(DeviceLayoutStats::with_segment_size(
                config.media_class.default_segment_size(),
            ));
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);
        self.health = compute_health(&self.devices);
        self.config.devices.push(config_for_record);
        self.bump_placement_epoch();
        self.record_health_transitions();
        Ok(())
    }

    /// Add a device with label persistence.
    ///
    /// Extends the in-memory [`add_device`](Self::add_device) by writing
    /// PoolLabelV1 labels to the new device and updating topology labels on
    /// all existing devices via [`DeviceManager`].  The topology generation is
    /// incremented and device_count is bumped.
    ///
    /// Returns an error if label writing fails on any device.
    pub fn add_device_labeled(
        &mut self,
        config: DeviceConfig,
        options: &StoreOptions,
        pool_name: &str,
        commit_group: u64,
    ) -> Result<()> {
        // Compute the new device GUID before opening (the device may not
        // have a label yet, so we generate one).
        let new_device_guid: [u8; 16] = rand::random();

        // Preserve explicit media identity while writing updated labels.
        let existing_configs = self.config.devices.clone();

        // Add the device in-memory first.
        self.add_device(config.clone(), options)?;

        // Now write labels via DeviceManager.
        DeviceManager::add_device(
            &existing_configs,
            &config,
            self.pool_guid,
            &self.device_guids[..self.device_guids.len().saturating_sub(1)], // GUIDs before the new one
            new_device_guid,
            pool_name,
            commit_group,
        )?;

        // Update the device_guids entry that add_device pushed randomly.
        if let Some(last) = self.device_guids.last_mut() {
            *last = new_device_guid;
        }

        Ok(())
    }

    /// Activate a hot-spare to replace a faulted device.
    ///
    /// Finds the faulted device by GUID, selects the spare device, writes
    /// labels through [`DeviceManager::activate_spare`], and updates the
    /// in-memory pool state.  The caller is responsible for providing the
    /// spare device configuration and ensuring data evacuation/rebuild is
    /// scheduled.
    pub fn activate_spare(
        &mut self,
        faulted_device_guid: [u8; 16],
        spare_config: DeviceConfig,
        spare_device_guid: [u8; 16],
        policy: SparePolicy,
        pool_name: &str,
        commit_group: u64,
        options: &StoreOptions,
    ) -> Result<()> {
        // Find the faulted device's index.
        let faulted_index = self
            .device_guids
            .iter()
            .position(|g| g == &faulted_device_guid)
            .ok_or(StoreError::InvalidOptions {
                reason: "faulted device GUID not found in pool",
            })?;

        let existing_configs = self.config.devices.clone();

        // Delegate to DeviceManager for label persistence.
        let request = crate::device_manager::SpareActivationRequest {
            existing_device_configs: &existing_configs,
            faulted_device_guid,
            spare_device_config: &spare_config,
            spare_device_guid,
            policy,
            pool_guid: self.pool_guid,
            device_guids: &self.device_guids,
            pool_name,
            commit_group,
        };
        DeviceManager::activate_spare(request)?;

        // Update in-memory device at the faulted index.
        let mut dev_opts = options.clone();
        dev_opts.max_segment_bytes = spare_config.media_class.default_segment_size();
        let new_device = open_single_device(&spare_config, &dev_opts)?;
        self.devices[faulted_index] = new_device;
        self.device_guids[faulted_index] = spare_device_guid;

        // Update media class and layout stats.
        if faulted_index < self.media_classes.len() {
            self.media_classes[faulted_index] = spare_config.media_class;
        }
        if faulted_index < self.device_layout_stats.len() {
            self.device_layout_stats[faulted_index] = DeviceLayoutStats::with_segment_size(
                spare_config.media_class.default_segment_size(),
            );
        }
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);

        self.health = compute_health(&self.devices);
        self.bump_placement_epoch();
        self.record_health_transitions();

        Ok(())
    }

    /// Set the hot-spare activation policy for this pool.
    ///
    /// When set to [`SparePolicy::AutoOnFault`], the pool will
    /// automatically attempt to activate a registered spare device
    /// whenever any non-spare device transitions to FAULTED.
    /// [`SparePolicy::Manual`] (the default) requires explicit
    /// operator calls to [`activate_spare`](Self::activate_spare).
    pub fn set_spare_policy(&mut self, policy: SparePolicy) {
        self.spare_policy = policy;
    }

    /// Register a spare device configuration that can be activated
    /// automatically or manually to replace a faulted device.
    ///
    /// The spare device is not added to the active pool devices until
    /// [`activate_spare`](Self::activate_spare) or the auto-spare
    /// policy triggers activation.
    pub fn register_spare_device(
        &mut self,
        _config: DeviceConfig,
        _spare_guid: [u8; 16],
    ) -> Result<()> {
        // Spare registration deferred to pool-label wire-up.
        // Currently the caller passes the spare config directly to
        // activate_spare(); this method exists as the future registration
        // point for pre-staged hot-spares stored in pool labels.
        Ok(())
    }

    /// Check spare policy after health transitions and auto-activate
    /// a spare if a device has faulted and the policy permits it.
    ///
    /// Called automatically by [`record_health_transitions`](Self::record_health_transitions)
    /// when [`SparePolicy::AutoOnFault`] or [`SparePolicy::AutoOnDegraded`] is set.
    fn check_spare_policy(&mut self, faulted_device_idx: usize) {
        match self.spare_policy {
            SparePolicy::Manual => {}
            SparePolicy::AutoOnFault => {
                // Auto-activation: the caller (health monitor / operator)
                // should call activate_spare() with a concrete spare device.
                // We log the event but do not auto-activate without a
                // pre-registered spare device — that integration is deferred
                // to the pool-label wire-up (U6-U7).
                let _ = faulted_device_idx;
            }
            SparePolicy::AutoOnDegraded { error_threshold: _ } => {
                // Same as AutoOnFault for now.
                let _ = faulted_device_idx;
            }
        }
    }

    /// Remove a device by path. The device must be quiesced first (data on it
    /// will be unavailable after removal).
    pub fn remove_device(&mut self, path: &Path) -> Result<()> {
        let idx = self.devices.iter().position(|v| v.root() == path).ok_or(
            StoreError::InvalidOptions {
                reason: "device not found",
            },
        )?;
        self.devices.remove(idx);
        if idx < self.device_guids.len() {
            self.device_guids.remove(idx);
        }
        self.classes.remove(idx);
        self.class_map = build_class_map(&self.classes);
        if idx < self.media_classes.len() {
            self.media_classes.remove(idx);
        }
        if idx < self.device_layout_stats.len() {
            self.device_layout_stats.remove(idx);
        }
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);
        self.bump_placement_epoch();
        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        Ok(())
    }

    /// Safely remove a device by path, evacuating all objects to surviving
    /// devices before decommission.
    ///
    /// This is the preferred removal path. It enumerates objects resident on
    /// the target device, copies each to a surviving device (deterministic
    /// routing via key hash), verifies the target copy is readable, deletes
    /// the source copy, and finally removes the device from the pool.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOptions`] when the target device is not
    /// found or is the last remaining device in the pool.  Returns
    /// [`StoreError::Io`] when object read/write/delete fails.
    pub fn safe_remove_device(
        &mut self,
        path: &Path,
    ) -> Result<crate::device_removal::EvacuationResult> {
        use crate::device_removal::EvacuationResult;

        let target_idx = self.devices.iter().position(|v| v.root() == path).ok_or(
            StoreError::InvalidOptions {
                reason: "device not found for safe removal",
            },
        )?;

        // Refuse to remove the last device.
        if self.devices.len() <= 1 {
            return Err(StoreError::InvalidOptions {
                reason: "cannot remove the last device from the pool",
            });
        }

        // Write a removal-pending marker so a crash can be resumed on
        // next pool open. The file contains the path of the device being
        // removed.
        let marker_path = self.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
        if let Err(e) = std::fs::write(&marker_path, path.to_string_lossy().as_bytes()) {
            return Err(StoreError::Io {
                operation: "write_device_removal_marker",
                path: marker_path,
                source: e,
            });
        }

        // Compute surviving device indices (all except target).
        let surviving_indices: Vec<usize> = (0..self.devices.len())
            .filter(|&i| i != target_idx)
            .collect();

        // Enumerate objects on the target device.
        let keys = self.devices[target_idx]
            .store()
            .list_keys_including_internal();
        let mut result = EvacuationResult::default();

        if keys.is_empty() {
            // Nothing to evacuate -- remove immediately.
            self.remove_device(path)?;
            result.complete = true;
            return Ok(result);
        }

        let mut internal_placement_keys = BTreeSet::new();
        let mut rewritten_logical_keys = BTreeSet::new();
        let mut placement_receipts = Vec::new();

        for key in &keys {
            let Ok(Some(raw)) = self.devices[target_idx].get(*key) else {
                continue;
            };
            let Some(receipt) = PlacementReceipt::decode(&raw) else {
                continue;
            };
            if placement_receipt_object_key(receipt.object_key) != *key {
                continue;
            }

            internal_placement_keys.insert(*key);
            if matches!(receipt.policy, PoolRedundancyPolicy::Erasure { .. }) {
                for target in &receipt.targets {
                    internal_placement_keys.insert(placement_shard_object_key(
                        receipt.object_key,
                        target.shard_index,
                    ));
                }
            }
            placement_receipts.push(receipt);
        }

        for receipt in placement_receipts {
            let data = match self.get_with_receipt(&receipt)? {
                Some(data) => data,
                None => {
                    result.objects_failed += 1;
                    result.failed_keys.push(receipt.object_key);
                    continue;
                }
            };
            let digest: [u8; 32] = blake3::hash(&data).into();
            let len = data.len() as u64;

            if self
                .put_pool_wide(IoClass::Data, receipt.object_key, &data, &surviving_indices)
                .is_err()
            {
                result.objects_failed += 1;
                result.failed_keys.push(receipt.object_key);
                continue;
            }

            rewritten_logical_keys.insert(receipt.object_key);
            result.objects_evacuated += 1;
            result.bytes_evacuated += len;
            result.content_digests.insert(receipt.object_key, digest);
        }

        // For each legacy object on the target device: read, route to
        // survivor, write, verify, delete source. Receipt-backed logical
        // objects were rewritten above; receipt and shard records are internal
        // placement metadata and are intentionally skipped here.
        for key in &keys {
            if internal_placement_keys.contains(key) || rewritten_logical_keys.contains(key) {
                continue;
            }

            // Read from the target device.
            let data = match self.devices[target_idx].get(*key) {
                Ok(Some(d)) => d,
                Ok(None) => {
                    result.objects_failed += 1;
                    result.failed_keys.push(*key);
                    continue;
                }
                Err(_) => {
                    result.objects_failed += 1;
                    result.failed_keys.push(*key);
                    continue;
                }
            };

            let digest: [u8; 32] = blake3::hash(&data).into();
            let len = data.len() as u64;

            // Pick a surviving device by key hash.
            let survivor_idx = pick_device(*key, &surviving_indices);

            // Write to the surviving device.
            if self.devices[survivor_idx].put(*key, &data).is_err() {
                result.objects_failed += 1;
                result.failed_keys.push(*key);
                continue;
            }

            // Verify the write is readable with correct content.
            match self.devices[survivor_idx].get(*key) {
                Ok(Some(readback)) => {
                    let readback_digest: [u8; 32] = blake3::hash(&readback).into();
                    if readback_digest != digest {
                        result.objects_failed += 1;
                        result.failed_keys.push(*key);
                        continue;
                    }
                }
                _ => {
                    result.objects_failed += 1;
                    result.failed_keys.push(*key);
                    continue;
                }
            }

            self.retarget_replicated_receipt_after_evacuate(*key, target_idx, survivor_idx, &data)?;

            // Delete from the target device.
            let _ = self.devices[target_idx].delete(*key);

            result.objects_evacuated += 1;
            result.bytes_evacuated += len;
            result.content_digests.insert(*key, digest);
        }

        // If any objects failed, do not remove the device.
        if result.objects_failed > 0 {
            result.complete = false;
            return Ok(result);
        }

        // All objects evacuated -- remove the device.
        self.remove_device(path)?;

        // Remove the pending-removal marker on success.
        let marker_path = self.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
        let _ = std::fs::remove_file(&marker_path);

        result.complete = true;
        Ok(result)
    }

    /// Replace a device in the running pool with a new device.
    ///
    /// The old device (identified by `old_path`) is replaced by the new device
    /// described in `new_config`. The caller must ensure the new device has
    /// sufficient capacity and is on suitable physical media.
    ///
    /// # Replacement lifecycle
    ///
    /// 1. Open the new device via [`open_single_device`].
    /// 2. Attach the new device to the pool (label management via
    ///    [`DeviceManager::replace_device`]).
    /// 3. Initiate data evacuation from old to new (deferred to
    ///    [`ResilverService`]; the replacement state is tracked for
    ///    Review debt TFR-012 completion).
    /// 4. When evacuation completes, the old device is detached.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOptions`] when the old device path is not
    /// found in the pool, or when a replacement is already in progress.
    pub fn replace_device(
        &mut self,
        old_path: &Path,
        new_config: DeviceConfig,
        options: &StoreOptions,
    ) -> Result<()> {
        // Refuse if a replacement is already active.
        if self.replacement.as_ref().is_some_and(|r| r.is_active()) {
            return Err(StoreError::InvalidOptions {
                reason: "a device replacement is already in progress",
            });
        }

        // Find the device to replace.
        let idx = self
            .devices
            .iter()
            .position(|v| v.root() == old_path)
            .ok_or(StoreError::InvalidOptions {
                reason: "device to replace not found in pool",
            })?;
        let old_config = self
            .config
            .devices
            .get(idx)
            .cloned()
            .unwrap_or_else(|| DeviceConfig {
                path: old_path.to_path_buf(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                media_class: self.media_classes.get(idx).copied().unwrap_or_default(),
                class: self.classes[idx],
                kind: DeviceKind::Single {
                    path: old_path.to_path_buf(),
                },
                encryption: None,
                compression: None,
            });

        // Open the replacement device.
        let new_device = open_single_device(&new_config, options)?;

        // Swap the device in the pool list (old out, new in).
        let _old_device = std::mem::replace(&mut self.devices[idx], new_device);
        if idx < self.config.devices.len() {
            self.config.devices[idx] = new_config.clone();
        }
        // Update device GUID for the replacement.
        if idx < self.device_guids.len() {
            self.device_guids[idx] = rand::random();
        }

        // Update the media class and layout stats for the replaced device.
        if idx < self.media_classes.len() {
            self.media_classes[idx] = new_config.media_class;
        }
        if idx < self.device_layout_stats.len() {
            self.device_layout_stats[idx] =
                DeviceLayoutStats::with_segment_size(new_config.media_class.default_segment_size());
        }
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);

        // Review debt TFR-012: track the replacement for evacuate + detach.
        self.replacement = Some(DeviceReplacement::new(
            old_config,
            new_config.path.clone(),
            idx,
        ));

        // Recompute pool health: the new device starts Online, so health
        // should improve if the old device was degraded/faulted.
        self.bump_placement_epoch();
        self.health = compute_health(&self.devices);
        self.record_health_transitions();

        Ok(())
    }

    /// Current replacement status, if a replacement is in progress or was
    /// recently completed.
    pub fn replacement_status(&self) -> Option<&DeviceReplacement> {
        self.replacement.as_ref()
    }

    /// Cancel an in-progress device replacement.
    ///
    /// Restores the old device to the pool and detaches the new device.
    /// This is a best-effort operation; if the old device was already
    /// removed or is no longer accessible, the pool continues with the
    /// new device in place.
    pub fn cancel_replacement(&mut self, options: &StoreOptions) -> Result<()> {
        // Peek before taking: avoid dropping state on early returns.
        if !self.replacement.as_ref().is_some_and(|r| r.is_active()) {
            return Ok(());
        }

        let replacement = self.replacement.take().unwrap(); // safe: we checked

        // If the old device can still be opened, swap it back using the exact
        // media configuration captured before replacement.
        if let Ok(old_device) = open_single_device(&replacement.old_config, options) {
            self.devices[replacement.device_index] = old_device;
            if replacement.device_index < self.config.devices.len() {
                self.config.devices[replacement.device_index] = replacement.old_config.clone();
            }
            if replacement.device_index < self.classes.len() {
                self.classes[replacement.device_index] = replacement.old_config.class;
                self.class_map = build_class_map(&self.classes);
            }
            if replacement.device_index < self.media_classes.len() {
                self.media_classes[replacement.device_index] = replacement.old_config.media_class;
            }
            if replacement.device_index < self.device_layout_stats.len() {
                self.device_layout_stats[replacement.device_index] =
                    DeviceLayoutStats::with_segment_size(
                        replacement.old_config.media_class.default_segment_size(),
                    );
            }
            let total_bytes: Vec<u64> = self
                .devices
                .iter()
                .map(|d| d.store().capacity_bytes())
                .collect();
            self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);
        }

        self.replacement = Some(DeviceReplacement {
            state: ReplacementState::Cancelled,
            ..replacement
        });
        self.bump_placement_epoch();
        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Observability
    // ------------------------------------------------------------------

    /// Current pool health.
    pub fn health(&self) -> PoolHealth {
        self.health
    }

    /// Number of dedicated intent-log (LOG_DEVICE) devices.
    ///
    /// Counts only devices whose [`DeviceClass`] is [`DeviceClass::IntentLog`],
    /// excluding the fallback Data devices that also appear in the intent-log
    /// routing list.
    pub fn log_device_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| matches!(c, DeviceClass::IntentLog))
            .count()
    }

    /// Check whether at least one healthy intent-log device is available.
    ///
    /// Returns `true` when a dedicated log device is present and not
    /// faulted; `false` when writes will fall back to Data devices.
    pub fn log_device_healthy(&self) -> bool {
        self.classes.iter().enumerate().any(|(i, c)| {
            matches!(c, DeviceClass::IntentLog)
                && self.devices[i].status().state != DeviceState::Faulted
        })
    }

    /// Pool-level statistics.
    pub fn stats(&self) -> PoolStats {
        let per_device: Vec<DeviceStats> = self.devices.iter().map(|v| v.stats()).collect();
        let (total_comp_in, total_comp_out): (u64, u64) = self
            .devices
            .iter()
            .map(|v| (v.compression_bytes_in(), v.compression_bytes_out()))
            .fold((0, 0), |(a_in, a_out), (v_in, v_out)| {
                (a_in.saturating_add(v_in), a_out.saturating_add(v_out))
            });
        let compression_ratio = if total_comp_in == 0 {
            1.0
        } else {
            total_comp_out as f64 / total_comp_in as f64
        };
        PoolStats {
            device_count: self.devices.len(),
            total_objects: per_device.iter().map(|s| s.live_objects).sum(),
            total_bytes: per_device.iter().map(|s| s.live_bytes).sum(),
            total_read_ops: per_device.iter().map(|s| s.read_ops).sum(),
            total_write_ops: per_device.iter().map(|s| s.write_ops).sum(),
            total_delete_ops: per_device.iter().map(|s| s.delete_ops).sum(),
            per_device,
            compression_ratio,
        }
    }

    /// Pool capacity statistics for statfs integration.
    ///
    /// Computes total capacity from all data-class devices, live (used) bytes
    /// from the aggregate pool stats, and derives available bytes.
    #[must_use]
    pub fn pool_stats(&self) -> PoolCapacityStats {
        let total_capacity_bytes: u64 = self
            .class_map
            .get(IoClass::Data)
            .iter()
            .filter_map(|idx| self.devices.get(*idx))
            .map(|device| device.store().capacity_bytes())
            .sum();
        let op_stats = self.stats();
        let used_bytes = op_stats.total_bytes;
        let available_bytes = total_capacity_bytes.saturating_sub(used_bytes);
        let object_count = op_stats.total_objects as u64;
        PoolCapacityStats {
            total_capacity_bytes,
            used_bytes,
            available_bytes,
            object_count,
        }
    }

    /// Recompute pool capacity from device geometry after device resize.
    ///
    /// After an online ublk block-volume grow (see #6657), the underlying
    /// device capacities have changed but the pool's write allocator and
    /// layout stats still reflect the old sizes.  This method:
    ///
    /// 1. Rebuilds the [`WriteAllocator`] from current device capacity bytes
    /// 2. If [`PoolProperties::autoexpand`] is set, recomputes pool health
    ///    and records health transitions
    /// 3. Returns the updated [`PoolCapacityStats`]
    ///
    /// Call this after every device resize that affects pool capacity.
    pub fn expand_capacity(&mut self) -> PoolCapacityStats {
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);

        if self.properties.autoexpand {
            self.health = compute_health(&self.devices);
            self.record_health_transitions();
        }

        self.pool_stats()
    }

    /// List of device statuses.
    pub fn device_statuses(&self) -> Vec<DeviceStatus> {
        self.devices.iter().map(|v| v.status()).collect()
    }

    /// Pool name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Pool root path.
    pub fn root_path(&self) -> &Path {
        &self.config.root_path
    }

    /// Pool properties.
    pub fn properties(&self) -> &PoolProperties {
        &self.properties
    }

    /// Set the free-space low-watermark threshold in bytes.
    /// Data writes that would reduce available capacity below this
    /// threshold are refused with `StoreError::NoSpace`.
    /// Set to 0 to disable the watermark.
    pub fn set_low_watermark_bytes(&mut self, bytes: u64) {
        self.properties.low_watermark_bytes = bytes;
    }

    // ------------------------------------------------------------------
    // Maintenance: scheduling class delegation
    // ------------------------------------------------------------------

    /// Set the I/O scheduling class on all devices.
    pub fn set_scheduling_class(&mut self, class: SchedClass) {
        for device in &mut self.devices {
            device.set_scheduling_class(class);
        }
    }

    // ------------------------------------------------------------------
    // Maintenance: compaction
    // ------------------------------------------------------------------

    /// Compact all devices, retaining only the given keys.
    pub fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        let indices = self.class_map.get(IoClass::Data);
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for compaction",
            });
        }
        let mut report = None;
        for &idx in indices {
            report = Some(
                self.devices[idx].compact_retaining(protected_keys, protected_exact_locations)?,
            );
        }
        self.health = compute_health(&self.devices);
        report.ok_or(StoreError::InvalidOptions {
            reason: "no devices available for compaction",
        })
    }

    /// Whether any device should be compacted given the waste threshold.
    pub fn should_compact(&self, threshold: f64) -> bool {
        self.devices.iter().any(|v| v.should_compact(threshold))
    }

    // ------------------------------------------------------------------
    // Maintenance: segment rotation
    // ------------------------------------------------------------------

    /// Rotate segments on all devices if needed.
    ///
    /// After calling each device's rotation, increments the per-device
    /// segment rollover counter in [`DeviceLayoutStats`].
    pub fn rotate_if_needed(&mut self) -> Result<()> {
        for (i, device) in self.devices.iter_mut().enumerate() {
            device.rotate_if_needed()?;
            self.device_layout_stats[i].segment_rollovers += 1;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Maintenance: scrub
    // ------------------------------------------------------------------

    /// Run an incremental background integrity scrub on all devices.
    ///
    /// Each device's store is scrubbed independently.  The scrub is gated
    /// by the configured `background_scrub_interval_secs` on each store
    /// (no-op when 0 or interval not elapsed).  Returns a report per device.
    pub fn maybe_run_background_scrub(&mut self) -> Result<Vec<crate::ScrubReport>> {
        let mut reports = Vec::with_capacity(self.devices.len());
        for device in &mut self.devices {
            reports.push(device.maybe_run_background_scrub()?);
        }
        Ok(reports)
    }

    /// Whether any device should be scrubbed.
    pub fn should_scrub(&self) -> bool {
        self.devices.iter().any(|v| v.should_scrub())
    }

    /// Scrub all devices, repairing mismatched or missing entries.
    pub fn scrub_mirror(&mut self) -> Result<ScrubStats> {
        let mut total = ScrubStats::default();
        for device in &mut self.devices {
            let s = device.scrub_mirror()?;
            total.keys_examined += s.keys_examined;
            total.keys_healthy += s.keys_healthy;
            total.keys_resynced += s.keys_resynced;
            total.keys_repaired += s.keys_repaired;
            total.errors += s.errors;
            total.duration_secs += s.duration_secs;
        }
        Ok(total)
    }

    /// Discard (TRIM/UNMAP) allocator free ranges on devices that support it.
    ///
    /// Reads the allocator's free ranges and feeds every contiguous range to
    /// [`discard_ranges`] in batches of 64, sleeping 10 ms between batches to
    /// avoid I/O storms.
    ///
    /// When no allocator is registered, this is a no-op.
    ///
    /// Returns the total number of bytes accepted by discard-capable devices.
    /// Directory-backed devices currently report no proven discard capability,
    /// so directory-only pools return 0.
    pub fn discard_unused(&mut self) -> u64 {
        if let Some(ref allocator) = self.allocator {
            let free_ranges = allocator.free_ranges();
            self.trim_free_space(&free_ranges, 64, Duration::from_millis(10))
        } else {
            0
        }
    }

    /// Discard (TRIM/UNMAP) explicit byte ranges on all devices that
    /// support discard operations.
    ///
    /// Each `(offset, length)` pair is dispatched to every discard-capable
    /// device in the pool. The number of bytes successfully trimmed is
    /// accumulated and returned. Individual device failures are logged and
    /// skipped so that one unhealthy device does not block the entire trim
    /// pass.
    ///
    /// Returns the total number of bytes accepted by discard-capable devices.
    /// A return value of 0 can mean no discard-capable devices exist.
    pub fn discard_ranges(&mut self, ranges: &[(u64, u64)]) -> u64 {
        let mut total = 0u64;
        for (offset, length) in ranges {
            if *length == 0 {
                continue;
            }
            for device in &mut self.devices {
                if device.supports_discard() {
                    match device.discard_range(*offset, *length) {
                        Ok(()) => {
                            total = total.saturating_add(*length);
                        }
                        Err(e) => {
                            eprintln!("TRIM: device discard_range({offset}, {length}) failed: {e}");
                        }
                    }
                }
            }
        }
        total
    }

    /// Register a block allocator with the pool.
    ///
    /// Register a block allocator with the pool.
    ///
    /// Pool uses the allocator for free-block tracking and TRIM
    /// coordination. When `trim_on_delete` is enabled,
    /// [`free_blocks`] automatically issues discard after freeing;
    /// otherwise TRIM is deferred to [`trim_free_space`].
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn set_allocator(&mut self, allocator: BlockAllocator) {
        assert!(self.allocator.is_none(), "allocator already set");
        self.allocator = Some(allocator);
    }

    /// Free blocks in the allocator, triggering TRIM when enabled.
    ///
    /// Delegates to [`BlockAllocator::free`] which invokes the configured
    /// [`TrimSink`] for coalesced extents meeting the minimum discard
    /// threshold.  When `trim_on_delete` is false the allocator is created
    /// without a sink so `free` becomes a pure no-side-effect bitmap update.
    ///
    /// Returns the [`TrimStats`] accumulated from this free operation.
    #[must_use]
    /// Free blocks in the allocator, triggering TRIM when enabled.
    ///
    /// Computes coalesced TRIM ranges from the block list via the allocator,
    /// then calls [`BlockAllocator::free`] to update the free bitmap.
    /// When `trim_on_delete` is true, immediately issues TRIM for the
    /// freed ranges through [`discard_ranges`]. When false, only the
    /// bitmap is updated; TRIM is deferred to a later batch pass.
    ///
    /// Returns the total bytes actually discarded.
    pub fn free_blocks(&mut self, blocks: &[BlockId]) -> u64 {
        let ranges = if let Some(ref allocator) = self.allocator {
            if self.properties.trim_on_delete {
                allocator.trim_requests_for(blocks, allocator.min_discard_bytes())
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        // Free blocks in the bitmap (no trim sink in this path).
        if let Some(ref allocator) = self.allocator {
            allocator.free(blocks);
        }
        // Issue TRIM when enabled and we have ranges.
        if self.properties.trim_on_delete && !ranges.is_empty() {
            let range_pairs: Vec<(u64, u64)> =
                ranges.iter().map(|r| (r.offset, r.length)).collect();
            self.discard_ranges(&range_pairs)
        } else {
            0
        }
    }

    /// Walk the allocator's free extents and issue batched TRIM commands.
    ///
    /// When an allocator is registered, reads its
    /// [`BlockAllocator::free_ranges`] and issues batched TRIM via
    /// [`discard_ranges`]. Without an allocator, falls back to the
    /// supplied `free_ranges` slice.
    ///
    /// Calls `discard_ranges` in batches of `batch_size` ranges, sleeping
    /// `inter_batch_delay` between batches to avoid I/O storms. Set
    /// `batch_size` to 0 to issue all ranges in a single batch.
    ///
    /// Returns the total number of bytes trimmed across all batches.
    pub fn trim_free_space(
        &mut self,
        free_ranges: &[TrimRequest],
        batch_size: usize,
        inter_batch_delay: Duration,
    ) -> u64 {
        if free_ranges.is_empty() {
            return 0;
        }
        if batch_size == 0 || batch_size >= free_ranges.len() {
            let range_pairs: Vec<(u64, u64)> =
                free_ranges.iter().map(|r| (r.offset, r.length)).collect();
            return self.discard_ranges(&range_pairs);
        }

        let mut total = 0u64;
        for chunk in free_ranges.chunks(batch_size) {
            let range_pairs: Vec<(u64, u64)> = chunk.iter().map(|r| (r.offset, r.length)).collect();
            total = total.saturating_add(self.discard_ranges(&range_pairs));
            std::thread::sleep(inter_batch_delay);
        }
        total
    }

    // ------------------------------------------------------------------
    // Path access
    // ------------------------------------------------------------------

    /// Return the root path of the pool.
    pub fn root(&self) -> &Path {
        &self.config.root_path
    }

    /// Return the segments directory path from the primary Data device.
    pub fn segments_dir(&self) -> &Path {
        let indices = self.class_map.get(IoClass::Data);
        indices
            .first()
            .and_then(|&idx| self.devices.get(idx))
            .map(|v| v.segments_dir())
            .unwrap_or(Path::new(""))
    }

    /// Return StoreStats for the primary Data device.
    pub fn store_stats(&self) -> StoreStats {
        let indices = self.class_map.get(IoClass::Data);
        indices
            .first()
            .and_then(|&idx| self.devices.get(idx))
            .map(|v| {
                let vs = v.stats();
                StoreStats {
                    live_objects: vs.live_objects,
                    live_bytes: vs.live_bytes,
                    segment_count: vs.segment_count,
                    free_segments: 0,
                    free_bytes: 0,
                    next_sequence: vs.next_sequence,
                    tombstone_count: 0,
                    replay: Default::default(),
                    mirror_degraded: matches!(v.status().state, DeviceState::Degraded),
                    mirror_live_objects: 0,
                    mirror_live_bytes: 0,
                    replica_healthy: vec![true],
                    replica_live_objects: vec![vs.live_objects],
                    last_scrub_secs: 0,
                    committed_root_txg: 0,
                    committed_root_generation: 0,
                }
            })
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // PoolStore handles — Device-compression-aware I/O for LocalFileSystem
    // ------------------------------------------------------------------

    /// Acquire a read-only PoolStore handle for the primary Data device.
    ///
    /// All reads go through the Pool → Device → compression/encryption layers.
    pub fn primary_store(&self) -> PoolStore<'_> {
        PoolStore { pool: self }
    }

    /// Acquire a mutable PoolStore handle for the primary Data device.
    ///
    /// All reads and writes go through the Pool → Device → compression/encryption layers.
    pub fn primary_store_mut(&mut self) -> PoolStoreMut<'_> {
        PoolStoreMut { pool: self }
    }

    /// Access the primary Data device's raw LocalObjectStore, bypassing
    /// compression/encryption. Prefer `primary_store` or `primary_store_mut`
    /// for normal I/O; use this only for low-level operations like scrubbing,
    /// recovery, or format migration that need raw byte access.
    pub fn raw_primary_store(&self) -> &LocalObjectStore {
        let indices = self.class_map.get(IoClass::Data);
        indices
            .first()
            .and_then(|&idx| self.devices.get(idx))
            .map(|v| v.store())
            .expect("pool has no data device")
    }

    /// Mutable access to the primary Data device's raw LocalObjectStore.
    pub fn raw_primary_store_mut(&mut self) -> &mut LocalObjectStore {
        let indices = self.class_map.get(IoClass::Data);
        let idx = *indices.first().expect("pool has no data device");
        self.devices[idx].store_mut()
    }

    /// Update the SpaceBook's cached pool-level physical counters.
    ///
    /// Delegates to the primary data device's [`LocalObjectStore`].
    pub fn update_space_book_pool_counters(&mut self, counters: PoolCounters) {
        self.raw_primary_store_mut()
            .update_space_book_pool_counters(counters);
    }

    /// Compute statfs(2) fields for a dataset from the store-layer
    /// [`SpaceBook`], delegating to the primary data device.
    #[must_use]
    pub fn statfs_for_dataset(&mut self, dataset_id: [u8; 16]) -> Option<StatfsResult> {
        self.raw_primary_store_mut().statfs_for_dataset(dataset_id)
    }

    /// Obtain a PoolStore handle to the primary Data device.
    /// This is the preferred read handle for new code — it is Copy and
    /// derefs to `&LocalObjectStore`.
    pub fn pool_store(&self) -> PoolStore<'_> {
        PoolStore { pool: self }
    }

    /// Obtain a PoolStoreMut handle to the primary Data device.
    /// This is the preferred write handle for new code — it derefs to
    /// `&LocalObjectStore` and `&mut LocalObjectStore`.
    pub fn pool_store_mut(&mut self) -> PoolStoreMut<'_> {
        PoolStoreMut { pool: self }
    }
    // ------------------------------------------------------------------
    // LOG_DEVICE: separate intent log device
    // ------------------------------------------------------------------

    /// Returns `true` if the pool has a dedicated log device attached.
    pub fn has_log_device(&self) -> bool {
        self.log_device.is_some()
    }

    /// Append a record to the log device with `fdatasync` commit.
    ///
    /// This is the fast path for synchronous writes: only the log device
    /// device is touched; the main data-device write proceeds
    /// asynchronously.  Returns `Ok(())` even when no log device is
    /// present -- callers that require log device should check `has_log_device`
    /// first.
    pub fn log_device_append(&mut self, payload: &[u8]) -> Result<()> {
        match self.log_device.as_mut() {
            Some(w) => w.append(payload),
            None => Ok(()),
        }
    }

    /// Commit (fdatasync) the log device.
    ///
    /// In the current design every `log_device_append` already syncs, so
    /// this is a no-op.  It exists as a public barrier for future
    /// batching.
    pub fn log_device_commit(&self) -> Result<()> {
        match self.log_device.as_ref() {
            Some(w) => w.commit(),
            None => Ok(()),
        }
    }

    /// Flush and close the log device, consuming it.
    ///
    /// After close, the log_device is set to `None`.  Subsequent
    /// `log_device_append` calls become no-ops (graceful degradation).
    pub fn close_log_device(&mut self) -> Result<()> {
        match self.log_device.take() {
            Some(w) => w.close(),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// PoolStore — read-only Device-aware handle
// ---------------------------------------------------------------------------

/// Read-only handle for I/O through a Pool, routing through all Device layers
/// (compression, encryption, mirroring) transparently.
///
/// Every `get` call goes through `Pool::get` → `DeviceImpl::get`, which
/// applies decompression/decryption as configured.
#[derive(Clone, Copy)]
pub struct PoolStore<'a> {
    pool: &'a Pool,
}

impl<'a> PoolStore<'a> {
    /// Retrieve an object by key, decompressing/decrypting transparently.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        self.pool.get(IoClass::Data, key)
    }

    /// Check whether an object exists (Device-aware, via get).
    pub fn exists(&self, key: ObjectKey) -> Result<bool> {
        self.get(key).map(|v| v.is_some())
    }

    /// Access the underlying raw LocalObjectStore, bypassing Device layers.
    /// Prefer [`PoolStore::get`] for normal reads; use this only for
    /// low-level operations like scrubbing or recovery.
    pub fn raw_store(&self) -> &LocalObjectStore {
        self.pool.raw_primary_store()
    }
}

// ---------------------------------------------------------------------------
// PoolStoreMut — mutable Device-aware handle
// ---------------------------------------------------------------------------

/// Mutable handle for I/O through a Pool, routing through all Device layers.
pub struct PoolStoreMut<'a> {
    pool: &'a mut Pool,
}

impl<'a> PoolStoreMut<'a> {
    /// Produce a read-only `PoolStore` from this mutable handle.
    pub fn as_read(&self) -> PoolStore<'_> {
        PoolStore { pool: self.pool }
    }

    /// Reborrow this mutable handle, producing a new `PoolStoreMut`
    /// with a shorter borrow.  Use this in loops or anywhere the
    /// handle would otherwise be consumed by a single call.
    pub fn reborrow(&mut self) -> PoolStoreMut<'_> {
        PoolStoreMut {
            pool: &mut *self.pool,
        }
    }

    /// Retrieve an object by key.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        self.pool.get(IoClass::Data, key)
    }

    /// Store an object, compressing/encrypting transparently.
    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.pool.put(IoClass::Data, key, payload)
    }

    /// Delete an object.
    pub fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.pool.delete(IoClass::Data, key)
    }

    /// Check whether an object exists (Device-aware, via get).
    pub fn exists(&self, key: ObjectKey) -> Result<bool> {
        self.get(key).map(|v| v.is_some())
    }

    /// Sync all devices to durable storage.
    pub fn sync_all(&mut self) -> Result<()> {
        self.pool.sync_all()
    }

    /// Lightweight data-only flush across all devices.
    pub fn sync_data(&mut self) -> Result<()> {
        self.pool.sync_data()
    }

    /// Access the underlying raw LocalObjectStore, bypassing Device layers.
    pub fn raw_store_mut(&mut self) -> &mut LocalObjectStore {
        self.pool.raw_primary_store_mut()
    }

    /// Immutable access to the underlying raw LocalObjectStore.
    pub fn raw_store(&self) -> &LocalObjectStore {
        self.pool.raw_primary_store()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open_devices(configs: &[DeviceConfig], options: &StoreOptions) -> Result<Vec<Device>> {
    configs
        .iter()
        .map(|vc| {
            let mut dev_opts = options.clone();
            dev_opts.max_segment_bytes = vc.media_class.default_segment_size();
            open_single_device(vc, &dev_opts)
        })
        .collect()
}

fn open_single_device(config: &DeviceConfig, options: &StoreOptions) -> Result<Device> {
    let device = match &config.kind {
        DeviceKind::Single { path } => {
            if config.backing != DeviceBacking::DirectoryObjectStoreCompat {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "DeviceKind::Single requires directory object-store compatibility backing",
                });
            }
            Device::open_single(path, options.clone())
        }
        DeviceKind::Mirror { paths } => {
            require_directory_compat_backing(
                config.backing,
                "DeviceKind::Mirror requires directory object-store compatibility backing",
            )?;
            Device::open_mirror(paths, options)
        }
        DeviceKind::LogDevice { path } => {
            require_directory_compat_backing(
                config.backing,
                "DeviceKind::LogDevice requires directory object-store compatibility backing",
            )?;
            Device::open_log_device(path, options.clone())
        }
        DeviceKind::ParityRaid1 { paths } => {
            require_directory_compat_backing(
                config.backing,
                "DeviceKind::ParityRaid1 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid1(paths, options)
        }
        DeviceKind::ParityRaid2 { paths } => {
            require_directory_compat_backing(
                config.backing,
                "DeviceKind::ParityRaid2 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid2(paths, options)
        }
        DeviceKind::ParityRaid3 { paths } => {
            require_directory_compat_backing(
                config.backing,
                "DeviceKind::ParityRaid3 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid3(paths, options)
        }
        DeviceKind::Block { path } => {
            if !config.backing.is_byte_addressable_pool_member() {
                return Err(StoreError::InvalidOptions {
                    reason: "DeviceKind::Block requires block-device or regular-file backing",
                });
            }
            Device::open_single_block(path, options.clone())
        }
    }?;
    // Place compression outside encryption so writes compress plaintext first,
    // then encrypt the compressed frame before it reaches raw storage.
    let device = if let Some(ref enc_cfg) = config.encryption {
        Device::open_encrypted(device, enc_cfg.clone())
    } else {
        device
    };
    if let Some(ref comp_cfg) = config.compression {
        Ok(Device::open_compressed(device, comp_cfg.clone()))
    } else {
        Ok(device)
    }
}

fn require_directory_compat_backing(backing: DeviceBacking, reason: &'static str) -> Result<()> {
    if backing == DeviceBacking::DirectoryObjectStoreCompat {
        Ok(())
    } else {
        Err(StoreError::InvalidOptions { reason })
    }
}

/// Return the filesystem path that serves as the device root.
/// Filename for the log device file within an IntentLog device root.
const LOG_DEVICE_FILENAME: &str = ".tidefs_log_device";

/// Open a [`LogDeviceWriter`] on the first IntentLog-class device found in `configs`.
///
/// Returns `None` if no IntentLog device is configured -- callers fall back
/// to in-place ZIL writes through the normal data-device path.
fn open_log_device_for_devices(configs: &[DeviceConfig]) -> Result<Option<LogDeviceWriter>> {
    for vc in configs {
        if vc.class == DeviceClass::IntentLog {
            let root = device_root_path(vc);
            let log_device_path = root.join(LOG_DEVICE_FILENAME);
            let log_device = LogDeviceWriter::open(&log_device_path)?;
            return Ok(Some(log_device));
        }
    }
    Ok(None)
}

fn device_root_path(config: &DeviceConfig) -> PathBuf {
    match &config.kind {
        DeviceKind::Single { path } => path.clone(),
        DeviceKind::Mirror { paths } => paths.first().cloned().unwrap_or_default(),
        DeviceKind::LogDevice { path } => path.clone(),
        DeviceKind::ParityRaid1 { paths }
        | DeviceKind::ParityRaid2 { paths }
        | DeviceKind::ParityRaid3 { paths } => paths.first().cloned().unwrap_or_default(),
        DeviceKind::Block { path } => path.clone(),
    }
}

/// Path to the pool label file within a device root.
fn label_file_path(device_root: &Path) -> PathBuf {
    device_root.join(".tidefs_label")
}

/// Map the runtime [`crate::device::DeviceClass`] to the on-disk
/// [`tidefs_types_pool_label_core::DeviceClass`].
fn runtime_class_to_label(class: Option<DeviceClass>) -> LabelDeviceClass {
    match class {
        Some(DeviceClass::Data) | None => LabelDeviceClass::Hdd,
        Some(DeviceClass::Metadata) => LabelDeviceClass::Special,
        Some(DeviceClass::IntentLog) => LabelDeviceClass::LogDevice,
        Some(DeviceClass::ReadCache) => LabelDeviceClass::Cache,
        Some(DeviceClass::Special) => LabelDeviceClass::Special,
        Some(DeviceClass::Spare) => LabelDeviceClass::Spare,
        Some(DeviceClass::Unknown(_)) => LabelDeviceClass::Hdd,
    }
}

fn compute_health(devices: &[Device]) -> PoolHealth {
    let mut has_degraded = false;
    let mut has_faulted = false;

    for device in devices {
        match device.status().state {
            DeviceState::Online | DeviceState::Offline => {}
            DeviceState::Degraded => has_degraded = true,
            DeviceState::Faulted => has_faulted = true,
            DeviceState::Removed => {}
        }
    }

    if has_faulted {
        PoolHealth::Faulted
    } else if has_degraded {
        PoolHealth::Degraded
    } else {
        PoolHealth::Online
    }
}

/// Deterministic device selection by key hash.
///
/// Uses a simple multiply-shift hash over the 32-byte key to pick a stable
/// index from the candidate set. This ensures the same key always routes to
/// the same device for data and metadata classes.
fn pick_device(key: ObjectKey, candidates: &[usize]) -> usize {
    if candidates.len() <= 1 {
        return candidates.first().copied().unwrap_or(0);
    }
    // Multiply-shift hash
    let mut h: u64 = 0x9e37_79b9_7f4a_7c15;
    for chunk in key.as_bytes32().chunks(8) {
        let mut word = [0u8; 8];
        let len = chunk.len().min(8);
        word[..len].copy_from_slice(chunk);
        h = h.wrapping_mul(0xc6a4_a793_5bd1_e995);
        h ^= u64::from_le_bytes(word);
    }
    h = h.wrapping_mul(0xc6a4_a793_5bd1_e995);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc6a4_a793_5bd1_e995);
    candidates[(h as usize) % candidates.len()]
}

fn placement_key_pair(key: ObjectKey) -> (u64, u64) {
    let digest = blake3::hash(&key.as_bytes32());
    let bytes = digest.as_bytes();
    (
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
    )
}

fn digest32(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn placement_receipt_object_key(key: ObjectKey) -> ObjectKey {
    let mut hasher = blake3::Hasher::new_derive_key(PLACEMENT_RECEIPT_CONTEXT);
    hasher.update(b"receipt");
    hasher.update(&key.as_bytes32());
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[..8].copy_from_slice(&crate::POOL_PLACEMENT_RECEIPT_KEY_PREFIX);
    ObjectKey::from_bytes32(bytes)
}

fn placement_shard_object_key(key: ObjectKey, shard_index: u16) -> ObjectKey {
    let mut hasher = blake3::Hasher::new_derive_key(PLACEMENT_RECEIPT_CONTEXT);
    hasher.update(b"shard");
    hasher.update(&key.as_bytes32());
    hasher.update(&shard_index.to_le_bytes());
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[..8].copy_from_slice(&crate::POOL_PLACEMENT_SHARD_KEY_PREFIX);
    ObjectKey::from_bytes32(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceClass;
    use crate::ObjectKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-pool-test-{ts}-{label}"))
    }

    fn test_options() -> StoreOptions {
        StoreOptions::test_fast()
    }

    fn single_device_config(root: &Path) -> PoolConfig {
        let data_dir = root.join("data");
        PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        }
    }

    fn multi_data_device_config(root: &Path, count: usize) -> PoolConfig {
        let devices = (0..count)
            .map(|idx| {
                let path = root.join(format!("data-{idx}"));
                DeviceConfig {
                    media_class: Default::default(),
                    path: path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path },
                    encryption: None,
                    compression: None,
                }
            })
            .collect();
        PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices,
        }
    }

    fn deterministic_device_guid(idx: usize) -> [u8; 16] {
        let mut guid = [0x42; 16];
        guid[..8].copy_from_slice(&(0xA11C_E000_0000_0000u64 + idx as u64).to_le_bytes());
        guid[8..].copy_from_slice(&(0x51A7_0000_0000_0000u64 + idx as u64).to_le_bytes());
        guid
    }

    fn set_deterministic_device_guids(pool: &mut Pool) {
        for idx in 0..pool.device_guids.len() {
            pool.device_guids[idx] = deterministic_device_guid(idx);
        }
    }

    #[test]
    fn block_device_kind_requires_byte_addressable_backing() {
        let root = temp_dir("block-backing-mismatch");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("pool.img");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(2 * 1024 * 1024).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Block { path },
            encryption: None,
            compression: None,
        };

        let err = open_single_device(&config, &test_options()).unwrap_err();
        assert!(matches!(err, StoreError::InvalidOptions { reason } if reason.contains("Block")));

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Pool lifecycle
    // ------------------------------------------------------------------

    #[test]
    fn create_and_open_pool() {
        let root = temp_dir("create-open");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();

        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        assert_eq!(pool.name(), "testpool");
        assert_eq!(pool.health(), PoolHealth::Online);

        let stats = pool.stats();
        assert_eq!(stats.device_count, 1);

        // Re-open
        drop(pool);
        let pool2 = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(pool2.health(), PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // I/O routing
    // ------------------------------------------------------------------

    #[test]
    fn put_get_delete_data_class() {
        let root = temp_dir("put-get-data");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"data-object");
        let stored = pool.put(IoClass::Data, key, b"payload").unwrap();
        assert_eq!(stored.key, key);

        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(b"payload".to_vec()));

        assert!(pool.delete(IoClass::Data, key).unwrap());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_falls_back_to_data() {
        let root = temp_dir("metadata-fallback");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // Metadata should fall back to the Data device
        let key = ObjectKey::from_name(b"inode-42");
        pool.put(IoClass::Metadata, key, b"inode-data").unwrap();
        let val = pool.get(IoClass::Metadata, key).unwrap();
        assert_eq!(val, Some(b"inode-data".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn intent_log_write_all_to_data_fallback() {
        let root = temp_dir("ilog-fallback");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // IntentLog falls back to Data device (write-all to one device)
        let key = ObjectKey::from_name(b"ilog-entry");
        pool.put(IoClass::IntentLog, key, b"intent").unwrap();
        let val = pool.get(IoClass::IntentLog, key).unwrap();
        assert_eq!(val, Some(b"intent".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_cache_falls_back_to_data() {
        let root = temp_dir("cache-fallback");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // ReadCache falls back to Data device
        let key = ObjectKey::from_name(b"cached");
        pool.put(IoClass::ReadCache, key, b"cached-data").unwrap();
        let val = pool.get(IoClass::ReadCache, key).unwrap();
        assert_eq!(val, Some(b"cached-data".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_pool_wide_receipts_use_all_eligible_devices() {
        let root = temp_dir("pool-wide-replicated");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 5);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let mut seen = BTreeSet::new();
        for i in 0..128 {
            let name = format!("pool-wide-object-{i}");
            let key = ObjectKey::from_name(name.as_bytes());
            let payload = format!("payload-{i}");
            pool.put(IoClass::Data, key, payload.as_bytes()).unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("placement receipt must persist");
            assert_eq!(receipt.policy, PoolRedundancyPolicy::replicated(2));
            assert_eq!(receipt.targets.len(), 2);
            for target in receipt.targets {
                seen.insert(target.device_index);
            }
            assert_eq!(
                pool.get(IoClass::Data, key).unwrap(),
                Some(payload.into_bytes())
            );
        }

        assert_eq!(
            seen.len(),
            5,
            "pool-wide placement should eventually use every eligible data device"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placement_epoch_add_device_leaves_old_receipt_readable_and_new_allocations_expand() {
        let root = temp_dir("epoch-add-device");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let old_key = ObjectKey::from_name(b"old-before-add");
        pool.put(IoClass::Data, old_key, b"old-payload").unwrap();
        let old_receipt = pool
            .placement_receipt_for_key(IoClass::Data, old_key)
            .unwrap()
            .expect("old receipt");
        assert_eq!(old_receipt.epoch, 1);

        let new_path = root.join("data-3");
        let new_config = DeviceConfig {
            media_class: Default::default(),
            path: new_path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: new_path },
            encryption: None,
            compression: None,
        };
        pool.add_device(new_config, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);
        assert_eq!(pool.placement_epoch(), 2);

        assert_eq!(
            pool.get(IoClass::Data, old_key).unwrap(),
            Some(b"old-payload".to_vec()),
            "old receipt must remain readable after topology epoch changes"
        );

        let mut new_device_seen = false;
        for i in 0..256 {
            let key = ObjectKey::from_name(format!("after-add-{i}").as_bytes());
            pool.put(IoClass::Data, key, b"new-payload").unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("new receipt");
            assert_eq!(receipt.epoch, 2);
            new_device_seen |= receipt
                .targets
                .iter()
                .any(|target| target.device_index == 3);
            if new_device_seen {
                break;
            }
        }
        assert!(
            new_device_seen,
            "new placement epoch should allow allocations to use the added device"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_policy_receipt_width_and_reconstructs_missing_shard() {
        let root = temp_dir("erasure-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-object");
        let payload = b"payload large enough to span both data shards";
        pool.put(IoClass::Data, key, payload).unwrap();

        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("erasure receipt must persist");
        assert_eq!(receipt.policy, PoolRedundancyPolicy::erasure(2, 1));
        assert_eq!(receipt.targets.len(), 3);
        let receipt_key = placement_receipt_object_key(key);
        assert!(
            pool.devices.iter().any(|device| device
                .store()
                .list_keys_including_internal()
                .contains(&receipt_key)),
            "receipt key should be visible to internal scans"
        );
        for device in &pool.devices {
            assert!(
                !device.store().list_keys().contains(&receipt_key),
                "receipt key must stay hidden from public object scans"
            );
        }
        assert_eq!(
            receipt
                .targets
                .iter()
                .filter(|target| target.role == PlacementTargetRole::Data)
                .count(),
            2
        );
        assert_eq!(
            receipt
                .targets
                .iter()
                .filter(|target| target.role == PlacementTargetRole::Parity)
                .count(),
            1
        );
        for target in &receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            let shard_key = placement_shard_object_key(key, target.shard_index);
            assert!(
                pool.devices[idx]
                    .store()
                    .list_keys_including_internal()
                    .contains(&shard_key),
                "shard key should be visible to internal scans"
            );
            assert!(
                !pool.devices[idx].store().list_keys().contains(&shard_key),
                "shard key must stay hidden from public object scans"
            );
        }
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let victim = receipt.targets[0].clone();
        let victim_idx = pool.resolve_receipt_target(&victim).unwrap();
        let victim_key = placement_shard_object_key(key, victim.shard_index);
        assert!(pool.devices[victim_idx].delete(victim_key).unwrap());

        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "receipt-backed erasure read should reconstruct from surviving shards"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_rewrites_receipt_backed_erasure_object_to_survivors() {
        let root = temp_dir("safe-remove-erasure-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-before-remove");
        let payload = b"receipt-backed erasure payload before device removal";
        pool.put(IoClass::Data, key, payload).unwrap();
        let before = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&before.targets[0]).unwrap();
        let victim_guid = pool.device_guid_for_index(victim_idx);
        let victim_path = pool.devices[victim_idx].root().to_path_buf();

        let removal = pool.safe_remove_device(&victim_path).unwrap();
        assert!(removal.complete);
        assert_eq!(removal.objects_failed, 0);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let after = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt after removal");
        assert_eq!(after.targets.len(), 3);
        assert!(
            after
                .targets
                .iter()
                .all(|target| target.device_guid != victim_guid),
            "rewritten receipt must not target the removed device"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn multi_device_delete_removes_all_class_copies() {
        let root = temp_dir("delete-all-copies");
        let _ = std::fs::remove_dir_all(&root);
        let d0 = root.join("data0");
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "multi".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: d0.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d0 },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d1.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d1 },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d2.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d2 },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"stale-delete-object");
        for device in &mut pool.devices {
            device.put(key, b"copy").unwrap();
        }

        assert!(pool.delete(IoClass::Data, key).unwrap());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        for device in &pool.devices {
            assert_eq!(device.get(key).unwrap(), None);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Device add/remove
    // ------------------------------------------------------------------

    #[test]
    fn add_device() {
        let root = temp_dir("add-device");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 1);

        let new_path = root.join("data2");
        pool.add_device(
            DeviceConfig {
                media_class: Default::default(),
                path: new_path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: new_path },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();

        assert_eq!(pool.stats().device_count, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_device() {
        let root = temp_dir("remove-device");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single {
                    path: data_dir.clone(),
                },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 1);

        pool.remove_device(&data_dir).unwrap();
        assert_eq!(pool.stats().device_count, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_evacuates_objects() {
        let root = temp_dir("safe-remove");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: d1.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d1.clone() },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d2.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d2.clone() },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 2);

        // Write some objects via the pool — they route deterministically to one device.
        let key1 = ObjectKey::from_name("obj-1");
        let key2 = ObjectKey::from_name("obj-2");
        let key3 = ObjectKey::from_name("obj-3");
        let data1 = b"safe-remove-test-data-object-1".to_vec();
        let data2 = b"safe-remove-test-data-object-2".to_vec();
        let data3 = b"safe-remove-test-data-object-3".to_vec();
        pool.put(IoClass::Data, key1, &data1).unwrap();
        pool.put(IoClass::Data, key2, &data2).unwrap();
        pool.put(IoClass::Data, key3, &data3).unwrap();
        pool.sync_all().unwrap();

        // All objects should be readable now.
        assert!(pool.get(IoClass::Data, key1).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key2).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key3).unwrap().is_some());

        // Remove device 1. Objects on it are evacuated to device 2.
        let result = pool.safe_remove_device(&d1).unwrap();
        assert!(result.complete);
        assert_eq!(result.objects_failed, 0);

        // Pool now has 1 device.
        assert_eq!(pool.stats().device_count, 1);

        // All objects should still be readable.
        assert!(pool.get(IoClass::Data, key1).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key2).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key3).unwrap().is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_last_device() {
        let root = temp_dir("safe-remove-last");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 1);

        let result = pool.safe_remove_device(&d1);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_three_device_pool_100_objects() {
        let root = temp_dir("safe-remove-3dev");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let d3 = root.join("data3");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: d1.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d1.clone() },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d2.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d2.clone() },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d3.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d3.clone() },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 3);

        // Write 100 objects. Routing by key hash may send some to each device.
        let mut keys: Vec<ObjectKey> = Vec::new();
        let mut original_data: Vec<(ObjectKey, Vec<u8>, [u8; 32])> = Vec::new();
        for i in 0u64..100 {
            let key = ObjectKey::from_name(format!("obj-{i:04x}"));
            let data = format!("three-device-evacuation-test-object-{i:04x}-payload").into_bytes();
            let digest: [u8; 32] = blake3::hash(&data).into();
            pool.put(IoClass::Data, key, &data).unwrap();
            keys.push(key);
            original_data.push((key, data, digest));
        }
        pool.sync_all().unwrap();

        // Verify all 100 objects are readable before removal.
        for (key, expected_data, _expected_digest) in &original_data {
            let val = pool.get(IoClass::Data, *key).unwrap();
            assert!(val.is_some(), "object {{key:?}} not found before removal");
            assert_eq!(val.unwrap(), *expected_data);
        }

        // Remove device 1. Objects on it are evacuated.
        let result = pool.safe_remove_device(&d1).unwrap();
        assert!(result.complete);
        assert_eq!(result.objects_failed, 0);

        // Pool now has 2 devices.
        assert_eq!(pool.stats().device_count, 2);

        // Verify all 100 objects are still readable with correct BLAKE3 digests.
        let mut verified = 0u64;
        for (key, expected_data, expected_digest) in &original_data {
            let val = pool.get(IoClass::Data, *key).unwrap();
            assert!(
                val.is_some(),
                "object {{key:?}} not found after device removal"
            );
            let actual_data = val.unwrap();
            assert_eq!(actual_data, *expected_data, "data mismatch for {{key:?}}");
            let actual_digest: [u8; 32] = blake3::hash(&actual_data).into();
            assert_eq!(
                actual_digest, *expected_digest,
                "BLAKE3 digest mismatch for {{key:?}}"
            );
            verified += 1;
        }
        assert_eq!(verified, 100);

        // Confirm the pool health is still Online after device removal.
        assert_eq!(pool.health(), PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_after_interrupt() {
        // Simulate a crash during device removal.
        // 1. Create a 2-device pool with objects.
        // 2. Manually write the removal-pending marker (as if crash in safe_remove_device).
        // 3. Re-open the pool -- the resume should evacuate objects and remove the device.

        let root = temp_dir("safe-remove-resume");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: d1.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d1.clone() },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: d2.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: d2.clone() },
                    encryption: None,
                    compression: None,
                },
            ],
        };

        // Create the pool and write some objects.
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 2);

        let key1 = ObjectKey::from_name(b"resume-obj-1");
        let key2 = ObjectKey::from_name(b"resume-obj-2");
        let key3 = ObjectKey::from_name(b"resume-obj-3");
        let data1 = b"resume-test-data-object-1".to_vec();
        let data2 = b"resume-test-data-object-2".to_vec();
        let data3 = b"resume-test-data-object-3".to_vec();
        pool.put(IoClass::Data, key1, &data1).unwrap();
        pool.put(IoClass::Data, key2, &data2).unwrap();
        pool.put(IoClass::Data, key3, &data3).unwrap();
        pool.sync_all().unwrap();

        assert!(pool.get(IoClass::Data, key1).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key2).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key3).unwrap().is_some());

        // Simulate crash: write the marker file manually.
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        std::fs::write(&marker_path, d1.to_string_lossy().as_bytes()).unwrap();
        assert!(marker_path.exists());

        // Drop the pool (simulating crash / process exit).
        drop(pool);

        // Re-open. The resume logic in Pool::open should detect the marker,
        // evacuate objects from d1 to d2, and remove d1.
        let pool2 = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();

        // Marker file should be removed after resume.
        assert!(!marker_path.exists());

        // Pool should now have 1 device (d1 was removed).
        assert_eq!(pool2.stats().device_count, 1);

        // All objects must still be readable.
        let obj1 = pool2.get(IoClass::Data, key1).unwrap();
        assert!(obj1.is_some(), "key1 not found after resume");
        assert_eq!(obj1.unwrap(), data1);

        let obj2 = pool2.get(IoClass::Data, key2).unwrap();
        assert!(obj2.is_some(), "key2 not found after resume");
        assert_eq!(obj2.unwrap(), data2);

        let obj3 = pool2.get(IoClass::Data, key3).unwrap();
        assert!(obj3.is_some(), "key3 not found after resume");
        assert_eq!(obj3.unwrap(), data3);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Device replacement
    // ------------------------------------------------------------------

    #[test]
    fn replace_device_swaps_and_tracks_state() {
        let root = temp_dir("replace-swap");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.stats().device_count, 1);
        assert!(pool.replacement_status().is_none());

        // Replace the single device.
        pool.replace_device(
            &d1,
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d2.clone() },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();

        assert_eq!(pool.stats().device_count, 1);
        let r = pool.replacement_status().unwrap();
        assert_eq!(r.old_path, d1);
        assert_eq!(r.new_path, d2);
        assert!(r.is_active());
        // New device should be operative — write and read through it.
        let key = ObjectKey::from_name(b"after-replace");
        pool.put(IoClass::Data, key, b"payload").unwrap();
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(b"payload".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_device_refuses_concurrent_replacement() {
        let root = temp_dir("replace-concurrent");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let d3 = root.join("data3");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // First replacement succeeds.
        pool.replace_device(
            &d1,
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d2.clone() },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();

        // Second replacement on the new device path must fail.
        let result = pool.replace_device(
            &d2,
            DeviceConfig {
                media_class: Default::default(),
                path: d3.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d3.clone() },
                encryption: None,
                compression: None,
            },
            &test_options(),
        );
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_device_errors_on_unknown_path() {
        let root = temp_dir("replace-unknown");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let result = pool.replace_device(
            &root.join("nonexistent"),
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d2 },
                encryption: None,
                compression: None,
            },
            &test_options(),
        );
        assert!(result.is_err());
        // Pool state unchanged.
        assert_eq!(pool.stats().device_count, 1);
        assert!(pool.replacement_status().is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_replacement_swaps_old_device_back() {
        let root = temp_dir("replace-cancel");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // Write data through old device before replace.
        let key = ObjectKey::from_name(b"pre-replace");
        pool.put(IoClass::Data, key, b"before").unwrap();

        pool.replace_device(
            &d1,
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d2.clone() },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();
        assert!(pool.replacement_status().unwrap().is_active());

        // Cancel the replacement.
        pool.cancel_replacement(&test_options()).unwrap();
        let r = pool.replacement_status().unwrap();
        assert!(!r.is_active());
        assert!(matches!(r.state, ReplacementState::Cancelled));

        // Old device should be back and data still accessible.
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(b"before".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_replacement_restores_regular_file_dev_backing() {
        let root = temp_dir("replace-cancel-file-dev");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let d1 = root.join("pool0.img");
        let d2 = root.join("pool1.img");
        for path in [&d1, &d2] {
            let file = std::fs::File::create(path).unwrap();
            file.set_len(2 * 1024 * 1024).unwrap();
        }
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.join("metadata"),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::RegularFileDev,
                class: DeviceClass::Data,
                kind: DeviceKind::Block { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"pre-file-dev-replace");
        pool.put(IoClass::Data, key, b"before").unwrap();

        pool.replace_device(
            &d1,
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::RegularFileDev,
                class: DeviceClass::Data,
                kind: DeviceKind::Block { path: d2 },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();
        assert_eq!(
            pool.replacement_status().unwrap().old_config.backing,
            DeviceBacking::RegularFileDev
        );

        pool.cancel_replacement(&test_options()).unwrap();
        assert_eq!(
            pool.config.devices[0].backing,
            DeviceBacking::RegularFileDev
        );
        assert!(matches!(
            pool.config.devices[0].kind,
            DeviceKind::Block { .. }
        ));
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(b"before".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_replacement_is_idempotent() {
        let root = temp_dir("replace-cancel2");
        let _ = std::fs::remove_dir_all(&root);
        let d1 = root.join("data1");
        let d2 = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: d1.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d1.clone() },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // No active replacement — cancel should be a no-op.
        assert!(pool.cancel_replacement(&test_options()).is_ok());
        assert!(pool.replacement_status().is_none());

        pool.replace_device(
            &d1,
            DeviceConfig {
                media_class: Default::default(),
                path: d2.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: d2.clone() },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();

        // Cancel twice.
        pool.cancel_replacement(&test_options()).unwrap();
        pool.cancel_replacement(&test_options()).unwrap(); // second call is a no-op
        assert!(!pool.replacement_status().unwrap().is_active());

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Health
    // ------------------------------------------------------------------

    #[test]
    fn health_online() {
        let root = temp_dir("health-online");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.health(), PoolHealth::Online);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Pool export / import (label persistence)
    // ------------------------------------------------------------------

    #[test]
    fn export_writes_labels_to_device_roots() {
        let root = temp_dir("export-labels");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();

        pool.export().unwrap();

        // Check that the label file exists in the device root.
        let data_dir = root.join("data");
        let label_path = data_dir.join(".tidefs_label");
        assert!(label_path.exists(), "label file must exist after export");

        let buf = fs::read(&label_path).unwrap();
        let label = pool_label::decode_label(&buf).unwrap();
        assert_eq!(label.pool_name_str(), "testpool");
        assert_eq!(label.pool_state, PoolState::Exported);
        assert_eq!(label.device_index, 0);
        assert_eq!(label.device_count, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_imports_exported_pool() {
        let root = temp_dir("import-exported");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();

        // Create, export, then drop.
        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let orig_guid = pool.pool_guid;
        pool.export().unwrap();
        drop(pool);

        // Re-open — labels should be found and validated.
        let pool2 = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(pool2.health(), PoolHealth::Online);
        assert_eq!(
            pool2.pool_guid, orig_guid,
            "pool GUID must survive export/import"
        );
        assert_eq!(pool2.name(), "testpool");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_without_labels_creates_fresh_pool() {
        let root = temp_dir("no-labels-create");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();

        // No prior export — open should create a fresh pool (legacy path).
        let pool = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(pool.health(), PoolHealth::Online);
        // pool_guid must be non-zero (random generation worked).
        assert_ne!(pool.pool_guid, [0u8; 16]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn each_create_gets_unique_guid() {
        let root = temp_dir("unique-guids");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();
        let pool1 = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let pool2 = Pool::create(config, PoolProperties::default(), &options).unwrap();
        assert_ne!(pool1.pool_guid, pool2.pool_guid);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // PoolStore type-level checks
    // ------------------------------------------------------------------

    #[test]
    fn poolstore_type_checks() {
        fn _takes_poolstore(_s: PoolStore<'_>) {}
        fn _takes_poolstoremut(_s: PoolStoreMut<'_>) {}
    }

    #[test]
    fn poolstore_reborrow_and_as_read() {
        let root = temp_dir("ps-reborrow");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let ps = pool.pool_store();
        assert!(ps.raw_store().list_keys().is_empty());

        let mut psm = pool.pool_store_mut();
        let read_handle = psm.as_read();
        assert!(read_handle.raw_store().list_keys().is_empty());
        let _psm2 = psm.reborrow();

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Pool capacity stats for statfs integration
    // ------------------------------------------------------------------

    #[test]
    fn pool_stats_reports_capacity_greater_than_used() {
        let root = temp_dir("capacity-gt-used");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // Write some data so used > 0
        let key = ObjectKey::from_name(b"payload");
        pool.put(IoClass::Data, key, b"hello").unwrap();

        let cap = pool.pool_stats();
        assert!(cap.total_capacity_bytes > 0, "capacity must be positive");
        assert!(cap.used_bytes > 0, "used must be positive after put");
        assert!(cap.available_bytes > 0, "available must be positive");
        assert!(
            cap.available_bytes < cap.total_capacity_bytes,
            "available {} < total {}",
            cap.available_bytes,
            cap.total_capacity_bytes
        );
        assert_eq!(cap.object_count, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_stats_empty_pool_reports_full_capacity_available() {
        let root = temp_dir("empty-capacity");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let cap = pool.pool_stats();
        assert!(cap.total_capacity_bytes > 0);
        assert_eq!(cap.used_bytes, 0);
        assert_eq!(cap.available_bytes, cap.total_capacity_bytes);
        assert_eq!(cap.object_count, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_stats_after_delete_reclaims_available_bytes() {
        let root = temp_dir("delete-reclaim");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"temp");
        pool.put(IoClass::Data, key, b"temp-data").unwrap();
        let cap_before_delete = pool.pool_stats();
        assert!(cap_before_delete.used_bytes > 0);

        pool.delete(IoClass::Data, key).unwrap();
        let cap_after_delete = pool.pool_stats();
        // After delete, used_bytes may not go to zero (tombstone semantics),
        // but available must not decrease.
        assert!(cap_after_delete.available_bytes >= cap_before_delete.available_bytes);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_stats_is_consistent_with_operational_stats() {
        let root = temp_dir("consistent-stats");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        pool.put(IoClass::Data, ObjectKey::from_name(b"a"), b"aaa")
            .unwrap();
        pool.put(IoClass::Data, ObjectKey::from_name(b"b"), b"bbb")
            .unwrap();

        let op = pool.stats();
        let cap = pool.pool_stats();

        assert_eq!(cap.used_bytes, op.total_bytes);
        assert_eq!(cap.object_count, op.total_objects as u64);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn log_device_dedicated_device_receives_writes() {
        let root = temp_dir("log_device-dedicated");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let log_dir = root.join("log");

        let config = PoolConfig {
            name: "testpool-log_device".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: log_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::IntentLog,
                    kind: DeviceKind::Single { path: log_dir },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: data_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data_dir },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // Dedicated log device should be recognized
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.log_device_healthy());

        // IntentLog writes should succeed (routed to log device)
        let key = ObjectKey::from_name(b"commit_group-commit-1");
        pool.put(IoClass::IntentLog, key, b"intent-record").unwrap();
        let val = pool.get(IoClass::IntentLog, key).unwrap();
        assert_eq!(val, Some(b"intent-record".to_vec()));

        // Pool should remain healthy
        assert_eq!(pool.health(), PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn log_device_fallback_when_no_log_device() {
        let root = temp_dir("log_device-fallback");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");

        let config = PoolConfig {
            name: "testpool-fallback".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        // No dedicated log device
        assert_eq!(pool.log_device_count(), 0);
        assert!(!pool.log_device_healthy());

        // IntentLog writes fall back to Data device
        let key = ObjectKey::from_name(b"ilog-fallback");
        pool.put(IoClass::IntentLog, key, b"intent").unwrap();
        let val = pool.get(IoClass::IntentLog, key).unwrap();
        assert_eq!(val, Some(b"intent".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn log_device_online_remove_add_lifecycle() {
        let root = temp_dir("log_device-lifecycle");
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let log_dir = root.join("log");

        let config = PoolConfig {
            name: "testpool-lifecycle".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: log_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::IntentLog,
                    kind: DeviceKind::Single {
                        path: log_dir.clone(),
                    },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: data_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data_dir },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.log_device_healthy());

        // Write via log device
        let key = ObjectKey::from_name(b"lifecycle-test");
        pool.put(IoClass::IntentLog, key, b"before-remove").unwrap();

        // Remove the log device
        pool.remove_device(&log_dir).unwrap();
        assert_eq!(pool.log_device_count(), 0);
        assert!(!pool.log_device_healthy());

        // Writes should still succeed via data fallback
        pool.put(IoClass::IntentLog, key, b"after-remove").unwrap();
        let val = pool.get(IoClass::IntentLog, key).unwrap();
        assert_eq!(val, Some(b"after-remove".to_vec()));

        // Re-add a log device
        let log2_dir = root.join("log2");
        let log2_config = DeviceConfig {
            media_class: Default::default(),
            path: log2_dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::IntentLog,
            kind: DeviceKind::Single { path: log2_dir },
            encryption: None,
            compression: None,
        };
        pool.add_device(log2_config, &test_options()).unwrap();
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.log_device_healthy());

        // Writes with LOG_DEVICE active again
        pool.put(IoClass::IntentLog, key, b"after-re-add").unwrap();
        let val = pool.get(IoClass::IntentLog, key).unwrap();
        assert_eq!(val, Some(b"after-re-add".to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // PARITY_RAID1 pool integration
    // ------------------------------------------------------------------

    fn parity_raid1_device_config(root: &Path, n_data: u8) -> PoolConfig {
        let total = n_data as usize + 1;
        let paths: Vec<_> = (0..total)
            .map(|i| root.join(format!("device-{i}")))
            .collect();
        let first = paths[0].clone();
        PoolConfig {
            name: "parity_raid1-test-pool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: first,
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::ParityRaid1 { paths },
                encryption: None,
                compression: None,
            }],
        }
    }

    #[test]
    fn pool_parity_raid1_put_get_no_faults() {
        let root = temp_dir("parity_raid1-pool-putget");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2); // 2 data + 1 parity = 3 children
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool.health(), PoolHealth::Online);

        let key = ObjectKey::from_name(b"pool-parity_raid-data");
        let payload = b"Pool-level PARITY_RAID1 write with 2+1 layout";
        pool.put(IoClass::Data, key, payload).unwrap();

        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_reconstruct_after_child_fault() {
        let root = temp_dir("parity_raid1-pool-recon");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"recon-payload");
        let payload = b"PARITY_RAID1 pool reconstruction -- single child fault";
        pool.put(IoClass::Data, key, payload).unwrap();

        // Simulate fault: delete segments dir of data child 1 (index 1)
        let child1_path = root.join("device-1");
        let seg = child1_path.join("segments");
        let _ = std::fs::remove_dir_all(&seg);

        // Read should still succeed via reconstruction.
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_reconstruct_parity_fault() {
        let root = temp_dir("parity_raid1-pool-parity");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"parity-fault-data");
        let payload = b"PARITY_RAID1 parity column fault test";
        pool.put(IoClass::Data, key, payload).unwrap();

        // Simulate fault in parity child (index 2, the last one).
        let parity_path = root.join("device-2");
        let seg = parity_path.join("segments");
        let _ = std::fs::remove_dir_all(&seg);

        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(payload.to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_double_fault_returns_error() {
        let root = temp_dir("parity_raid1-pool-double");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"double-fault");
        pool.put(IoClass::Data, key, b"doomed-data").unwrap();

        // Delete device root directories for children 1 and 2.
        // Losing 2 out of 3 columns is unrecoverable in PARITY_RAID1.
        let _ = std::fs::remove_dir_all(root.join("device-1"));
        let _ = std::fs::remove_dir_all(root.join("device-2"));

        // Pool::get swallows device errors (by design: mirrors fail over
        // between legs).  With a single PARITY_RAID1 device and two faulted
        // children, data is unrecoverable so get returns None.
        let val = pool.get(IoClass::Data, key).unwrap();
        assert!(
            val.is_none(),
            "unrecoverable double fault: data must be None"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_four_data_columns() {
        let root = temp_dir("parity_raid1-pool-4data");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 4); // 4 data + 1 parity = 5 children
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"four-col-pool");
        let payload = vec![0x5Au8; 2048];
        pool.put(IoClass::Data, key, &payload).unwrap();

        // Corrupt column 2.
        let _ = std::fs::remove_dir_all(root.join("device-2").join("segments"));
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, Some(payload));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_stats_and_status() {
        let root = temp_dir("parity_raid1-pool-stats");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        pool.put(IoClass::Data, ObjectKey::from_name(b"a"), b"aaa")
            .unwrap();
        pool.put(IoClass::Data, ObjectKey::from_name(b"b"), b"bbb")
            .unwrap();

        let stats = pool.stats();
        assert_eq!(stats.device_count, 1, "one PARITY_RAID1 device");
        assert!(stats.total_write_ops > 0, "writes should be recorded");

        let cap = pool.pool_stats();
        assert!(cap.total_capacity_bytes > 0);
        assert!(cap.used_bytes > 0);

        assert_eq!(pool.health(), PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_delete_then_get_returns_none() {
        let root = temp_dir("parity_raid1-pool-del");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"pool-delete-me");
        pool.put(IoClass::Data, key, b"temp-data").unwrap();
        pool.delete(IoClass::Data, key).unwrap();
        let val = pool.get(IoClass::Data, key).unwrap();
        assert_eq!(val, None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_parity_raid1_multi_key_reconstruction() {
        // Write multiple keys, fault a child, verify all keys survive.
        let root = temp_dir("parity_raid1-pool-multi");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let keys: Vec<_> = (0..5)
            .map(|i| {
                (
                    ObjectKey::from_name(format!("k{i}").as_bytes()),
                    format!("payload-{i}").into_bytes(),
                )
            })
            .collect();

        for (k, data) in &keys {
            pool.put(IoClass::Data, *k, data).unwrap();
        }

        // Fault child 1.
        let _ = std::fs::remove_dir_all(root.join("device-1").join("segments"));

        for (k, data) in &keys {
            let val = pool.get(IoClass::Data, *k).unwrap();
            assert_eq!(
                val.as_ref(),
                Some(data),
                "key {k:?} should survive reconstruction"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Health transition end-to-end: device error → drain → pool log
    // ------------------------------------------------------------------

    #[test]
    fn fresh_pool_has_zero_health_transitions() {
        let root = temp_dir("ht-zero");
        let pool = Pool::create(
            PoolConfig {
                name: "ht-zero".into(),
                root_path: root.clone(),
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: root.join("device0"),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single {
                        path: root.join("device0"),
                    },
                    compression: None,
                    encryption: None,
                }],
            },
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();

        assert_eq!(pool.health_transition_count(), 0);
        assert!(pool.health_transitions().is_empty());
        assert_eq!(pool.health, PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn health_transition_count_after_successful_io_is_stable() {
        let root = temp_dir("ht-stable");
        let mut pool = Pool::create(
            PoolConfig {
                name: "ht-stable".into(),
                root_path: root.clone(),
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: root.join("device0"),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single {
                        path: root.join("device0"),
                    },
                    compression: None,
                    encryption: None,
                }],
            },
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();

        // Successful I/O on healthy devices should produce no transitions
        let key = ObjectKey::from_name(b"stable-key");
        pool.put(IoClass::Data, key, b"payload").unwrap();
        assert_eq!(
            pool.health_transition_count(),
            0,
            "no transitions expected on healthy I/O"
        );
        assert_eq!(pool.health, PoolHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn health_transitions_are_valid_after_record_call() {
        let root = temp_dir("ht-record");
        let mut pool = Pool::create(
            PoolConfig {
                name: "ht-record".into(),
                root_path: root.clone(),
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: root.join("device0"),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single {
                        path: root.join("device0"),
                    },
                    compression: None,
                    encryption: None,
                }],
            },
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();

        // Explicit record_health_transitions on a healthy pool is safe
        pool.record_health_transitions();
        assert_eq!(pool.health_transition_count(), 0);

        // recompute_health on healthy devices
        let h = pool.recompute_health_from_devices();
        assert_eq!(h, PoolHealth::Online);

        // device_health_states should return one entry per device
        let states = pool.device_health_states();
        assert_eq!(states.len(), 1, "one device -> one health state");
        assert_eq!(states[0].1.health, DeviceHealth::Online);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn health_transition_count_and_log_plumbing_is_wired() {
        // Verify that the public API surface for health transitions
        // compiles and returns the expected types.
        let root = temp_dir("ht-plumbing");
        let pool = Pool::create(
            PoolConfig {
                name: "ht-plumbing".into(),
                root_path: root.clone(),
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: root.join("device0"),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single {
                        path: root.join("device0"),
                    },
                    compression: None,
                    encryption: None,
                }],
            },
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();

        // health_transitions() returns a slice
        let transitions: &[DeviceHealthTransition] = pool.health_transitions();
        assert!(transitions.is_empty());

        // health_transition_count() returns a usize
        let count: usize = pool.health_transition_count();
        assert_eq!(count, 0);

        // health_transitions are iterable
        for _t in pool.health_transitions() {
            // Each DeviceHealthTransition has to, from, reason, device_guid, pool_uuid
        }

        // device_health_states returns per-device snapshots
        let snapshots = pool.device_health_states();
        assert_eq!(snapshots.len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ─── TRIM / discard_unused tests ───

    #[test]
    fn discard_unused_returns_zero_when_no_allocator() {
        let root = temp_dir("discard-no-alloc");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();
        // No allocator set → discard_unused is a no-op.
        let trimmed = pool.discard_unused();
        assert_eq!(trimmed, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn free_blocks_with_trim_on_delete_reports_zero_for_directory_device() {
        let root = temp_dir("free-trim");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let props = PoolProperties {
            trim_on_delete: true,
            ..Default::default()
        };
        let options = test_options();
        let mut pool = Pool::create(config, props, &options).unwrap();

        // Register an allocator
        let ba = tidefs_block_allocator::BlockAllocator::new(
            64,
            4096,
            tidefs_block_allocator::Region::new(0, 64),
        );
        // Allocate some blocks to free later
        let blocks = ba.alloc_contiguous(10).unwrap();
        pool.set_allocator(ba);

        let trimmed = pool.free_blocks(&blocks);
        assert_eq!(trimmed, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn discard_ranges_returns_zero_for_directory_device() {
        let root = temp_dir("discard-ranges-dir");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();

        assert_eq!(pool.discard_ranges(&[(0, 4096), (4096, 0)]), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn trim_free_space_with_batching_reports_zero_for_directory_device() {
        use tidefs_block_allocator::TrimRequest;
        let root = temp_dir("trim-batch");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();

        // 10 ranges of 4 KiB each
        let ranges: Vec<TrimRequest> = (0..10).map(|i| TrimRequest::new(i * 4096, 4096)).collect();

        // batch_size=0 → all at once
        let t0 = pool.trim_free_space(&ranges, 0, std::time::Duration::from_millis(0));
        assert_eq!(t0, 0);

        // batch_size=3 → 4 batches (3+3+3+1)
        let t3 = pool.trim_free_space(&ranges, 3, std::time::Duration::from_millis(0));
        assert_eq!(t3, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn discard_unused_with_allocator_reports_zero_without_discard_device() {
        let root = temp_dir("discard-alloc");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();

        // 64 blocks, all free initially
        let ba = tidefs_block_allocator::BlockAllocator::new(
            64,
            4096,
            tidefs_block_allocator::Region::new(0, 64),
        );
        // Allocate 10 blocks so not all are free
        let _used = ba.alloc_contiguous(10).unwrap();
        pool.set_allocator(ba);

        let trimmed = pool.discard_unused();
        assert_eq!(trimmed, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn free_blocks_with_trim_on_delete_false_defers_trim() {
        let root = temp_dir("free-no-trim");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let props = PoolProperties {
            trim_on_delete: false,
            ..Default::default()
        };
        let options = test_options();
        let mut pool = Pool::create(config, props, &options).unwrap();

        let ba = tidefs_block_allocator::BlockAllocator::new(
            64,
            4096,
            tidefs_block_allocator::Region::new(0, 64),
        );
        let blocks = ba.alloc_contiguous(10).unwrap();
        pool.set_allocator(ba);

        // trim_on_delete=false → free_blocks only updates bitmap, no TRIM.
        let trimmed = pool.free_blocks(&blocks);
        assert_eq!(trimmed, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    // Free-space watermark admission tests.

    #[test]
    fn watermark_default_does_not_refuse_writes() {
        // Default low_watermark_bytes (0) means the gate is disabled;
        // all writes proceed as before.
        let root = temp_dir("wm-default");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"data-default");
        let result = pool.put(IoClass::Data, key, b"payload");
        assert!(result.is_ok(), "default watermark must admit data writes");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn watermark_refuses_data_write_below_reserve() {
        // Configure a watermark larger than available capacity so the
        // write is refused with NoSpace.
        let root = temp_dir("wm-refuse");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let props = PoolProperties {
            low_watermark_bytes: u64::MAX,
            ..Default::default()
        };
        // The test pool has a small capacity (~segment_count * max_segment_bytes).
        // Set watermark to a very large value so any data write is blocked.
        let mut pool = Pool::create(config, props, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"data-blocked");
        let result = pool.put(IoClass::Data, key, b"payload");
        match result {
            Err(StoreError::NoSpace) => {}
            other => panic!("expected NoSpace, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn watermark_admits_data_write_at_reserve() {
        let root = temp_dir("wm-at-reserve");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let payload = b"payload";
        let cap = pool.pool_stats();
        pool.properties.low_watermark_bytes =
            cap.available_bytes.saturating_sub(payload.len() as u64);

        let key = ObjectKey::from_name(b"data-at-reserve");
        let result = pool.put(IoClass::Data, key, payload);
        assert!(
            result.is_ok(),
            "data write that leaves the configured reserve must pass"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn watermark_metadata_bypasses_gate() {
        // Metadata writes bypass the watermark so forward progress for
        // reclaim and allocator metadata remains possible.
        let root = temp_dir("wm-meta-bypass");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let props = PoolProperties {
            low_watermark_bytes: u64::MAX,
            ..Default::default()
        };
        let mut pool = Pool::create(config, props, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"meta-entry");
        let result = pool.put(IoClass::Metadata, key, b"metadata-payload");
        assert!(result.is_ok(), "metadata must bypass watermark");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn watermark_intent_log_bypasses_gate() {
        let root = temp_dir("wm-ilog-bypass");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let props = PoolProperties {
            low_watermark_bytes: u64::MAX,
            ..Default::default()
        };
        let mut pool = Pool::create(config, props, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"ilog-entry");
        let result = pool.put(IoClass::IntentLog, key, b"intent-payload");
        assert!(result.is_ok(), "intent-log must bypass watermark");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_prefers_nvme_over_hdd_in_mixed_class_pool() {
        let root = temp_dir("md-nvme-pref");
        let _ = std::fs::remove_dir_all(&root);

        let nvme_path = root.join("nvme-device");
        let hdd_path = root.join("hdd-device");
        std::fs::create_dir_all(&nvme_path).unwrap();
        std::fs::create_dir_all(&hdd_path).unwrap();

        let config = PoolConfig {
            name: "mixed-class".into(),
            root_path: root.clone(),
            devices: vec![
                DeviceConfig {
                    path: hdd_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    media_class: DeviceMediaClass::Hdd,
                    class: DeviceClass::Metadata,
                    kind: DeviceKind::Single { path: hdd_path },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    path: nvme_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    media_class: DeviceMediaClass::Nvme,
                    class: DeviceClass::Metadata,
                    kind: DeviceKind::Single { path: nvme_path },
                    encryption: None,
                    compression: None,
                },
            ],
        };

        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"inode-table-entry");
        let result = pool.put(IoClass::Metadata, key, b"inode-data");
        assert!(
            result.is_ok(),
            "metadata put should succeed in mixed-class pool"
        );

        let nvme_stats = &pool.device_layout_stats[1];
        let hdd_stats = &pool.device_layout_stats[0];
        assert_eq!(
            nvme_stats.write_allocations, 1,
            "NVMe should receive metadata write"
        );
        assert_eq!(
            hdd_stats.write_allocations, 0,
            "HDD should not receive metadata when NVMe is available"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_falls_back_to_hdd_when_nvme_is_full() {
        let root = temp_dir("md-hdd-meta");
        let _ = std::fs::remove_dir_all(&root);

        let hdd_path = root.join("hdd-device");
        std::fs::create_dir_all(&hdd_path).unwrap();

        let config = PoolConfig {
            name: "hdd-only-metadata".into(),
            root_path: root.clone(),
            devices: vec![DeviceConfig {
                path: hdd_path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                media_class: DeviceMediaClass::Hdd,
                class: DeviceClass::Metadata,
                kind: DeviceKind::Single { path: hdd_path },
                encryption: None,
                compression: None,
            }],
        };

        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();

        let key = ObjectKey::from_name(b"extent-map-entry");
        let result = pool.put(IoClass::Metadata, key, b"extent-data");
        assert!(
            result.is_ok(),
            "metadata put should succeed via fallback in HDD-only pool"
        );

        assert_eq!(
            pool.device_layout_stats[0].write_allocations, 1,
            "HDD should receive metadata write via fallback when no NVMe/SSD available"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_redundancy_expands_beyond_short_preferred_tier() {
        let root = temp_dir("md-redundancy-fallback");
        let _ = std::fs::remove_dir_all(&root);

        let metadata_path = root.join("metadata-nvme");
        let data0_path = root.join("data-ssd-0");
        let data1_path = root.join("data-ssd-1");
        let config = PoolConfig {
            name: "metadata-redundancy".into(),
            root_path: root.clone(),
            devices: vec![
                DeviceConfig {
                    path: metadata_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    media_class: DeviceMediaClass::Nvme,
                    class: DeviceClass::Metadata,
                    kind: DeviceKind::Single {
                        path: metadata_path,
                    },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    path: data0_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    media_class: DeviceMediaClass::Ssd,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data0_path },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    path: data1_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    media_class: DeviceMediaClass::Ssd,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data1_path },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"metadata-replicated-entry");
        pool.put(IoClass::Metadata, key, b"metadata-payload")
            .unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Metadata, key)
            .unwrap()
            .expect("metadata receipt");

        assert_eq!(receipt.targets.len(), 2);
        assert!(
            receipt.targets.iter().any(|target| target.device_index != 0),
            "metadata redundancy should expand to fallback data devices when the preferred tier is too short"
        );
        assert_eq!(
            pool.get(IoClass::Metadata, key).unwrap(),
            Some(b"metadata-payload".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    // ── Locked-dataset refusal tests ─────────────────────────────────

    fn encrypted_device_config(root: &Path) -> (PoolConfig, crate::encrypt::StoreEncryptionKey) {
        let data_dir = root.join("data");
        let key = crate::encrypt::StoreEncryptionKey::generate();
        let enc_cfg = crate::encrypt::EncryptionConfig::new(key.clone());
        let config = PoolConfig {
            name: "encpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: DeviceMediaClass::Ssd,
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: Some(enc_cfg),
                compression: None,
            }],
        };
        (config, key)
    }

    fn encrypted_compressed_device_config(
        root: &Path,
    ) -> (PoolConfig, crate::encrypt::StoreEncryptionKey) {
        let (mut config, key) = encrypted_device_config(root);
        config.name = "enc-comp-pool".into();
        config.devices[0].compression = Some(crate::compress::CompressionConfig::default());
        (config, key)
    }

    #[test]
    fn locked_pool_is_locked_returns_true_after_export_import_without_key() {
        let root = temp_dir("locked-detect");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        // Create and export an encrypted pool.
        let (config, _key) = encrypted_device_config(&root);
        let pool = Pool::create(config.clone(), PoolProperties::default(), &options)
            .expect("create encrypted pool");
        assert!(!pool.is_locked(), "freshly created pool must not be locked");
        pool.export().expect("export encrypted pool");
        drop(pool);

        // Re-open without encryption key — should be locked.
        let config_no_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config
        };
        let mut imported = Pool::open(config_no_key, PoolProperties::default(), &options)
            .expect("open encrypted pool without key");
        assert!(
            imported.is_locked(),
            "pool opened without encryption key must be locked"
        );
        assert!(
            imported
                .put(IoClass::Data, ObjectKey::from_name(b"data"), b"test")
                .is_err(),
            "locked pool must refuse put"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_pool_detects_encrypted_device_behind_compression() {
        let root = temp_dir("locked-detect-compressed");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        let (config, _key) = encrypted_compressed_device_config(&root);
        let pool = Pool::create(config.clone(), PoolProperties::default(), &options)
            .expect("create encrypted compressed pool");
        assert!(!pool.is_locked(), "freshly created pool must not be locked");
        pool.export().expect("export encrypted compressed pool");
        drop(pool);

        let config_no_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config
        };
        let imported = Pool::open(config_no_key, PoolProperties::default(), &options)
            .expect("open encrypted compressed pool without key");
        assert!(
            imported.is_locked(),
            "pool label must keep encrypted+compressed pools locked without a key"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_pool_put_returns_invalid_options_error() {
        let root = temp_dir("locked-put");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        let (config, _key) = encrypted_device_config(&root);
        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        pool.export().unwrap();
        drop(pool);

        let config_no_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config
        };
        let mut locked_pool =
            Pool::open(config_no_key, PoolProperties::default(), &options).unwrap();
        assert!(locked_pool.is_locked());

        let err = locked_pool
            .put(
                IoClass::Data,
                ObjectKey::from_name(b"locked-put"),
                b"payload",
            )
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("locked"),
            "error message must mention locked: {msg}"
        );
        assert!(
            msg.contains("encryption key"),
            "error message must mention encryption key: {msg}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_pool_get_returns_invalid_options_error() {
        let root = temp_dir("locked-get");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        let (config, _key) = encrypted_device_config(&root);
        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        // Write some data while the pool has the key.
        let data_key = ObjectKey::from_name(b"secret");
        pool.put(IoClass::Data, data_key, b"classified").unwrap();
        pool.export().unwrap();
        drop(pool);

        let config_no_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config
        };
        let locked_pool = Pool::open(config_no_key, PoolProperties::default(), &options).unwrap();
        assert!(locked_pool.is_locked());

        let err = locked_pool.get(IoClass::Data, data_key).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("locked"),
            "get error message must mention locked: {msg}"
        );
        assert!(
            msg.contains("encryption key"),
            "get error message must mention encryption key: {msg}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_with_key_not_locked_put_get_works() {
        let root = temp_dir("unlocked-export-import");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        let (config, _key) = encrypted_device_config(&root);
        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        assert!(!pool.is_locked());

        let data_key = ObjectKey::from_name(b"survive-roundtrip");
        pool.put(IoClass::Data, data_key, b"persistent data")
            .unwrap();
        pool.export().unwrap();
        drop(pool);

        // Re-open WITH the same encryption key — should NOT be locked.
        let imported = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert!(
            !imported.is_locked(),
            "pool opened with encryption key must not be locked"
        );
        let read_back = imported.get(IoClass::Data, data_key).unwrap();
        assert!(
            read_back.is_some(),
            "data must survive export/import roundtrip"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
