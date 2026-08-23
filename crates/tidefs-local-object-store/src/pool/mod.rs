// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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
pub mod transform_pipeline;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand;

#[cfg(any(feature = "distributed-repair", test))]
use tidefs_membership_epoch::{EpochId, MemberId};
#[cfg(any(feature = "distributed-repair", test))]
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};
use tidefs_types_pool_label_core::{
    self as pool_label, features, DeviceClass as LabelDeviceClass, PoolLabelV1, PoolState,
};

use crate::device::{
    Device, DeviceBacking, DeviceClass, DeviceConfig, DeviceImpl, DeviceKind, DeviceState,
    DeviceStats, DeviceStatus, IoClass,
};
use crate::device_health::{DeviceHealth, DeviceHealthState, DeviceHealthTransition};
use crate::device_layout::{
    decode_device_layout_v1, encode_device_layout_v1, DeviceClassPolicy, DeviceLayoutPolicy,
    DeviceLayoutPolicyDiscriminant, DeviceLayoutStats, DeviceLayoutV1, DeviceMediaClass,
    WriteAllocator,
};
use crate::device_manager::{DeviceManager, SparePolicy};
use crate::io_scheduler::IoClass as SchedClass;
use crate::log_device::{LogDeviceWriter, LOG_DEVICE_HEADER_SIZE};
use crate::{
    BlockStoreBootstrapInspection, BlockStoreIdentity, LocalObjectStore, ObjectKey, ObjectLocation,
    Result, ScrubStats, StoreError, StoreOptions, StoreRetentionCompactionReport, StoreStats,
    StoredObject,
};
use tidefs_block_allocator::{BlockAllocator, BlockId, TrimRequest};
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};
#[cfg(any(feature = "distributed-repair", test))]
use tidefs_erasure_coding::{
    encode_receipt_stripe, reconstruct_receipt_stripe, ErasureShard, ReceiptStripeError, ShardKind,
    StripeConfig,
};
use tidefs_placement_planner::{
    AllocationRequest, DeviceHealthCapacity, HashRingPlacementPlanner, PlacementDecision,
    PlacementPlanner, PlacementReplayReceipt, PlacementReplayShardRole, PlacementReplayTarget,
};
use tidefs_space_accounting::{PoolCounters, StatfsResult};
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReceiptPolicy, DeadObjectReplacementReceipt,
    ObjectKey as ReclaimObjectKey,
};

const RECEIPT_GENERATION_HIGH_WATER_MAGIC: [u8; 8] = *b"TFSPGH1\0";
const RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN: usize = 64;
const RECEIPT_GENERATION_RESERVATION_SIZE: u64 = 4096;
const PENDING_DELETION_MAGIC: [u8; 8] = *b"TFSPDH1\0";
const PENDING_DELETION_CONTEXT: &str = "TideFS pool pending deletion object key v1";

/// One exact labelled byte-addressable member admitted for fresh Pool bootstrap.
#[derive(Debug)]
pub struct PoolBootstrapMember {
    /// Exact creator-opened media handle retained across admission and
    /// bootstrap. The path is diagnostic and topology state, not I/O authority.
    pub file: fs::File,
    pub path: PathBuf,
    pub backing: DeviceBacking,
    pub device_index: u32,
    pub capacity_bytes: u64,
    pub device_guid: [u8; 16],
    pub expected_label: PoolLabelV1,
    pub device_layout_v1: pool_label::DeviceLayoutV1Bytes,
    /// Whether this exact member already carried a valid same-Pool label when
    /// the creation attempt began. Only such a member may contain partial
    /// same-Pool Store bootstrap state; a member that began blank must still
    /// have a completely blank Store region.
    pub label_was_present: bool,
}

/// Pool-owned bootstrap input after the creator has validated label agreement.
#[derive(Debug)]
pub struct PoolBootstrapConfig {
    pub pool_guid: [u8; 16],
    pub members: Vec<PoolBootstrapMember>,
    pub encryption: Option<crate::encrypt::EncryptionConfig>,
}

/// One-shot proof that the exact retained media is safe for fresh bootstrap.
#[derive(Debug)]
pub struct PoolBootstrapAdmission {
    config: PoolBootstrapConfig,
    inspections: Vec<BlockStoreBootstrapInspection>,
}

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

    fn ensure_available(self) -> Result<()> {
        #[cfg(all(not(feature = "distributed-repair"), not(test)))]
        if matches!(self, Self::Erasure { .. }) {
            return Err(StoreError::InvalidOptions {
                reason: "erasure pool operation requires the distributed-repair feature",
            });
        }
        Ok(())
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

    fn to_label_policy(self) -> pool_label::PoolRedundancyPolicy {
        match self {
            Self::Replicated { copies } => pool_label::PoolRedundancyPolicy::replicated(copies),
            Self::Erasure {
                data_shards,
                parity_shards,
            } => pool_label::PoolRedundancyPolicy::erasure(data_shards, parity_shards),
        }
    }

    /// Reconstruct the allocation policy persisted in a pool label.
    #[must_use]
    pub const fn from_label_policy(policy: pool_label::PoolRedundancyPolicy) -> Self {
        match policy {
            pool_label::PoolRedundancyPolicy::Replicated { copies } => Self::Replicated { copies },
            pool_label::PoolRedundancyPolicy::Erasure {
                data_shards,
                parity_shards,
            } => Self::Erasure {
                data_shards,
                parity_shards,
            },
        }
    }

    /// Number of physical placement targets required by this local policy.
    #[must_use]
    pub const fn target_width(self) -> u16 {
        match self {
            Self::Replicated { copies } => copies as u16,
            Self::Erasure {
                data_shards,
                parity_shards,
            } => data_shards as u16 + parity_shards as u16,
        }
    }

    /// Whether this policy can describe a usable local placement.
    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        match self {
            Self::Replicated { copies } => copies > 0,
            Self::Erasure {
                data_shards,
                parity_shards,
            } => data_shards > 0 && parity_shards > 0,
        }
    }

    /// Project this local pool policy into the shared distributed receipt
    /// policy identity.
    #[must_use]
    #[cfg(any(feature = "distributed-repair", test))]
    pub const fn to_receipt_redundancy_policy(self) -> ReceiptRedundancyPolicy {
        match self {
            Self::Replicated { copies } => ReceiptRedundancyPolicy::Replicated { copies },
            Self::Erasure {
                data_shards,
                parity_shards,
            } => ReceiptRedundancyPolicy::Erasure {
                data_shards,
                parity_shards,
            },
        }
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
    /// Layout policy for computing per-device region segmentation.
    pub layout_policy: DeviceLayoutPolicy,
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
            layout_policy: DeviceLayoutPolicy::default(),
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

/// One durable Pool member identity and whether its device is present in this
/// imported runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolMemberStatus {
    pub device_index: u32,
    pub device_guid: [u8; 16],
    pub present: bool,
}

/// Truthful topology projection for operator-visible Pool status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolTopologyStatus {
    pub health: PoolHealth,
    pub read_only: bool,
    pub expected_members: u32,
    pub present_members: u32,
    pub missing_members: u32,
    pub members: Vec<PoolMemberStatus>,
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
    /// Original stable device GUID for receipts that still target the old media.
    pub old_device_guid: [u8; 16],
    /// Path of the new replacement device.
    pub new_path: PathBuf,
    /// Current replacement state.
    pub state: ReplacementState,
    /// Index of the device in the pool's device list during replacement.
    pub device_index: usize,
}

/// Receipt-backed result of replacing one present, readable Pool member.
///
/// `complete` becomes true only after the replacement receipts, mounted
/// filesystem roots (when a mounted owner is involved), and redundant
/// same-cardinality labels are durable. The old media is never erased by this
/// operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceReplacementResult {
    pub old_path: PathBuf,
    pub new_path: PathBuf,
    pub old_device_guid: [u8; 16],
    pub new_device_guid: [u8; 16],
    pub topology_generation: u64,
    pub objects_total: u64,
    pub objects_rebuilt: u64,
    pub objects_failed: u64,
    pub verified_receipt_count: u64,
    pub bytes_rebuilt: u64,
    pub state: ReplacementRebuildStatusState,
    pub detach_decision: ReplacementDetachDecision,
    pub remanence_treatment: ReplacementRemanenceTreatment,
    pub topology_commit_pending: bool,
    pub complete: bool,
}

/// Local replacement/rebuild status projected from pool replacement state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementRebuildStatusState {
    Pending,
    Resuming,
    Completed,
    Refused,
}

impl ReplacementRebuildStatusState {
    fn is_active(self) -> bool {
        matches!(self, Self::Pending | Self::Resuming)
    }
}

/// Whether current replacement evidence permits detaching the old device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementDetachDecision {
    SafeToDetach,
    UnsafeToDetach,
}

impl ReplacementDetachDecision {
    pub fn is_safe(self) -> bool {
        matches!(self, Self::SafeToDetach)
    }
}

/// Remanence treatment surfaced with replacement status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementRemanenceTreatment {
    pub old_device_detach_allowed: bool,
    pub media_privacy_claimed: bool,
    pub secure_erase_claimed: bool,
    pub sanitization_claimed: bool,
    pub decommissioning_claimed: bool,
}

impl ReplacementRemanenceTreatment {
    pub fn from_detach_decision(detach_decision: ReplacementDetachDecision) -> Self {
        Self {
            old_device_detach_allowed: detach_decision.is_safe(),
            media_privacy_claimed: false,
            secure_erase_claimed: false,
            sanitization_claimed: false,
            decommissioning_claimed: false,
        }
    }
}

/// Fail-closed replacement/rebuild evidence status for local pool state.
#[cfg(any(feature = "distributed-repair", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementRebuildEvidenceStatus {
    pub old_device_guid: [u8; 16],
    pub new_device_guid: [u8; 16],
    pub old_path: PathBuf,
    pub new_path: PathBuf,
    pub old_member: MemberId,
    pub new_member: MemberId,
    pub topology_epoch: u64,
    pub total_subjects: u64,
    pub subjects_completed: u64,
    pub subjects_failed: u64,
    pub verified_receipt_count: u64,
    pub bytes_rebuilt: u64,
    pub evidence_stable: bool,
    pub evidence_replayable_after_reopen: bool,
    pub state: ReplacementRebuildStatusState,
    pub detach_decision: ReplacementDetachDecision,
    pub remanence_treatment: ReplacementRemanenceTreatment,
}

impl DeviceReplacement {
    /// Create a new replacement tracker.
    pub fn new(
        old_config: DeviceConfig,
        old_device_guid: [u8; 16],
        new_path: PathBuf,
        device_index: usize,
    ) -> Self {
        let old_path = old_config.path.clone();
        Self {
            old_path,
            old_config,
            old_device_guid,
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

/// Aggregate stats from a receipt-bound dead-object drain across pool devices.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolReceiptBoundDeadObjectDrainStats {
    /// Number of writable pool devices whose dead-object queues were examined.
    pub devices_scanned: usize,
    /// Number of receipt-authorized dead objects examined.
    pub objects_examined: usize,
    /// Number of segments identified as fully dead and freed.
    pub segments_reclaimed: u64,
    /// Number of dead-object records accounted as freed.
    pub blocks_freed: u64,
    /// Remaining receipt-bound dead-object queue depth across scanned devices.
    pub reclaim_queue_depth: usize,
    /// Number of checkpoint batches emitted by lower-level drains.
    pub checkpoint_batches: usize,
}

impl PoolReceiptBoundDeadObjectDrainStats {
    fn absorb_reclaim_stats(&mut self, stats: tidefs_reclaim::ReclaimConsumerStats) {
        self.objects_examined += stats.entries_processed;
        self.segments_reclaimed += stats.segments_reclaimed;
        self.blocks_freed += stats.blocks_freed;
        self.reclaim_queue_depth += stats.reclaim_queue_depth;
        self.checkpoint_batches += stats.checkpoint_batches;
    }
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

/// Provenance of a repair that produced a replacement receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairSource {
    /// Data was reconstructed from a healthy replica.
    Replica { source_device_index: u32 },
    /// Data was reconstructed from erasure-coding parity shards.
    ErasureReconstruction,
    /// Data was recovered from a backup or send stream.
    ExternalRecovery,
    /// Repair source unknown or not recorded.
    Unknown,
}

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
    /// Monotonic per-pool receipt write generation.
    pub generation: u64,
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
    /// Sealed planner replay authority for the placement decision.
    pub planner_replay_receipt: Option<PlacementReplayReceipt>,
}

/// Receipt-bound observation of one physical replicated target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicatedTargetReadOutcome {
    /// The target returned the exact length and BLAKE3 payload digest named by
    /// the current receipt.
    Clean,
    /// The target returned bytes that do not match the current receipt.
    Corrupt {
        actual_len: u64,
        actual_digest: [u8; 32],
    },
    /// The current receipt target has no object at the receipt-bound key.
    Missing,
    /// The target could not return bytes through its ordinary checked read.
    Unreadable,
}

/// Current-receipt evidence for one replicated target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedTargetEvidence {
    pub target: PlacementReceiptTarget,
    pub outcome: ReplicatedTargetReadOutcome,
    payload: Option<Vec<u8>>,
}

impl ReplicatedTargetEvidence {
    /// Bytes returned by this exact target, when its checked read completed.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
}

/// Target-by-target evidence under one exact current replicated receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedReceiptEvidence {
    pub receipt: PlacementReceipt,
    pub targets: Vec<ReplicatedTargetEvidence>,
}

/// Completed two-copy repair with durable replacement placement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedRepairResult {
    pub previous_receipt: PlacementReceipt,
    pub replacement_receipt: PlacementReceipt,
    pub source_device_index: u32,
    pub repaired_device_index: u32,
}

/// Durable evidence that a newer receipt came from one target-only repair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedRepairReconciliationEvidence {
    /// Receipt generation still embedded in the unreconciled filesystem root.
    pub embedded_predecessor_generation: u64,
    /// Clean, current Pool receipt that superseded the embedded generation.
    pub current_receipt: PlacementReceipt,
    /// Exact receipt target whose predecessor physical object is queued.
    pub repaired_target: PlacementReceiptTarget,
    /// Whether reclaim evidence for the current receipt is already attached.
    pub replacement_receipt_attached: bool,
    /// Exact physical predecessor lifetime retained for receipt-bound reclaim.
    reclaim_object_id: ReclaimObjectKey,
}

/// Durable receipt-copy state for one interrupted target-only repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingReplicatedRepairReceiptCopies {
    /// Every receipt carrier still names the predecessor generation.
    Predecessor,
    /// Receipt publication stopped with exact predecessor and replacement
    /// generations on different physical carriers.
    Mixed,
    /// Every receipt carrier names the replacement generation.
    Replacement,
}

/// Physical state of the exact target named by a pending repair transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingReplicatedRepairTargetState {
    /// The target remains corrupt or unreadable and must be rewritten from the
    /// authenticated clean source before receipt convergence.
    NeedsRewrite,
    /// The target already contains the receipt-bound bytes, so only receipt
    /// convergence and reclaim attachment remain.
    Clean,
}

/// Read-only discovery evidence for one interrupted replicated-target repair.
///
/// This value does not authorize mutation by itself. A filesystem owner must
/// first authenticate an exact predecessor root and object reference using the
/// clean source payload, then pass the unchanged value back to the Pool's
/// completion boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingReplicatedRepairRecoveryEvidence {
    pub predecessor_receipt: PlacementReceipt,
    pub replacement_receipt: PlacementReceipt,
    pub repaired_target: PlacementReceiptTarget,
    pub clean_source: PlacementReceiptTarget,
    pub receipt_copies: PendingReplicatedRepairReceiptCopies,
    pub target_state: PendingReplicatedRepairTargetState,
    /// Exact durable reclaim-row identity for the predecessor target bytes.
    reclaim_object_id: ReclaimObjectKey,
    clean_source_payload: Vec<u8>,
}

impl PendingReplicatedRepairRecoveryEvidence {
    /// Exact receipt-clean bytes used to authenticate the predecessor root.
    #[must_use]
    pub fn clean_source_payload(&self) -> &[u8] {
        &self.clean_source_payload
    }
}

/// Durable receipt-publication truth when replicated repair returns an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedRepairReceiptPublicationState {
    /// Repair did not call the receipt-publication boundary.
    NotAttempted,
    /// Receipt publication returned success before the later failure.
    Completed,
    /// Receipt publication was attempted but did not return success.
    Uncertain,
}

impl std::fmt::Display for ReplicatedRepairReceiptPublicationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAttempted => "not-attempted",
            Self::Completed => "completed",
            Self::Uncertain => "uncertain",
        })
    }
}

/// Phase-accurate failure from one exact replicated-target repair.
#[derive(Debug)]
pub struct ReplicatedRepairFailure {
    /// Underlying Pool or device failure.
    pub error: StoreError,
    /// Whether any persistent repair writeback began, including durable
    /// pre-publication reclaim intent.
    pub writeback_started: bool,
    /// Allocated replacement generation, when allocation completed.
    pub replacement_generation: Option<u64>,
    /// Durable replacement-receipt publication state at failure time.
    pub receipt_publication: ReplicatedRepairReceiptPublicationState,
}

impl std::fmt::Display for ReplicatedRepairFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (writeback_started={}, replacement_generation={:?}, receipt_publication={})",
            self.error,
            self.writeback_started,
            self.replacement_generation,
            self.receipt_publication
        )
    }
}

impl std::error::Error for ReplicatedRepairFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Clone, Copy, Debug)]
struct ReplicatedRepairProgress {
    writeback_started: bool,
    replacement_generation: Option<u64>,
    receipt_publication: ReplicatedRepairReceiptPublicationState,
}

impl ReplicatedRepairProgress {
    const fn new() -> Self {
        Self {
            writeback_started: false,
            replacement_generation: None,
            receipt_publication: ReplicatedRepairReceiptPublicationState::NotAttempted,
        }
    }

    fn failure(self, error: StoreError) -> ReplicatedRepairFailure {
        ReplicatedRepairFailure {
            error,
            writeback_started: self.writeback_started,
            replacement_generation: self.replacement_generation,
            receipt_publication: self.receipt_publication,
        }
    }
}

/// Receipt publication state for a mutable erasure-coded read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErasureReadRepairStatus {
    /// Every receipt target supplied a verified shard, so no repair was needed.
    NotRequired,
    /// Missing or corrupt shards were reconstructed and a replacement receipt
    /// was persisted for the whole-object rewrite.
    ReplacementPublished {
        /// Receipt shard slots reconstructed by the shared EC helper.
        rebuilt_shard_indices: Vec<u16>,
    },
}

/// Payload and authoritative receipt returned by a mutable erasure-coded read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureReadWithReceipt {
    /// Reconstructed logical payload.
    pub payload: Vec<u8>,
    /// Current placement authority after the read. This is the original
    /// receipt for a clean read and the replacement receipt after repair.
    pub receipt: PlacementReceipt,
    /// Whether this read published replacement placement evidence.
    pub repair_status: ErasureReadRepairStatus,
}

struct ReconstructedErasureRead {
    payload: Vec<u8>,
    rebuilt_shard_indices: Vec<u16>,
}

const PLACEMENT_RECEIPT_MAGIC_V1: &[u8; 8] = b"TFSPRC1\0";
const PLACEMENT_RECEIPT_MAGIC_V2: &[u8; 8] = b"TFSPRC2\0";
const PLACEMENT_RECEIPT_MAGIC_V3: &[u8; 8] = b"TFSPRC3\0";
const PLACEMENT_RECEIPT_CONTEXT: &str = "TideFS pool placement receipt object key v1";
const PLACEMENT_HASH_RING_VNODES_PER_GB: u64 = 16;

impl PlacementReceipt {
    /// Deterministic object-store subject id for shared rebuild/backfill models.
    ///
    /// Local pool receipts carry the full 32-byte object key rather than a
    /// separate logical subject id. The shared ref keeps that full key; this
    /// u64 projection is only the object-store-level subject id used by current
    /// rebuild model APIs. Callers that already have a richer object identity
    /// can use [`PlacementReceipt::shared_receipt_ref_for_subject`].
    #[must_use]
    pub fn object_store_subject_id(&self) -> u64 {
        object_store_subject_id_from_key(self.object_key)
    }

    /// Project this local placement receipt into the shared distributed receipt
    /// reference using the object-store-level subject id.
    #[cfg(any(feature = "distributed-repair", test))]
    pub fn shared_receipt_ref(&self) -> Result<PlacementReceiptRef> {
        self.shared_receipt_ref_for_subject(self.object_store_subject_id())
    }

    /// Project this local placement receipt into the shared distributed receipt
    /// reference with an explicit caller-supplied subject id.
    #[cfg(any(feature = "distributed-repair", test))]
    pub fn shared_receipt_ref_for_subject(&self, object_id: u64) -> Result<PlacementReceiptRef> {
        let target_count =
            u16::try_from(self.targets.len()).map_err(|_| StoreError::InvalidOptions {
                reason: "placement receipt target count exceeds shared receipt ref format",
            })?;
        Ok(PlacementReceiptRef::new(
            object_id,
            self.object_key.as_bytes32(),
            EpochId::new(self.epoch),
            self.generation,
            self.policy.to_receipt_redundancy_policy(),
            self.payload_len,
            self.payload_digest,
            target_count,
        ))
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.targets.len() > u16::MAX as usize {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt target count exceeds wire format",
            });
        }
        let Some(replay_receipt) = self.planner_replay_receipt.as_ref() else {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt missing planner replay authority",
            });
        };
        if replay_receipt.targets.len() > u16::MAX as usize {
            return Err(StoreError::InvalidOptions {
                reason: "placement replay receipt target count exceeds wire format",
            });
        }
        let replay_policy = replay_receipt.policy.encode();
        if replay_policy.len() > u8::MAX as usize {
            return Err(StoreError::InvalidOptions {
                reason: "placement replay receipt policy exceeds wire format",
            });
        }

        let mut out =
            Vec::with_capacity(194 + self.targets.len() * 55 + replay_receipt.targets.len() * 21);
        out.extend_from_slice(PLACEMENT_RECEIPT_MAGIC_V3);
        out.extend_from_slice(&self.object_key.as_bytes32());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
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
        encode_planner_replay_receipt(&mut out, replay_receipt, &replay_policy);
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        let mut cursor = ReceiptCursor::new(raw);
        let magic = cursor.take(PLACEMENT_RECEIPT_MAGIC_V3.len())?;
        let (has_generation, has_replay_receipt) = match magic {
            m if m == PLACEMENT_RECEIPT_MAGIC_V3 => (true, true),
            m if m == PLACEMENT_RECEIPT_MAGIC_V2 => (true, false),
            m if m == PLACEMENT_RECEIPT_MAGIC_V1 => (false, false),
            _ => return None,
        };
        let object_key = ObjectKey::from_bytes32(cursor.array()?);
        let epoch = u64::from_le_bytes(cursor.array()?);
        let generation = if has_generation {
            u64::from_le_bytes(cursor.array()?)
        } else {
            0
        };
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
        let planner_replay_receipt = if has_replay_receipt {
            Some(decode_planner_replay_receipt(&mut cursor)?)
        } else {
            None
        };
        if !cursor.is_finished() {
            return None;
        }
        let receipt = Self {
            object_key,
            epoch,
            generation,
            policy,
            failure_domain_level,
            payload_len,
            shard_len,
            payload_digest,
            targets,
            planner_replay_receipt,
        };
        if !planner_replay_receipt_matches_receipt(&receipt) {
            return None;
        }
        Some(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PendingDeletionPhase {
    Prepared = 1,
    Committed = 2,
}

impl PendingDeletionPhase {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Prepared),
            2 => Some(Self::Committed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolPendingDeletion {
    pool_guid: [u8; 16],
    class: IoClass,
    receipt: PlacementReceipt,
    receipt_carrier_guids: Vec<[u8; 16]>,
    phase: PendingDeletionPhase,
}

impl PoolPendingDeletion {
    fn object_key(&self) -> ObjectKey {
        pool_pending_deletion_object_key(
            self.class,
            self.receipt.object_key,
            self.receipt.generation,
        )
    }

    fn same_identity_and_authority(&self, other: &Self) -> bool {
        self.pool_guid == other.pool_guid
            && self.class == other.class
            && self.receipt == other.receipt
            && self.receipt_carrier_guids == other.receipt_carrier_guids
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.receipt_carrier_guids.is_empty()
            || self.receipt_carrier_guids.len() > u16::MAX as usize
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending deletion requires a bounded nonempty receipt-carrier set",
            });
        }
        let distinct_carriers = self
            .receipt_carrier_guids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if distinct_carriers.len() != self.receipt_carrier_guids.len() {
            return Err(StoreError::InvalidOptions {
                reason: "pending deletion receipt-carrier set contains duplicates",
            });
        }
        let receipt = self.receipt.encode()?;
        let receipt_len = u32::try_from(receipt.len()).map_err(|_| StoreError::InvalidOptions {
            reason: "pending deletion placement receipt exceeds wire format",
        })?;
        let mut out = Vec::with_capacity(
            8 + 16 + 1 + 1 + 2 + 4 + self.receipt_carrier_guids.len() * 16 + receipt.len() + 32,
        );
        out.extend_from_slice(&PENDING_DELETION_MAGIC);
        out.extend_from_slice(&self.pool_guid);
        out.push(io_class_as_u8(self.class));
        out.push(self.phase as u8);
        out.extend_from_slice(&(self.receipt_carrier_guids.len() as u16).to_le_bytes());
        out.extend_from_slice(&receipt_len.to_le_bytes());
        for guid in &self.receipt_carrier_guids {
            out.extend_from_slice(guid);
        }
        out.extend_from_slice(&receipt);
        let checksum = blake3::hash(&out);
        out.extend_from_slice(checksum.as_bytes());
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 8 + 16 + 1 + 1 + 2 + 4 + 32 {
            return None;
        }
        let checksum_offset = raw.len().checked_sub(32)?;
        if blake3::hash(raw.get(..checksum_offset)?).as_bytes() != raw.get(checksum_offset..)? {
            return None;
        }
        let mut cursor = ReceiptCursor::new(raw.get(..checksum_offset)?);
        if cursor.take(PENDING_DELETION_MAGIC.len())? != PENDING_DELETION_MAGIC {
            return None;
        }
        let pool_guid = cursor.array()?;
        let class = io_class_from_u8(cursor.u8()?)?;
        let phase = PendingDeletionPhase::from_u8(cursor.u8()?)?;
        let carrier_count = u16::from_le_bytes(cursor.array()?) as usize;
        let receipt_len = u32::from_le_bytes(cursor.array()?) as usize;
        if carrier_count == 0 {
            return None;
        }
        let mut receipt_carrier_guids = Vec::with_capacity(carrier_count);
        let mut distinct_carriers = BTreeSet::new();
        for _ in 0..carrier_count {
            let guid = cursor.array()?;
            if !distinct_carriers.insert(guid) {
                return None;
            }
            receipt_carrier_guids.push(guid);
        }
        let receipt = PlacementReceipt::decode(cursor.take(receipt_len)?)?;
        if !cursor.is_finished() || receipt.generation == 0 || receipt.epoch == 0 {
            return None;
        }
        let pending = Self {
            pool_guid,
            class,
            receipt,
            receipt_carrier_guids,
            phase,
        };
        Some(pending)
    }
}

const fn io_class_as_u8(class: IoClass) -> u8 {
    match class {
        IoClass::Data => 0,
        IoClass::Metadata => 1,
        IoClass::IntentLog => 2,
        IoClass::ReadCache => 3,
    }
}

const fn io_class_from_u8(raw: u8) -> Option<IoClass> {
    match raw {
        0 => Some(IoClass::Data),
        1 => Some(IoClass::Metadata),
        2 => Some(IoClass::IntentLog),
        3 => Some(IoClass::ReadCache),
        _ => None,
    }
}

fn encode_planner_replay_receipt(
    out: &mut Vec<u8>,
    receipt: &PlacementReplayReceipt,
    encoded_policy: &[u8],
) {
    out.extend_from_slice(&receipt.object_id.to_le_bytes());
    out.extend_from_slice(&receipt.placement_key.to_le_bytes());
    out.extend_from_slice(&receipt.size_hint_bytes.to_le_bytes());
    out.extend_from_slice(&receipt.per_target_bytes.to_le_bytes());
    out.extend_from_slice(&receipt.topology_epoch.to_le_bytes());
    out.extend_from_slice(&receipt.deterministic_seed.to_le_bytes());
    out.push(encoded_policy.len() as u8);
    out.extend_from_slice(encoded_policy);
    out.push(receipt.failure_domain_level.discriminant());
    out.push(u8::from(receipt.failure_domain_separation));
    out.extend_from_slice(&(receipt.targets.len() as u16).to_le_bytes());
    for target in &receipt.targets {
        out.extend_from_slice(&target.target_index.to_le_bytes());
        out.extend_from_slice(&target.shard_index.to_le_bytes());
        out.push(replay_shard_role_as_u8(target.shard_role));
        out.extend_from_slice(&target.device_id.to_le_bytes());
        out.extend_from_slice(&target.failure_domain_key.to_le_bytes());
    }
    out.extend_from_slice(&receipt.seal());
}

fn decode_planner_replay_receipt(cursor: &mut ReceiptCursor<'_>) -> Option<PlacementReplayReceipt> {
    let object_id = u64::from_le_bytes(cursor.array()?);
    let placement_key = u64::from_le_bytes(cursor.array()?);
    let size_hint_bytes = u64::from_le_bytes(cursor.array()?);
    let per_target_bytes = u64::from_le_bytes(cursor.array()?);
    let topology_epoch = u64::from_le_bytes(cursor.array()?);
    let deterministic_seed = u64::from_le_bytes(cursor.array()?);
    let policy_len = cursor.u8()? as usize;
    let policy = DurabilityPolicy::decode(cursor.take(policy_len)?).ok()?;
    let failure_domain_level = FailureDomainLevel::from_u8(cursor.u8()?)?;
    let failure_domain_separation = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let target_count = u16::from_le_bytes(cursor.array()?) as usize;
    let mut targets = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        targets.push(PlacementReplayTarget {
            target_index: u16::from_le_bytes(cursor.array()?),
            shard_index: u16::from_le_bytes(cursor.array()?),
            shard_role: replay_shard_role_from_u8(cursor.u8()?)?,
            device_id: u64::from_le_bytes(cursor.array()?),
            failure_domain_key: u64::from_le_bytes(cursor.array()?),
        });
    }
    let seal = cursor.array()?;
    let receipt = PlacementReplayReceipt {
        object_id,
        placement_key,
        size_hint_bytes,
        per_target_bytes,
        topology_epoch,
        deterministic_seed,
        policy,
        failure_domain_level,
        failure_domain_separation,
        targets,
        seal,
    };
    receipt.replay_decision().ok()?;
    Some(receipt)
}

const fn replay_shard_role_as_u8(role: PlacementReplayShardRole) -> u8 {
    match role {
        PlacementReplayShardRole::Data => 0,
        PlacementReplayShardRole::Parity => 1,
    }
}

const fn replay_shard_role_from_u8(raw: u8) -> Option<PlacementReplayShardRole> {
    match raw {
        0 => Some(PlacementReplayShardRole::Data),
        1 => Some(PlacementReplayShardRole::Parity),
        _ => None,
    }
}

const fn placement_role_from_replay(role: PlacementReplayShardRole) -> PlacementTargetRole {
    match role {
        PlacementReplayShardRole::Data => PlacementTargetRole::Data,
        PlacementReplayShardRole::Parity => PlacementTargetRole::Parity,
    }
}

fn placement_target_device_id(target: &PlacementReceiptTarget) -> u64 {
    u64::from_le_bytes(target.device_guid[..8].try_into().unwrap())
}

fn planner_replay_receipt_matches_receipt(receipt: &PlacementReceipt) -> bool {
    let Some(replay_receipt) = receipt.planner_replay_receipt.as_ref() else {
        return true;
    };
    let Ok(layout) = receipt.policy.layout() else {
        return false;
    };
    let (object_id, placement_key) = placement_key_pair(receipt.object_key);
    if replay_receipt.topology_epoch != receipt.epoch
        || replay_receipt.object_id != object_id
        || replay_receipt.placement_key != placement_key
        || replay_receipt.size_hint_bytes != receipt.payload_len
        || replay_receipt.failure_domain_level != receipt.failure_domain_level
        || replay_receipt.policy != layout.policy
        || replay_receipt.targets.len() != receipt.targets.len()
    {
        return false;
    }
    let Ok(decision) = replay_receipt.replay_decision() else {
        return false;
    };
    if decision.device_targets.len() != receipt.targets.len() {
        return false;
    }
    let mut replay_device_ids = BTreeSet::new();
    let mut replay_failure_domains = BTreeSet::new();
    for (idx, target) in receipt.targets.iter().enumerate() {
        let replay_target = &replay_receipt.targets[idx];
        if replay_target.target_index as usize != idx
            || replay_target.shard_index != target.shard_index
            || placement_role_from_replay(replay_target.shard_role) != target.role
            || replay_target.device_id != placement_target_device_id(target)
            || decision.device_targets[idx] != placement_target_device_id(target)
            || !replay_device_ids.insert(replay_target.device_id)
            || (replay_receipt.failure_domain_separation
                && !replay_failure_domains.insert(replay_target.failure_domain_key))
        {
            return false;
        }
    }
    true
}

fn dead_object_replacement_receipt_for_object(
    _object_key: ObjectKey,
    reclaim_object_id: ReclaimObjectKey,
    receipt: &PlacementReceipt,
) -> Result<DeadObjectReplacementReceipt> {
    let target_count =
        u16::try_from(receipt.targets.len()).map_err(|_| StoreError::InvalidOptions {
            reason: "placement receipt target count exceeds dead-object receipt format",
        })?;
    let redundancy_policy = match receipt.policy {
        PoolRedundancyPolicy::Replicated { copies } => {
            DeadObjectReceiptPolicy::Replicated { copies }
        }
        PoolRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => DeadObjectReceiptPolicy::Erasure {
            data_shards,
            parity_shards,
        },
    };
    Ok(DeadObjectReplacementReceipt::new(
        reclaim_object_id,
        receipt.epoch,
        receipt.generation,
        redundancy_policy,
        receipt.payload_len,
        receipt.payload_digest,
        target_count,
    ))
}

fn receipt_supersedes(candidate: &PlacementReceipt, current: &PlacementReceipt) -> Result<bool> {
    if candidate.generation == current.generation {
        if candidate != current {
            return Err(StoreError::InvalidOptions {
                reason: "conflicting placement receipts reuse one generation",
            });
        }
        return Ok(false);
    }
    if (candidate.generation > current.generation && candidate.epoch < current.epoch)
        || (candidate.generation < current.generation && candidate.epoch > current.epoch)
    {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt epoch and generation order conflict",
        });
    }
    Ok(candidate.generation > current.generation)
}

#[derive(Debug, Default)]
struct PlacementReceiptInventory {
    latest_by_object: BTreeMap<ObjectKey, PlacementReceipt>,
    max_generation: u64,
}

fn discover_placement_receipt_inventory(devices: &[Device]) -> Result<PlacementReceiptInventory> {
    let mut inventory = PlacementReceiptInventory::default();
    let mut receipts_by_generation = BTreeMap::new();
    for device in devices {
        for (receipt_key, raw) in device.placement_receipt_candidates()? {
            let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "physical placement receipt is corrupt or unverifiable",
            })?;
            if placement_receipt_object_key(receipt.object_key) != receipt_key {
                return Err(StoreError::InvalidOptions {
                    reason: "physical placement receipt is stored under the wrong key",
                });
            }
            if receipt.epoch == 0 || receipt.generation == 0 {
                return Err(StoreError::InvalidOptions {
                    reason: "physical placement receipt has a zero epoch or generation",
                });
            }
            if let Some(existing) = receipts_by_generation.get(&receipt.generation) {
                if existing != &receipt {
                    return Err(StoreError::InvalidOptions {
                        reason: "physical placement receipts reuse one pool generation",
                    });
                }
            } else {
                receipts_by_generation.insert(receipt.generation, receipt.clone());
            }

            inventory.max_generation = inventory.max_generation.max(receipt.generation);
            let replace = match inventory.latest_by_object.get(&receipt.object_key) {
                Some(current) => receipt_supersedes(&receipt, current)?,
                None => true,
            };
            if replace {
                inventory
                    .latest_by_object
                    .insert(receipt.object_key, receipt);
            }
        }
    }
    Ok(inventory)
}

fn validate_strict_receipt_structure(receipt: &PlacementReceipt) -> Result<()> {
    let distinct_device_count = receipt
        .targets
        .iter()
        .map(|target| target.device_guid)
        .collect::<BTreeSet<_>>()
        .len();
    if distinct_device_count != receipt.targets.len() {
        return Err(StoreError::InvalidOptions {
            reason: "strict read found duplicate physical placement targets",
        });
    }

    match receipt.policy {
        PoolRedundancyPolicy::Replicated { copies } => {
            let width = usize::from(copies);
            let targets_are_canonical = receipt.targets.iter().enumerate().all(|(slot, target)| {
                target.shard_index as usize == slot
                    && target.role == PlacementTargetRole::Data
                    && target.stored_digest == receipt.payload_digest
            });
            if width == 0
                || receipt.targets.len() != width
                || receipt.shard_len != 0
                || !targets_are_canonical
            {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read found a malformed replicated placement receipt",
                });
            }
        }
        PoolRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => {
            let data_width = usize::from(data_shards);
            let width = data_width.saturating_add(usize::from(parity_shards));
            let targets_are_canonical = receipt.targets.iter().enumerate().all(|(slot, target)| {
                target.shard_index as usize == slot
                    && target.role
                        == if slot < data_width {
                            PlacementTargetRole::Data
                        } else {
                            PlacementTargetRole::Parity
                        }
            });
            if data_width == 0
                || parity_shards == 0
                || receipt.targets.len() != width
                || receipt.shard_len == 0
                || !targets_are_canonical
            {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read found a malformed erasure placement receipt",
                });
            }
        }
    }
    Ok(())
}

/// Whether `error` reports invalid or unavailable authority discovered by a
/// strict placement-receipt read.
///
/// Operational Pool failures such as a locked pool or missing I/O class are
/// deliberately excluded. Callers may treat this class as object-local
/// authority failure without hiding an import or configuration error.
pub fn is_strict_read_authority_error(error: &StoreError) -> bool {
    let StoreError::InvalidOptions { reason } = error else {
        return false;
    };
    reason.starts_with("strict read ")
        || matches!(
            *reason,
            "placement receipt payload length exceeds platform usize"
                | "placement receipt shard length exceeds platform usize"
                | "placement receipt changed during strict read"
                | "conflicting placement receipts share epoch and generation"
                | "conflicting placement receipts reuse one generation"
                | "placement receipt epoch and generation order conflict"
                | "placement replay receipt does not match local locator authority"
                | "invalid erasure placement receipt availability set"
                | "erasure placement receipt has zero shard length"
                | "erasure placement receipt reconstruction rejected payload"
                | "reconstructed erasure shard index exceeds u16"
        )
}

fn map_strict_read_object_io<T>(result: Result<T>, authority_reason: &'static str) -> Result<T> {
    result.map_err(|error| match error {
        StoreError::Io { .. } => StoreError::InvalidOptions {
            reason: authority_reason,
        },
        error => error,
    })
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

fn discover_pending_deletions(
    devices: &[Device],
    device_guids: &[[u8; 16]],
    pool_guid: [u8; 16],
    reserved_placement_receipt_generation_through: u64,
) -> Result<BTreeMap<ObjectKey, PoolPendingDeletion>> {
    if devices.len() != device_guids.len() {
        return Err(StoreError::InvalidOptions {
            reason: "pending deletion discovery device identity count mismatch",
        });
    }
    let mut pending: BTreeMap<ObjectKey, PoolPendingDeletion> = BTreeMap::new();
    for (device, device_guid) in devices.iter().zip(device_guids) {
        for (handoff_key, raw) in device.pending_deletion_candidates()? {
            let candidate =
                PoolPendingDeletion::decode(&raw).ok_or(StoreError::InvalidOptions {
                    reason: "pending deletion handoff is corrupt or unverifiable",
                })?;
            if candidate.pool_guid != pool_guid || candidate.object_key() != handoff_key {
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion handoff identity does not match its pool or key",
                });
            }
            if candidate.class == IoClass::IntentLog {
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion handoff cannot govern receiptless intent-log I/O",
                });
            }
            if !candidate.receipt_carrier_guids.contains(device_guid) {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "pending deletion handoff was found outside its declared receipt carriers",
                });
            }
            if candidate.receipt.generation > reserved_placement_receipt_generation_through {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "pending deletion receipt generation exceeds the durable high-water reservation",
                });
            }
            if candidate.receipt.planner_replay_receipt.is_none()
                || !planner_replay_receipt_matches_receipt(&candidate.receipt)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion requires matching placement replay authority",
                });
            }
            validate_strict_receipt_structure(&candidate.receipt)?;
            match pending.get_mut(&handoff_key) {
                Some(current) if !current.same_identity_and_authority(&candidate) => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending deletion handoff copies conflict",
                    });
                }
                Some(current) if candidate.phase > current.phase => {
                    current.phase = candidate.phase;
                }
                Some(_) => {}
                None => {
                    pending.insert(handoff_key, candidate);
                }
            }
        }
    }
    Ok(pending)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OldReceiptPolicy<'a> {
    RequireValid,
    KnownCurrent(&'a PlacementReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PoolOpenMode {
    Writable,
    ReadOnlyExisting,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObsoletePhysicalPlacement {
    device_index: usize,
    object_key: ObjectKey,
    reclaim_object_id: ReclaimObjectKey,
}

/// A TideFS storage pool, analogous to a ZFS zpool.
#[derive(Debug)]
pub struct Pool {
    config: PoolConfig,
    properties: PoolProperties,
    /// Whether this Pool was imported for side-effect-free inspection.
    read_only: bool,
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
    /// Per-device layout records computed from the pool's layout policy.
    /// Populated during pool creation and reconstructed during import.
    device_layouts: Vec<DeviceLayoutV1>,
    /// Optional separate intent-log device writer (LOG_DEVICE).
    log_device: Option<LogDeviceWriter>,
    /// Persistent pool identity (randomly generated on create).
    pool_guid: [u8; 16],
    /// Per-device GUIDs matching device order for label-based topology updates.
    device_guids: Vec<[u8; 16]>,
    /// Complete durable index/GUID authority decoded from surviving labels.
    /// Unlike `device_guids`, this retains identities for physically absent
    /// members during a degraded read-only import.
    durable_device_guids: Vec<[u8; 16]>,
    /// Durable member count declared by the imported labels.
    ///
    /// Writable opens require this to equal `devices.len()`. A read-only open
    /// may retain fewer present devices so replicated receipt reads can use a
    /// surviving member without renumbering the durable topology.
    expected_device_count: u32,
    /// Durable label index for each present device, parallel to `devices`.
    device_label_indices: Vec<u32>,
    /// Monotonic local placement epoch. Receipts bind reads to the epoch that
    /// selected their targets while later topology changes can steer new
    /// allocations elsewhere.
    placement_epoch: u64,
    /// Topology epoch currently reflected by durable pool labels.
    persisted_label_epoch: Option<u64>,
    /// Next monotonic receipt generation for distinguishing same-topology
    /// rewrites of the same logical object.
    next_placement_receipt_generation: u64,
    /// Inclusive durable ceiling reserved before any receipt in the range is
    /// published. Reopen burns the unused tail rather than risking reuse.
    reserved_placement_receipt_generation_through: u64,
    /// Whether receipt-generation authority is writable, retrying one exact
    /// reservation, or waiting for explicit topology recovery.
    receipt_generation_authority_state: ReceiptGenerationAuthorityState,
    /// Shared fail-closed gate consulted by public raw-store mutations.
    raw_store_mutation_allowed: Arc<AtomicBool>,
    /// Pending removal result established after this Pool instance evacuated
    /// the target. The target remains attached until the mounted owner has
    /// advanced any receipt references embedded above Pool authority.
    pending_device_removal: Option<(PathBuf, [u8; 16], crate::device_removal::EvacuationResult)>,
    /// Device-authoritative removal intent decoded from the selected label
    /// family before receipt recovery begins.
    device_removal_marker: Option<DeviceRemovalMarker>,
    /// Attached predecessor excluded from new placement while a durable
    /// removal or replacement lifecycle record is active.
    allocation_fenced_device_guid: Option<[u8; 16]>,
    /// Hot-spare activation policy.  Defaults to [`SparePolicy::Manual`].
    spare_policy: SparePolicy,
    /// Log of device health transitions for observability.
    health_transitions: Vec<DeviceHealthTransition>,
    /// Currently in-progress device replacement, if any.
    replacement: Option<DeviceReplacement>,
    /// Durable replacement evidence restored independently of the live
    /// replacement device configuration. The marker deliberately excludes
    /// transform keys; callers must supply device configuration again when
    /// resuming after reopen.
    replacement_evidence: Option<DeviceReplacementEvidenceMarker>,
    /// Highest complete lifecycle record selected with the current label
    /// topology. A cleared record retains the monotonic sequence so stale
    /// label copies cannot resurrect an earlier operation.
    label_lifecycle: Option<PoolLifecycleLabelRecord>,
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
    /// Durable logical deletion publications keyed by the handoff object key.
    /// Committed entries suppress the matching receipt generation and raw
    /// fallback until every recorded target and receipt carrier is reconciled.
    pending_deletions: BTreeMap<ObjectKey, PoolPendingDeletion>,
    #[cfg(test)]
    fail_post_publication_reclaim_attachment_once: bool,
    #[cfg(test)]
    fail_pending_deletion_preflight_once: bool,
    #[cfg(test)]
    fail_post_deletion_publication_cleanup_once: bool,
    #[cfg(test)]
    fail_placement_receipt_verification_once: bool,
    #[cfg(test)]
    fail_replicated_repair_after_generation_allocation_once: bool,
    #[cfg(test)]
    fail_replicated_repair_after_reclaim_intent_once: bool,
    #[cfg(test)]
    fail_replicated_repair_after_receipt_publication_once: bool,
}

/// Versioned, checksummed replacement evidence published before an in-memory
/// topology swap. Device transform configuration is intentionally absent: it
/// may carry key material and must be supplied again by the caller on resume.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceReplacementEvidenceMarker {
    pool_guid: [u8; 16],
    old_device_guid: [u8; 16],
    new_device_guid: [u8; 16],
    topology_epoch: u64,
    device_index: usize,
    old_path: PathBuf,
    new_path: PathBuf,
    total_subjects: u64,
    subjects_completed: u64,
    subjects_failed: u64,
    verified_receipt_count: u64,
    bytes_rebuilt: u64,
    evidence_stable: bool,
    state: ReplacementRebuildStatusState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolLifecycleLabelRecord {
    sequence: u64,
    kind: pool_label::PoolLifecycleKindV1,
    payload: Vec<u8>,
}

type SelectedPoolTopology = (Vec<DeviceConfig>, BTreeMap<PathBuf, Vec<u8>>);

fn next_pool_lifecycle_sequence(current: Option<u64>) -> Result<u64> {
    match current {
        None => Ok(1),
        Some(sequence) => sequence.checked_add(1).ok_or(StoreError::InvalidOptions {
            reason: "Pool lifecycle label sequence exhausted",
        }),
    }
}

fn checked_successor_topology_generation(current: u64) -> Option<u64> {
    current.checked_add(1)
}

/// Discover the current logical subjects whose authoritative placement receipt
/// still names the device being replaced. The resulting count is only a
/// durable progress baseline: replacement remains incomplete until later work
/// records verified replacement receipts for every discovered subject.
fn discover_replacement_rebuild_subject_count(
    pool: &Pool,
    old_device_guid: [u8; 16],
) -> Result<u64> {
    let mut receipts = BTreeMap::new();

    for device in &pool.devices {
        for receipt_key in device.store().list_keys_including_internal() {
            if !crate::is_pool_placement_receipt_key(receipt_key) {
                continue;
            }

            let raw = device.get(receipt_key)?.ok_or(StoreError::InvalidOptions {
                reason: "replacement subject discovery found an unreadable placement receipt",
            })?;
            let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "replacement subject discovery found a corrupt placement receipt",
            })?;
            if placement_receipt_object_key(receipt.object_key) != receipt_key
                || receipt.planner_replay_receipt.is_none()
                || !planner_replay_receipt_matches_receipt(&receipt)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "replacement subject discovery requires verified placement receipt authority",
                });
            }

            let replace = match receipts.get(&receipt.object_key) {
                Some(current) => receipt_supersedes(&receipt, current)?,
                None => true,
            };
            if replace {
                receipts.insert(receipt.object_key, receipt);
            }
        }
    }

    u64::try_from(
        receipts
            .values()
            .filter(|receipt| {
                receipt
                    .targets
                    .iter()
                    .any(|target| target.device_guid == old_device_guid)
            })
            .count(),
    )
    .map_err(|_| StoreError::InvalidOptions {
        reason: "replacement subject count exceeds durable evidence format",
    })
}

impl DeviceReplacementEvidenceMarker {
    #[cfg(any(feature = "distributed-repair", test))]
    fn covers_state(&self, state: ReplacementRebuildStatusState) -> bool {
        self.state == state
            || matches!(
                (self.state, state),
                (
                    ReplacementRebuildStatusState::Pending,
                    ReplacementRebuildStatusState::Resuming
                ) | (
                    ReplacementRebuildStatusState::Resuming,
                    ReplacementRebuildStatusState::Pending
                )
            )
    }

    fn result(&self, complete: bool) -> DeviceReplacementResult {
        let detach_decision = if complete
            && self.state == ReplacementRebuildStatusState::Completed
            && self.evidence_stable
        {
            ReplacementDetachDecision::SafeToDetach
        } else {
            ReplacementDetachDecision::UnsafeToDetach
        };
        DeviceReplacementResult {
            old_path: self.old_path.clone(),
            new_path: self.new_path.clone(),
            old_device_guid: self.old_device_guid,
            new_device_guid: self.new_device_guid,
            topology_generation: self.topology_epoch,
            objects_total: self.total_subjects,
            objects_rebuilt: self.subjects_completed,
            objects_failed: self.subjects_failed,
            verified_receipt_count: self.verified_receipt_count,
            bytes_rebuilt: self.bytes_rebuilt,
            state: self.state,
            detach_decision,
            remanence_treatment: ReplacementRemanenceTreatment::from_detach_decision(
                detach_decision,
            ),
            topology_commit_pending: !complete,
            complete,
        }
    }
}

const DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V2: &[u8; 8] = b"TFSDRP2\0";
const DEVICE_REPLACEMENT_EVIDENCE_CHECKSUM_LEN: usize = 32;
const DEVICE_REPLACEMENT_EVIDENCE_STABLE_FLAG: u8 = 1;

fn invalid_device_replacement_evidence() -> StoreError {
    StoreError::InvalidOptions {
        reason: "device replacement evidence is corrupt or unverifiable",
    }
}

fn replacement_evidence_state_code(state: ReplacementRebuildStatusState) -> u8 {
    match state {
        ReplacementRebuildStatusState::Pending => 0,
        ReplacementRebuildStatusState::Resuming => 1,
        ReplacementRebuildStatusState::Completed => 2,
        ReplacementRebuildStatusState::Refused => 3,
    }
}

fn replacement_evidence_state_from_code(code: u8) -> Option<ReplacementRebuildStatusState> {
    match code {
        0 => Some(ReplacementRebuildStatusState::Pending),
        1 => Some(ReplacementRebuildStatusState::Resuming),
        2 => Some(ReplacementRebuildStatusState::Completed),
        3 => Some(ReplacementRebuildStatusState::Refused),
        _ => None,
    }
}

fn encode_device_replacement_evidence(
    evidence: &DeviceReplacementEvidenceMarker,
) -> Result<Vec<u8>> {
    let old_path = evidence.old_path.as_os_str().as_bytes();
    let new_path = evidence.new_path.as_os_str().as_bytes();
    let old_path_len =
        u32::try_from(old_path.len()).map_err(|_| invalid_device_replacement_evidence())?;
    let new_path_len =
        u32::try_from(new_path.len()).map_err(|_| invalid_device_replacement_evidence())?;
    let device_index =
        u32::try_from(evidence.device_index).map_err(|_| invalid_device_replacement_evidence())?;
    let completed_or_failed = evidence
        .subjects_completed
        .checked_add(evidence.subjects_failed)
        .ok_or_else(invalid_device_replacement_evidence)?;
    if old_path.is_empty()
        || new_path.is_empty()
        || old_path == new_path
        || evidence.old_device_guid == evidence.new_device_guid
        || evidence.topology_epoch == 0
        || completed_or_failed > evidence.total_subjects
        || evidence.verified_receipt_count < evidence.subjects_completed
        || (evidence.evidence_stable
            && (evidence.subjects_completed != evidence.total_subjects
                || evidence.subjects_failed != 0
                || evidence.verified_receipt_count < evidence.total_subjects))
        || (evidence.state == ReplacementRebuildStatusState::Completed && !evidence.evidence_stable)
    {
        return Err(invalid_device_replacement_evidence());
    }

    let mut encoded = Vec::with_capacity(
        DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V2.len()
            + 16 * 3
            + std::mem::size_of::<u64>() * 6
            + std::mem::size_of::<u32>() * 3
            + 2
            + old_path.len()
            + new_path.len()
            + DEVICE_REPLACEMENT_EVIDENCE_CHECKSUM_LEN,
    );
    encoded.extend_from_slice(DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V2);
    encoded.extend_from_slice(&evidence.pool_guid);
    encoded.extend_from_slice(&evidence.old_device_guid);
    encoded.extend_from_slice(&evidence.new_device_guid);
    encoded.extend_from_slice(&evidence.topology_epoch.to_le_bytes());
    encoded.extend_from_slice(&device_index.to_le_bytes());
    encoded.push(replacement_evidence_state_code(evidence.state));
    encoded.push(if evidence.evidence_stable {
        DEVICE_REPLACEMENT_EVIDENCE_STABLE_FLAG
    } else {
        0
    });
    encoded.extend_from_slice(&evidence.total_subjects.to_le_bytes());
    encoded.extend_from_slice(&evidence.subjects_completed.to_le_bytes());
    encoded.extend_from_slice(&evidence.subjects_failed.to_le_bytes());
    encoded.extend_from_slice(&evidence.verified_receipt_count.to_le_bytes());
    encoded.extend_from_slice(&evidence.bytes_rebuilt.to_le_bytes());
    encoded.extend_from_slice(&old_path_len.to_le_bytes());
    encoded.extend_from_slice(&new_path_len.to_le_bytes());
    encoded.extend_from_slice(old_path);
    encoded.extend_from_slice(new_path);
    let checksum = blake3::hash(&encoded);
    encoded.extend_from_slice(checksum.as_bytes());
    Ok(encoded)
}

fn decode_device_replacement_evidence(encoded: &[u8]) -> Result<DeviceReplacementEvidenceMarker> {
    let decoded = (|| -> Option<DeviceReplacementEvidenceMarker> {
        let checksum_input_len = encoded
            .len()
            .checked_sub(DEVICE_REPLACEMENT_EVIDENCE_CHECKSUM_LEN)?;
        let (checksum_input, checksum) = encoded.split_at(checksum_input_len);
        if blake3::hash(checksum_input).as_bytes() != checksum {
            return None;
        }

        let mut cursor = ReceiptCursor::new(checksum_input);
        if cursor.take(DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V2.len())?
            != DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V2
        {
            return None;
        }
        let pool_guid = cursor.array()?;
        let old_device_guid = cursor.array()?;
        let new_device_guid = cursor.array()?;
        let topology_epoch = u64::from_le_bytes(cursor.array()?);
        let device_index = u32::from_le_bytes(cursor.array()?) as usize;
        let state = replacement_evidence_state_from_code(cursor.u8()?)?;
        let flags = cursor.u8()?;
        if flags & !DEVICE_REPLACEMENT_EVIDENCE_STABLE_FLAG != 0 {
            return None;
        }
        let total_subjects = u64::from_le_bytes(cursor.array()?);
        let subjects_completed = u64::from_le_bytes(cursor.array()?);
        let subjects_failed = u64::from_le_bytes(cursor.array()?);
        let verified_receipt_count = u64::from_le_bytes(cursor.array()?);
        let bytes_rebuilt = u64::from_le_bytes(cursor.array()?);
        let old_path_len = u32::from_le_bytes(cursor.array()?) as usize;
        let new_path_len = u32::from_le_bytes(cursor.array()?) as usize;
        if old_path_len == 0 || new_path_len == 0 {
            return None;
        }
        let old_path = PathBuf::from(OsString::from_vec(cursor.take(old_path_len)?.to_vec()));
        let new_path = PathBuf::from(OsString::from_vec(cursor.take(new_path_len)?.to_vec()));
        if !cursor.is_finished() {
            return None;
        }

        Some(DeviceReplacementEvidenceMarker {
            pool_guid,
            old_device_guid,
            new_device_guid,
            topology_epoch,
            device_index,
            old_path,
            new_path,
            total_subjects,
            subjects_completed,
            subjects_failed,
            verified_receipt_count,
            bytes_rebuilt,
            evidence_stable: flags & DEVICE_REPLACEMENT_EVIDENCE_STABLE_FLAG != 0,
            state,
        })
    })()
    .ok_or_else(invalid_device_replacement_evidence)?;

    // Reuse the encoder's semantic checks, not only its byte-shape checks.
    encode_device_replacement_evidence(&decoded)?;
    Ok(decoded)
}

fn replacement_evidence_matches_topology(
    evidence: &DeviceReplacementEvidenceMarker,
    device_guids: &[[u8; 16]],
    topology_generation: u64,
) -> bool {
    match device_guids.get(evidence.device_index) {
        Some(guid) if *guid == evidence.old_device_guid => {
            !device_guids.contains(&evidence.new_device_guid)
                && checked_successor_topology_generation(topology_generation)
                    == Some(evidence.topology_epoch)
        }
        Some(guid) if *guid == evidence.new_device_guid => {
            !device_guids.contains(&evidence.old_device_guid)
                && evidence.topology_epoch == topology_generation
        }
        _ => false,
    }
}

fn validate_label_lifecycle_topology(
    pool_guid: [u8; 16],
    durable_device_guids: &[[u8; 16]],
    topology_generation: u64,
    lifecycle: Option<&PoolLifecycleLabelRecord>,
) -> Result<()> {
    let Some(lifecycle) = lifecycle else {
        return Ok(());
    };
    match lifecycle.kind {
        pool_label::PoolLifecycleKindV1::Clear => Ok(()),
        pool_label::PoolLifecycleKindV1::DeviceRemoval => {
            let marker = decode_device_removal_marker(&lifecycle.payload)?;
            if marker.pool_guid != pool_guid {
                return Err(StoreError::InvalidOptions {
                    reason: "device removal label intent belongs to a different pool",
                });
            }
            if durable_device_guids.get(marker.target_index) != Some(&marker.target_guid)
                || checked_successor_topology_generation(topology_generation)
                    != Some(marker.successor_topology_generation)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "device removal label intent does not match the durable topology",
                });
            }
            Ok(())
        }
        pool_label::PoolLifecycleKindV1::DeviceReplacement => {
            let evidence = decode_device_replacement_evidence(&lifecycle.payload)?;
            if evidence.pool_guid != pool_guid {
                return Err(StoreError::InvalidOptions {
                    reason: "device replacement label intent belongs to a different pool",
                });
            }
            if !replacement_evidence_matches_topology(
                &evidence,
                durable_device_guids,
                topology_generation,
            ) {
                return Err(StoreError::InvalidOptions {
                    reason: "device replacement evidence does not match the loaded topology",
                });
            }
            let loaded_guid = durable_device_guids.get(evidence.device_index).copied();
            if evidence.state == ReplacementRebuildStatusState::Completed
                && (!evidence.evidence_stable
                    || loaded_guid != Some(evidence.new_device_guid)
                    || evidence.topology_epoch != topology_generation)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "completed device replacement evidence does not match committed replacement topology",
                });
            }
            Ok(())
        }
    }
}

fn restore_device_replacement_evidence(pool: &mut Pool) -> Result<()> {
    let Some(lifecycle) = pool.label_lifecycle.as_ref() else {
        return Ok(());
    };
    if lifecycle.kind != pool_label::PoolLifecycleKindV1::DeviceReplacement {
        return Ok(());
    }
    let mut evidence = decode_device_replacement_evidence(&lifecycle.payload)?;
    if evidence.pool_guid != pool.pool_guid {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence belongs to a different pool",
        });
    }
    let loaded_guid = pool.device_guids.get(evidence.device_index).copied();
    let old_topology_loaded = loaded_guid == Some(evidence.old_device_guid);
    let new_topology_loaded = loaded_guid == Some(evidence.new_device_guid);
    if !replacement_evidence_matches_topology(&evidence, &pool.device_guids, pool.placement_epoch) {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence does not match the loaded topology",
        });
    }
    if let Some(current_path) = pool
        .devices
        .get(evidence.device_index)
        .map(|device| device.root().to_path_buf())
    {
        if old_topology_loaded {
            evidence.old_path = current_path;
        } else if new_topology_loaded {
            evidence.new_path = current_path;
        }
    }
    if evidence.state == ReplacementRebuildStatusState::Completed
        && (!new_topology_loaded
            || !evidence.evidence_stable
            || evidence.topology_epoch != pool.placement_epoch)
    {
        return Err(StoreError::InvalidOptions {
            reason: "completed device replacement evidence does not match committed replacement topology",
        });
    }
    if evidence.state.is_active() {
        pool.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::ReplacementResumeRequired,
        );
        if old_topology_loaded {
            // Receipt-backed replacement may have published newer successor
            // receipts on the survivor while the durable labels still select
            // the predecessor topology. Exclude the old member from strict
            // current-receipt selection, but retain it as authenticated
            // predecessor authority until mounted roots are reconciled.
            pool.allocation_fenced_device_guid = Some(evidence.old_device_guid);
        }
        evidence.state = ReplacementRebuildStatusState::Resuming;
    }
    pool.replacement_evidence = Some(evidence);
    Ok(())
}

/// Payload committed to redundant Pool labels for crash-safe device-removal
/// resume on the next Pool open.
const DEVICE_REMOVAL_MARKER_MAGIC_V3: &[u8; 8] = b"TFSDRM3\0";
const DEVICE_REMOVAL_MARKER_CHECKSUM_LEN: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceRemovalMarker {
    pool_guid: [u8; 16],
    target_index: usize,
    target_path: PathBuf,
    target_guid: [u8; 16],
    successor_topology_generation: u64,
}

fn invalid_device_removal_marker() -> StoreError {
    StoreError::InvalidOptions {
        reason: "device removal marker is corrupt or unverifiable",
    }
}

fn encode_device_removal_marker(
    pool_guid: [u8; 16],
    target_index: usize,
    target_path: &Path,
    target_guid: [u8; 16],
    successor_topology_generation: u64,
) -> Result<Vec<u8>> {
    let path = target_path.as_os_str().as_bytes();
    if path.is_empty() || successor_topology_generation == 0 {
        return Err(invalid_device_removal_marker());
    }
    let target_index = u32::try_from(target_index).map_err(|_| invalid_device_removal_marker())?;
    let path_len = u32::try_from(path.len()).map_err(|_| invalid_device_removal_marker())?;
    let mut encoded = Vec::with_capacity(
        DEVICE_REMOVAL_MARKER_MAGIC_V3.len()
            + pool_guid.len()
            + target_guid.len()
            + std::mem::size_of::<u32>() * 2
            + std::mem::size_of::<u64>()
            + path.len()
            + DEVICE_REMOVAL_MARKER_CHECKSUM_LEN,
    );
    encoded.extend_from_slice(DEVICE_REMOVAL_MARKER_MAGIC_V3);
    encoded.extend_from_slice(&pool_guid);
    encoded.extend_from_slice(&target_guid);
    encoded.extend_from_slice(&target_index.to_le_bytes());
    encoded.extend_from_slice(&successor_topology_generation.to_le_bytes());
    encoded.extend_from_slice(&path_len.to_le_bytes());
    encoded.extend_from_slice(path);
    let checksum = blake3::hash(&encoded);
    encoded.extend_from_slice(checksum.as_bytes());
    Ok(encoded)
}

fn decode_device_removal_marker(encoded: &[u8]) -> Result<DeviceRemovalMarker> {
    let decoded = (|| -> Option<DeviceRemovalMarker> {
        let mut cursor = ReceiptCursor::new(encoded);
        if cursor.take(DEVICE_REMOVAL_MARKER_MAGIC_V3.len())? != DEVICE_REMOVAL_MARKER_MAGIC_V3 {
            return None;
        }
        let pool_guid = cursor.array()?;
        let target_guid = cursor.array()?;
        let target_index = u32::from_le_bytes(cursor.array()?) as usize;
        let successor_topology_generation = u64::from_le_bytes(cursor.array()?);
        let path_len = u32::from_le_bytes(cursor.array()?) as usize;
        if path_len == 0 || successor_topology_generation == 0 {
            return None;
        }
        let target_path = PathBuf::from(OsString::from_vec(cursor.take(path_len)?.to_vec()));
        let checksum = cursor.array::<DEVICE_REMOVAL_MARKER_CHECKSUM_LEN>()?;
        if !cursor.is_finished() {
            return None;
        }
        let checksum_input_len = encoded
            .len()
            .checked_sub(DEVICE_REMOVAL_MARKER_CHECKSUM_LEN)?;
        if blake3::hash(&encoded[..checksum_input_len]).as_bytes() != &checksum {
            return None;
        }
        Some(DeviceRemovalMarker {
            pool_guid,
            target_index,
            target_path,
            target_guid,
            successor_topology_generation,
        })
    })();

    decoded.ok_or_else(invalid_device_removal_marker)
}

fn validate_read_only_lifecycle_state(
    durable_device_guids: &[[u8; 16]],
    topology_generation: u64,
    lifecycle: Option<&PoolLifecycleLabelRecord>,
) -> Result<()> {
    let Some(lifecycle) = lifecycle else {
        return Ok(());
    };
    if lifecycle.kind == pool_label::PoolLifecycleKindV1::Clear {
        return Ok(());
    }
    if lifecycle.kind == pool_label::PoolLifecycleKindV1::DeviceRemoval {
        return Err(StoreError::InvalidOptions {
            reason: "read-only pool import refuses pending device removal",
        });
    }
    let evidence = decode_device_replacement_evidence(&lifecycle.payload)?;
    let loaded_guid = durable_device_guids.get(evidence.device_index).copied();
    let new_topology_loaded = loaded_guid == Some(evidence.new_device_guid);
    if evidence.state == ReplacementRebuildStatusState::Completed
        && evidence.evidence_stable
        && new_topology_loaded
        && evidence.topology_epoch == topology_generation
    {
        return Ok(());
    }
    Err(StoreError::InvalidOptions {
        reason: "read-only pool import refuses unresolved device replacement",
    })
}

fn restore_device_removal_evidence(pool: &mut Pool) -> Result<()> {
    let Some(lifecycle) = pool.label_lifecycle.as_ref() else {
        return Ok(());
    };
    if lifecycle.kind != pool_label::PoolLifecycleKindV1::DeviceRemoval {
        return Ok(());
    }
    let mut marker = decode_device_removal_marker(&lifecycle.payload)?;
    if marker.pool_guid != pool.pool_guid {
        return Err(StoreError::InvalidOptions {
            reason: "device removal label intent belongs to a different pool",
        });
    }
    if pool.durable_device_guids.get(marker.target_index) != Some(&marker.target_guid)
        || pool.device_guids.get(marker.target_index) != Some(&marker.target_guid)
        || checked_successor_topology_generation(pool.placement_epoch)
            != Some(marker.successor_topology_generation)
    {
        return Err(StoreError::InvalidOptions {
            reason: "device removal label intent does not match the durable topology",
        });
    }
    marker.target_path = pool
        .devices
        .get(marker.target_index)
        .ok_or(StoreError::InvalidOptions {
            reason: "device removal label intent target is missing",
        })?
        .root()
        .to_path_buf();
    pool.device_removal_marker = Some(marker);
    Ok(())
}

/// Check for a pending device removal marker and finish only an already
/// committed reduced topology.
///
/// A still-attached target is deliberately left for the mounted owner. Pool
/// relocation rotates placement receipt generations, and only the filesystem
/// owner can durably advance receipt references embedded in content manifests
/// before the target is detached.
fn resume_device_removal_if_pending(pool: &mut Pool) -> Result<()> {
    if let Some(marker) = pool.device_removal_marker.clone() {
        if marker.pool_guid != pool.pool_guid {
            return Err(StoreError::InvalidOptions {
                reason: "device removal label intent belongs to a different pool",
            });
        }
        let mut unique_device_guids = BTreeSet::new();
        if pool.device_guids.len() != pool.devices.len()
            || !pool
                .device_guids
                .iter()
                .copied()
                .all(|guid| unique_device_guids.insert(guid))
        {
            // Preserve the marker when topology identity cannot be trusted.
            return Ok(());
        }
        if pool.device_guids.get(marker.target_index) != Some(&marker.target_guid)
            || pool.devices.get(marker.target_index).is_none()
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal label intent target is missing or mismatched",
            });
        }
        pool.allocation_fenced_device_guid = Some(marker.target_guid);
    }
    Ok(())
}

fn placement_receipt_proves_device_evacuation(
    pool: &Pool,
    receipt: &PlacementReceipt,
    expected_payload: &[u8],
    payload_digest: [u8; 32],
    removed_device_guid: [u8; 16],
) -> bool {
    receipt.payload_digest == payload_digest
        && receipt.payload_len == expected_payload.len() as u64
        && receipt.planner_replay_receipt.is_some()
        && !receipt.targets.is_empty()
        && receipt
            .targets
            .iter()
            .all(|target| target.device_guid != removed_device_guid)
        && planner_replay_receipt_matches_receipt(receipt)
        && matches!(
            pool.get_with_receipt(receipt),
            Ok(Some(payload)) if payload.as_slice() == expected_payload
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptGenerationHighWater {
    pool_guid: [u8; 16],
    reserved_through: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptGenerationAuthorityState {
    Converged,
    ReservationPending { from: u64, through: u64 },
    ReplacementResumeRequired,
    RemovalTopologyCommitRequired,
    RecoveryRequired,
}

fn receipt_generation_high_water_key() -> ObjectKey {
    crate::pool_receipt_generation_high_water_key()
}

fn encode_receipt_generation_high_water(marker: ReceiptGenerationHighWater) -> [u8; 64] {
    let mut encoded = [0u8; RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN];
    encoded[..8].copy_from_slice(&RECEIPT_GENERATION_HIGH_WATER_MAGIC);
    encoded[8..24].copy_from_slice(&marker.pool_guid);
    encoded[24..32].copy_from_slice(&marker.reserved_through.to_le_bytes());
    let checksum = blake3::hash(&encoded[..32]);
    encoded[32..].copy_from_slice(checksum.as_bytes());
    encoded
}

fn decode_receipt_generation_high_water(encoded: &[u8]) -> Result<ReceiptGenerationHighWater> {
    if encoded.len() != RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water marker has an invalid length",
        });
    }
    if encoded[..8] != RECEIPT_GENERATION_HIGH_WATER_MAGIC {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water marker has invalid magic",
        });
    }
    if encoded[32..] != *blake3::hash(&encoded[..32]).as_bytes() {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water marker checksum mismatch",
        });
    }

    let mut pool_guid = [0u8; 16];
    pool_guid.copy_from_slice(&encoded[8..24]);
    Ok(ReceiptGenerationHighWater {
        pool_guid,
        reserved_through: u64::from_le_bytes(encoded[24..32].try_into().unwrap()),
    })
}

fn read_receipt_generation_high_water(
    device: &Device,
) -> Result<Option<ReceiptGenerationHighWater>> {
    device
        .get(receipt_generation_high_water_key())?
        .map(|encoded| decode_receipt_generation_high_water(&encoded))
        .transpose()
}

fn require_receipt_generation_high_water(
    device: &Device,
    pool_guid: [u8; 16],
) -> Result<ReceiptGenerationHighWater> {
    let marker = read_receipt_generation_high_water(device)?.ok_or(StoreError::InvalidOptions {
        reason: "placement receipt generation high-water marker is missing",
    })?;
    if marker.pool_guid != pool_guid {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water marker belongs to another pool",
        });
    }
    Ok(marker)
}

fn receipt_generation_high_water_for_devices(
    devices: &[Device],
    pool_guid: [u8; 16],
) -> Result<u64> {
    let mut expected = None;
    for device in devices {
        let marker = require_receipt_generation_high_water(device, pool_guid)?;
        match expected {
            Some(reserved_through) if reserved_through != marker.reserved_through => {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "placement receipt generation high-water markers conflict across devices",
                });
            }
            None => expected = Some(marker.reserved_through),
            Some(_) => {}
        }
    }
    expected.ok_or(StoreError::InvalidOptions {
        reason: "placement receipt generation high-water authority has no devices",
    })
}

fn max_valid_placement_receipt_generation(devices: &[Device]) -> Result<u64> {
    Ok(discover_placement_receipt_inventory(devices)?.max_generation)
}

fn validate_receipts_within_generation_high_water(
    devices: &[Device],
    reserved_through: u64,
) -> Result<()> {
    if max_valid_placement_receipt_generation(devices)? > reserved_through {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation exceeds durable high-water authority",
        });
    }
    Ok(())
}

fn verify_receipt_generation_high_water_copy(
    device: &Device,
    expected: ReceiptGenerationHighWater,
) -> Result<()> {
    if require_receipt_generation_high_water(device, expected.pool_guid)? != expected {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water publication did not converge",
        });
    }
    Ok(())
}

fn sync_receipt_generation_high_water_devices(devices: &mut [Device]) -> Result<()> {
    let mut first_error = None;
    for device in devices {
        if let Err(error) = device.sync_strict_pool_authority() {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn initialize_receipt_generation_high_water(
    devices: &mut [Device],
    pool_guid: [u8; 16],
) -> Result<u64> {
    if devices.is_empty() {
        return Err(StoreError::InvalidOptions {
            reason: "pool receipt generation authority requires at least one device",
        });
    }
    if devices.iter().any(Device::has_any_physical_key) {
        return Err(StoreError::InvalidOptions {
            reason: "new pool receipt generation authority requires empty devices",
        });
    }

    let marker = ReceiptGenerationHighWater {
        pool_guid,
        reserved_through: 0,
    };
    let key = receipt_generation_high_water_key();
    let encoded = encode_receipt_generation_high_water(marker);
    for device in devices.iter_mut() {
        device.put_pool_internal(key, &encoded)?;
    }
    sync_receipt_generation_high_water_devices(devices)?;
    for device in devices.iter() {
        verify_receipt_generation_high_water_copy(device, marker)?;
    }
    Ok(marker.reserved_through)
}

fn validate_fresh_pool_bootstrap_marker(
    inspection: &BlockStoreBootstrapInspection,
    pool_guid: [u8; 16],
) -> Result<bool> {
    let Some((key, payload)) = inspection.record.as_ref() else {
        return Ok(false);
    };
    if *key != receipt_generation_high_water_key() {
        return Err(StoreError::InvalidOptions {
            reason: "fresh Pool bootstrap contains an unexpected object key",
        });
    }
    let marker = decode_receipt_generation_high_water(payload)?;
    if marker.pool_guid != pool_guid || marker.reserved_through != 0 {
        return Err(StoreError::InvalidOptions {
            reason: "fresh Pool bootstrap marker is foreign or already used",
        });
    }
    Ok(true)
}

fn inspect_pool_store_bootstrap(
    config: &mut PoolBootstrapConfig,
) -> Result<Vec<BlockStoreBootstrapInspection>> {
    if config.members.is_empty() {
        return Err(StoreError::InvalidOptions {
            reason: "fresh Pool bootstrap requires at least one labelled member",
        });
    }

    let expected_count =
        u32::try_from(config.members.len()).map_err(|_| StoreError::InvalidOptions {
            reason: "fresh Pool bootstrap member count exceeds u32",
        })?;
    let mut seen_guids = BTreeSet::new();
    let mut inspections = Vec::with_capacity(config.members.len());
    for (index, member) in config.members.iter_mut().enumerate() {
        if member.device_index != index as u32 || member.device_index >= expected_count {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap member order is not exact",
            });
        }
        if !member.backing.is_byte_addressable_pool_member() {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap requires byte-addressable members",
            });
        }
        if !seen_guids.insert(member.device_guid) {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap contains duplicate device GUIDs",
            });
        }
        if member.expected_label.pool_guid != config.pool_guid
            || member.expected_label.device_guid != member.device_guid
            || member.expected_label.device_index != member.device_index
            || member.expected_label.device_count != expected_count
            || member.expected_label.device_capacity_bytes != member.capacity_bytes
        {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap expected label does not match member topology",
            });
        }
        let layout = decode_device_layout_v1(&member.device_layout_v1).map_err(|_| {
            StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap DeviceLayoutV1 is invalid",
            }
        })?;
        if layout.device_size_bytes != member.capacity_bytes {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap layout capacity does not match member",
            });
        }
        validate_device_layout_policy_record(&layout)?;

        let actual_capacity =
            member
                .file
                .seek(SeekFrom::End(0))
                .map_err(|source| StoreError::Io {
                    operation: "pool_bootstrap_member_capacity",
                    path: member.path.clone(),
                    source,
                })?;
        if actual_capacity != member.capacity_bytes {
            return Err(StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap member capacity changed after label inspection",
            });
        }
        let identity = BlockStoreIdentity {
            pool_guid: config.pool_guid,
            device_guid: member.device_guid,
        };
        let inspection = LocalObjectStore::inspect_open_block_device_bootstrap(
            &mut member.file,
            &member.path,
            member.capacity_bytes,
        )?;
        if let Some(actual) = inspection.identity {
            if actual != identity {
                return Err(StoreError::InvalidOptions {
                    reason: "fresh Pool bootstrap Store identity is foreign",
                });
            }
        }
        validate_fresh_pool_bootstrap_marker(&inspection, config.pool_guid)?;
        if !member.label_was_present
            && (inspection.identity.is_some() || inspection.record.is_some())
        {
            return Err(StoreError::InvalidOptions {
                reason: "blank member labels conflict with existing Pool Store bootstrap state",
            });
        }
        inspections.push(inspection);
    }
    Ok(inspections)
}

/// Prove that every target Store region is blank or one exact fresh retry.
///
/// This is the creator's read-only admission pass before it publishes any pool
/// label.  It does not initialize, repair, or otherwise mutate media.
pub fn preflight_labelled_pool_bootstrap(
    mut config: PoolBootstrapConfig,
) -> Result<PoolBootstrapAdmission> {
    let inspections = inspect_pool_store_bootstrap(&mut config)?;
    Ok(PoolBootstrapAdmission {
        config,
        inspections,
    })
}

fn validate_pool_bootstrap_labels(config: &mut PoolBootstrapConfig) -> Result<()> {
    for member in &mut config.members {
        for offset in [
            0,
            member.capacity_bytes - pool_label::POOL_LABEL_SIZE as u64,
        ] {
            let mut actual = vec![0u8; pool_label::POOL_LABEL_SIZE];
            member
                .file
                .seek(SeekFrom::Start(offset))
                .and_then(|_| member.file.read_exact(&mut actual))
                .map_err(|source| StoreError::Io {
                    operation: "pool_bootstrap_read_label",
                    path: member.path.clone(),
                    source,
                })?;
            let decoded =
                pool_label::decode_label(&actual).map_err(|_| StoreError::InvalidOptions {
                    reason: "fresh Pool bootstrap label is corrupt",
                })?;
            let layout_bytes = pool_label::decode_device_layout_v1_bytes(&actual)
                .map_err(|_| StoreError::InvalidOptions {
                    reason: "fresh Pool bootstrap label layout sidecar is corrupt",
                })?
                .ok_or(StoreError::InvalidOptions {
                    reason: "fresh Pool bootstrap label lacks DeviceLayoutV1",
                })?;
            decode_device_layout_v1(&layout_bytes).map_err(|_| StoreError::InvalidOptions {
                reason: "fresh Pool bootstrap label DeviceLayoutV1 is invalid",
            })?;
            if decoded != member.expected_label || layout_bytes != member.device_layout_v1 {
                return Err(StoreError::InvalidOptions {
                    reason: "fresh Pool bootstrap label does not match the exact intended topology",
                });
            }
        }
    }
    Ok(())
}

/// Initialize the immutable Store headers and zero-generation receipt marker
/// for one already-labelled fresh Pool topology.
///
/// Every member is inspected before the first mutation.  Retry accepts only a
/// missing header, a matching immutable header, and an optional exact
/// same-Pool zero-generation marker.  Store inspection proves that no other
/// physical record or non-zero tail exists.
pub fn bootstrap_labelled_pool(admission: PoolBootstrapAdmission) -> Result<()> {
    let PoolBootstrapAdmission {
        mut config,
        inspections,
    } = admission;
    validate_pool_bootstrap_labels(&mut config)?;

    for (member, inspection) in config.members.iter_mut().zip(&inspections) {
        if inspection.identity.is_none() {
            LocalObjectStore::initialize_open_block_device_bootstrap_after_inspection(
                &mut member.file,
                &member.path,
                BlockStoreIdentity {
                    pool_guid: config.pool_guid,
                    device_guid: member.device_guid,
                },
                inspection,
            )?;
        }
    }

    let mut devices = Vec::with_capacity(config.members.len());
    for member in config.members {
        let options = StoreOptions::default();
        let identity = BlockStoreIdentity {
            pool_guid: config.pool_guid,
            device_guid: member.device_guid,
        };
        let device = Device::open_single_block_writable_existing_file(
            member.file,
            member.path,
            options,
            identity,
        )?;
        let device = if let Some(encryption) = config.encryption.as_ref() {
            Device::open_encrypted(device, encryption.clone())
        } else {
            device
        };
        devices.push(device);
    }

    let marker = ReceiptGenerationHighWater {
        pool_guid: config.pool_guid,
        reserved_through: 0,
    };
    let encoded = encode_receipt_generation_high_water(marker);
    for (device, inspection) in devices.iter_mut().zip(&inspections) {
        if inspection.record.is_none() {
            device.put_pool_internal(receipt_generation_high_water_key(), &encoded)?;
        }
    }
    sync_receipt_generation_high_water_devices(&mut devices)?;
    for device in &devices {
        verify_receipt_generation_high_water_copy(device, marker)?;
    }
    Ok(())
}

fn publish_receipt_generation_high_water(
    devices: &mut [Device],
    pool_guid: [u8; 16],
    current_reserved_through: u64,
    new_reserved_through: u64,
) -> Result<()> {
    if new_reserved_through < current_reserved_through {
        return Err(StoreError::InvalidOptions {
            reason: "placement receipt generation high-water cannot move backward",
        });
    }

    let mut needs_write = Vec::with_capacity(devices.len());
    for device in devices.iter() {
        let marker = require_receipt_generation_high_water(device, pool_guid)?;
        if marker.reserved_through != current_reserved_through
            && marker.reserved_through != new_reserved_through
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "placement receipt generation high-water reservation conflicts across devices",
            });
        }
        needs_write.push(marker.reserved_through != new_reserved_through);
    }

    let marker = ReceiptGenerationHighWater {
        pool_guid,
        reserved_through: new_reserved_through,
    };
    let key = receipt_generation_high_water_key();
    let encoded = encode_receipt_generation_high_water(marker);
    for (device, needs_write) in devices.iter_mut().zip(needs_write) {
        if needs_write {
            device.put_pool_internal(key, &encoded)?;
        }
    }
    sync_receipt_generation_high_water_devices(devices)?;
    for device in devices.iter() {
        verify_receipt_generation_high_water_copy(device, marker)?;
    }
    Ok(())
}

fn seed_receipt_generation_high_water_on_candidate(
    device: &mut Device,
    pool_guid: [u8; 16],
    reserved_through: u64,
) -> Result<()> {
    let existing = read_receipt_generation_high_water(device)?;
    if let Some(marker) = existing {
        if marker.pool_guid != pool_guid {
            return Err(StoreError::InvalidOptions {
                reason: "candidate device receipt generation authority belongs to another pool",
            });
        }
        if marker.reserved_through > reserved_through {
            return Err(StoreError::InvalidOptions {
                reason: "candidate device receipt generation authority exceeds the active pool",
            });
        }
    }
    if max_valid_placement_receipt_generation(std::slice::from_ref(&*device))? > reserved_through {
        return Err(StoreError::InvalidOptions {
            reason: "candidate device contains a receipt beyond the active generation authority",
        });
    }

    if existing.is_some_and(|marker| marker.reserved_through == reserved_through) {
        device.sync_strict_pool_authority()?;
        return verify_receipt_generation_high_water_copy(
            device,
            ReceiptGenerationHighWater {
                pool_guid,
                reserved_through,
            },
        );
    }

    let marker = ReceiptGenerationHighWater {
        pool_guid,
        reserved_through,
    };
    let key = receipt_generation_high_water_key();
    let encoded = encode_receipt_generation_high_water(marker);
    device.put_pool_internal(key, &encoded)?;
    device.sync_strict_pool_authority()?;
    verify_receipt_generation_high_water_copy(device, marker)
}

fn install_pool_raw_mutation_guard(
    devices: &mut [Device],
    initially_allowed: bool,
) -> Arc<AtomicBool> {
    let allowed = Arc::new(AtomicBool::new(initially_allowed));
    for device in devices {
        device.install_pool_raw_mutation_guard(Arc::clone(&allowed));
    }
    allowed
}

#[derive(Clone)]
struct PoolLabelCopy {
    bytes: Vec<u8>,
    label: PoolLabelV1,
    topology_roster: Option<Vec<[u8; 16]>>,
    lifecycle: Option<PoolLifecycleLabelRecord>,
}

impl PoolLabelCopy {
    fn has_self_consistent_roster(&self) -> bool {
        let Some(roster) = self.topology_roster.as_ref() else {
            return false;
        };
        roster.len() == self.label.device_count as usize
            && roster.get(self.label.device_index as usize) == Some(&self.label.device_guid)
            && roster.iter().copied().collect::<BTreeSet<_>>().len() == roster.len()
    }

    fn same_topology_authority(&self, other: &Self) -> bool {
        self.label.pool_guid == other.label.pool_guid
            && self.label.topology_generation == other.label.topology_generation
            && self.label.device_count == other.label.device_count
            && self.label.pool_name_len == other.label.pool_name_len
            && self.label.pool_name == other.label.pool_name
            && self.label.redundancy_policy == other.label.redundancy_policy
            && self.topology_roster == other.topology_roster
            && self.lifecycle == other.lifecycle
    }

    fn same_topology(&self, other: &Self) -> bool {
        self.same_topology_authority(other) && self.label.pool_state == other.label.pool_state
    }

    fn lifecycle_sequence(&self) -> u64 {
        self.lifecycle.as_ref().map_or(0, |record| record.sequence)
    }
}

fn pool_state_transition_rank(state: PoolState) -> u8 {
    match state {
        PoolState::Destroyed => 2,
        PoolState::Active => 1,
        PoolState::Exported => 0,
    }
}

fn decode_pool_label_copy(bytes: Vec<u8>) -> Option<PoolLabelCopy> {
    let label = pool_label::decode_label(&bytes).ok()?;
    let topology_roster = pool_label::decode_topology_roster_v1(&bytes)
        .ok()?
        .and_then(|roster| {
            (0..roster.len())
                .map(|index| roster.member_guid(index))
                .collect::<Option<Vec<_>>>()
        });
    let lifecycle = pool_label::decode_pool_lifecycle_v1(&bytes)
        .ok()?
        .map(|record| PoolLifecycleLabelRecord {
            sequence: record.sequence(),
            kind: record.kind(),
            payload: record.payload().to_vec(),
        });
    Some(PoolLabelCopy {
        bytes,
        label,
        topology_roster,
        lifecycle,
    })
}

fn read_pool_label_copies(config: &DeviceConfig) -> Result<Vec<PoolLabelCopy>> {
    let device_root = device_root_path(config);
    if !config.backing.uses_fixed_offset_pool_labels() {
        let label_path = label_file_path(&device_root);
        return match fs::read(&label_path) {
            Ok(bytes) => Ok(decode_pool_label_copy(bytes).into_iter().collect()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(StoreError::Io {
                operation: "read_pool_label_copy",
                path: label_path,
                source,
            }),
        };
    }

    let mut file = fs::File::open(&device_root).map_err(|source| StoreError::Io {
        operation: "open_pool_label_copies",
        path: device_root.clone(),
        source,
    })?;
    let size = file
        .seek(SeekFrom::End(0))
        .map_err(|source| StoreError::Io {
            operation: "size_pool_label_copies",
            path: device_root.clone(),
            source,
        })?;
    let label_size = pool_label::POOL_LABEL_SIZE as u64;
    let mut copies = Vec::with_capacity(2);
    for offset in [0, size.saturating_sub(label_size)] {
        if size < label_size || (offset == 0 && !copies.is_empty()) {
            continue;
        }
        let mut bytes = vec![0; pool_label::POOL_LABEL_SIZE];
        if file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut bytes))
            .is_ok()
        {
            if let Some(copy) = decode_pool_label_copy(bytes) {
                copies.push(copy);
            }
        }
    }
    Ok(copies)
}

fn select_highest_complete_pool_topology(
    config: &PoolConfig,
) -> Result<Option<SelectedPoolTopology>> {
    let mut scanned = Vec::with_capacity(config.devices.len());
    for device_config in &config.devices {
        scanned.push((device_config, read_pool_label_copies(device_config)?));
    }
    let pool_guids = scanned
        .iter()
        .flat_map(|(_, copies)| copies.iter().map(|copy| copy.label.pool_guid))
        .collect::<BTreeSet<_>>();
    if pool_guids.len() != 1 {
        return Ok(None);
    }

    let mut complete = Vec::new();
    for (_, copies) in &scanned {
        for candidate in copies {
            if !candidate.has_self_consistent_roster() {
                continue;
            }
            let roster = candidate.topology_roster.as_ref().unwrap();
            let mut configs = Vec::with_capacity(roster.len());
            let mut selected = BTreeMap::new();
            let mut complete_candidate = true;
            for (index, guid) in roster.iter().enumerate() {
                let mut matching: Option<(&DeviceConfig, &PoolLabelCopy)> = None;
                for (device_config, path_copies) in &scanned {
                    if let Some(copy) = path_copies.iter().find(|copy| {
                        copy.same_topology(candidate)
                            && copy.label.device_guid == *guid
                            && copy.label.device_index == index as u32
                    }) {
                        if matching.is_some() {
                            complete_candidate = false;
                            break;
                        }
                        matching = Some((device_config, copy));
                    }
                }
                let Some((device_config, copy)) = matching else {
                    complete_candidate = false;
                    break;
                };
                configs.push(device_config.clone());
                selected.insert(device_root_path(device_config), copy.bytes.clone());
            }
            if complete_candidate && configs.len() == roster.len() {
                complete.push((candidate.clone(), configs, selected));
            }
        }
    }

    let Some(max_generation) = complete
        .iter()
        .map(|(candidate, _, _)| candidate.label.topology_generation)
        .max()
    else {
        return Ok(None);
    };
    let highest = complete
        .into_iter()
        .filter(|(candidate, _, _)| candidate.label.topology_generation == max_generation);
    let highest_generation = highest
        .clone()
        .map(|(candidate, _, _)| candidate.lifecycle_sequence())
        .max()
        .unwrap_or(0);
    let highest = highest
        .filter(|(candidate, _, _)| candidate.lifecycle_sequence() == highest_generation)
        .collect::<Vec<_>>();
    let lifecycle_authority = &highest[0].0;
    if highest
        .iter()
        .any(|(candidate, _, _)| !candidate.same_topology_authority(lifecycle_authority))
    {
        return Err(StoreError::InvalidOptions {
            reason:
                "conflicting complete pool topology or lifecycle authority at the same generation",
        });
    }
    // ACTIVE is the completed successor of EXPORTED during import, while
    // DESTROYED is terminal. A partial state transition has no complete
    // successor family and therefore continues selecting its predecessor.
    let state_rank = highest
        .iter()
        .map(|(candidate, _, _)| pool_state_transition_rank(candidate.label.pool_state))
        .max()
        .unwrap();
    let mut highest = highest.into_iter().filter(|(candidate, _, _)| {
        pool_state_transition_rank(candidate.label.pool_state) == state_rank
    });
    let (authority, configs, selected) = highest.next().unwrap();
    if highest.any(|(candidate, _, _)| !candidate.same_topology(&authority)) {
        return Err(StoreError::InvalidOptions {
            reason: "conflicting complete pool topology rosters at the same generation",
        });
    }
    Ok(Some((configs, selected)))
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

    fn refresh_raw_store_mutation_gate(&self) {
        let allowed = !self.read_only
            && !self.locked
            && self.next_placement_receipt_generation != 0
            && self.receipt_generation_authority_state
                == ReceiptGenerationAuthorityState::Converged;
        self.raw_store_mutation_allowed
            .store(allowed, Ordering::Release);
    }

    fn set_receipt_generation_authority_state(&mut self, state: ReceiptGenerationAuthorityState) {
        self.receipt_generation_authority_state = state;
        self.raw_store_mutation_allowed
            .store(false, Ordering::Release);
    }

    fn converge_receipt_generation_authority(&mut self) -> Result<()> {
        self.validate_loaded_receipt_generation_high_water()?;
        validate_receipts_within_generation_high_water(
            &self.devices,
            self.reserved_placement_receipt_generation_through,
        )?;
        if self.next_placement_receipt_generation == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation exhausted",
            });
        }
        self.receipt_generation_authority_state = ReceiptGenerationAuthorityState::Converged;
        self.refresh_raw_store_mutation_gate();
        Ok(())
    }

    /// Create a new pool from a configuration.
    ///
    /// Creates the root directory and initializes every device.
    pub fn create(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
        properties.redundancy_policy.ensure_available()?;
        if pool_config_has_label_authority(&config) {
            return Self::open(config, properties, options);
        }

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

        let identities: Vec<_> = device_guids
            .iter()
            .map(|device_guid| BlockStoreIdentity {
                pool_guid,
                device_guid: *device_guid,
            })
            .collect();
        let mut devices = open_candidate_devices(&config, options, &identities)?;
        let reserved_placement_receipt_generation_through =
            initialize_receipt_generation_high_water(&mut devices, pool_guid)?;
        let next_placement_receipt_generation = 1;
        let raw_store_mutation_allowed = install_pool_raw_mutation_guard(&mut devices, true);

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

        // Compute per-device layout records from the pool's layout policy.
        let device_layouts: Vec<DeviceLayoutV1> = devices
            .iter()
            .map(|d| {
                properties
                    .layout_policy
                    .compute(d.store().capacity_bytes())
                    .unwrap_or_else(|_| {
                        // Fall back to Slice0Small on any error.
                        DeviceLayoutPolicy::Slice0Small
                            .compute(d.store().capacity_bytes())
                            .expect("Slice0Small must succeed for non-zero device")
                    })
            })
            .collect();

        let expected_device_count = config.devices.len() as u32;
        let device_label_indices = (0..expected_device_count).collect();
        let mut pool = Self {
            config,
            properties,
            read_only: false,
            classes,
            devices,
            class_map,
            health,
            media_classes,
            write_allocator,
            device_class_policy,
            device_layout_stats,
            device_layouts,
            log_device,
            pool_guid,
            durable_device_guids: device_guids.clone(),
            device_guids,
            expected_device_count,
            device_label_indices,
            placement_epoch: 1,
            persisted_label_epoch: None,
            next_placement_receipt_generation,
            reserved_placement_receipt_generation_through,
            receipt_generation_authority_state: ReceiptGenerationAuthorityState::Converged,
            raw_store_mutation_allowed,
            pending_device_removal: None,
            device_removal_marker: None,
            allocation_fenced_device_guid: None,
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            replacement_evidence: None,
            label_lifecycle: None,
            allocator: None,
            locked: false,
            pending_deletions: BTreeMap::new(),
            #[cfg(test)]
            fail_post_publication_reclaim_attachment_once: false,
            #[cfg(test)]
            fail_pending_deletion_preflight_once: false,
            #[cfg(test)]
            fail_post_deletion_publication_cleanup_once: false,
            #[cfg(test)]
            fail_placement_receipt_verification_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_generation_allocation_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_reclaim_intent_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_receipt_publication_once: false,
        };

        pool.persist_active_labels_if_needed()?;

        // Resume interrupted device removal if a pending marker exists.
        resume_device_removal_if_pending(&mut pool)?;

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
        Self::open_with_mode(config, properties, options, PoolOpenMode::Writable)
    }

    /// Open an existing Pool topology for side-effect-free inspection.
    ///
    /// This import accepts a nonempty, label-consistent subset of the durable
    /// member set without renumbering the surviving members. It refuses
    /// unlabelled or inconsistent configured members and supports only
    /// byte-addressable block/regular-file devices. It never creates storage,
    /// opens an intent-log writer, or resumes device lifecycle work.
    pub fn open_read_only_existing(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
        Self::open_with_mode(config, properties, options, PoolOpenMode::ReadOnlyExisting)
    }

    fn open_with_mode(
        mut config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
        mode: PoolOpenMode,
    ) -> Result<Self> {
        let selected_label_bytes = if let Some((selected_configs, selected_labels)) =
            select_highest_complete_pool_topology(&config)?
        {
            config.devices = selected_configs;
            selected_labels
        } else {
            BTreeMap::new()
        };
        let mut properties = properties;
        if mode == PoolOpenMode::ReadOnlyExisting {
            if !config.root_path.is_dir() {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool import requires an existing metadata directory",
                });
            }
            if config.devices.is_empty() {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool import requires at least one configured device",
                });
            }
            for device in &config.devices {
                let DeviceKind::Block { path } = &device.kind else {
                    return Err(StoreError::InvalidOptions {
                        reason:
                            "read-only pool import supports only byte-addressable Block members",
                    });
                };
                if !device.backing.is_byte_addressable_pool_member() || device.path != *path {
                    return Err(StoreError::InvalidOptions {
                        reason: "read-only pool device path/backing configuration is inconsistent",
                    });
                }
            }
        }
        let mut pool_guid: Option<[u8; 16]> = None;
        let mut device_guids: Vec<[u8; 16]> = Vec::new();
        let mut label_health_states: Vec<(usize, u8, u64, u64, u64)> = Vec::new();
        let mut label_found = false;
        let mut labeled_device_count = 0usize;
        let mut label_redundancy_policy: Option<PoolRedundancyPolicy> = None;
        // Pool-level feature bitmasks captured from the first valid label
        // for post-import compatibility gating.
        let mut saved_features_incompat: u64 = 0;
        let mut saved_features_ro_compat: u64 = 0;
        let mut saved_features_valid = false;
        let mut label_is_encrypted = false;
        let mut topology_generation: Option<u64> = None;
        let mut label_device_layouts: Vec<DeviceLayoutV1> = Vec::new();
        let mut read_only_label_features: Option<(u64, u64, u64)> = None;
        let mut read_only_pool_state: Option<PoolState> = None;
        let mut read_only_device_guids = BTreeSet::new();
        let mut read_only_device_indices = BTreeSet::new();
        let mut expected_device_count: Option<u32> = None;
        let mut device_label_indices = Vec::with_capacity(config.devices.len());
        let mut durable_device_guids: Option<Vec<[u8; 16]>> = None;
        let mut topology_roster_label_count = 0usize;
        let mut selected_lifecycle: Option<PoolLifecycleLabelRecord> = None;
        let mut lifecycle_label_count = 0usize;

        // Attempt to read a label from each configured device path.
        for (configured_index, vc) in config.devices.iter().enumerate() {
            let device_root = device_root_path(vc);

            // Byte-addressable pool members have labels at fixed offset 0,
            // not in compatibility directory label files.
            let buf = if let Some(selected) = selected_label_bytes.get(&device_root) {
                selected.clone()
            } else if vc.backing.uses_fixed_offset_pool_labels() {
                match fs::File::open(&device_root) {
                    Ok(mut f) => {
                        use std::io::Read;
                        let mut raw = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
                        match f.read_exact(&mut raw) {
                            Ok(()) => raw,
                            Err(source) if mode == PoolOpenMode::ReadOnlyExisting => {
                                return Err(StoreError::Io {
                                    operation: "pool_read_only_read_label",
                                    path: device_root.clone(),
                                    source,
                                })
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(source) if mode == PoolOpenMode::ReadOnlyExisting => {
                        return Err(StoreError::Io {
                            operation: "pool_read_only_open_label",
                            path: device_root.clone(),
                            source,
                        })
                    }
                    Err(_) => continue,
                }
            } else {
                let label_path = label_file_path(&device_root);
                if !label_path.exists() {
                    if mode == PoolOpenMode::ReadOnlyExisting {
                        return Err(StoreError::InvalidOptions {
                            reason:
                                "read-only pool import requires a label on every configured device",
                        });
                    }
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
            let decoded_roster = pool_label::decode_topology_roster_v1(&buf).map_err(|_| {
                StoreError::InvalidOptions {
                    reason: "pool label topology roster is corrupt or unreadable",
                }
            })?;
            if let Some(roster) = decoded_roster {
                topology_roster_label_count += 1;
                let roster_guids = (0..roster.len())
                    .map(|index| {
                        roster.member_guid(index).ok_or(StoreError::InvalidOptions {
                            reason: "pool label topology roster member is unreadable",
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                match durable_device_guids.as_ref() {
                    Some(existing) if existing != &roster_guids => {
                        return Err(StoreError::InvalidOptions {
                            reason: "pool topology roster mismatch across labels",
                        });
                    }
                    None => durable_device_guids = Some(roster_guids),
                    Some(_) => {}
                }
            }
            let decoded_lifecycle = pool_label::decode_pool_lifecycle_v1(&buf).map_err(|_| {
                StoreError::InvalidOptions {
                    reason: "pool label lifecycle record is corrupt or unreadable",
                }
            })?;
            if let Some(record) = decoded_lifecycle {
                lifecycle_label_count += 1;
                let owned = PoolLifecycleLabelRecord {
                    sequence: record.sequence(),
                    kind: record.kind(),
                    payload: record.payload().to_vec(),
                };
                match selected_lifecycle.as_ref() {
                    Some(existing) if existing != &owned => {
                        return Err(StoreError::InvalidOptions {
                            reason: "pool lifecycle record mismatch across labels",
                        });
                    }
                    None => selected_lifecycle = Some(owned),
                    Some(_) => {}
                }
            }
            labeled_device_count += 1;
            if label.device_count == 0 || label.device_index >= label.device_count {
                return Err(StoreError::InvalidOptions {
                    reason: "pool label device index is outside the durable member set",
                });
            }
            match expected_device_count {
                Some(count) if count != label.device_count => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pool topology member count mismatch across labels",
                    });
                }
                None => expected_device_count = Some(label.device_count),
                Some(_) => {}
            }
            if mode == PoolOpenMode::Writable && label.device_count as usize != config.devices.len()
            {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology is missing or has extra configured members",
                });
            }
            if mode == PoolOpenMode::Writable && label.device_index as usize != configured_index {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology device order does not match labels",
                });
            }
            if mode == PoolOpenMode::ReadOnlyExisting
                && config.devices.len() > label.device_count as usize
            {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool topology has extra configured members",
                });
            }
            if !read_only_device_guids.insert(label.device_guid) {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology contains duplicate device GUIDs",
                });
            }
            if !read_only_device_indices.insert(label.device_index) {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology contains duplicate device indices",
                });
            }
            match topology_generation {
                Some(generation) if generation != label.topology_generation => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pool topology generation mismatch across devices",
                    });
                }
                _ => {}
            }
            if mode == PoolOpenMode::ReadOnlyExisting {
                let configured_name = config.name.as_bytes();
                let configured_name_len = configured_name.len().min(pool_label::POOL_NAME_MAX);
                if label.pool_name_len as usize != configured_name_len
                    || label.pool_name[..configured_name_len]
                        != configured_name[..configured_name_len]
                {
                    return Err(StoreError::InvalidOptions {
                        reason: "read-only pool name does not match device labels",
                    });
                }
                if label.device_class != runtime_class_to_label(Some(vc.class)) {
                    return Err(StoreError::InvalidOptions {
                        reason: "read-only pool device class does not match label",
                    });
                }
                let features = (
                    label.features_compat,
                    label.features_ro_compat,
                    label.features_incompat,
                );
                match read_only_label_features {
                    Some(existing) if existing != features => {
                        return Err(StoreError::InvalidOptions {
                            reason: "read-only pool feature flags mismatch across devices",
                        });
                    }
                    None => read_only_label_features = Some(features),
                    Some(_) => {}
                }
                match read_only_pool_state {
                    Some(existing) if existing != label.pool_state => {
                        return Err(StoreError::InvalidOptions {
                            reason: "read-only pool state mismatch across devices",
                        });
                    }
                    None => read_only_pool_state = Some(label.pool_state),
                    Some(_) => {}
                }
            }
            let layout_bytes = pool_label::decode_device_layout_v1_bytes(&buf).map_err(|_| {
                StoreError::InvalidOptions {
                    reason: "pool label DeviceLayoutV1 record is truncated",
                }
            })?;
            let layout_bytes = layout_bytes.ok_or(StoreError::InvalidOptions {
                reason: "pool label missing DeviceLayoutV1 record",
            })?;
            let device_layout =
                decode_device_layout_v1(&layout_bytes).map_err(|_| StoreError::InvalidOptions {
                    reason: "pool label DeviceLayoutV1 record is corrupt",
                })?;
            if mode == PoolOpenMode::ReadOnlyExisting {
                validate_read_only_label_geometry(&label, &device_layout)?;
            }
            let recovered_redundancy_policy =
                PoolRedundancyPolicy::from_label_policy(label.redundancy_policy);
            match label_redundancy_policy {
                None => label_redundancy_policy = Some(recovered_redundancy_policy),
                Some(existing) if existing != recovered_redundancy_policy => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pool redundancy policy mismatch across devices",
                    });
                }
                Some(_) => {}
            }
            device_guids.push(label.device_guid);
            device_label_indices.push(label.device_index);
            label_device_layouts.push(device_layout);
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
                    configured_index,
                    label.device_health,
                    label.device_read_errors,
                    label.device_write_errors,
                    label.device_checksum_errors,
                ));
            }
        }

        if label_found && labeled_device_count != config.devices.len() {
            return Err(StoreError::InvalidOptions {
                reason: "pool import requires a label on every configured device",
            });
        }
        if topology_roster_label_count != 0 && topology_roster_label_count != labeled_device_count {
            return Err(StoreError::InvalidOptions {
                reason: "pool topology roster presence mismatch across labels",
            });
        }
        if lifecycle_label_count != 0 && lifecycle_label_count != labeled_device_count {
            return Err(StoreError::InvalidOptions {
                reason: "pool lifecycle record presence mismatch across labels",
            });
        }

        let expected_device_count = expected_device_count.unwrap_or(config.devices.len() as u32);

        let durable_device_guids = match durable_device_guids {
            Some(roster) if roster.len() == expected_device_count as usize => roster,
            Some(_) => {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology roster member count does not match labels",
                })
            }
            None if config.devices.len() < expected_device_count as usize => {
                return Err(StoreError::InvalidOptions {
                    reason: "degraded pool import requires a durable topology roster",
                })
            }
            None => {
                let mut roster = vec![[0u8; 16]; expected_device_count as usize];
                for (&index, &guid) in device_label_indices.iter().zip(&device_guids) {
                    let slot =
                        roster
                            .get_mut(index as usize)
                            .ok_or(StoreError::InvalidOptions {
                                reason: "pool topology label index is outside the member roster",
                            })?;
                    *slot = guid;
                }
                roster
            }
        };

        if !label_found {
            if mode == PoolOpenMode::ReadOnlyExisting {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool import requires existing labels",
                });
            }
            // Legacy path: no labels present, create a fresh pool identity.
            return Self::create(config, properties, options);
        }

        if let Some(recovered_redundancy_policy) = label_redundancy_policy {
            if mode == PoolOpenMode::ReadOnlyExisting
                && properties.redundancy_policy != recovered_redundancy_policy
            {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool redundancy policy does not match device labels",
                });
            }
            properties.redundancy_policy = recovered_redundancy_policy;
        }
        properties.redundancy_policy.ensure_available()?;

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
        let selected_topology_generation = topology_generation.unwrap_or(1).max(1);
        validate_label_lifecycle_topology(
            pg,
            &durable_device_guids,
            selected_topology_generation,
            selected_lifecycle.as_ref(),
        )?;
        if mode == PoolOpenMode::ReadOnlyExisting {
            validate_read_only_lifecycle_state(
                &durable_device_guids,
                selected_topology_generation,
                selected_lifecycle.as_ref(),
            )?;
        }

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

        // Writable store open can repair segment tails and replay committed
        // object-store WAL. Accept the raw marker and the currently visible
        // receipt ceiling through a no-create, no-repair, no-replay topology
        // projection before any of those recovery mutations are possible.
        let preflight_reserved_through = if mode == PoolOpenMode::Writable {
            let identities: Vec<_> = device_guids
                .iter()
                .map(|device_guid| BlockStoreIdentity {
                    pool_guid: pg,
                    device_guid: *device_guid,
                })
                .collect();
            let preflight_devices = open_devices_preflight_existing(&config, options, &identities)?;
            let reserved_through =
                receipt_generation_high_water_for_devices(&preflight_devices, pg)?;
            if !locked {
                validate_receipts_within_generation_high_water(
                    &preflight_devices,
                    reserved_through,
                )?;
            }
            Some(reserved_through)
        } else {
            None
        };

        let classes: Vec<DeviceClass> = config.devices.iter().map(|vc| vc.class).collect();
        let class_map = build_class_map(&classes);
        let identities: Vec<_> = device_guids
            .iter()
            .map(|device_guid| BlockStoreIdentity {
                pool_guid: pg,
                device_guid: *device_guid,
            })
            .collect();
        let mut devices = match mode {
            PoolOpenMode::Writable => open_devices_existing(&config, options, &identities)?,
            PoolOpenMode::ReadOnlyExisting => {
                open_devices_read_only_existing(&config, options, &identities)?
            }
        };
        let reserved_placement_receipt_generation_through =
            receipt_generation_high_water_for_devices(&devices, pg)?;
        if preflight_reserved_through
            .is_some_and(|preflight| preflight != reserved_placement_receipt_generation_through)
        {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation high-water changed during pool import",
            });
        }
        // Without the key, placement receipts remain encrypted frames. The
        // raw-only high-water marker is still fully validated above, while
        // semantic receipt validation is deferred to a key-bearing reopen.
        // A locked import has no generation allocator and its raw mutation
        // gate remains closed, so deferral cannot publish or reuse a
        // generation.
        if !locked {
            validate_receipts_within_generation_high_water(
                &devices,
                reserved_placement_receipt_generation_through,
            )?;
        }
        let next_placement_receipt_generation = match mode {
            PoolOpenMode::Writable if !locked => reserved_placement_receipt_generation_through
                .checked_add(1)
                .unwrap_or(0),
            PoolOpenMode::Writable | PoolOpenMode::ReadOnlyExisting => 0,
        };
        let raw_store_mutation_allowed = install_pool_raw_mutation_guard(
            &mut devices,
            mode == PoolOpenMode::Writable && !locked && next_placement_receipt_generation != 0,
        );
        if label_device_layouts.len() != devices.len() {
            return Err(StoreError::InvalidOptions {
                reason: "pool label DeviceLayoutV1 count does not match devices",
            });
        }
        let device_layouts = config
            .devices
            .iter()
            .zip(devices.iter())
            .zip(label_device_layouts.iter())
            .map(|((device_config, device), layout)| {
                normalize_imported_device_layout(device_config, device, layout)
            })
            .collect::<Result<Vec<_>>>()?;

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
        let mut health = compute_health(&devices);
        if mode == PoolOpenMode::ReadOnlyExisting
            && devices.len() < expected_device_count as usize
            && health == PoolHealth::Online
        {
            health = PoolHealth::Degraded;
        }

        // A read-only inspection import must not create/open a writable log.
        let log_device = if mode == PoolOpenMode::Writable {
            open_log_device_for_devices(&config.devices)?
        } else {
            None
        };

        let mut pool = Self {
            config,
            properties,
            read_only: mode == PoolOpenMode::ReadOnlyExisting,
            classes,
            devices,
            class_map,
            health,
            media_classes,
            write_allocator,
            device_class_policy,
            device_layout_stats,
            device_layouts,
            log_device,
            pool_guid: pg,
            durable_device_guids,
            device_guids,
            expected_device_count,
            device_label_indices,
            placement_epoch: selected_topology_generation,
            persisted_label_epoch: Some(selected_topology_generation),
            next_placement_receipt_generation,
            reserved_placement_receipt_generation_through,
            receipt_generation_authority_state: ReceiptGenerationAuthorityState::Converged,
            raw_store_mutation_allowed,
            pending_device_removal: None,
            device_removal_marker: None,
            allocation_fenced_device_guid: None,
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            replacement_evidence: None,
            label_lifecycle: selected_lifecycle,
            allocator: None,
            locked,
            pending_deletions: BTreeMap::new(),
            #[cfg(test)]
            fail_post_publication_reclaim_attachment_once: false,
            #[cfg(test)]
            fail_pending_deletion_preflight_once: false,
            #[cfg(test)]
            fail_post_deletion_publication_cleanup_once: false,
            #[cfg(test)]
            fail_placement_receipt_verification_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_generation_allocation_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_reclaim_intent_once: false,
            #[cfg(test)]
            fail_replicated_repair_after_receipt_publication_once: false,
        };

        // Locked imports cannot decode encrypted placement or deletion
        // authority. They expose no data I/O or generation allocator, so
        // defer semantic discovery to the first key-bearing reopen just as we
        // already do for placement receipts above.
        if !pool.locked {
            pool.pending_deletions = discover_pending_deletions(
                &pool.devices,
                &pool.device_guids,
                pool.pool_guid,
                pool.reserved_placement_receipt_generation_through,
            )?;
        }

        if mode == PoolOpenMode::Writable && !pool.locked {
            pool.reconcile_pending_deletions_on_open();
        }
        if mode == PoolOpenMode::Writable {
            restore_device_removal_evidence(&mut pool)?;
            restore_device_replacement_evidence(&mut pool)?;
            // Resume interrupted device removal if a pending marker exists.
            resume_device_removal_if_pending(&mut pool)?;
        }

        Ok(pool)
    }

    /// Export the pool: write PoolLabelV1 labels to every device root
    /// directory with `PoolState::Exported`.  After a successful export,
    /// the pool can be re-opened via [`Pool::open`] and the labels will
    /// be validated.
    pub fn export(&self) -> Result<()> {
        self.ensure_writable("pool export")?;
        self.validate_receipt_generation_high_water()?;
        // Flush the log device before export.
        if let Some(ref log_device) = self.log_device {
            log_device.commit()?;
        }
        for (i, device) in self.devices.iter().enumerate() {
            let config = self
                .config
                .devices
                .get(i)
                .ok_or(StoreError::InvalidOptions {
                    reason: "pool export missing device config",
                })?;
            let label = self.build_label(i, device);
            write_pool_label_with_lifecycle(
                config,
                label,
                self.device_layouts.get(i),
                &self.device_guids,
                self.label_lifecycle.as_ref(),
                "pool_export_write_label",
            )?;
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

    /// The exact topology configuration used to open this Pool.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    fn ensure_writable(&self, operation: &'static str) -> Result<()> {
        if self.read_only {
            Err(StoreError::ReadOnly { operation })
        } else {
            Ok(())
        }
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

    /// Per-device layout records, indexed by device position.
    #[must_use]
    pub fn device_layouts(&self) -> &[DeviceLayoutV1] {
        &self.device_layouts
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
        self.build_label_with_state(device_index, device, PoolState::Exported)
    }

    /// Build a PoolLabelV1 for a single device with the requested pool state.
    fn build_label_with_state(
        &self,
        device_index: usize,
        device: &Device,
        pool_state: PoolState,
    ) -> PoolLabelV1 {
        let device_guid = self.device_guid_for_index(device_index);

        let device_count = self.devices.len() as u32;

        PoolLabelV1 {
            pool_guid: self.pool_guid,
            device_guid,
            pool_name_len: self.config.name.len().min(255) as u16,
            pool_state,
            device_index: device_index as u32,
            topology_generation: self.placement_epoch,
            device_count,
            device_class: runtime_class_to_label(self.classes.get(device_index).copied()),
            device_capacity_bytes: device.store().capacity_bytes(),
            system_area_pointer: self
                .device_layouts
                .get(device_index)
                .map_or(0, |layout| layout.system_area_offset),
            system_area_size: self
                .device_layouts
                .get(device_index)
                .map_or(0, |layout| layout.system_area_len),
            features_compat: features::DEVICE_HEALTH_STATE
                | features::DEVICE_LAYOUT_V1
                | features::TOPOLOGY_ROSTER_V1,
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
            redundancy_policy: self.properties.redundancy_policy.to_label_policy(),
            ..PoolLabelV1::new(self.pool_guid, device_guid, &self.config.name)
        }
    }

    fn next_lifecycle_record(
        &self,
        kind: pool_label::PoolLifecycleKindV1,
        payload: Vec<u8>,
    ) -> Result<PoolLifecycleLabelRecord> {
        let sequence = next_pool_lifecycle_sequence(
            self.label_lifecycle
                .as_ref()
                .map(|current| current.sequence),
        )?;
        pool_label::PoolLifecycleRecordV1::new(sequence, self.placement_epoch, kind, &payload)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "Pool lifecycle label record is invalid",
            })?;
        Ok(PoolLifecycleLabelRecord {
            sequence,
            kind,
            payload,
        })
    }

    fn persist_lifecycle_record_on_current_topology(
        &mut self,
        kind: pool_label::PoolLifecycleKindV1,
        payload: Vec<u8>,
        operation: &'static str,
    ) -> Result<()> {
        let next = self.next_lifecycle_record(kind, payload)?;
        for (device_index, device) in self.devices.iter().enumerate() {
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label_copies_with_lifecycle(
                &self.config.devices[device_index],
                label,
                self.device_layouts.get(device_index),
                &self.device_guids,
                Some(&next),
                PoolLabelCopyTarget::Backup,
                operation,
            )?;
        }
        self.verify_active_topology_label_copies(1, operation, Some(&next))?;
        for (device_index, device) in self.devices.iter().enumerate() {
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label_copies_with_lifecycle(
                &self.config.devices[device_index],
                label,
                self.device_layouts.get(device_index),
                &self.device_guids,
                Some(&next),
                PoolLabelCopyTarget::Primary,
                operation,
            )?;
        }
        self.verify_active_topology_label_copies(2, operation, Some(&next))?;
        self.label_lifecycle = Some(next);
        Ok(())
    }

    fn persist_replacement_evidence_in_labels(
        &mut self,
        evidence: &DeviceReplacementEvidenceMarker,
    ) -> Result<()> {
        let payload = encode_device_replacement_evidence(evidence)?;
        if self.devices.len() == self.expected_device_count as usize {
            return self.persist_lifecycle_record_on_current_topology(
                pool_label::PoolLifecycleKindV1::DeviceReplacement,
                payload,
                "replacement-lifecycle",
            );
        }

        // During rebuild the candidate occupies the durable target index and
        // the predecessor is retained as one extra runtime device. Update
        // only the still-authoritative predecessor label topology; the
        // candidate cannot become topology authority until higher roots are
        // reconciled.
        if self.devices.len() != self.expected_device_count as usize + 1
            || self.expected_device_count != 2
            || self.durable_device_guids.len() != self.expected_device_count as usize
        {
            return Err(StoreError::InvalidOptions {
                reason: "replacement lifecycle label topology is not reconstructable",
            });
        }
        let old_runtime_index = self
            .device_guids
            .iter()
            .position(|guid| *guid == evidence.old_device_guid)
            .ok_or(StoreError::InvalidOptions {
                reason: "replacement lifecycle labels lost the predecessor member",
            })?;
        let topology_generation = self
            .persisted_label_epoch
            .ok_or(StoreError::InvalidOptions {
                reason: "replacement lifecycle labels lost predecessor topology generation",
            })?;
        let next = self
            .next_lifecycle_record(pool_label::PoolLifecycleKindV1::DeviceReplacement, payload)?;

        for target in [PoolLabelCopyTarget::Backup, PoolLabelCopyTarget::Primary] {
            for durable_index in 0..self.expected_device_count as usize {
                let runtime_index = if durable_index == evidence.device_index {
                    old_runtime_index
                } else {
                    durable_index
                };
                let device = &self.devices[runtime_index];
                let mut label =
                    self.build_label_with_state(runtime_index, device, PoolState::Active);
                label.device_guid = self.durable_device_guids[durable_index];
                label.device_index = durable_index as u32;
                label.device_count = self.expected_device_count;
                label.topology_generation = topology_generation;
                write_pool_label_copies_with_lifecycle(
                    &self.config.devices[runtime_index],
                    label,
                    self.device_layouts.get(runtime_index),
                    &self.durable_device_guids,
                    Some(&next),
                    target,
                    "replacement-lifecycle",
                )?;
            }

            let required_matches = if matches!(target, PoolLabelCopyTarget::Backup) {
                1
            } else {
                2
            };
            for durable_index in 0..self.expected_device_count as usize {
                let runtime_index = if durable_index == evidence.device_index {
                    old_runtime_index
                } else {
                    durable_index
                };
                let config = &self.config.devices[runtime_index];
                let matching = read_pool_label_copies(config)?
                    .into_iter()
                    .filter(|copy| {
                        copy.label.pool_guid == self.pool_guid
                            && copy.label.device_guid == self.durable_device_guids[durable_index]
                            && copy.label.device_index == durable_index as u32
                            && copy.label.device_count == self.expected_device_count
                            && copy.label.topology_generation == topology_generation
                            && copy.topology_roster.as_deref()
                                == Some(self.durable_device_guids.as_slice())
                            && copy.lifecycle.as_ref() == Some(&next)
                    })
                    .count();
                let required_matches = if config.backing.uses_fixed_offset_pool_labels() {
                    required_matches
                } else {
                    1
                };
                if matching < required_matches {
                    return Err(StoreError::InvalidOptions {
                        reason: "replacement lifecycle label readback did not verify every required copy",
                    });
                }
            }
        }
        self.label_lifecycle = Some(next);
        Ok(())
    }

    fn persist_active_labels_if_needed(&mut self) -> Result<()> {
        if self.persisted_label_epoch == Some(self.placement_epoch) {
            return Ok(());
        }

        if let Some(marker) = self.device_removal_marker.as_ref() {
            if marker.pool_guid == self.pool_guid {
                // The current device list and placement epoch are in-memory
                // state until removal has one durable topology commit. Do not
                // let a later data write publish that reduced topology through
                // the ordinary active-label refresh path.
                return Ok(());
            }
        }

        if self.replacement_evidence.as_ref().is_some_and(|evidence| {
            evidence.pool_guid == self.pool_guid && evidence.state.is_active()
        }) {
            // Replacement changes the in-memory member at one fixed index so
            // receipt-backed rebuild can target it. The old topology remains
            // authoritative until the mounted owner has reconciled embedded
            // receipts and explicitly publishes both replacement label
            // copies. Ordinary writes must not publish that topology early.
            return Ok(());
        }

        let lifecycle = match self.label_lifecycle.as_ref() {
            Some(record) if record.kind == pool_label::PoolLifecycleKindV1::DeviceReplacement => {
                let evidence = decode_device_replacement_evidence(&record.payload)?;
                if replacement_evidence_matches_topology(
                    &evidence,
                    &self.device_guids,
                    self.placement_epoch,
                ) {
                    Some(record.clone())
                } else {
                    Some(self.next_lifecycle_record(
                        pool_label::PoolLifecycleKindV1::Clear,
                        Vec::new(),
                    )?)
                }
            }
            Some(record) => Some(record.clone()),
            None => None,
        };

        for (device_index, device) in self.devices.iter().enumerate() {
            let config =
                self.config
                    .devices
                    .get(device_index)
                    .ok_or(StoreError::InvalidOptions {
                        reason: "pool device label persistence missing device config",
                    })?;
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label_with_lifecycle(
                config,
                label,
                self.device_layouts.get(device_index),
                &self.device_guids,
                lifecycle.as_ref(),
                "pool_active_write_label",
            )?;
        }

        self.persisted_label_epoch = Some(self.placement_epoch);
        self.durable_device_guids.clone_from(&self.device_guids);
        self.expected_device_count = self.device_guids.len() as u32;
        self.device_label_indices = (0..self.expected_device_count).collect();
        self.label_lifecycle = lifecycle;
        Ok(())
    }

    fn publish_pending_removal_topology(&mut self) -> Result<()> {
        let marker =
            self.device_removal_marker
                .as_ref()
                .cloned()
                .ok_or(StoreError::InvalidOptions {
                    reason:
                        "device removal label intent is missing while topology commit is pending",
                })?;
        if marker.pool_guid != self.pool_guid
            || self.durable_device_guids.get(marker.target_index) != Some(&marker.target_guid)
            || self.device_guids.contains(&marker.target_guid)
            || marker.successor_topology_generation != self.placement_epoch
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal label intent does not authorize the reduced topology",
            });
        }

        let cleared =
            self.next_lifecycle_record(pool_label::PoolLifecycleKindV1::Clear, Vec::new())?;

        for (device_index, device) in self.devices.iter().enumerate() {
            let config =
                self.config
                    .devices
                    .get(device_index)
                    .ok_or(StoreError::InvalidOptions {
                        reason: "removal topology commit missing survivor device config",
                    })?;
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label_copies_with_lifecycle(
                config,
                label,
                self.device_layouts.get(device_index),
                &self.device_guids,
                Some(&cleared),
                PoolLabelCopyTarget::Backup,
                "pool_removal_stage_backup_label",
            )?;
        }
        self.verify_active_topology_label_copies(1, "removal", Some(&cleared))?;

        for (device_index, device) in self.devices.iter().enumerate() {
            let config = &self.config.devices[device_index];
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label_copies_with_lifecycle(
                config,
                label,
                self.device_layouts.get(device_index),
                &self.device_guids,
                Some(&cleared),
                PoolLabelCopyTarget::Primary,
                "pool_removal_promote_primary_label",
            )?;
        }
        self.verify_active_topology_label_copies(2, "removal", Some(&cleared))?;
        self.persisted_label_epoch = Some(self.placement_epoch);
        self.durable_device_guids.clone_from(&self.device_guids);
        self.expected_device_count = self.device_guids.len() as u32;
        self.device_label_indices = (0..self.expected_device_count).collect();
        self.converge_receipt_generation_authority()?;
        self.label_lifecycle = Some(cleared);
        self.device_removal_marker = None;
        self.allocation_fenced_device_guid = None;
        Ok(())
    }

    fn verify_active_topology_label_copies(
        &self,
        required_matches: usize,
        operation: &'static str,
        expected_lifecycle: Option<&PoolLifecycleLabelRecord>,
    ) -> Result<()> {
        for (device_index, config) in self.config.devices.iter().enumerate() {
            let expected = self.build_label_with_state(
                device_index,
                &self.devices[device_index],
                PoolState::Active,
            );
            let matching = read_pool_label_copies(config)?
                .into_iter()
                .filter(|copy| {
                    copy.label.pool_guid == expected.pool_guid
                        && copy.label.device_guid == expected.device_guid
                        && copy.label.pool_name_len == expected.pool_name_len
                        && copy.label.pool_name == expected.pool_name
                        && copy.label.pool_state == expected.pool_state
                        && copy.label.device_index == expected.device_index
                        && copy.label.device_count == expected.device_count
                        && copy.label.topology_generation == expected.topology_generation
                        && copy.label.redundancy_policy == expected.redundancy_policy
                        && copy.topology_roster.as_deref() == Some(self.device_guids.as_slice())
                        && copy.lifecycle.as_ref() == expected_lifecycle
                })
                .count();
            let required_matches = if config.backing.uses_fixed_offset_pool_labels() {
                required_matches
            } else {
                1
            };
            if matching < required_matches {
                return Err(StoreError::InvalidOptions {
                    reason: match operation {
                        "replacement" | "replacement-lifecycle" => {
                            "replacement topology label readback did not verify every required copy"
                        }
                        _ => "removal topology label readback did not verify every required copy",
                    },
                });
            }
        }
        Ok(())
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
        self.ensure_writable("pool write admission")?;
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

    fn ensure_receipt_generation_authority_converged(&self) -> Result<()> {
        if self.next_placement_receipt_generation == 0 {
            Err(StoreError::InvalidOptions {
                reason: "placement receipt generation exhausted",
            })
        } else {
            match self.receipt_generation_authority_state {
            ReceiptGenerationAuthorityState::Converged => Ok(()),
            ReceiptGenerationAuthorityState::ReservationPending { .. } => {
                Err(StoreError::InvalidOptions {
                    reason: "placement receipt generation high-water reservation has not converged",
                })
            }
            ReceiptGenerationAuthorityState::ReplacementResumeRequired => {
                Err(StoreError::InvalidOptions {
                    reason: "placement receipt generation authority requires explicit replacement resume",
                })
            }
            ReceiptGenerationAuthorityState::RemovalTopologyCommitRequired => {
                Err(StoreError::InvalidOptions {
                    reason: "placement receipt generation authority awaits durable removal topology commit",
                })
            }
            ReceiptGenerationAuthorityState::RecoveryRequired => {
                Err(StoreError::InvalidOptions {
                    reason: "placement receipt generation authority requires explicit recovery",
                })
            }
            }
        }
    }

    fn validate_loaded_receipt_generation_high_water(&self) -> Result<()> {
        let result = (|| {
            let reserved_through =
                receipt_generation_high_water_for_devices(&self.devices, self.pool_guid)?;
            if reserved_through != self.reserved_placement_receipt_generation_through {
                return Err(StoreError::InvalidOptions {
                    reason: "placement receipt generation high-water differs from loaded authority",
                });
            }
            Ok(())
        })();
        if result.is_err() {
            self.raw_store_mutation_allowed
                .store(false, Ordering::Release);
        }
        result
    }

    fn validate_receipt_generation_high_water(&self) -> Result<()> {
        self.ensure_receipt_generation_authority_converged()?;
        if !self.raw_store_mutation_allowed.load(Ordering::Acquire) {
            return Err(StoreError::InvalidOptions {
                reason:
                    "placement receipt generation authority is fenced until the pool is reopened",
            });
        }
        self.validate_loaded_receipt_generation_high_water()
    }

    fn reconcile_receipt_generation_high_water_with_replacement(
        &mut self,
        candidate: &mut Device,
    ) -> Result<()> {
        if self.receipt_generation_authority_state
            != ReceiptGenerationAuthorityState::ReplacementResumeRequired
        {
            return Err(StoreError::InvalidOptions {
                reason: "receipt generation reconciliation requires replacement-resume state",
            });
        }
        self.validate_loaded_receipt_generation_high_water()?;
        let candidate_marker = require_receipt_generation_high_water(candidate, self.pool_guid)?;
        validate_receipts_within_generation_high_water(
            std::slice::from_ref(&*candidate),
            candidate_marker.reserved_through,
        )?;

        let loaded = self.reserved_placement_receipt_generation_through;
        let reconciled = loaded.max(candidate_marker.reserved_through);
        if reconciled > loaded {
            publish_receipt_generation_high_water(
                &mut self.devices,
                self.pool_guid,
                loaded,
                reconciled,
            )?;
        }
        seed_receipt_generation_high_water_on_candidate(candidate, self.pool_guid, reconciled)?;
        self.reserved_placement_receipt_generation_through = reconciled;
        self.next_placement_receipt_generation = reconciled.checked_add(1).unwrap_or(0);
        Ok(())
    }

    fn allocate_placement_receipt_generation(&mut self) -> Result<u64> {
        let mut persistent_write_started = false;
        self.allocate_placement_receipt_generation_reporting_writeback(
            &mut persistent_write_started,
        )
    }

    fn allocate_placement_receipt_generation_reporting_writeback(
        &mut self,
        persistent_write_started: &mut bool,
    ) -> Result<u64> {
        let generation = self.next_placement_receipt_generation;
        if generation == 0 {
            self.ensure_receipt_generation_authority_converged()?;
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation exhausted",
            });
        }
        // Burn the final value rather than wrapping the in-memory zero
        // sentinel after a successful allocation.
        if generation == u64::MAX {
            self.next_placement_receipt_generation = 0;
            self.refresh_raw_store_mutation_gate();
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation exhausted",
            });
        }

        if generation > self.reserved_placement_receipt_generation_through {
            let new_reserved_through =
                generation.saturating_add(RECEIPT_GENERATION_RESERVATION_SIZE.saturating_sub(1));
            match self.receipt_generation_authority_state {
                ReceiptGenerationAuthorityState::Converged => {
                    self.set_receipt_generation_authority_state(
                        ReceiptGenerationAuthorityState::ReservationPending {
                            from: self.reserved_placement_receipt_generation_through,
                            through: new_reserved_through,
                        },
                    );
                }
                ReceiptGenerationAuthorityState::ReservationPending { from, through }
                    if from == self.reserved_placement_receipt_generation_through
                        && through == new_reserved_through => {}
                _ => {
                    self.ensure_receipt_generation_authority_converged()?;
                }
            }
            // Reservation publication changes durable device authority even
            // when the caller never reaches its later payload write. Mark the
            // mutation boundary before entering the fallible publisher so a
            // partial reservation cannot be reported as a no-write refusal.
            *persistent_write_started = true;
            publish_receipt_generation_high_water(
                &mut self.devices,
                self.pool_guid,
                self.reserved_placement_receipt_generation_through,
                new_reserved_through,
            )?;
            self.reserved_placement_receipt_generation_through = new_reserved_through;
            self.converge_receipt_generation_authority()?;
        } else {
            self.ensure_receipt_generation_authority_converged()?;
        }

        self.next_placement_receipt_generation = generation.checked_add(1).unwrap_or(0);
        Ok(generation)
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
        self.device_guids
            .iter()
            .position(|guid| *guid == target.device_guid)
    }

    fn read_only_missing_member_budget(&self, receipt: &PlacementReceipt) -> Option<usize> {
        if self.device_label_indices.len() != self.devices.len() {
            return None;
        }
        let missing =
            (self.expected_device_count as usize).checked_sub(self.device_label_indices.len())?;
        if !self.read_only
            || missing == 0
            || receipt.policy != self.properties.redundancy_policy
            || !matches!(receipt.policy, PoolRedundancyPolicy::Replicated { copies } if copies > 1)
        {
            return None;
        }
        Some(missing)
    }

    fn admit_read_only_missing_receipt_target(
        &self,
        receipt: &PlacementReceipt,
        target: &PlacementReceiptTarget,
        missing_indices: &mut BTreeSet<u32>,
    ) -> bool {
        let Some(budget) = self.read_only_missing_member_budget(receipt) else {
            return false;
        };
        target.device_index < self.expected_device_count
            && !self.device_label_indices.contains(&target.device_index)
            && missing_indices.insert(target.device_index)
            && missing_indices.len() <= budget
    }

    fn replacement_resume_evidence(&self) -> Option<&DeviceReplacementEvidenceMarker> {
        let evidence = self.replacement_evidence.as_ref()?;
        let old_topology_loaded = self.device_guids.get(evidence.device_index)
            == Some(&evidence.old_device_guid)
            && replacement_evidence_matches_topology(
                evidence,
                &self.device_guids,
                self.placement_epoch,
            )
            && self.allocation_fenced_device_guid == Some(evidence.old_device_guid);
        let new_topology_loaded = self.device_guids.get(evidence.device_index)
            == Some(&evidence.new_device_guid)
            && replacement_evidence_matches_topology(
                evidence,
                &self.device_guids,
                self.placement_epoch,
            )
            && self.allocation_fenced_device_guid.is_none();

        (!self.read_only
            && self.expected_device_count == 2
            && self.devices.len() == 2
            && matches!(
                self.properties.redundancy_policy,
                PoolRedundancyPolicy::Replicated { copies: 2 }
            )
            && self.receipt_generation_authority_state
                == ReceiptGenerationAuthorityState::ReplacementResumeRequired
            && evidence.state.is_active()
            && (old_topology_loaded || new_topology_loaded))
            .then_some(evidence)
    }

    fn predecessor_replacement_resume_evidence(&self) -> Option<&DeviceReplacementEvidenceMarker> {
        let evidence = self.replacement_resume_evidence()?;
        (self.device_guids.get(evidence.device_index) == Some(&evidence.old_device_guid)
            && replacement_evidence_matches_topology(
                evidence,
                &self.device_guids,
                self.placement_epoch,
            ))
        .then_some(evidence)
    }

    /// Admit the not-yet-loaded replacement target while reopening the old
    /// topology after receipt rebuilding became durable.
    ///
    /// This is not writable degraded-read authority. The durable replacement
    /// record must bind the exact candidate identity before any successor
    /// receipt can exist, the old member must still occupy its
    /// label-authoritative slot and remain allocation-fenced, and the other
    /// successor target must resolve to the attached survivor. The strict
    /// callers still verify that survivor's exact receipt copy and payload
    /// before returning any bytes. Global completion evidence need not yet be
    /// stable because a crash may expose a durable per-object receipt before
    /// the later aggregate progress-marker update.
    fn admit_replacement_resume_missing_receipt_target(
        &self,
        receipt: &PlacementReceipt,
        target: &PlacementReceiptTarget,
        missing_indices: &mut BTreeSet<u32>,
    ) -> bool {
        let Some(evidence) = self.predecessor_replacement_resume_evidence() else {
            return false;
        };
        let exact_successor_targets = receipt.targets.len() == 2
            && receipt
                .targets
                .iter()
                .all(|candidate| candidate.device_guid != evidence.old_device_guid)
            && receipt
                .targets
                .iter()
                .filter(|candidate| candidate.device_guid == evidence.new_device_guid)
                .count()
                == 1
            && receipt
                .targets
                .iter()
                .filter(|candidate| self.resolve_receipt_target(candidate).is_some())
                .count()
                == 1;

        matches!(
            receipt.policy,
            PoolRedundancyPolicy::Replicated { copies: 2 }
        ) && receipt.epoch == evidence.topology_epoch
            && target.device_guid == evidence.new_device_guid
            && target.device_index as usize == evidence.device_index
            && exact_successor_targets
            && missing_indices.insert(target.device_index)
            && missing_indices.len() == 1
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

        let replay_receipt = decision
            .to_replay_receipt(&layout, &devices, &request, self.placement_epoch)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "pool-wide placement planner could not mint replay receipt",
            })?;

        self.receipt_from_decision(key, payload_len, decision, &candidates, replay_receipt)
    }

    fn receipt_from_decision(
        &self,
        key: ObjectKey,
        payload_len: usize,
        decision: PlacementDecision,
        candidates: &[usize],
        planner_replay_receipt: PlacementReplayReceipt,
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
            generation: 0,
            policy: self.properties.redundancy_policy,
            failure_domain_level: self.properties.failure_domain_level,
            payload_len: payload_len as u64,
            shard_len: 0,
            payload_digest: [0u8; 32],
            targets,
            planner_replay_receipt: Some(planner_replay_receipt),
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
        let receipt = self.load_placement_receipt(&indices, key)?;
        Ok(receipt.filter(|receipt| {
            !self.pending_deletion_hides_generation(class, key, Some(receipt.generation))
        }))
    }

    /// Return the latest persisted placement receipt for every logical object
    /// in an I/O class.
    ///
    /// This is the public receipt-authority scan for rebuild, repair,
    /// relocation, and distributed state-transfer consumers. It hides the
    /// internal receipt object-key namespace and returns decoded logical
    /// receipts keyed by `object_key`.
    pub fn placement_receipts(&self, class: IoClass) -> Result<Vec<PlacementReceipt>> {
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Ok(Vec::new());
        }

        // Receipt authority is physical durable state, not a function of the
        // current health/class planner. Scan every admitted device so a newer
        // copy on a faulted, cache, metadata, or composite member cannot be
        // hidden by write eligibility.
        Ok(discover_placement_receipt_inventory(&self.devices)?
            .latest_by_object
            .into_values()
            .filter(|receipt| {
                !self.pending_deletion_hides_generation(
                    class,
                    receipt.object_key,
                    Some(receipt.generation),
                )
            })
            .collect())
    }

    /// Return the latest local placement receipts projected into the shared
    /// distributed receipt reference model.
    #[cfg(any(feature = "distributed-repair", test))]
    pub fn placement_receipt_refs(&self, class: IoClass) -> Result<Vec<PlacementReceiptRef>> {
        self.placement_receipts(class)?
            .into_iter()
            .map(|receipt| receipt.shared_receipt_ref())
            .collect()
    }

    fn load_placement_receipt(
        &self,
        indices: &[usize],
        key: ObjectKey,
    ) -> Result<Option<PlacementReceipt>> {
        let receipt_key = placement_receipt_object_key(key);
        let mut best: Option<PlacementReceipt> = None;
        let mut saw_invalid_receipt = false;
        for idx in self.usable_candidates(indices) {
            let raw = match self.devices[idx].get(receipt_key) {
                Ok(Some(raw)) => raw,
                Ok(None) | Err(_) => continue,
            };
            let Some(receipt) = PlacementReceipt::decode(&raw) else {
                saw_invalid_receipt = true;
                continue;
            };
            if receipt.object_key != key {
                saw_invalid_receipt = true;
                continue;
            }
            let replace = match best.as_ref() {
                Some(current) => receipt_supersedes(&receipt, current)?,
                None => true,
            };
            if replace {
                best = Some(receipt);
            }
        }
        if best.is_none() && saw_invalid_receipt {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt corrupt or unverifiable",
            });
        }
        Ok(best)
    }

    fn load_current_placement_receipt_strict(
        &self,
        indices: &[usize],
        key: ObjectKey,
    ) -> Result<Option<PlacementReceipt>> {
        let receipt_key = placement_receipt_object_key(key);
        let mut receipts: BTreeMap<(u64, u64), PlacementReceipt> = BTreeMap::new();

        for &idx in indices {
            for (candidate_key, raw) in self.devices[idx].placement_receipt_candidates()? {
                if candidate_key != receipt_key {
                    continue;
                }
                let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                    reason: "strict read found a corrupt or unverifiable placement receipt",
                })?;
                if receipt.object_key != key
                    || placement_receipt_object_key(receipt.object_key) != receipt_key
                {
                    return Err(StoreError::InvalidOptions {
                        reason: "strict read found a placement receipt key mismatch",
                    });
                }
                if receipt.epoch == 0 || receipt.generation == 0 {
                    return Err(StoreError::InvalidOptions {
                        reason:
                            "strict read requires nonzero placement receipt epoch and generation",
                    });
                }
                if receipt.planner_replay_receipt.is_none()
                    || !planner_replay_receipt_matches_receipt(&receipt)
                {
                    return Err(StoreError::InvalidOptions {
                        reason: "strict read requires matching planner replay authority",
                    });
                }
                validate_strict_receipt_structure(&receipt)?;

                let version = (receipt.epoch, receipt.generation);
                if let Some(canonical) = receipts.get(&version) {
                    if canonical != &receipt {
                        return Err(StoreError::InvalidOptions {
                            reason: "conflicting placement receipts share epoch and generation",
                        });
                    }
                } else {
                    receipts.insert(version, receipt);
                }
            }
        }

        if receipts.len() > 1 {
            return Err(StoreError::InvalidOptions {
                reason: "strict read found heterogeneous placement receipt versions",
            });
        }

        Ok(receipts.into_iter().next().map(|(_, receipt)| receipt))
    }

    fn logical_raw_payload_visible_for_policy(
        &self,
        indices: &[usize],
        key: ObjectKey,
        policy: PoolRedundancyPolicy,
    ) -> Result<bool> {
        let mut visible = false;
        for &idx in indices {
            visible |= self.devices[idx].get(key)?.is_some();
        }
        if let PoolRedundancyPolicy::Erasure { .. } = policy {
            let width = policy.total_targets()?;
            for shard_index in 0..width {
                let shard_index =
                    u16::try_from(shard_index).map_err(|_| StoreError::InvalidOptions {
                        reason: "pool erasure width exceeds placement shard key format",
                    })?;
                let shard_key = placement_shard_object_key(key, shard_index);
                for &idx in indices {
                    visible |= self.devices[idx].get(shard_key)?.is_some();
                }
            }
        }
        Ok(visible)
    }

    fn logical_raw_payload_visible(&self, indices: &[usize], key: ObjectKey) -> Result<bool> {
        self.logical_raw_payload_visible_for_policy(indices, key, self.properties.redundancy_policy)
    }

    fn restore_device_objects(&mut self, previous: &[(usize, ObjectKey, Option<Vec<u8>>)]) -> bool {
        let mut restored = true;
        for (idx, key, payload) in previous {
            let pool_internal = crate::is_pool_placement_scan_internal_key(*key)
                || crate::store::is_pool_pending_deletion_key(*key);
            let result = match (payload, pool_internal) {
                (Some(payload), true) => self.devices[*idx]
                    .put_pool_internal(*key, payload)
                    .map(|_| ()),
                (Some(payload), false) => self.devices[*idx].put(*key, payload).map(|_| ()),
                (None, true) => self.devices[*idx].delete_pool_internal(*key).map(|_| ()),
                (None, false) => self.devices[*idx].delete(*key).map(|_| ()),
            };
            restored &= result.is_ok();
        }
        restored
    }

    fn verify_placement_receipt_publication(
        &self,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) -> Result<()> {
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        let encoded = receipt.encode()?;
        for &idx in indices {
            let raw = self.devices[idx]
                .get(receipt_key)?
                .ok_or(StoreError::InvalidOptions {
                    reason:
                        "placement receipt publication verification found a missing receipt copy",
                })?;
            let persisted = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "placement receipt publication verification found a corrupt receipt copy",
            })?;
            if persisted != *receipt {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "placement receipt publication verification found a non-identical receipt copy",
                });
            }
            let physical = self.devices[idx]
                .placement_receipt_candidates()?
                .into_iter()
                .filter(|(key, _)| *key == receipt_key)
                .map(|(_, payload)| payload)
                .collect::<Vec<_>>();
            if physical.is_empty() || physical.iter().any(|payload| payload != &encoded) {
                return Err(StoreError::InvalidOptions {
                    reason: "placement receipt publication did not converge across physical copies",
                });
            }
        }
        Ok(())
    }

    fn write_placement_receipt(
        &mut self,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) -> Result<()> {
        self.validate_receipt_generation_high_water()?;
        self.ensure_receipt_replay_authority(receipt)?;
        validate_strict_receipt_structure(receipt)?;
        if receipt.epoch == 0 || receipt.generation == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt publication requires nonzero epoch and generation",
            });
        }
        if receipt.generation > self.reserved_placement_receipt_generation_through {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation exceeds the durable high-water reservation",
            });
        }
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        let encoded = receipt.encode()?;
        let mut previous = Vec::with_capacity(indices.len());
        for &idx in indices {
            previous.push((idx, receipt_key, self.devices[idx].get(receipt_key)?));
        }
        for position in 0..previous.len() {
            let idx = previous[position].0;
            if let Err(error) = self.devices[idx].put_pool_internal(receipt_key, &encoded) {
                // A device write may report an error after the record reached
                // media. Restore the failing slot as well as every successful
                // prefix instead of assuming that Err implies no mutation.
                if !self.restore_and_sync_device_objects(&previous[..=position]) {
                    return Err(StoreError::InvalidOptions {
                        reason: "placement receipt publication failed and rollback was incomplete",
                    });
                }
                return Err(error);
            }
        }
        for &idx in indices {
            if let Err(error) = self.devices[idx].sync_strict_pool_authority() {
                if !self.restore_and_sync_device_objects(&previous) {
                    return Err(StoreError::InvalidOptions {
                        reason: "placement receipt sync failed and rollback was incomplete",
                    });
                }
                return Err(error);
            }
        }

        #[cfg(test)]
        let verification = if std::mem::take(&mut self.fail_placement_receipt_verification_once) {
            Err(StoreError::InvalidOptions {
                reason: "test fault: placement receipt verification failed",
            })
        } else {
            self.verify_placement_receipt_publication(indices, receipt)
        };
        #[cfg(not(test))]
        let verification = self.verify_placement_receipt_publication(indices, receipt);

        match verification {
            Ok(()) => Ok(()),
            Err(error) => {
                if !self.restore_and_sync_device_objects(&previous) {
                    return Err(StoreError::InvalidOptions {
                        reason: "placement receipt verification failed and rollback was incomplete",
                    });
                }
                Err(error)
            }
        }
    }

    fn ensure_receipt_replay_authority(&self, receipt: &PlacementReceipt) -> Result<()> {
        if planner_replay_receipt_matches_receipt(receipt) {
            Ok(())
        } else {
            Err(StoreError::InvalidOptions {
                reason: "placement replay receipt does not match local locator authority",
            })
        }
    }

    fn put_pool_wide(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        payload: &[u8],
        indices: &[usize],
        old_receipt_policy: OldReceiptPolicy<'_>,
    ) -> Result<(StoredObject, PlacementReceipt)> {
        self.validate_receipt_generation_high_water()?;
        if crate::is_pool_placement_scan_internal_key(key)
            || crate::store::is_pool_pending_deletion_key(key)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pool receipt, shard, generation, and deletion namespaces are reserved",
            });
        }
        let authority_indices = indices
            .iter()
            .copied()
            .filter(|idx| {
                self.allocation_fenced_device_guid
                    .is_none_or(|guid| self.device_guids.get(*idx) != Some(&guid))
            })
            .collect::<Vec<_>>();
        if authority_indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "device lifecycle allocation fence leaves no eligible write target",
            });
        }
        let old_receipt = match old_receipt_policy {
            OldReceiptPolicy::RequireValid => {
                match self.load_current_placement_receipt_strict(&authority_indices, key)? {
                    Some(receipt) => Some(receipt),
                    None if self.logical_raw_payload_visible(&authority_indices, key)? => {
                        return Err(StoreError::InvalidOptions {
                            reason: "strict read refuses a receiptless raw payload",
                        });
                    }
                    None => None,
                }
            }
            OldReceiptPolicy::KnownCurrent(receipt) => {
                if receipt.object_key != key || receipt.epoch == 0 || receipt.generation == 0 {
                    return Err(StoreError::InvalidOptions {
                        reason: "known current placement receipt has invalid identity",
                    });
                }
                self.ensure_receipt_replay_authority(receipt)?;
                validate_strict_receipt_structure(receipt)?;
                Some(receipt.clone())
            }
        };
        let mut receipt =
            self.plan_pool_wide_placement(class, key, payload.len(), &authority_indices)?;
        receipt.generation = self.allocate_placement_receipt_generation()?;
        receipt.payload_digest = digest32(payload);

        // Persist fail-closed cleanup intent before overwriting any physical
        // payload. The entries carry no replacement receipt yet, so a crash or
        // publication failure cannot make them eligible for reclaim. A retry
        // can safely reuse the idempotent queue entries.
        let pending_obsolete_placements = match old_receipt.as_ref() {
            Some(old_receipt) => {
                self.persist_pending_obsolete_placements(old_receipt, receipt.generation)?
            }
            None => Vec::new(),
        };
        self.persist_active_labels_if_needed()?;

        let stored = match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                self.put_replicated_with_receipt(key, payload, &authority_indices, &mut receipt)
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                self.put_erasure_with_receipt(key, payload, &authority_indices, &mut receipt)
            }
        }?;

        // The exact replacement receipt is current at this point. Cleanup is
        // post-commit work: an attachment failure must not turn a committed
        // write into an ambiguous Err. The durable receiptless entries remain
        // ineligible and can be attached by an idempotent retry.
        if !pending_obsolete_placements.is_empty() {
            if let Err(error) =
                self.attach_obsolete_placement_receipt(&pending_obsolete_placements, &receipt)
            {
                eprintln!(
                    "tidefs: placement replacement committed for {key:?}; obsolete-placement reclaim remains pending: {error}"
                );
            }
        }

        // A new receipt generation is allowed to supersede a logically
        // deleted generation while its exact old target remains pending (for
        // example, because that device is temporarily absent). Reconcile what
        // is now safe, but never turn the committed replacement write into an
        // ordinary failure if old deletion cleanup still cannot finish.
        let prior_deletions = self
            .pending_deletions
            .values()
            .filter(|pending| {
                pending.class == class
                    && pending.receipt.object_key == key
                    && pending.receipt.generation < receipt.generation
            })
            .cloned()
            .collect::<Vec<_>>();
        for pending in prior_deletions {
            if let Err(error) = self.reconcile_one_pending_deletion(&pending) {
                eprintln!(
                    "tidefs: replacement generation {} is current for {key:?}; prior deletion cleanup remains pending: {error}",
                    receipt.generation
                );
            }
        }

        Ok((stored, receipt))
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

        let mut previous_payloads = Vec::with_capacity(target_indices.len());
        for (_, idx) in &target_indices {
            previous_payloads.push((*idx, key, self.devices[*idx].get(key)?));
        }
        let mut last_object = None;
        for (target_pos, idx) in target_indices {
            let result = self.devices[idx].put(key, payload);
            self.record_device_write_result(idx, payload.len(), &result);
            match result {
                Ok(object) => {
                    receipt.targets[target_pos].stored_digest = receipt.payload_digest;
                    last_object = Some(object);
                }
                Err(err) => {
                    if !self.restore_and_sync_device_objects(&previous_payloads) {
                        return Err(StoreError::InvalidOptions {
                            reason: "replicated payload write failed and rollback was incomplete",
                        });
                    }
                    self.health = compute_health(&self.devices);
                    self.record_health_transitions();
                    return Err(err);
                }
            }
        }

        if let Err(error) = self.write_placement_receipt(indices, receipt) {
            if !self.restore_and_sync_device_objects(&previous_payloads) {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "replicated receipt publication failed and payload rollback was incomplete",
                });
            }
            return Err(error);
        }
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

    #[cfg(any(feature = "distributed-repair", test))]
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
        let encoded = encode_receipt_stripe(&stripe_config, payload).map_err(|_| {
            StoreError::InvalidOptions {
                reason: "erasure encoder rejected pool placement payload",
            }
        })?;
        receipt.shard_len = shard_len as u32;

        let mut target_writes = Vec::with_capacity(receipt.targets.len());
        let mut previous_shards = Vec::with_capacity(receipt.targets.len());
        for target_pos in 0..receipt.targets.len() {
            let shard_index = receipt.targets[target_pos].shard_index as usize;
            if !encoded
                .shards
                .iter()
                .any(|shard| shard.index == shard_index)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement receipt missing encoded shard",
                });
            }
            let Some(idx) = self.resolve_receipt_target(&receipt.targets[target_pos]) else {
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement receipt references unavailable device",
                });
            };
            let shard_key = placement_shard_object_key(key, shard_index as u16);
            previous_shards.push((idx, shard_key, self.devices[idx].get(shard_key)?));
            target_writes.push((target_pos, idx, shard_index, shard_key));
        }

        for (target_pos, idx, shard_index, shard_key) in target_writes {
            let Some(shard) = encoded
                .shards
                .iter()
                .find(|shard| shard.index == shard_index)
            else {
                let _ = self.restore_and_sync_device_objects(&previous_shards);
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement lost a validated encoded shard",
                });
            };
            let result = self.devices[idx].put_pool_internal(shard_key, &shard.bytes);
            self.record_device_write_result(idx, shard.bytes.len(), &result);
            match result {
                Ok(_) => {
                    receipt.targets[target_pos].stored_digest = digest32(&shard.bytes);
                }
                Err(err) => {
                    if !self.restore_and_sync_device_objects(&previous_shards) {
                        return Err(StoreError::InvalidOptions {
                            reason: "erasure payload write failed and rollback was incomplete",
                        });
                    }
                    self.health = compute_health(&self.devices);
                    self.record_health_transitions();
                    return Err(err);
                }
            }
        }

        if let Err(error) = self.write_placement_receipt(indices, receipt) {
            if !self.restore_and_sync_device_objects(&previous_shards) {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "erasure receipt publication failed and payload rollback was incomplete",
                });
            }
            return Err(error);
        }
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

    #[cfg(all(not(feature = "distributed-repair"), not(test)))]
    fn put_erasure_with_receipt(
        &mut self,
        _key: ObjectKey,
        _payload: &[u8],
        _indices: &[usize],
        _receipt: &mut PlacementReceipt,
    ) -> Result<StoredObject> {
        Err(StoreError::InvalidOptions {
            reason: "erasure pool operation requires the distributed-repair feature",
        })
    }

    fn pending_deletion_hides_generation(
        &self,
        class: IoClass,
        key: ObjectKey,
        receipt_generation: Option<u64>,
    ) -> bool {
        self.pending_deletions.values().any(|pending| {
            pending.class == class
                && pending.receipt.object_key == key
                && pending.phase >= PendingDeletionPhase::Committed
                && receipt_generation
                    .map(|generation| pending.receipt.generation >= generation)
                    .unwrap_or(true)
        })
    }

    fn pending_deletion_for_subject(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Option<PoolPendingDeletion> {
        self.pending_deletions
            .values()
            .filter(|pending| pending.class == class && pending.receipt.object_key == key)
            .max_by_key(|pending| (pending.receipt.generation, pending.phase))
            .cloned()
    }

    fn receipt_carriers(
        &self,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) -> Result<Vec<usize>> {
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        let mut carriers = Vec::new();
        for &idx in indices {
            let mut carries_receipt = false;
            for (candidate_key, raw) in self.devices[idx].placement_receipt_candidates()? {
                if candidate_key != receipt_key {
                    continue;
                }
                let persisted =
                    PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                        reason: "pending deletion preflight found a corrupt receipt carrier",
                    })?;
                if persisted != *receipt {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending deletion preflight found conflicting receipt authority",
                    });
                }
                carries_receipt = true;
            }
            if carries_receipt {
                carriers.push(idx);
            }
        }
        if carriers.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pending deletion preflight found no current receipt carrier",
            });
        }
        Ok(carriers)
    }

    fn device_index_for_guid(&self, guid: [u8; 16]) -> Option<usize> {
        self.device_guids
            .iter()
            .position(|candidate| *candidate == guid)
    }

    fn restore_and_sync_device_objects(
        &mut self,
        previous: &[(usize, ObjectKey, Option<Vec<u8>>)],
    ) -> bool {
        if !self.restore_device_objects(previous) {
            return false;
        }
        let mut restored = true;
        for (idx, key, expected) in previous {
            restored &= self.devices[*idx].sync_strict_pool_authority().is_ok();
            restored &= self.devices[*idx].get(*key).ok().as_ref() == Some(expected);
        }
        restored
    }

    fn finish_committed_pending_deletion_after_rollback_failure(
        &mut self,
        pending: &PoolPendingDeletion,
        carrier_indices: &[usize],
        encoded: &[u8],
    ) -> bool {
        if pending.phase < PendingDeletionPhase::Committed {
            return false;
        }

        // Prepared already carries identical cleanup authority on every
        // receipt carrier. Once rollback cannot prove that every higher phase
        // was removed, any independently synced Committed copy is the
        // irreversible decision: returning an ordinary error would make the
        // public result depend on which phase copy a crash exposes. Discovery
        // reads every physical representation, validates identical authority,
        // and selects the monotonic maximum phase, so reopen/retry can converge
        // the remaining Prepared copies before exact cleanup is forgotten.
        let handoff_key = pending.object_key();
        let mut durable_copy = false;
        for &idx in carrier_indices {
            let _ = self.devices[idx].put_pool_internal(handoff_key, encoded);
            if self.devices[idx].sync_strict_pool_authority().is_err() {
                continue;
            }
            durable_copy |=
                self.devices[idx]
                    .pending_deletion_candidates()
                    .is_ok_and(|candidates| {
                        candidates.iter().any(|(candidate_key, payload)| {
                            *candidate_key == handoff_key && payload == encoded
                        })
                    });
        }
        if durable_copy {
            self.pending_deletions.insert(handoff_key, pending.clone());
        }
        durable_copy
    }

    fn persist_pending_deletion_phase(&mut self, pending: &PoolPendingDeletion) -> Result<()> {
        let handoff_key = pending.object_key();
        let encoded = pending.encode()?;
        let mut carrier_indices = Vec::with_capacity(pending.receipt_carrier_guids.len());
        for guid in &pending.receipt_carrier_guids {
            carrier_indices.push(self.device_index_for_guid(*guid).ok_or(
                StoreError::InvalidOptions {
                    reason: "pending deletion receipt carrier is absent from the current topology",
                },
            )?);
        }
        let mut previous = Vec::with_capacity(carrier_indices.len());
        for &idx in &carrier_indices {
            match self.devices[idx].get(handoff_key) {
                Ok(payload) => previous.push((idx, handoff_key, payload)),
                Err(error) if pending.phase >= PendingDeletionPhase::Committed => {
                    if self.finish_committed_pending_deletion_after_rollback_failure(
                        pending,
                        &carrier_indices,
                        &encoded,
                    ) {
                        return Ok(());
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }

        for position in 0..previous.len() {
            let idx = previous[position].0;
            if let Err(error) = self.devices[idx].put_pool_internal(handoff_key, &encoded) {
                if self.restore_and_sync_device_objects(&previous[..=position]) {
                    return Err(error);
                }
                if self.finish_committed_pending_deletion_after_rollback_failure(
                    pending,
                    &carrier_indices,
                    &encoded,
                ) {
                    return Ok(());
                }
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion publication failed and rollback was incomplete",
                });
            }
        }
        for &idx in &carrier_indices {
            if self.devices[idx].get(handoff_key)?.as_deref() != Some(encoded.as_slice()) {
                if self.restore_and_sync_device_objects(&previous) {
                    return Err(StoreError::InvalidOptions {
                        reason:
                            "pending deletion publication did not converge across receipt carriers",
                    });
                }
                if self.finish_committed_pending_deletion_after_rollback_failure(
                    pending,
                    &carrier_indices,
                    &encoded,
                ) {
                    return Ok(());
                }
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion verification failed and rollback was incomplete",
                });
            }
        }
        for &idx in &carrier_indices {
            if let Err(error) = self.devices[idx].sync_strict_pool_authority() {
                if self.restore_and_sync_device_objects(&previous) {
                    return Err(error);
                }
                if self.finish_committed_pending_deletion_after_rollback_failure(
                    pending,
                    &carrier_indices,
                    &encoded,
                ) {
                    return Ok(());
                }
                return Err(StoreError::InvalidOptions {
                    reason: "pending deletion sync failed and rollback was incomplete",
                });
            }
        }
        self.pending_deletions.insert(handoff_key, pending.clone());
        Ok(())
    }

    fn clear_pending_deletion_handoff(&mut self, pending: &PoolPendingDeletion) -> Result<bool> {
        let handoff_key = pending.object_key();
        let mut resolved = true;
        for guid in &pending.receipt_carrier_guids {
            let Some(idx) = self.device_index_for_guid(*guid) else {
                resolved = false;
                continue;
            };
            self.devices[idx].delete_pool_internal(handoff_key)?;
            self.devices[idx].sync_strict_pool_authority()?;
            resolved &= self.devices[idx]
                .pending_deletion_candidates()?
                .iter()
                .all(|(candidate_key, _)| *candidate_key != handoff_key);
        }
        if resolved {
            self.pending_deletions.remove(&handoff_key);
        }
        Ok(resolved)
    }

    fn newer_receipt_superseding_deletion(
        &self,
        pending: &PoolPendingDeletion,
    ) -> Result<Option<PlacementReceipt>> {
        let current = discover_placement_receipt_inventory(&self.devices)?
            .latest_by_object
            .remove(&pending.receipt.object_key);
        Ok(current.filter(|receipt| receipt.generation > pending.receipt.generation))
    }

    fn newer_receipt_owns_physical_target(
        &self,
        newer: &PlacementReceipt,
        deleted: &PlacementReceipt,
        deleted_target: &PlacementReceiptTarget,
    ) -> bool {
        newer.targets.iter().any(|target| {
            target.device_guid == deleted_target.device_guid
                && match (newer.policy, deleted.policy) {
                    (
                        PoolRedundancyPolicy::Replicated { .. },
                        PoolRedundancyPolicy::Replicated { .. },
                    ) => true,
                    (
                        PoolRedundancyPolicy::Erasure { .. },
                        PoolRedundancyPolicy::Erasure { .. },
                    ) => target.shard_index == deleted_target.shard_index,
                    _ => false,
                }
        })
    }

    fn reconcile_one_pending_deletion(&mut self, pending: &PoolPendingDeletion) -> Result<bool> {
        if pending.phase == PendingDeletionPhase::Prepared {
            return self.clear_pending_deletion_handoff(pending);
        }

        let newer_receipt = self.newer_receipt_superseding_deletion(pending)?;
        if let Some(newer) = &newer_receipt {
            let indices = self.class_map.get(pending.class);
            self.verify_placement_receipt_publication(indices, newer)?;
        }
        let clearance_receipt = newer_receipt.as_ref().unwrap_or(&pending.receipt);
        let mut resolved = true;

        for target in &pending.receipt.targets {
            let Some(idx) = self.device_index_for_guid(target.device_guid) else {
                resolved = false;
                continue;
            };
            if newer_receipt.as_ref().is_some_and(|newer| {
                self.newer_receipt_owns_physical_target(newer, &pending.receipt, target)
            }) {
                continue;
            }
            let physical_key = match pending.receipt.policy {
                PoolRedundancyPolicy::Replicated { .. } => pending.receipt.object_key,
                PoolRedundancyPolicy::Erasure { .. } => {
                    placement_shard_object_key(pending.receipt.object_key, target.shard_index)
                }
            };
            if self.devices[idx].get(physical_key)?.is_some() {
                self.enqueue_replaced_physical_object(idx, physical_key, clearance_receipt)?;
                match pending.receipt.policy {
                    PoolRedundancyPolicy::Replicated { .. } => {
                        self.devices[idx].delete_exact_logical_object(physical_key)?;
                    }
                    PoolRedundancyPolicy::Erasure { .. } => {
                        self.devices[idx].delete_exact_pool_internal_object(physical_key)?;
                    }
                }
            }
            resolved &= self.devices[idx].get(physical_key)?.is_none();
        }

        let receipt_key = placement_receipt_object_key(pending.receipt.object_key);
        for guid in &pending.receipt_carrier_guids {
            let Some(idx) = self.device_index_for_guid(*guid) else {
                resolved = false;
                continue;
            };
            if let Some(raw) = self.devices[idx].get(receipt_key)? {
                let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                    reason: "pending deletion cleanup found a corrupt receipt carrier",
                })?;
                if receipt.generation > pending.receipt.generation {
                    continue;
                }
                if receipt != pending.receipt {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending deletion cleanup found conflicting receipt authority",
                    });
                }
                self.devices[idx].delete_exact_pool_internal_object(receipt_key)?;
            }
            if let Some(raw) = self.devices[idx].get(receipt_key)? {
                let retained =
                    PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                        reason: "pending deletion cleanup retained a corrupt receipt carrier",
                    })?;
                resolved &= retained.generation > pending.receipt.generation;
            }
        }

        if newer_receipt.is_none() {
            let indices = self.class_map.get(pending.class);
            resolved &= !self.logical_raw_payload_visible_for_policy(
                indices,
                pending.receipt.object_key,
                pending.receipt.policy,
            )?;
        }
        if !resolved {
            return Ok(false);
        }

        self.clear_pending_deletion_handoff(pending)
    }

    fn reconcile_pending_deletions_on_open(&mut self) {
        let pending = self.pending_deletions.values().cloned().collect::<Vec<_>>();
        for handoff in pending {
            if let Err(error) = self.reconcile_one_pending_deletion(&handoff) {
                eprintln!(
                    "tidefs: pending deletion for {:?} remains replayable after reopen: {error}",
                    handoff.receipt.object_key
                );
            }
        }
    }

    fn obsolete_physical_placements(
        &self,
        receipt: &PlacementReceipt,
    ) -> Result<Vec<ObsoletePhysicalPlacement>> {
        let mut placements = BTreeSet::new();
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                for target in &receipt.targets {
                    let Some(device_index) = self.resolve_receipt_target(target) else {
                        continue;
                    };
                    let object_key = receipt.object_key;
                    let lifetime = self.devices[device_index]
                        .store()
                        .current_receipt_bound_physical_lifetime_pool_internal(object_key)?;
                    placements.insert(ObsoletePhysicalPlacement {
                        device_index,
                        object_key,
                        reclaim_object_id: lifetime.reclaim_object_id,
                    });
                }
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                for target in &receipt.targets {
                    let Some(device_index) = self.resolve_receipt_target(target) else {
                        continue;
                    };
                    let object_key =
                        placement_shard_object_key(receipt.object_key, target.shard_index);
                    let lifetime = self.devices[device_index]
                        .store()
                        .current_receipt_bound_physical_lifetime_pool_internal(object_key)?;
                    placements.insert(ObsoletePhysicalPlacement {
                        device_index,
                        object_key,
                        reclaim_object_id: lifetime.reclaim_object_id,
                    });
                }
            }
        }
        Ok(placements.into_iter().collect())
    }

    fn persist_pending_obsolete_placements(
        &mut self,
        old_receipt: &PlacementReceipt,
        replacement_generation: u64,
    ) -> Result<Vec<ObsoletePhysicalPlacement>> {
        let placements = self.obsolete_physical_placements(old_receipt)?;
        self.persist_pending_obsolete_placement_set(
            &placements,
            replacement_generation,
            replacement_generation,
        )?;
        Ok(placements)
    }

    fn persist_pending_obsolete_placement_set(
        &mut self,
        placements: &[ObsoletePhysicalPlacement],
        death_generation: u64,
        enqueued_generation: u64,
    ) -> Result<()> {
        for placement in placements {
            let entry = DeadObjectEntry::new(
                placement.reclaim_object_id,
                self.pool_guid,
                death_generation,
                true,
                enqueued_generation,
            );
            self.devices[placement.device_index]
                .store_mut()
                .enqueue_pending_receipt_bound_dead_object_pool_internal(entry)?;
        }
        Ok(())
    }

    fn attach_obsolete_placement_receipt(
        &mut self,
        placements: &[ObsoletePhysicalPlacement],
        replacement_receipt: &PlacementReceipt,
    ) -> Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_post_publication_reclaim_attachment_once) {
            return Err(StoreError::InvalidOptions {
                reason: "test fault: post-publication reclaim attachment failed",
            });
        }

        for placement in placements {
            let object_id = placement.reclaim_object_id;
            let replacement = dead_object_replacement_receipt_for_object(
                placement.object_key,
                object_id,
                replacement_receipt,
            )?;
            let _updated = self.devices[placement.device_index]
                .store_mut()
                .publish_dead_object_replacement_receipt_pool_internal(&object_id, replacement)?;
        }
        Ok(())
    }

    fn enqueue_replaced_physical_object(
        &mut self,
        device_index: usize,
        object_key: ObjectKey,
        replacement_receipt: &PlacementReceipt,
    ) -> Result<()> {
        let lifetime = self.devices[device_index]
            .store()
            .current_receipt_bound_physical_lifetime_pool_internal(object_key)?;
        let replacement = dead_object_replacement_receipt_for_object(
            object_key,
            lifetime.reclaim_object_id,
            replacement_receipt,
        )?;
        let death_txg = replacement.receipt_generation;
        let entry = DeadObjectEntry::new(
            lifetime.reclaim_object_id,
            self.pool_guid,
            death_txg,
            true,
            death_txg,
        );
        let store = self.devices[device_index].store_mut();
        store.enqueue_pending_receipt_bound_dead_object_pool_internal(entry)?;
        store
            .publish_dead_object_replacement_receipt_pool_internal(&entry.object_id, replacement)?;
        Ok(())
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

    #[cfg(any(feature = "distributed-repair", test))]
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
                    let _ = self.devices[idx].delete_pool_internal(shard_key);
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
        self.ensure_writable("pool put")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        if crate::is_pool_placement_scan_internal_key(key)
            || crate::store::is_pool_pending_deletion_key(key)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pool receipt, shard, generation, and deletion namespaces are reserved",
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
                self.validate_receipt_generation_high_water()?;
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
            IoClass::Metadata => self
                .put_pool_wide(
                    class,
                    key,
                    payload,
                    &indices,
                    OldReceiptPolicy::RequireValid,
                )
                .map(|(stored, _receipt)| stored),
            IoClass::Data => {
                self.check_write_admission(class, payload.len() as u64)?;
                self.put_pool_wide(
                    class,
                    key,
                    payload,
                    &indices,
                    OldReceiptPolicy::RequireValid,
                )
                .map(|(stored, _receipt)| stored)
            }
            IoClass::ReadCache => self
                .put_pool_wide(
                    class,
                    key,
                    payload,
                    &indices,
                    OldReceiptPolicy::RequireValid,
                )
                .map(|(stored, _receipt)| stored),
        }
    }

    /// Store an object and return the authoritative placement receipt.
    ///
    /// Identical to [`Pool::put`] for receipt-publishing I/O classes except
    /// that it also returns the persisted [`PlacementReceipt`] that records
    /// the pool-wide placement decision.
    /// Callers that need durable receipt references for distributed
    /// rebuild/backfill, rebake gating, or reclaim durability checks should
    /// use this method rather than [`Pool::put`] plus a subsequent receipt
    /// lookup.
    pub fn put_with_receipt(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)> {
        self.ensure_writable("pool put with receipt")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        if matches!(class, IoClass::IntentLog) {
            return Err(StoreError::InvalidOptions {
                reason: "IntentLog writes do not publish placement receipts",
            });
        }
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }
        if matches!(class, IoClass::Data) {
            self.check_write_admission(class, payload.len() as u64)?;
        }
        self.put_pool_wide(
            class,
            key,
            payload,
            &indices,
            OldReceiptPolicy::RequireValid,
        )
    }

    /// Ensure one deterministic pre-publication data object has current
    /// placement-receipt authority without replacing different current data.
    ///
    /// An exact strict read is returned unchanged. A different payload with a
    /// valid current receipt is refused, as is every malformed, conflicting,
    /// stale, receiptless, or otherwise ambiguous state. Only a mechanically
    /// absent key may be published. Callers that own a separately proven
    /// prepublication rewrite must use an exact compare-and-replace path rather
    /// than weakening this generic ensure operation.
    pub fn ensure_prepublication_data_object_with_receipt(
        &mut self,
        key: ObjectKey,
        expected_payload: &[u8],
    ) -> Result<PlacementReceipt> {
        self.ensure_writable("pool prepublication write")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        let class = IoClass::Data;
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        match self.get_with_current_receipt(class, key) {
            Ok(Some((payload, receipt))) if payload == expected_payload => return Ok(receipt),
            Ok(Some(_)) => {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "prepublication object key already has different current receipt-backed payload",
                });
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }

        self.check_write_admission(class, expected_payload.len() as u64)?;
        let (_stored, receipt) = self.put_pool_wide(
            class,
            key,
            expected_payload,
            &indices,
            OldReceiptPolicy::RequireValid,
        )?;
        match self.get_with_current_receipt(class, key)? {
            Some((payload, current)) if payload == expected_payload && current == receipt => {
                Ok(receipt)
            }
            Some((_payload, _current)) => Err(StoreError::InvalidOptions {
                reason:
                    "replay object publication did not preserve exact payload and receipt authority",
            }),
            None => Err(StoreError::InvalidOptions {
                reason: "replay object publication left no current placement receipt",
            }),
        }
    }

    /// Repair an object using receipt authority and record a replacement receipt.
    ///
    /// On corruption detected during scrub or degraded read, the caller can
    /// supply reconstructed data via `repaired_payload`. This method rewrites
    /// the data through the pool-wide placement planner, producing a fresh
    /// [`PlacementReceipt`] that supersedes any prior receipt for `key`.
    /// The old receipt is automatically queued for dead-object reclaim with
    /// the new receipt as replacement evidence.
    pub fn repair_with_receipt(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        repaired_payload: &[u8],
        _repair_source: RepairSource,
    ) -> Result<(StoredObject, PlacementReceipt)> {
        self.ensure_writable("pool repair")?;
        self.put_with_receipt(class, key, repaired_payload)
    }

    /// Read an erasure-coded object and publish replacement receipt evidence
    /// when reconstruction was required.
    ///
    /// Unlike [`Pool::get`], this mutable entry point consumes the rebuilt
    /// shard evidence returned by the shared receipt-aware EC helper. A
    /// degraded read is rewritten through [`Pool::repair_with_receipt`], and
    /// repair success is reported only after the replacement receipt has been
    /// persisted. The ordinary read path remains available when callers do not
    /// own mutable pool authority.
    pub fn get_erasure_with_repair_receipt(
        &mut self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<ErasureReadWithReceipt>> {
        self.ensure_writable("pool erasure read repair")?;
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
        let receipt =
            self.load_placement_receipt(&indices, key)?
                .ok_or(StoreError::InvalidOptions {
                    reason: "erasure read repair requires a placement receipt",
                })?;
        if self.pending_deletion_hides_generation(class, key, Some(receipt.generation)) {
            return Ok(None);
        }
        if !matches!(receipt.policy, PoolRedundancyPolicy::Erasure { .. }) {
            return Err(StoreError::InvalidOptions {
                reason: "erasure read repair requires an erasure placement receipt",
            });
        }

        let Some(read) = self.reconstruct_erasure_with_receipt(&receipt)? else {
            return Ok(None);
        };
        if read.rebuilt_shard_indices.is_empty() {
            return Ok(Some(ErasureReadWithReceipt {
                payload: read.payload,
                receipt,
                repair_status: ErasureReadRepairStatus::NotRequired,
            }));
        }

        let ReconstructedErasureRead {
            payload,
            rebuilt_shard_indices,
        } = read;
        let (_, replacement_receipt) =
            self.repair_with_receipt(class, key, &payload, RepairSource::ErasureReconstruction)?;
        Ok(Some(ErasureReadWithReceipt {
            payload,
            receipt: replacement_receipt,
            repair_status: ErasureReadRepairStatus::ReplacementPublished {
                rebuilt_shard_indices,
            },
        }))
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
            if self.pending_deletion_hides_generation(class, key, Some(receipt.generation)) {
                return Ok(None);
            }
            return self.get_with_receipt(&receipt);
        }

        if self.pending_deletion_hides_generation(class, key, None) {
            return Ok(None);
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

    fn verify_strict_receipt_target_copies(&self, receipt: &PlacementReceipt) -> Result<()> {
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        let mut missing_indices = BTreeSet::new();
        let mut present_targets = 0usize;
        for target in &receipt.targets {
            let Some(idx) = self.resolve_receipt_target(target) else {
                if self.admit_read_only_missing_receipt_target(
                    receipt,
                    target,
                    &mut missing_indices,
                ) || self.admit_replacement_resume_missing_receipt_target(
                    receipt,
                    target,
                    &mut missing_indices,
                ) {
                    continue;
                }
                return Err(StoreError::InvalidOptions {
                    reason: "strict read could not resolve every receipt target",
                });
            };
            present_targets = present_targets.saturating_add(1);
            let raw = self.devices[idx]
                .get(receipt_key)
                .map_err(|_| StoreError::InvalidOptions {
                    reason: "strict read could not read every target receipt copy",
                })?
                .ok_or(StoreError::InvalidOptions {
                    reason: "strict read found a missing target receipt copy",
                })?;
            let persisted = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "strict read found a corrupt target receipt copy",
            })?;
            if persisted != *receipt {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "strict read found a target receipt copy that does not match current authority",
                });
            }
        }
        if present_targets == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "strict read has no present receipt target authority",
            });
        }
        Ok(())
    }

    /// Read only through one current, internally consistent placement receipt.
    ///
    /// Unlike [`Pool::get`], this entry point rejects receiptless raw payloads
    /// and any malformed, replayless, zero-version, or conflicting receipt.
    /// Every present encoded target must retain the exact receipt copy and
    /// exact payload or shard named by it. A read-only import whose labels
    /// prove a larger replicated member set may omit no more unresolved
    /// targets than the label-declared missing-member count; at least one
    /// present replica must still verify. Writable and erasure-coded opens
    /// keep requiring every target. The selected receipt is scanned again
    /// after the exact-receipt read so callers never receive bytes under
    /// authority that changed in flight.
    pub fn get_with_current_receipt(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
        let indices = self
            .class_map
            .get(class)
            .iter()
            .copied()
            .filter(|idx| {
                self.allocation_fenced_device_guid
                    .is_none_or(|guid| self.device_guids.get(*idx) != Some(&guid))
            })
            .collect::<Vec<_>>();
        if indices.is_empty() && self.allocation_fenced_device_guid.is_some() {
            return self.get_with_removal_predecessor_receipt(class, key);
        }
        let current = self.get_with_current_receipt_from_indices(class, key, &indices)?;
        if current.is_some() || self.allocation_fenced_device_guid.is_none() {
            return Ok(current);
        }
        // A partial evacuation can legitimately leave an unrelocated object
        // current only on the still-attached fenced target. Preserve mounted
        // reads through that exact predecessor until a retry relocates it.
        self.get_with_removal_predecessor_receipt(class, key)
    }

    /// Strictly read the current receipt authority from survivor devices while
    /// one marker-bound removal target remains attached and allocation-fenced.
    ///
    /// This boundary exists only so higher-layer embedded receipt references
    /// can advance before detach. It does not admit arbitrary degraded reads.
    pub fn get_with_removal_survivor_receipt(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
        let fenced_guid = self
            .allocation_fenced_device_guid
            .ok_or(StoreError::InvalidOptions {
                reason: "removal survivor read requires an allocation-fenced target",
            })?;
        let indices = self
            .class_map
            .get(class)
            .iter()
            .copied()
            .filter(|idx| self.device_guids.get(*idx) != Some(&fenced_guid))
            .collect::<Vec<_>>();
        self.get_with_current_receipt_from_indices(class, key, &indices)
    }

    /// Read the exact pre-relocation payload whose receipt copy remains on
    /// the allocation-fenced removal target.
    ///
    /// This authority exists only while the durable removal marker keeps the
    /// target attached. Mounted recovery uses it to authenticate the previous
    /// content-manifest bytes after a crash between survivor reconciliation
    /// and publication of the first replacement filesystem root. It does not
    /// make the predecessor receipt current again.
    pub fn get_with_removal_predecessor_receipt(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
        let fenced_guid = self
            .allocation_fenced_device_guid
            .ok_or(StoreError::InvalidOptions {
                reason: "removal predecessor read requires an allocation-fenced target",
            })?;
        let fenced_idx = self
            .device_guids
            .iter()
            .position(|guid| *guid == fenced_guid)
            .ok_or(StoreError::InvalidOptions {
                reason: "removal predecessor target is no longer attached",
            })?;
        if !self.class_map.get(class).contains(&fenced_idx) {
            return Ok(None);
        }

        let receipt_key = placement_receipt_object_key(key);
        let Some(encoded_receipt) = self.devices[fenced_idx].get(receipt_key)? else {
            return Ok(None);
        };
        let receipt =
            PlacementReceipt::decode(&encoded_receipt).ok_or(StoreError::InvalidOptions {
                reason: "removal predecessor receipt copy is corrupt",
            })?;
        validate_strict_receipt_structure(&receipt)?;
        self.ensure_receipt_replay_authority(&receipt)?;
        if receipt.object_key != key || receipt.generation == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "removal predecessor receipt has invalid identity",
            });
        }
        if !receipt
            .targets
            .iter()
            .any(|target| target.device_guid == fenced_guid)
        {
            // Placement receipts can have redundant copies beyond their
            // payload targets. A copy on the fenced device that names only
            // survivors is not predecessor authority for this key.
            return Ok(None);
        }
        if self.pending_deletion_hides_generation(class, key, Some(receipt.generation)) {
            return Ok(None);
        }

        let Some(payload) = self.get_with_receipt(&receipt)? else {
            return Err(StoreError::InvalidOptions {
                reason: "removal predecessor receipt cannot recover its payload",
            });
        };
        let expected_len =
            usize::try_from(receipt.payload_len).map_err(|_| StoreError::InvalidOptions {
                reason: "removal predecessor payload length exceeds platform usize",
            })?;
        if payload.len() != expected_len || digest32(&payload) != receipt.payload_digest {
            return Err(StoreError::InvalidOptions {
                reason: "removal predecessor payload does not match its receipt",
            });
        }
        Ok(Some((payload, receipt)))
    }

    fn get_with_current_receipt_from_indices(
        &self,
        class: IoClass,
        key: ObjectKey,
        indices: &[usize],
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        let Some(receipt) = map_strict_read_object_io(
            self.load_current_placement_receipt_strict(indices, key),
            "strict read could not inspect every placement receipt copy",
        )?
        else {
            if self.pending_deletion_hides_generation(class, key, None) {
                return Ok(None);
            }
            if map_strict_read_object_io(
                self.logical_raw_payload_visible(indices, key),
                "strict read could not establish receiptless raw payload absence",
            )? {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read refuses a receiptless raw payload",
                });
            }
            return Ok(None);
        };

        if self.pending_deletion_hides_generation(class, key, Some(receipt.generation)) {
            return Ok(None);
        }

        self.verify_strict_receipt_target_copies(&receipt)?;
        let payload =
            self.get_with_receipt_strict(&receipt)?
                .ok_or(StoreError::InvalidOptions {
                    reason: "strict read could not recover the current receipted payload",
                })?;
        let expected_len =
            usize::try_from(receipt.payload_len).map_err(|_| StoreError::InvalidOptions {
                reason: "placement receipt payload length exceeds platform usize",
            })?;
        if payload.len() != expected_len {
            return Err(StoreError::InvalidOptions {
                reason: "strict read payload length does not match placement receipt",
            });
        }
        if digest32(&payload) != receipt.payload_digest {
            return Err(StoreError::InvalidOptions {
                reason: "strict read payload digest does not match placement receipt",
            });
        }

        let current = map_strict_read_object_io(
            self.load_current_placement_receipt_strict(indices, key),
            "strict read could not inspect every placement receipt copy",
        )?;
        if current.as_ref() != Some(&receipt) {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt changed during strict read",
            });
        }
        self.verify_strict_receipt_target_copies(&receipt)?;

        Ok(Some((payload, receipt)))
    }

    fn get_with_receipt(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => self.get_replicated_with_receipt(receipt),
            PoolRedundancyPolicy::Erasure { .. } => self.get_erasure_with_receipt(receipt),
        }
    }

    fn get_with_receipt_strict(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                self.get_replicated_with_receipt_strict(receipt)
            }
            PoolRedundancyPolicy::Erasure { .. } => self.get_erasure_with_receipt_strict(receipt),
        }
    }

    fn get_replicated_with_receipt_strict(
        &self,
        receipt: &PlacementReceipt,
    ) -> Result<Option<Vec<u8>>> {
        self.ensure_receipt_replay_authority(receipt)?;
        let mut missing_indices = BTreeSet::new();
        let expected_len =
            usize::try_from(receipt.payload_len).map_err(|_| StoreError::InvalidOptions {
                reason: "placement receipt payload length exceeds platform usize",
            })?;
        let mut canonical = None;
        for target in &receipt.targets {
            let Some(idx) = self.resolve_receipt_target(target) else {
                if self.admit_read_only_missing_receipt_target(
                    receipt,
                    target,
                    &mut missing_indices,
                ) || self.admit_replacement_resume_missing_receipt_target(
                    receipt,
                    target,
                    &mut missing_indices,
                ) {
                    continue;
                }
                return Err(StoreError::InvalidOptions {
                    reason: "strict read could not resolve every replicated placement target",
                });
            };
            let payload = self.devices[idx]
                .get(receipt.object_key)
                .map_err(|_| StoreError::InvalidOptions {
                    reason: "strict read could not read every replicated placement target",
                })?
                .ok_or(StoreError::InvalidOptions {
                    reason: "strict read found a missing replicated placement target",
                })?;
            if payload.len() != expected_len {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read found a wrong-length replicated placement target",
                });
            }
            if digest32(&payload) != target.stored_digest
                || target.stored_digest != receipt.payload_digest
            {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read found a corrupt replicated placement target",
                });
            }
            if canonical
                .as_ref()
                .is_some_and(|canonical: &Vec<u8>| canonical != &payload)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read found divergent replicated placement targets",
                });
            }
            canonical.get_or_insert(payload);
        }
        if canonical.is_none() {
            return Err(StoreError::InvalidOptions {
                reason: "strict read has no present replicated placement target",
            });
        }
        Ok(canonical)
    }

    fn get_erasure_with_receipt_strict(
        &self,
        receipt: &PlacementReceipt,
    ) -> Result<Option<Vec<u8>>> {
        let read = self
            .reconstruct_erasure_with_receipt(receipt)
            .map_err(|error| {
                if is_strict_read_authority_error(&error) {
                    error
                } else {
                    StoreError::InvalidOptions {
                        reason: "strict read could not verify every erasure placement target",
                    }
                }
            })?;
        let Some(read) = read else {
            return Ok(None);
        };
        if !read.rebuilt_shard_indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "strict read found a missing or corrupt erasure placement target",
            });
        }
        Ok(Some(read.payload))
    }

    fn get_replicated_with_receipt(&self, receipt: &PlacementReceipt) -> Result<Option<Vec<u8>>> {
        self.ensure_receipt_replay_authority(receipt)?;
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
        Ok(self
            .reconstruct_erasure_with_receipt(receipt)?
            .map(|read| read.payload))
    }

    #[cfg(any(feature = "distributed-repair", test))]
    fn reconstruct_erasure_with_receipt(
        &self,
        receipt: &PlacementReceipt,
    ) -> Result<Option<ReconstructedErasureRead>> {
        self.ensure_receipt_replay_authority(receipt)?;
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
        if receipt.targets.len() != width {
            return Err(StoreError::InvalidOptions {
                reason: "invalid erasure placement receipt availability set",
            });
        }
        let mut available = vec![None; width];
        let mut seen_indices = vec![false; width];

        for target in &receipt.targets {
            let shard_index = target.shard_index as usize;
            if shard_index >= width {
                return Err(StoreError::InvalidOptions {
                    reason: "invalid erasure placement receipt availability set",
                });
            }
            if seen_indices[shard_index] {
                return Err(StoreError::InvalidOptions {
                    reason: "invalid erasure placement receipt availability set",
                });
            }
            let role_matches_index = match target.role {
                PlacementTargetRole::Data => shard_index < config.data_shards,
                PlacementTargetRole::Parity => shard_index >= config.data_shards,
            };
            if !role_matches_index {
                return Err(StoreError::InvalidOptions {
                    reason: "invalid erasure placement receipt availability set",
                });
            }
            seen_indices[shard_index] = true;
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

        let mut reconstructed = match reconstruct_receipt_stripe(&config, &available) {
            Ok(reconstructed) => reconstructed,
            Err(ReceiptStripeError::InsufficientShards { .. }) => return Ok(None),
            Err(ReceiptStripeError::InvalidAvailableSet { .. }) => {
                return Err(StoreError::InvalidOptions {
                    reason: "invalid erasure placement receipt availability set",
                });
            }
            Err(ReceiptStripeError::EncodeRejected) => {
                return Err(StoreError::InvalidOptions {
                    reason: "erasure placement receipt reconstruction rejected payload",
                });
            }
        };
        reconstructed.payload.truncate(receipt.payload_len as usize);
        if digest32(&reconstructed.payload) != receipt.payload_digest {
            return Ok(None);
        }
        let rebuilt_shard_indices = reconstructed
            .rebuilt_shards
            .iter()
            .map(|shard| {
                u16::try_from(shard.index).map_err(|_| StoreError::InvalidOptions {
                    reason: "reconstructed erasure shard index exceeds u16",
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(ReconstructedErasureRead {
            payload: reconstructed.payload,
            rebuilt_shard_indices,
        }))
    }

    #[cfg(all(not(feature = "distributed-repair"), not(test)))]
    fn reconstruct_erasure_with_receipt(
        &self,
        _receipt: &PlacementReceipt,
    ) -> Result<Option<ReconstructedErasureRead>> {
        Err(StoreError::InvalidOptions {
            reason: "erasure pool operation requires the distributed-repair feature",
        })
    }

    /// Publish logical deletion for one receipted object.
    pub fn delete(&mut self, class: IoClass, key: ObjectKey) -> Result<bool> {
        self.ensure_writable("pool delete")?;
        if crate::is_pool_placement_scan_internal_key(key)
            || crate::store::is_pool_pending_deletion_key(key)
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "pool receipt, shard, generation, and deletion metadata cannot be deleted directly",
            });
        }
        self.validate_receipt_generation_high_water()?;
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        if let Some(pending) = self.pending_deletion_for_subject(class, key) {
            if pending.phase >= PendingDeletionPhase::Committed {
                if let Err(error) = self.reconcile_one_pending_deletion(&pending) {
                    eprintln!(
                        "tidefs: committed deletion retry for {key:?} retained cleanup: {error}"
                    );
                }
                let current = match self.load_current_placement_receipt_strict(&indices, key) {
                    Ok(current) => current,
                    Err(error) => {
                        eprintln!(
                            "tidefs: committed deletion retry for {key:?} retained unresolved replacement authority: {error}"
                        );
                        self.health = compute_health(&self.devices);
                        self.record_health_transitions();
                        return Ok(false);
                    }
                };
                if current
                    .as_ref()
                    .is_none_or(|receipt| receipt.generation <= pending.receipt.generation)
                {
                    self.health = compute_health(&self.devices);
                    self.record_health_transitions();
                    return Ok(false);
                }
            } else if !self.clear_pending_deletion_handoff(&pending)? {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "prepared deletion handoff cannot be cleared from every receipt carrier",
                });
            }
        }

        if let Some(receipt) = self.load_current_placement_receipt_strict(&indices, key)? {
            let carriers = self.receipt_carriers(&indices, &receipt)?;
            let receipt_carrier_guids = carriers
                .iter()
                .map(|idx| self.device_guid_for_index(*idx))
                .collect::<Vec<_>>();
            let mut pending = PoolPendingDeletion {
                pool_guid: self.pool_guid,
                class,
                receipt,
                receipt_carrier_guids,
                phase: PendingDeletionPhase::Prepared,
            };

            #[cfg(test)]
            if std::mem::take(&mut self.fail_pending_deletion_preflight_once) {
                return Err(StoreError::InvalidOptions {
                    reason: "test fault: pending deletion preflight failed",
                });
            }
            self.persist_pending_deletion_phase(&pending)?;

            pending.phase = PendingDeletionPhase::Committed;
            self.persist_pending_deletion_phase(&pending)?;

            #[cfg(test)]
            if std::mem::take(&mut self.fail_post_deletion_publication_cleanup_once) {
                self.health = compute_health(&self.devices);
                self.record_health_transitions();
                return Ok(true);
            }

            if let Err(error) = self.reconcile_one_pending_deletion(&pending) {
                eprintln!(
                    "tidefs: deletion committed for {key:?}; exact physical cleanup remains pending: {error}"
                );
            }
            self.health = compute_health(&self.devices);
            self.record_health_transitions();
            return Ok(true);
        }

        if self.logical_raw_payload_visible(&indices, key)? {
            Err(StoreError::InvalidOptions {
                reason: "pool delete refuses a receiptless raw payload",
            })
        } else {
            Ok(false)
        }
    }

    /// Drain receipt-authorized dead objects across the devices for an I/O class
    /// using the last generation strictly below `stable_committed_txg`.
    ///
    /// Prefer
    /// [`Self::drain_receipt_bound_dead_objects_at_stable_generation`] when the
    /// caller owns an explicit committed receipt-generation boundary.
    pub fn drain_receipt_bound_dead_objects_at_txg(
        &mut self,
        class: IoClass,
        stable_committed_txg: u64,
        max_count: usize,
    ) -> std::result::Result<
        PoolReceiptBoundDeadObjectDrainStats,
        crate::store::ReceiptBoundDeadObjectDrainError,
    > {
        self.drain_receipt_bound_dead_objects_at_stable_generation(
            class,
            stable_committed_txg,
            stable_committed_txg.saturating_sub(1),
            max_count,
        )
    }

    /// Drain receipt-authorized dead objects across the devices for an I/O class.
    ///
    /// The stable boundaries are caller-supplied so higher layers can tie
    /// source reclamation to the replacement placement receipt that made the
    /// new placement legal.
    pub fn drain_receipt_bound_dead_objects_at_stable_generation(
        &mut self,
        class: IoClass,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> std::result::Result<
        PoolReceiptBoundDeadObjectDrainStats,
        crate::store::ReceiptBoundDeadObjectDrainError,
    > {
        if let Err(error) = self.ensure_writable("pool receipt-bound reclaim") {
            return Err(error.into());
        }
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for receipt-bound reclaim",
            }
            .into());
        }
        if let Err(error) = self.validate_receipt_generation_high_water() {
            return Err(error.into());
        }

        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            }
            .into());
        }

        let mut aggregate = PoolReceiptBoundDeadObjectDrainStats::default();
        let mut remaining = max_count;
        for idx in self.usable_candidates(&indices) {
            let stats = self.devices[idx]
                .store_mut()
                .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                    stable_committed_txg,
                    stable_committed_generation,
                    remaining,
                )?;
            aggregate.devices_scanned += 1;
            aggregate.absorb_reclaim_stats(stats);
            remaining = remaining.saturating_sub(stats.entries_processed);
        }

        if aggregate.devices_scanned == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "receipt-bound reclaim found no writable pool devices",
            }
            .into());
        }

        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        Ok(aggregate)
    }

    /// Flush all devices.
    pub fn sync_all(&mut self) -> Result<()> {
        self.ensure_writable("pool sync_all")?;
        self.validate_receipt_generation_high_water()?;
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
        self.ensure_writable("pool sync_data")?;
        self.validate_receipt_generation_high_water()?;
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
        self.ensure_writable("pool add device")?;
        self.validate_receipt_generation_high_water()?;
        let config_for_record = config.clone();
        let mut dev_opts = options.clone();
        dev_opts.max_segment_bytes = config.media_class.default_segment_size();
        let device_guid: [u8; 16] = rand::random();
        let identity = BlockStoreIdentity {
            pool_guid: self.pool_guid,
            device_guid,
        };
        let mut device = open_candidate_device(
            &config,
            &dev_opts,
            options.is_test_fast_harness_fixture(),
            identity,
        )?;
        device.install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
        seed_receipt_generation_high_water_on_candidate(
            &mut device,
            self.pool_guid,
            self.reserved_placement_receipt_generation_through,
        )?;
        let added_log_device =
            if config.class == DeviceClass::IntentLog && self.log_device.is_none() {
                let mut prospective_configs = self.config.devices.clone();
                prospective_configs.push(config_for_record.clone());
                open_log_device_for_devices(&prospective_configs)?
            } else {
                None
            };
        let capacity_bytes = device.store().capacity_bytes();
        let device_layout = self
            .properties
            .layout_policy
            .compute(capacity_bytes)
            .unwrap_or_else(|_| {
                DeviceLayoutPolicy::Slice0Small
                    .compute(capacity_bytes)
                    .expect("Slice0Small must succeed for non-zero device")
            });
        self.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RecoveryRequired,
        );
        self.classes.push(config.class);
        self.media_classes.push(config.media_class);
        self.devices.push(device);
        self.device_guids.push(device_guid);
        self.device_layouts.push(device_layout);
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
        if added_log_device.is_some() {
            self.log_device = added_log_device;
        }
        self.bump_placement_epoch();
        self.persist_active_labels_if_needed()?;
        self.converge_receipt_generation_authority()?;
        self.record_health_transitions();
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
        self.ensure_writable("pool activate spare")?;
        self.validate_receipt_generation_high_water()?;
        // Find the faulted device's index.
        let faulted_index = self
            .device_guids
            .iter()
            .position(|g| g == &faulted_device_guid)
            .ok_or(StoreError::InvalidOptions {
                reason: "faulted device GUID not found in pool",
            })?;

        let existing_configs = self.config.devices.clone();

        // Seed and synchronise generation authority on the candidate before
        // label publication can admit it to the active topology.
        let mut dev_opts = options.clone();
        dev_opts.max_segment_bytes = spare_config.media_class.default_segment_size();
        let identity = BlockStoreIdentity {
            pool_guid: self.pool_guid,
            device_guid: spare_device_guid,
        };
        let mut new_device = open_candidate_device(
            &spare_config,
            &dev_opts,
            options.is_test_fast_harness_fixture(),
            identity,
        )?;
        new_device.install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
        seed_receipt_generation_high_water_on_candidate(
            &mut new_device,
            self.pool_guid,
            self.reserved_placement_receipt_generation_through,
        )?;
        self.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RecoveryRequired,
        );

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
        self.converge_receipt_generation_authority()?;
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
        self.ensure_writable("pool register spare")?;
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

    /// Detach an already-evacuated device from this Pool instance.
    ///
    /// This does not publish durable topology and therefore must remain behind
    /// [`Self::safe_remove_device`].
    fn remove_device(&mut self, path: &Path) -> Result<()> {
        let idx = self.devices.iter().position(|v| v.root() == path).ok_or(
            StoreError::InvalidOptions {
                reason: "device not found",
            },
        )?;
        let removes_active_log_device = self
            .config
            .devices
            .iter()
            .position(|config| config.class == DeviceClass::IntentLog)
            == Some(idx);
        if removes_active_log_device {
            let log_path = device_root_path(&self.config.devices[idx]).join(LOG_DEVICE_FILENAME);
            let log_len = fs::metadata(&log_path)
                .map_err(|source| StoreError::Io {
                    operation: "inspect_log_device_before_removal",
                    path: log_path.clone(),
                    source,
                })?
                .len();
            if log_len > LOG_DEVICE_HEADER_SIZE {
                return Err(StoreError::InvalidOptions {
                    reason: "cannot remove active intent-log device with undrained records",
                });
            }
            if log_len < LOG_DEVICE_HEADER_SIZE {
                return Err(StoreError::InvalidOptions {
                    reason: "cannot remove active intent-log device with truncated header",
                });
            }
            // Header-only is the drained state only when the header still
            // decodes as a valid log-device record. Re-open it read/write to
            // reuse the format validation without mutating a non-empty log.
            drop(LogDeviceWriter::open(&log_path)?);
        }
        let replacement_log_device = if removes_active_log_device {
            let remaining_configs: Vec<_> = self
                .config
                .devices
                .iter()
                .enumerate()
                .filter(|(device_idx, _)| *device_idx != idx)
                .map(|(_, config)| config.clone())
                .collect();
            Some(open_log_device_for_devices(&remaining_configs)?)
        } else {
            None
        };
        if replacement_log_device.is_some() {
            self.close_log_device()?;
        }
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
        if idx < self.device_layouts.len() {
            self.device_layouts.remove(idx);
        }
        if idx < self.config.devices.len() {
            self.config.devices.remove(idx);
        }
        if let Some(log_device) = replacement_log_device {
            self.log_device = log_device;
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

    /// Return a pending evacuation result established by this Pool instance.
    ///
    /// This is ephemeral operator-status state, not durable detach proof. It
    /// is available while the bound recovery marker remains valid and the
    /// target is still attached with the same identity.
    pub fn pending_device_removal_result(
        &self,
        path: &Path,
    ) -> Result<Option<crate::device_removal::EvacuationResult>> {
        let Some((pending_path, pending_guid, result)) = &self.pending_device_removal else {
            return Ok(None);
        };
        if pending_path != path {
            return Ok(None);
        }

        let marker = self
            .device_removal_marker
            .as_ref()
            .ok_or(StoreError::InvalidOptions {
                reason: "device removal label intent is missing while topology commit is pending",
            })?;
        if marker.pool_guid != self.pool_guid
            || marker.target_guid != *pending_guid
            || marker.target_path != *pending_path
            || self.device_guids.get(marker.target_index) != Some(pending_guid)
            || checked_successor_topology_generation(self.placement_epoch)
                != Some(marker.successor_topology_generation)
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal marker does not match pending in-memory detach",
            });
        }
        let Some(target_idx) = self
            .devices
            .iter()
            .position(|device| device.root() == pending_path)
        else {
            return Err(StoreError::InvalidOptions {
                reason: "pending device removal target is no longer attached",
            });
        };
        if target_idx != marker.target_index
            || self.device_guids.get(target_idx) != Some(pending_guid)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending device removal target identity changed",
            });
        }

        Ok(Some(result.clone()))
    }

    /// Return the attached target selected by the durable removal marker.
    ///
    /// The GUID, rather than the recorded path alone, selects the current
    /// member so a path rebound cannot redirect mounted resume.
    pub fn pending_device_removal_path(&self) -> Result<Option<PathBuf>> {
        let Some(marker) = self.device_removal_marker.as_ref() else {
            return Ok(None);
        };
        if marker.pool_guid != self.pool_guid {
            return Err(StoreError::InvalidOptions {
                reason: "device removal marker belongs to a different pool",
            });
        }
        if self.durable_device_guids.get(marker.target_index) != Some(&marker.target_guid)
            || self.device_guids.get(marker.target_index) != Some(&marker.target_guid)
            || checked_successor_topology_generation(self.placement_epoch)
                != Some(marker.successor_topology_generation)
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal label intent does not match the current topology",
            });
        }
        Ok(self
            .devices
            .get(marker.target_index)
            .map(|device| device.root().to_path_buf()))
    }

    /// Evacuate a device while keeping it attached to the current Pool.
    ///
    /// This is the preferred removal path. It enumerates current placement
    /// receipts and rewrites each receipt-backed logical object through the
    /// pool-wide redundancy policy on surviving devices. The target remains
    /// attached and the recovery marker remains durable so a mounted owner can
    /// advance embedded receipt references before topology commit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOptions`] when the pool is locked, the
    /// target device is not found, or it is the last remaining device in the
    /// pool. Returns [`StoreError::Io`] when object read/write/delete fails.
    pub fn prepare_safe_remove_device(
        &mut self,
        path: &Path,
    ) -> Result<crate::device_removal::EvacuationResult> {
        use crate::device_removal::EvacuationResult;

        self.ensure_writable("pool remove device")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }

        if let Some(result) = self.pending_device_removal_result(path)? {
            if result.objects_failed == 0 {
                return Ok(result);
            }
            self.pending_device_removal = None;
        }
        self.validate_receipt_generation_high_water()?;

        let target_idx = self.devices.iter().position(|v| v.root() == path).ok_or(
            StoreError::InvalidOptions {
                reason: "device not found for safe removal",
            },
        )?;
        let topology_len = self.devices.len();
        let mut unique_device_roots = BTreeSet::new();
        if self.config.devices.len() != topology_len
            || self.classes.len() != topology_len
            || self.media_classes.len() != topology_len
            || self.device_layout_stats.len() != topology_len
            || self.device_layouts.len() != topology_len
            || !self
                .devices
                .iter()
                .all(|device| unique_device_roots.insert(device.root().to_path_buf()))
            || self.config.devices.iter().enumerate().any(|(idx, config)| {
                config.path.as_path() != self.devices[idx].root()
                    || device_root_path(config) != self.devices[idx].root()
                    || config.class != self.classes[idx]
                    || config.media_class != self.media_classes[idx]
            })
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal topology tables are incomplete or misaligned",
            });
        }
        let target_guid = self.device_guid_for_index(target_idx);
        let mut matching_guid_indices = self
            .device_guids
            .iter()
            .enumerate()
            .filter_map(|(idx, guid)| (*guid == target_guid).then_some(idx));
        if matching_guid_indices.next() != Some(target_idx)
            || matching_guid_indices.next().is_some()
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal target GUID is missing or ambiguous",
            });
        }
        let mut unique_device_guids = BTreeSet::new();
        if self.device_guids.len() != self.devices.len()
            || !self
                .device_guids
                .iter()
                .copied()
                .all(|guid| unique_device_guids.insert(guid))
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal topology GUID table is incomplete or ambiguous",
            });
        }
        // Planner replay records project each GUID to its first 64 bits.
        // Full-GUID uniqueness alone does not make that locator one-to-one.
        let mut unique_replay_device_ids = BTreeSet::new();
        if !self
            .device_guids
            .iter()
            .map(|guid| u64::from_le_bytes(guid[..8].try_into().unwrap()))
            .all(|device_id| unique_replay_device_ids.insert(device_id))
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal placement replay IDs are ambiguous",
            });
        }

        // Refuse to remove the last device.
        if self.devices.len() <= 1 {
            return Err(StoreError::InvalidOptions {
                reason: "cannot remove the last device from the pool",
            });
        }

        // Write a removal-pending marker so a crash can be resumed on
        // next pool open. Device identity is GUID-bound so path rebinding
        // cannot make an attached target look already removed.
        if let Some(pending_marker) = self.device_removal_marker.as_ref() {
            if pending_marker.pool_guid != self.pool_guid {
                return Err(StoreError::InvalidOptions {
                    reason: "device removal marker belongs to a different pool",
                });
            }
            if pending_marker.target_guid != target_guid {
                return Err(StoreError::InvalidOptions {
                    reason: "another device removal is already pending",
                });
            }
        }
        // Publish the intent to both redundant label families before
        // evacuation starts. A crash during staging selects either the
        // previous complete label family or the higher lifecycle sequence.
        let successor_topology_generation = checked_successor_topology_generation(
            self.placement_epoch,
        )
        .ok_or(StoreError::InvalidOptions {
            reason: "device removal topology generation exhausted",
        })?;
        let marker = DeviceRemovalMarker {
            pool_guid: self.pool_guid,
            target_index: target_idx,
            target_path: path.to_path_buf(),
            target_guid,
            successor_topology_generation,
        };
        let payload = encode_device_removal_marker(
            marker.pool_guid,
            marker.target_index,
            &marker.target_path,
            marker.target_guid,
            marker.successor_topology_generation,
        )?;
        self.persist_lifecycle_record_on_current_topology(
            pool_label::PoolLifecycleKindV1::DeviceRemoval,
            payload,
            "removal-lifecycle",
        )?;
        self.device_removal_marker = Some(marker);
        self.allocation_fenced_device_guid = Some(target_guid);

        // This removal path rewrites every receipt-backed object through the
        // data-class fallback. Keep its candidates inside that I/O class: an
        // intent-log or read-cache device is not surviving authority for data.
        let surviving_indices: Vec<usize> = self
            .class_map
            .get(IoClass::Data)
            .iter()
            .copied()
            .filter(|&i| i != target_idx)
            .collect();

        // Enumerate objects on the target device so internal metadata can be
        // ignored and unreceipted logical keys can fail closed.
        let keys = self.devices[target_idx]
            .store()
            .list_keys_including_internal();
        let mut result = EvacuationResult::default();

        let mut accounted_internal_keys = BTreeSet::new();
        // Raw byte-device stores persist the transaction-group committed root
        // as a reserved object because they cannot use a sidecar file. It is
        // per-device commit bookkeeping, not receipt-backed logical payload
        // that must be evacuated.
        accounted_internal_keys.insert(ObjectKey::from_name(
            crate::txg_manager::COMMITTED_ROOT_FILE.as_bytes(),
        ));
        // Rewriting a receipt during evacuation records the obsolete physical
        // placement in the old store's receipt-bound reclaim queue. That queue
        // is local cleanup authority for extents on the device being detached,
        // not live pool payload; its bytes remain on the device for crash/retry.
        // Keep every other unknown internal object as a removal blocker.
        accounted_internal_keys.insert(ObjectKey::from_name(
            crate::reclaim_queue::DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes(),
        ));
        accounted_internal_keys.insert(receipt_generation_high_water_key());
        let mut current_logical_keys = BTreeSet::new();
        let mut rewritten_logical_keys = BTreeSet::new();
        let mut placement_receipts = BTreeMap::new();
        let mut failed_logical_keys = BTreeSet::new();
        let mut unverifiable_receipt_keys = BTreeSet::new();

        let mut mark_failed = |result: &mut EvacuationResult, key: ObjectKey| {
            if failed_logical_keys.insert(key) {
                result.objects_failed += 1;
                result.failed_keys.push(key);
            }
        };

        for key in &keys {
            if !crate::is_pool_placement_receipt_key(*key) {
                continue;
            }
            let raw = self.devices[target_idx]
                .get(*key)?
                .ok_or(StoreError::InvalidOptions {
                    reason: "placement receipt corrupt or unverifiable",
                })?;
            let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "placement receipt corrupt or unverifiable",
            })?;
            if placement_receipt_object_key(receipt.object_key) != *key {
                return Err(StoreError::InvalidOptions {
                    reason: "placement receipt corrupt or unverifiable",
                });
            }

            accounted_internal_keys.insert(*key);
            if matches!(receipt.policy, PoolRedundancyPolicy::Erasure { .. }) {
                for target in &receipt.targets {
                    accounted_internal_keys.insert(placement_shard_object_key(
                        receipt.object_key,
                        target.shard_index,
                    ));
                }
            }

            // Faulted devices are excluded from the pool-wide receipt scan,
            // so retain target-local authority for evacuation selection.
            let replace = match placement_receipts.get(&receipt.object_key) {
                Some(current) => receipt_supersedes(&receipt, current)?,
                None => true,
            };
            if replace {
                placement_receipts.insert(receipt.object_key, receipt);
            }
        }

        // Device class and health control rewrite eligibility, not receipt
        // authority. A dedicated metadata or cache device, including a
        // faulted one, can still carry a readable newer receipt; hiding it
        // here could let removal republish stale payload with a newer
        // generation. Inspect every other pool device and fail closed when a
        // visible receipt cannot be read or verified.
        for idx in (0..self.devices.len()).filter(|idx| *idx != target_idx) {
            for key in self.devices[idx].store().list_keys_including_internal() {
                if !crate::is_pool_placement_receipt_key(key) {
                    continue;
                }
                let Some(raw) = self.devices[idx].get(key)? else {
                    unverifiable_receipt_keys.insert(key);
                    continue;
                };
                let Some(receipt) = PlacementReceipt::decode(&raw) else {
                    unverifiable_receipt_keys.insert(key);
                    continue;
                };
                if placement_receipt_object_key(receipt.object_key) != key {
                    unverifiable_receipt_keys.insert(key);
                    continue;
                }

                accounted_internal_keys.insert(key);
                if matches!(receipt.policy, PoolRedundancyPolicy::Erasure { .. }) {
                    for target in &receipt.targets {
                        accounted_internal_keys.insert(placement_shard_object_key(
                            receipt.object_key,
                            target.shard_index,
                        ));
                    }
                }

                let replace = match placement_receipts.get(&receipt.object_key) {
                    Some(current) => receipt_supersedes(&receipt, current)?,
                    None => true,
                };
                if replace {
                    placement_receipts.insert(receipt.object_key, receipt);
                }
            }
        }

        let mut unverifiable_logical_keys = BTreeSet::new();
        for receipt_key in unverifiable_receipt_keys {
            let Some(receipt) = placement_receipts
                .values()
                .find(|receipt| placement_receipt_object_key(receipt.object_key) == receipt_key)
            else {
                return Err(StoreError::InvalidOptions {
                    reason: "placement receipt corrupt or unverifiable",
                });
            };
            unverifiable_logical_keys.insert(receipt.object_key);
        }

        for receipt in placement_receipts.into_values() {
            current_logical_keys.insert(receipt.object_key);

            if unverifiable_logical_keys.contains(&receipt.object_key) {
                mark_failed(&mut result, receipt.object_key);
                continue;
            }

            // Older receipt encodings have no sealed planner replay authority.
            // They remain readable for in-tree harness data, but cannot prove
            // which payload and targets are current enough to retire a source.
            if receipt.planner_replay_receipt.is_none() {
                mark_failed(&mut result, receipt.object_key);
                continue;
            }

            // Placement receipts are copied beyond their payload targets. If
            // the retiring device is not a current target and an identical
            // receipt and its payload are readable from a survivor, syncing
            // that survivor is sufficient: rewriting the object would churn
            // unrelated placement authority and inflate evacuation counts.
            let target_owns_payload = receipt
                .targets
                .iter()
                .any(|target| target.device_guid == target_guid);
            let survivor_has_current_receipt = matches!(
                self.load_placement_receipt(&surviving_indices, receipt.object_key),
                Ok(Some(survivor_receipt)) if survivor_receipt == receipt
            );
            if !target_owns_payload && survivor_has_current_receipt {
                match self.get_with_receipt(&receipt)? {
                    Some(_) => continue,
                    None => {
                        mark_failed(&mut result, receipt.object_key);
                        continue;
                    }
                }
            }

            let data = match self.get_with_receipt(&receipt)? {
                Some(data) => data,
                None => {
                    mark_failed(&mut result, receipt.object_key);
                    continue;
                }
            };
            let digest: [u8; 32] = blake3::hash(&data).into();
            let len = data.len() as u64;

            let survivor_receipt = match self.put_pool_wide(
                IoClass::Data,
                receipt.object_key,
                &data,
                &surviving_indices,
                OldReceiptPolicy::KnownCurrent(&receipt),
            ) {
                Ok((_stored, receipt)) => receipt,
                Err(_) => {
                    mark_failed(&mut result, receipt.object_key);
                    continue;
                }
            };

            if !placement_receipt_proves_device_evacuation(
                self,
                &survivor_receipt,
                &data,
                digest,
                target_guid,
            ) {
                mark_failed(&mut result, receipt.object_key);
                continue;
            }

            rewritten_logical_keys.insert(receipt.object_key);
            result.objects_evacuated += 1;
            result.bytes_evacuated += len;
            result.content_digests.insert(receipt.object_key, digest);
        }

        // A readable survivor receipt is not committed evacuation evidence
        // until its data, receipt, and commit-group root reach stable storage.
        // Do not require the target device to sync: only the survivor-side
        // evidence must become durable before detach.
        let usable_surviving_indices = self.usable_candidates(&surviving_indices);
        if usable_surviving_indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "safe removal requires at least one usable surviving device",
            });
        }
        for idx in usable_surviving_indices {
            self.devices[idx].sync_all()?;
        }

        // Receipt-backed logical objects were rewritten above; placement
        // metadata is skipped only when a readable receipt accounts for it.
        // An orphaned shard or any remaining logical key on the target is a
        // removal blocker, not a legacy hash-routed evacuation candidate.
        for key in &keys {
            if accounted_internal_keys.contains(key)
                || rewritten_logical_keys.contains(key)
                || current_logical_keys.contains(key)
            {
                continue;
            }

            mark_failed(&mut result, *key);
        }

        // If any objects failed, do not remove the device.
        if result.objects_failed > 0 {
            result.complete = false;
            result.topology_commit_pending = true;
            self.pending_device_removal = Some((path.to_path_buf(), target_guid, result.clone()));
            return Ok(result);
        }

        // Keep the target attached until the mounted owner has durably
        // advanced receipt generations embedded in filesystem manifests.
        result.complete = false;
        result.topology_commit_pending = true;
        self.pending_device_removal = Some((path.to_path_buf(), target_guid, result.clone()));
        Ok(result)
    }

    /// Detach an evacuated device and publish the reduced survivor topology.
    ///
    /// Mounted callers invoke this only after all higher-layer placement
    /// receipt references have been repaired and synced. The convenience
    /// [`Self::safe_remove_device`] wrapper retains the raw Pool behavior for
    /// callers with no embedded higher-layer references.
    pub fn finish_safe_remove_device(
        &mut self,
        path: &Path,
    ) -> Result<crate::device_removal::EvacuationResult> {
        let result = match self.pending_device_removal_result(path)? {
            Some(result) => result,
            None => self.prepare_safe_remove_device(path)?,
        };
        if result.objects_failed > 0 {
            return Ok(result);
        }

        self.remove_device(path)?;
        self.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RemovalTopologyCommitRequired,
        );
        self.publish_pending_removal_topology()?;
        let mut result = result;
        result.complete = true;
        result.topology_commit_pending = false;
        self.pending_device_removal = None;
        Ok(result)
    }

    /// Safely evacuate, detach, and commit one device for raw Pool callers.
    ///
    /// Mounted filesystem owners use the explicit prepare/finish boundary so
    /// they can advance embedded receipt references before topology commit.
    pub fn safe_remove_device(
        &mut self,
        path: &Path,
    ) -> Result<crate::device_removal::EvacuationResult> {
        let result = self.prepare_safe_remove_device(path)?;
        if result.objects_failed > 0 {
            return Ok(result);
        }
        self.finish_safe_remove_device(path)
    }

    fn replacement_transform_configuration_matches(
        old_config: &DeviceConfig,
        new_config: &DeviceConfig,
    ) -> bool {
        let compression_matches = match (&old_config.compression, &new_config.compression) {
            (None, None) => true,
            (Some(old), Some(new)) => {
                old.algorithm == new.algorithm
                    && old.level == new.level
                    && old.min_compress_bytes == new.min_compress_bytes
            }
            (None, Some(_)) | (Some(_), None) => false,
        };
        let encryption_matches = match (&old_config.encryption, &new_config.encryption) {
            (None, None) => true,
            (Some(old), Some(new)) => old.key.as_bytes() == new.key.as_bytes(),
            (None, Some(_)) | (Some(_), None) => false,
        };
        compression_matches && encryption_matches
    }

    fn rebuild_replacement_receipts(
        &mut self,
        mut evidence: DeviceReplacementEvidenceMarker,
        old_runtime_idx: usize,
    ) -> Result<DeviceReplacementResult> {
        if self.devices.len() != 3
            || self.config.devices.len() != 3
            || self.device_guids.len() != 3
            || old_runtime_idx == evidence.device_index
            || self.devices[old_runtime_idx].root() != evidence.old_path
            || self.device_guids.get(old_runtime_idx) != Some(&evidence.old_device_guid)
            || self
                .devices
                .get(evidence.device_index)
                .is_none_or(|device| device.root() != evidence.new_path)
            || self.device_guids.get(evidence.device_index) != Some(&evidence.new_device_guid)
            || self.allocation_fenced_device_guid != Some(evidence.old_device_guid)
            || self.placement_epoch != evidence.topology_epoch
        {
            return Err(StoreError::InvalidOptions {
                reason: "replacement rebuild runtime topology does not match durable evidence",
            });
        }

        let mut baseline_receipts = BTreeMap::new();
        for receipt_key in self.devices[old_runtime_idx]
            .store()
            .list_keys_including_internal()
            .into_iter()
            .filter(|key| crate::is_pool_placement_receipt_key(*key))
        {
            let raw = self.devices[old_runtime_idx].get(receipt_key)?.ok_or(
                StoreError::InvalidOptions {
                    reason: "replacement predecessor receipt is unreadable",
                },
            )?;
            let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                reason: "replacement predecessor receipt is corrupt or unverifiable",
            })?;
            if placement_receipt_object_key(receipt.object_key) != receipt_key {
                return Err(StoreError::InvalidOptions {
                    reason: "replacement predecessor receipt has invalid identity",
                });
            }
            if !receipt
                .targets
                .iter()
                .any(|target| target.device_guid == evidence.old_device_guid)
            {
                continue;
            }
            if !matches!(
                receipt.policy,
                PoolRedundancyPolicy::Replicated { copies: 2 }
            ) {
                return Err(StoreError::InvalidOptions {
                    reason: "safe replacement encountered a non-replicated predecessor receipt",
                });
            }
            self.ensure_receipt_replay_authority(&receipt)?;
            validate_strict_receipt_structure(&receipt)?;
            baseline_receipts.insert(receipt.object_key, receipt);
        }
        if u64::try_from(baseline_receipts.len()).ok() != Some(evidence.total_subjects) {
            return Err(StoreError::InvalidOptions {
                reason: "replacement predecessor subject inventory changed after durable admission",
            });
        }

        let authority_indices = self
            .class_map
            .get(IoClass::Data)
            .iter()
            .copied()
            .filter(|candidate| *candidate != old_runtime_idx)
            .collect::<Vec<_>>();
        let mut subjects_completed = 0_u64;
        let mut subjects_failed = 0_u64;
        let mut verified_receipt_count = 0_u64;
        let mut bytes_rebuilt = 0_u64;
        for (key, predecessor) in baseline_receipts {
            let expected_len = match usize::try_from(predecessor.payload_len) {
                Ok(len) => len,
                Err(_) => {
                    subjects_failed = subjects_failed.saturating_add(1);
                    continue;
                }
            };
            let payload = match self.devices[old_runtime_idx].get(key) {
                Ok(Some(payload))
                    if payload.len() == expected_len
                        && digest32(&payload) == predecessor.payload_digest =>
                {
                    payload
                }
                _ => {
                    subjects_failed = subjects_failed.saturating_add(1);
                    continue;
                }
            };
            bytes_rebuilt = bytes_rebuilt.saturating_add(predecessor.payload_len);

            let current = self.load_placement_receipt(&authority_indices, key)?;
            let already_rebuilt = current.as_ref().is_some_and(|receipt| {
                receipt.generation > predecessor.generation
                    && receipt.payload_len == predecessor.payload_len
                    && receipt.payload_digest == predecessor.payload_digest
                    && receipt
                        .targets
                        .iter()
                        .any(|target| target.device_guid == evidence.new_device_guid)
                    && receipt
                        .targets
                        .iter()
                        .all(|target| target.device_guid != evidence.old_device_guid)
                    && matches!(self.get_with_receipt(receipt), Ok(Some(bytes)) if bytes == payload)
            });
            if already_rebuilt {
                subjects_completed = subjects_completed.saturating_add(1);
                verified_receipt_count = verified_receipt_count.saturating_add(1);
                continue;
            }

            let current_authority = current.as_ref().unwrap_or(&predecessor);
            let replacement_receipt = match self.put_pool_wide(
                IoClass::Data,
                key,
                &payload,
                &authority_indices,
                OldReceiptPolicy::KnownCurrent(current_authority),
            ) {
                Ok((_stored, receipt)) => receipt,
                Err(_) => {
                    subjects_failed = subjects_failed.saturating_add(1);
                    continue;
                }
            };
            let verified = replacement_receipt.generation > predecessor.generation
                && replacement_receipt.payload_len == predecessor.payload_len
                && replacement_receipt.payload_digest == predecessor.payload_digest
                && replacement_receipt
                    .targets
                    .iter()
                    .any(|target| target.device_guid == evidence.new_device_guid)
                && replacement_receipt
                    .targets
                    .iter()
                    .all(|target| target.device_guid != evidence.old_device_guid)
                && matches!(
                    self.get_with_receipt(&replacement_receipt),
                    Ok(Some(bytes)) if bytes == payload
                );
            if verified {
                subjects_completed = subjects_completed.saturating_add(1);
                verified_receipt_count = verified_receipt_count.saturating_add(1);
            } else {
                subjects_failed = subjects_failed.saturating_add(1);
            }
        }

        self.sync_all()?;
        evidence.subjects_completed = subjects_completed;
        evidence.subjects_failed = subjects_failed;
        evidence.verified_receipt_count = verified_receipt_count;
        evidence.bytes_rebuilt = bytes_rebuilt;
        evidence.evidence_stable = subjects_failed == 0
            && subjects_completed == evidence.total_subjects
            && verified_receipt_count >= evidence.total_subjects;
        evidence.state = ReplacementRebuildStatusState::Pending;
        self.persist_replacement_evidence_in_labels(&evidence)?;
        self.replacement_evidence = Some(evidence.clone());
        if let Some(replacement) = self.replacement.as_mut() {
            replacement.state = if evidence.evidence_stable {
                ReplacementState::CopyComplete
            } else {
                ReplacementState::InProgress {
                    bytes_copied: evidence.bytes_rebuilt,
                    total_bytes: evidence.bytes_rebuilt,
                }
            };
        }

        Ok(evidence.result(false))
    }

    /// Rebuild a present, readable member onto a same-backing replacement.
    ///
    /// This preparation phase is deliberately bounded to the two-member
    /// replicated local carrier. It persists replacement identity first,
    /// keeps the old member attached and allocation-fenced, publishes newer
    /// verified receipts to the survivor plus replacement, and leaves label
    /// publication pending. A mounted owner must reconcile embedded receipt
    /// references before calling [`Self::finish_safe_replace_device`].
    pub fn replace_device(
        &mut self,
        old_path: &Path,
        new_config: DeviceConfig,
        options: &StoreOptions,
    ) -> Result<DeviceReplacementResult> {
        self.ensure_writable("pool replace device")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            });
        }

        let resuming_generation_authority = self.receipt_generation_authority_state
            == ReceiptGenerationAuthorityState::ReplacementResumeRequired;
        if resuming_generation_authority {
            self.validate_loaded_receipt_generation_high_water()?;
        } else {
            self.validate_receipt_generation_high_water()?;
        }

        if let Some(evidence) = self.replacement_evidence.as_ref().filter(|evidence| {
            evidence.state == ReplacementRebuildStatusState::Completed
                && evidence.evidence_stable
                && !self.devices.iter().any(|device| device.root() == old_path)
                && self
                    .devices
                    .get(evidence.device_index)
                    .is_some_and(|device| device.root() == new_config.path)
        }) {
            let new_topology_loaded = self.device_guids.get(evidence.device_index)
                == Some(&evidence.new_device_guid)
                && replacement_evidence_matches_topology(
                    evidence,
                    &self.device_guids,
                    self.placement_epoch,
                );
            if new_topology_loaded {
                let mut evidence = evidence.clone();
                evidence.old_path = old_path.to_path_buf();
                evidence.new_path = new_config.path.clone();
                return Ok(evidence.result(true));
            }
        }

        if let Some(replacement) = self.replacement.as_ref().filter(|_| {
            self.replacement_evidence
                .as_ref()
                .is_some_and(|evidence| evidence.state.is_active())
        }) {
            if replacement.old_path != old_path || replacement.new_path != new_config.path {
                return Err(StoreError::InvalidOptions {
                    reason: "a different device replacement is already in progress",
                });
            }
            let mut evidence = self
                .replacement_evidence
                .as_ref()
                .filter(|evidence| {
                    evidence.state.is_active()
                        && evidence.old_device_guid == replacement.old_device_guid
                        && evidence.device_index == replacement.device_index
                        && self.device_guids.get(evidence.device_index)
                            == Some(&evidence.new_device_guid)
                })
                .cloned()
                .ok_or(StoreError::InvalidOptions {
                    reason: "active device replacement lacks matching durable evidence",
                })?;
            let old_runtime_idx = self
                .device_guids
                .iter()
                .position(|guid| *guid == evidence.old_device_guid)
                .ok_or(StoreError::InvalidOptions {
                    reason: "active device replacement lost its predecessor member",
                })?;
            if self.devices[old_runtime_idx].root() != old_path
                || self
                    .devices
                    .get(evidence.device_index)
                    .is_none_or(|device| device.root() != new_config.path)
            {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "active device replacement paths do not resolve to its durable identities",
                });
            }
            evidence.old_path = old_path.to_path_buf();
            evidence.new_path = new_config.path.clone();
            return self.rebuild_replacement_receipts(evidence, old_runtime_idx);
        }

        let replayed_evidence = self
            .replacement_evidence
            .as_ref()
            .filter(|evidence| evidence.state.is_active())
            .cloned();

        let (idx, old_config, old_device_guid, replacement_evidence, resuming) = if let Some(
            mut evidence,
        ) =
            replayed_evidence
        {
            let new_topology_loaded = self.devices.len() == self.expected_device_count as usize
                && self
                    .devices
                    .get(evidence.device_index)
                    .is_some_and(|device| device.root() == new_config.path)
                && self.device_guids.get(evidence.device_index) == Some(&evidence.new_device_guid)
                && replacement_evidence_matches_topology(
                    &evidence,
                    &self.device_guids,
                    self.placement_epoch,
                );
            if new_topology_loaded {
                if !evidence.evidence_stable {
                    return Err(StoreError::InvalidOptions {
                        reason: "replacement topology is committed without stable rebuild evidence",
                    });
                }
                self.set_receipt_generation_authority_state(
                    ReceiptGenerationAuthorityState::RecoveryRequired,
                );
                self.converge_receipt_generation_authority()?;
                evidence.old_path = old_path.to_path_buf();
                evidence.new_path = new_config.path.clone();
                evidence.state = ReplacementRebuildStatusState::Pending;
                self.replacement_evidence = Some(evidence.clone());
                return Ok(evidence.result(false));
            }
            if self
                .devices
                .get(evidence.device_index)
                .is_none_or(|device| device.root() != old_path)
                || self.device_guids.get(evidence.device_index) != Some(&evidence.old_device_guid)
                || !replacement_evidence_matches_topology(
                    &evidence,
                    &self.device_guids,
                    self.placement_epoch,
                )
            {
                return Err(StoreError::InvalidOptions {
                    reason: "device replacement resume does not match durable evidence",
                });
            }
            let old_config = self
                .config
                .devices
                .get(evidence.device_index)
                .cloned()
                .ok_or(StoreError::InvalidOptions {
                    reason: "device replacement resume is missing old device configuration",
                })?;
            evidence.state = ReplacementRebuildStatusState::Pending;
            evidence.subjects_failed = 0;
            evidence.old_path = old_path.to_path_buf();
            evidence.new_path = new_config.path.clone();
            (
                evidence.device_index,
                old_config,
                evidence.old_device_guid,
                evidence,
                true,
            )
        } else {
            if self.devices.len() != 2
                || self.config.devices.len() != 2
                || self.classes.len() != 2
                || self.media_classes.len() != 2
                || self.device_layouts.len() != 2
                || self.device_layout_stats.len() != 2
                || self.device_guids.len() != 2
                || self.expected_device_count != 2
                || !matches!(
                    self.properties.redundancy_policy,
                    PoolRedundancyPolicy::Replicated { copies: 2 }
                )
                || self.classes.iter().any(|class| *class != DeviceClass::Data)
            {
                return Err(StoreError::InvalidOptions {
                        reason: "safe replacement currently requires an exact two-member replicated data Pool",
                    });
            }
            let idx = self
                .devices
                .iter()
                .position(|device| device.root() == old_path)
                .ok_or(StoreError::InvalidOptions {
                    reason: "device to replace not found in pool",
                })?;
            let old_config = self.config.devices[idx].clone();
            if new_config.path == old_path
                || device_root_path(&old_config) != old_config.path
                || device_root_path(&new_config) != new_config.path
                || self
                    .devices
                    .iter()
                    .any(|device| device.root() == new_config.path)
                || new_config.backing != old_config.backing
                || new_config.class != old_config.class
                || new_config.media_class != old_config.media_class
                || !Self::replacement_transform_configuration_matches(&old_config, &new_config)
                || !matches!(
                    (&old_config.kind, &new_config.kind),
                    (DeviceKind::Block { .. }, DeviceKind::Block { .. })
                        | (DeviceKind::Single { .. }, DeviceKind::Single { .. })
                )
            {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "replacement device must be a distinct same-backing member configuration",
                });
            }
            let old_device_guid = self.device_guid_for_index(idx);
            let total_subjects = discover_replacement_rebuild_subject_count(self, old_device_guid)?;
            let successor_topology_generation = checked_successor_topology_generation(
                self.placement_epoch,
            )
            .ok_or(StoreError::InvalidOptions {
                reason: "device replacement topology generation exhausted",
            })?;
            let evidence = DeviceReplacementEvidenceMarker {
                pool_guid: self.pool_guid,
                old_device_guid,
                new_device_guid: rand::random(),
                topology_epoch: successor_topology_generation,
                device_index: idx,
                old_path: old_path.to_path_buf(),
                new_path: new_config.path.clone(),
                total_subjects,
                subjects_completed: 0,
                subjects_failed: 0,
                verified_receipt_count: 0,
                bytes_rebuilt: 0,
                evidence_stable: false,
                state: ReplacementRebuildStatusState::Pending,
            };
            (idx, old_config, old_device_guid, evidence, false)
        };
        if resuming != resuming_generation_authority {
            return Err(StoreError::InvalidOptions {
                reason: "device replacement resume does not match generation recovery state",
            });
        }

        // Preflight production byte-addressable candidates without mutation,
        // then publish their exact identity before initializing them. A crash
        // cannot strand an initialized but evidence-free candidate, and an
        // exact retry can initialize a still-blank evidence-bound candidate.
        // Directory compatibility candidates remain test-only and use their
        // existing open path below.
        let replacement_identity = BlockStoreIdentity {
            pool_guid: self.pool_guid,
            device_guid: replacement_evidence.new_device_guid,
        };
        let minimum_raw_capacity = if new_config.backing.is_byte_addressable_pool_member() {
            byte_addressable_device_raw_capacity(&old_config)?
        } else {
            0
        };
        let preflighted_candidate = if resuming {
            None
        } else {
            preflight_blank_block_candidate(&new_config, minimum_raw_capacity)?
        };
        let evidence_persisted_before_candidate = preflighted_candidate.is_some();
        if evidence_persisted_before_candidate {
            self.persist_replacement_evidence_in_labels(&replacement_evidence)?;
            self.replacement_evidence = Some(replacement_evidence.clone());
            self.set_receipt_generation_authority_state(
                ReceiptGenerationAuthorityState::ReplacementResumeRequired,
            );
            self.allocation_fenced_device_guid = Some(old_device_guid);
        }

        let mut new_device = match preflighted_candidate {
            Some((file, inspection)) => open_preflighted_block_candidate(
                &new_config,
                options,
                replacement_identity,
                file,
                &inspection,
            )?,
            None if resuming => open_replacement_resume_candidate(
                &new_config,
                options,
                options.is_test_fast_harness_fixture(),
                replacement_identity,
                minimum_raw_capacity,
            )?,
            None => open_candidate_device(
                &new_config,
                options,
                options.is_test_fast_harness_fixture(),
                replacement_identity,
            )?,
        };
        new_device.install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
        let old_capacity = self.devices[idx].store().capacity_bytes();
        if new_config.backing.is_byte_addressable_pool_member()
            && new_device.store().capacity_bytes() < old_capacity
        {
            return Err(StoreError::InvalidOptions {
                reason: "replacement device capacity is smaller than the present member",
            });
        }
        if resuming {
            if read_receipt_generation_high_water(&new_device)?.is_none() {
                if new_device.has_any_physical_key() {
                    return Err(StoreError::InvalidOptions {
                        reason:
                            "replacement resume candidate has payload without generation authority",
                    });
                }
                seed_receipt_generation_high_water_on_candidate(
                    &mut new_device,
                    self.pool_guid,
                    self.reserved_placement_receipt_generation_through,
                )?;
            }
            self.reconcile_receipt_generation_high_water_with_replacement(&mut new_device)?;
        } else {
            seed_receipt_generation_high_water_on_candidate(
                &mut new_device,
                self.pool_guid,
                self.reserved_placement_receipt_generation_through,
            )?;
            self.set_receipt_generation_authority_state(
                ReceiptGenerationAuthorityState::RecoveryRequired,
            );
        }

        // Publish identity, epoch, and fail-closed progress before changing
        // the loaded topology. A crash therefore reopens either the old
        // device plus resumable evidence or a later label-persisted new
        // device plus the same evidence; it never relies on the in-memory
        // swap as proof of replacement completion.
        if !resuming && !evidence_persisted_before_candidate {
            if let Err(error) = self.persist_replacement_evidence_in_labels(&replacement_evidence) {
                self.receipt_generation_authority_state =
                    ReceiptGenerationAuthorityState::Converged;
                self.refresh_raw_store_mutation_gate();
                return Err(error);
            }
            self.replacement_evidence = Some(replacement_evidence.clone());
        }

        // Install the candidate at the durable index, but retain the exact old
        // device as an extra allocation-fenced runtime member. Its payload and
        // receipt bytes remain predecessor authority until higher-layer roots
        // have advanced; no label can publish the temporary three-device view.
        let old_device = std::mem::replace(&mut self.devices[idx], new_device);
        self.devices.push(old_device);
        self.config.devices[idx] = new_config.clone();
        self.config.devices.push(old_config.clone());
        self.device_guids[idx] = replacement_evidence.new_device_guid;
        self.device_guids.push(old_device_guid);
        let old_class = self.classes[idx];
        self.classes.push(old_class);
        self.class_map = build_class_map(&self.classes);
        let old_media_class = self.media_classes[idx];
        self.media_classes.push(old_media_class);
        let old_layout_stats = self.device_layout_stats[idx].clone();
        self.device_layout_stats[idx] =
            DeviceLayoutStats::with_segment_size(new_config.media_class.default_segment_size());
        self.device_layout_stats.push(old_layout_stats);
        let old_layout = self.device_layouts[idx].clone();
        let replacement_capacity = self.devices[idx].store().capacity_bytes();
        self.device_layouts[idx] = self
            .properties
            .layout_policy
            .compute(replacement_capacity)
            .unwrap_or_else(|_| {
                DeviceLayoutPolicy::Slice0Small
                    .compute(replacement_capacity)
                    .expect("Slice0Small must succeed for non-zero device")
            });
        self.device_layouts.push(old_layout);
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);

        // Review debt TFR-012: track the replacement for evacuate + detach.
        self.replacement = Some(DeviceReplacement::new(
            old_config,
            old_device_guid,
            new_config.path.clone(),
            idx,
        ));

        // Recompute pool health: the new device starts Online, so health
        // should improve if the old device was degraded/faulted.
        self.placement_epoch = replacement_evidence.topology_epoch;
        self.allocation_fenced_device_guid = Some(old_device_guid);
        self.health = compute_health(&self.devices);
        self.record_health_transitions();
        self.converge_receipt_generation_authority()?;

        let old_runtime_idx = self.devices.len() - 1;
        self.rebuild_replacement_receipts(replacement_evidence, old_runtime_idx)
    }

    /// Publish the replacement topology after mounted receipt references are
    /// durable, then make old-member detach safety truthful.
    pub fn finish_safe_replace_device(
        &mut self,
        old_path: &Path,
    ) -> Result<DeviceReplacementResult> {
        self.ensure_writable("pool finish device replacement")?;
        let mut evidence =
            self.replacement_evidence
                .as_ref()
                .cloned()
                .ok_or(StoreError::InvalidOptions {
                    reason: "device replacement evidence is missing",
                })?;
        if evidence.old_path != old_path || !evidence.evidence_stable {
            return Err(StoreError::InvalidOptions {
                reason: "device replacement is not stable enough to publish topology",
            });
        }
        if evidence.state == ReplacementRebuildStatusState::Completed {
            return Ok(evidence.result(true));
        }

        let new_topology_already_published = self.devices.len() == 2
            && self
                .devices
                .get(evidence.device_index)
                .is_some_and(|device| device.root() == evidence.new_path)
            && self.device_guids.get(evidence.device_index) == Some(&evidence.new_device_guid)
            && self.placement_epoch == evidence.topology_epoch;
        if !new_topology_already_published {
            let old_runtime_idx = self
                .device_guids
                .iter()
                .position(|guid| *guid == evidence.old_device_guid)
                .ok_or(StoreError::InvalidOptions {
                    reason: "replacement old member is no longer retained",
                })?;
            if self.devices.len() != 3
                || old_runtime_idx == evidence.device_index
                || self.devices[old_runtime_idx].root() != evidence.old_path
                || self
                    .devices
                    .get(evidence.device_index)
                    .is_none_or(|device| device.root() != evidence.new_path)
                || self.device_guids.get(evidence.device_index) != Some(&evidence.new_device_guid)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "replacement runtime topology does not match stable evidence",
                });
            }

            self.devices.remove(old_runtime_idx);
            self.config.devices.remove(old_runtime_idx);
            self.device_guids.remove(old_runtime_idx);
            self.classes.remove(old_runtime_idx);
            self.media_classes.remove(old_runtime_idx);
            self.device_layout_stats.remove(old_runtime_idx);
            self.device_layouts.remove(old_runtime_idx);
            self.class_map = build_class_map(&self.classes);
            self.allocation_fenced_device_guid = None;
            let total_bytes = self
                .devices
                .iter()
                .map(|device| device.store().capacity_bytes())
                .collect();
            self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);
            self.health = compute_health(&self.devices);
            self.record_health_transitions();
            self.set_receipt_generation_authority_state(
                ReceiptGenerationAuthorityState::RecoveryRequired,
            );

            // Carry the stable active replacement record onto the successor
            // topology. The higher topology is selectable only after one
            // complete redundant family has been written and reread.
            self.persist_replacement_evidence_in_labels(&evidence)?;
            self.persisted_label_epoch = Some(self.placement_epoch);
            self.durable_device_guids.clone_from(&self.device_guids);
            self.expected_device_count = self.device_guids.len() as u32;
            self.device_label_indices = (0..self.expected_device_count).collect();
            self.converge_receipt_generation_authority()?;
        } else {
            self.verify_active_topology_label_copies(
                2,
                "replacement",
                self.label_lifecycle.as_ref(),
            )?;
            self.set_receipt_generation_authority_state(
                ReceiptGenerationAuthorityState::RecoveryRequired,
            );
            self.converge_receipt_generation_authority()?;
        }

        evidence.state = ReplacementRebuildStatusState::Completed;
        self.persist_replacement_evidence_in_labels(&evidence)?;
        self.replacement_evidence = Some(evidence.clone());
        if let Some(replacement) = self.replacement.as_mut() {
            replacement.state = ReplacementState::CopyComplete;
        }
        Ok(evidence.result(true))
    }

    /// Complete replacement directly for Pool users with no embedded
    /// higher-layer receipt references.
    pub fn safe_replace_device(
        &mut self,
        old_path: &Path,
        new_config: DeviceConfig,
        options: &StoreOptions,
    ) -> Result<DeviceReplacementResult> {
        let preparation = self.replace_device(old_path, new_config, options)?;
        if preparation.objects_failed > 0 {
            return Ok(preparation);
        }
        self.finish_safe_replace_device(old_path)
    }

    /// Current replacement status, if a replacement is in progress or was
    /// recently completed.
    pub fn replacement_status(&self) -> Option<&DeviceReplacement> {
        self.replacement.as_ref()
    }

    /// Current durable local replacement result for operator projection.
    pub fn device_replacement_result(&self) -> Option<DeviceReplacementResult> {
        let evidence = self.replacement_evidence.as_ref()?;
        let complete = evidence.state == ReplacementRebuildStatusState::Completed
            && evidence.evidence_stable
            && self.placement_epoch == evidence.topology_epoch
            && self
                .devices
                .get(evidence.device_index)
                .is_some_and(|device| device.root() == evidence.new_path)
            && self.device_guids.get(evidence.device_index) == Some(&evidence.new_device_guid)
            && !self.device_guids.contains(&evidence.old_device_guid);
        Some(evidence.result(complete))
    }

    /// Whether explicit replacement resume is required for the loaded old or
    /// newly published topology.
    #[must_use]
    pub fn has_device_replacement_resume(&self) -> bool {
        self.replacement_resume_evidence().is_some()
    }

    /// Whether mounted recovery may use the authenticated predecessor state
    /// while replacement resumes against the old label topology.
    #[must_use]
    pub fn has_device_replacement_predecessor_resume(&self) -> bool {
        self.predecessor_replacement_resume_evidence().is_some()
    }

    /// Current local replacement/rebuild evidence projection.
    ///
    /// Durable evidence is replayable only with the exact loaded topology and
    /// the label epoch required for that state. Old-device detach remains
    /// fail-closed until receipt-backed progress is complete and stable.
    #[cfg(any(feature = "distributed-repair", test))]
    pub fn replacement_rebuild_evidence_status(&self) -> Option<ReplacementRebuildEvidenceStatus> {
        let replacement = self.replacement.as_ref();
        let live_state = replacement.map(|replacement| match &replacement.state {
            ReplacementState::InProgress { .. } => ReplacementRebuildStatusState::Pending,
            ReplacementState::CopyComplete => ReplacementRebuildStatusState::Completed,
            ReplacementState::Failed { .. } => ReplacementRebuildStatusState::Refused,
        });

        let (
            old_device_guid,
            new_device_guid,
            old_path,
            new_path,
            old_member,
            new_member,
            topology_epoch,
            total_subjects,
            subjects_completed,
            subjects_failed,
            verified_receipt_count,
            bytes_rebuilt,
            evidence_stable,
            evidence_replayable_after_reopen,
            state,
        ) = if let Some(evidence) = self.replacement_evidence.as_ref() {
            let state = evidence.state;
            let replayable = evidence.covers_state(state);
            (
                evidence.old_device_guid,
                evidence.new_device_guid,
                evidence.old_path.clone(),
                evidence.new_path.clone(),
                MemberId::new(u64::from_le_bytes(
                    evidence.old_device_guid[..8].try_into().unwrap(),
                )),
                MemberId::new(u64::from_le_bytes(
                    evidence.new_device_guid[..8].try_into().unwrap(),
                )),
                evidence.topology_epoch,
                evidence.total_subjects,
                evidence.subjects_completed,
                evidence.subjects_failed,
                evidence.verified_receipt_count,
                evidence.bytes_rebuilt,
                evidence.evidence_stable && replayable,
                replayable,
                state,
            )
        } else {
            let replacement = replacement?;
            (
                replacement.old_device_guid,
                self.device_guid_for_index(replacement.device_index),
                replacement.old_path.clone(),
                replacement.new_path.clone(),
                MemberId::new(u64::from_le_bytes(
                    replacement.old_device_guid[..8].try_into().unwrap(),
                )),
                MemberId::new(self.device_id_for_index(replacement.device_index)),
                self.placement_epoch(),
                0,
                0,
                0,
                0,
                0,
                false,
                false,
                live_state.unwrap(),
            )
        };

        let detach_decision = self
            .device_replacement_result()
            .map_or(ReplacementDetachDecision::UnsafeToDetach, |result| {
                result.detach_decision
            });
        Some(ReplacementRebuildEvidenceStatus {
            old_device_guid,
            new_device_guid,
            old_path,
            new_path,
            old_member,
            new_member,
            topology_epoch,
            total_subjects,
            subjects_completed,
            subjects_failed,
            verified_receipt_count,
            bytes_rebuilt,
            evidence_stable,
            evidence_replayable_after_reopen,
            state,
            detach_decision,
            remanence_treatment: ReplacementRemanenceTreatment::from_detach_decision(
                detach_decision,
            ),
        })
    }

    // ------------------------------------------------------------------
    // Observability
    // ------------------------------------------------------------------

    /// Current pool health.
    pub fn health(&self) -> PoolHealth {
        self.health
    }

    /// Whether this Pool was imported through the side-effect-free read-only
    /// path.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Return the durable topology and current presence truth used by
    /// operator-visible status.
    #[must_use]
    pub fn topology_status(&self) -> PoolTopologyStatus {
        let (roster, present_indices): (&[[u8; 16]], BTreeSet<u32>) = if self.read_only {
            (
                &self.durable_device_guids,
                self.device_label_indices.iter().copied().collect(),
            )
        } else {
            (
                &self.device_guids,
                (0..self.device_guids.len())
                    .filter_map(|index| u32::try_from(index).ok())
                    .collect(),
            )
        };
        let expected_members = u32::try_from(roster.len()).unwrap_or(u32::MAX);
        let present_members = u32::try_from(present_indices.len()).unwrap_or(u32::MAX);
        let members = roster
            .iter()
            .enumerate()
            .filter_map(|(index, &device_guid)| {
                let device_index = u32::try_from(index).ok()?;
                Some(PoolMemberStatus {
                    device_index,
                    device_guid,
                    present: present_indices.contains(&device_index),
                })
            })
            .collect();
        PoolTopologyStatus {
            health: self.health,
            read_only: self.read_only,
            expected_members,
            present_members,
            missing_members: expected_members.saturating_sub(present_members),
            members,
        }
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
        self.ensure_writable("pool compaction")?;
        self.validate_receipt_generation_high_water()?;
        let indices = self.class_map.get(IoClass::Data).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for compaction",
            });
        }
        let mut report = None;
        for idx in indices {
            match self.devices[idx].compact_retaining(protected_keys, protected_exact_locations) {
                Ok(device_report) => report = Some(device_report),
                Err(error) => {
                    self.set_receipt_generation_authority_state(
                        ReceiptGenerationAuthorityState::RecoveryRequired,
                    );
                    return Err(error);
                }
            }
        }
        self.health = compute_health(&self.devices);
        if let Err(error) = self.validate_loaded_receipt_generation_high_water() {
            self.set_receipt_generation_authority_state(
                ReceiptGenerationAuthorityState::RecoveryRequired,
            );
            return Err(error);
        }
        let report = report.ok_or(StoreError::InvalidOptions {
            reason: "no devices available for compaction",
        })?;
        Ok(report)
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
        self.ensure_writable("pool segment rotation")?;
        self.validate_receipt_generation_high_water()?;
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
        self.ensure_writable("pool background scrub")?;
        self.validate_receipt_generation_high_water()?;
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
        self.ensure_writable("pool mirror repair scrub")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for mirror repair scrub",
            });
        }
        self.validate_receipt_generation_high_water()?;
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
    /// Compatibility directory stores report no proven discard capability, so
    /// compatibility-only pools return 0.
    pub fn discard_unused(&mut self) -> u64 {
        if self.read_only {
            return 0;
        }
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
        if self.read_only || self.validate_receipt_generation_high_water().is_err() {
            return 0;
        }
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
        if self.read_only || self.validate_receipt_generation_high_water().is_err() {
            return 0;
        }
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
        if self.read_only {
            return 0;
        }
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
        assert!(
            !self.read_only,
            "read-only pool has no mutable store handle"
        );
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
        assert!(!self.read_only, "read-only pool has no mutable raw store");
        let _ = self.validate_receipt_generation_high_water();
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
        assert!(
            !self.read_only,
            "read-only pool has no mutable store handle"
        );
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
        self.ensure_writable("pool log append")?;
        self.validate_receipt_generation_high_water()?;
        if self
            .allocation_fenced_device_guid
            .is_some_and(|fenced_guid| {
                self.config
                    .devices
                    .iter()
                    .position(|config| config.class == DeviceClass::IntentLog)
                    .and_then(|idx| self.device_guids.get(idx))
                    .is_some_and(|guid| *guid == fenced_guid)
            })
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "device lifecycle allocation fence blocks writes to the predecessor log device",
            });
        }
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
        self.ensure_writable("pool log commit")?;
        self.validate_receipt_generation_high_water()?;
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
        self.ensure_writable("pool log close")?;
        self.validate_receipt_generation_high_water()?;
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

    /// Read an object through the reverse transform pipeline.
    ///
    /// Reads the raw stored frame from the pool's primary data device and
    /// applies checksum verification, decryption, and decompression in
    /// that order.  The caller must supply the [`StoredFrameMetadata`] that
    /// was recorded during the write pipeline.  Returns the recovered
    /// plaintext on success.
    ///
    /// This is the preferred read path for objects written through
    /// [`PoolStoreMut::transform_put`].
    pub fn transform_get(
        &self,
        key: ObjectKey,
        metadata: &transform_pipeline::StoredFrameMetadata,
        pipeline: &transform_pipeline::TransformPipelineAuthority,
    ) -> Result<Option<Vec<u8>>> {
        match self.pool.raw_primary_store().get(key)? {
            Some(stored_frame) => {
                let plaintext = pipeline.read_frame(&stored_frame, metadata)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
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

    /// Retrieve an object only through current placement-receipt authority.
    pub fn get_with_current_receipt(
        &self,
        key: ObjectKey,
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
        self.pool.get_with_current_receipt(IoClass::Data, key)
    }

    /// Store an object, compressing/encrypting transparently.
    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.pool.put(IoClass::Data, key, payload)
    }

    /// Store an object and return the authoritative placement receipt.
    pub fn put_with_receipt(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<(StoredObject, PlacementReceipt)> {
        self.pool.put_with_receipt(IoClass::Data, key, payload)
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

    /// Write a plaintext object through the transform pipeline, storing the
    /// resulting frame directly in the pool's primary data device with
    /// explicit compression, encryption, and checksum stages.
    ///
    /// The caller supplies a dedup decision and a configured
    /// [`TransformPipelineAuthority`].  The pipeline applies compression,
    /// optional encryption, and checksum before the frame is written to raw
    /// media.  The returned [`StoredFrameMetadata`] must be persisted
    /// alongside the object key or locator so the reverse read pipeline can
    /// replay the same transform decisions.
    ///
    /// This is the preferred write path for mounted content payloads;
    /// existing [`PoolStoreMut::put`] routes through device wrappers and
    /// should be migrated to this pipeline over time.
    pub fn transform_put(
        &mut self,
        key: ObjectKey,
        plaintext: &[u8],
        dedup: &transform_pipeline::DedupDecision,
        pipeline: &transform_pipeline::TransformPipelineAuthority,
    ) -> Result<(StoredObject, transform_pipeline::StoredFrameMetadata)> {
        let (frame, meta) = pipeline.write_frame(plaintext, dedup)?;
        let stored = self.pool.raw_primary_store_mut().put(key, &frame)?;
        Ok((stored, meta))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open_devices_existing(
    config: &PoolConfig,
    options: &StoreOptions,
    identities: &[BlockStoreIdentity],
) -> Result<Vec<Device>> {
    if identities.len() != config.devices.len() {
        return Err(StoreError::InvalidOptions {
            reason: "writable Pool Store identity count does not match topology",
        });
    }
    let allow_legacy_directory_shims =
        options.is_test_fast_harness_fixture() || is_legacy_single_directory_store_bridge(config);
    config
        .devices
        .iter()
        .zip(identities)
        .map(|(vc, identity)| {
            let mut dev_opts = options.clone();
            dev_opts.max_segment_bytes = vc.media_class.default_segment_size();
            open_single_device(vc, &dev_opts, allow_legacy_directory_shims, Some(*identity))
        })
        .collect()
}

fn open_candidate_devices(
    config: &PoolConfig,
    options: &StoreOptions,
    identities: &[BlockStoreIdentity],
) -> Result<Vec<Device>> {
    if identities.len() != config.devices.len() {
        return Err(StoreError::InvalidOptions {
            reason: "new Pool Store identity count does not match topology",
        });
    }
    let allow_legacy_directory_shims =
        options.is_test_fast_harness_fixture() || is_legacy_single_directory_store_bridge(config);
    config
        .devices
        .iter()
        .zip(identities)
        .map(|(device, identity)| {
            let mut device_options = options.clone();
            device_options.max_segment_bytes = device.media_class.default_segment_size();
            open_candidate_device(
                device,
                &device_options,
                allow_legacy_directory_shims,
                *identity,
            )
        })
        .collect()
}

fn open_devices_preflight_existing(
    config: &PoolConfig,
    options: &StoreOptions,
    identities: &[BlockStoreIdentity],
) -> Result<Vec<Device>> {
    if identities.len() != config.devices.len() {
        return Err(StoreError::InvalidOptions {
            reason: "Pool preflight Store identity count does not match topology",
        });
    }
    config
        .devices
        .iter()
        .zip(identities)
        .map(|(device_config, identity)| {
            let mut device_options = options.clone();
            device_options.max_segment_bytes = device_config.media_class.default_segment_size();
            open_single_device_preflight_existing(device_config, &device_options, *identity)
        })
        .collect()
}

fn open_single_device_preflight_existing(
    config: &DeviceConfig,
    options: &StoreOptions,
    identity: BlockStoreIdentity,
) -> Result<Device> {
    let device = match &config.kind {
        DeviceKind::Single { path } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::Single requires directory object-store compatibility backing",
            )?;
            Device::open_single_preflight_existing(path, options.clone())
        }
        DeviceKind::Mirror { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::Mirror requires directory object-store compatibility backing",
            )?;
            Device::open_mirror_preflight_existing(paths, options)
        }
        DeviceKind::LogDevice { path } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::LogDevice requires directory object-store compatibility backing",
            )?;
            Device::open_log_device_preflight_existing(path, options.clone())
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid1 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::ParityRaid1 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid1_preflight_existing(paths, options)
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid2 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::ParityRaid2 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid2_preflight_existing(paths, options)
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid3 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                true,
                "DeviceKind::ParityRaid3 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid3_preflight_existing(paths, options)
        }
        #[cfg(not(any(feature = "distributed-repair", test)))]
        DeviceKind::ParityRaid1 { .. }
        | DeviceKind::ParityRaid2 { .. }
        | DeviceKind::ParityRaid3 { .. } => Err(StoreError::InvalidOptions {
            reason: "PARITY_RAID devices require the distributed-repair feature",
        }),
        DeviceKind::Block { path } => {
            if !config.backing.is_byte_addressable_pool_member() {
                return Err(StoreError::InvalidOptions {
                    reason: "DeviceKind::Block requires block-device or regular-file backing",
                });
            }
            Device::open_single_block_preflight_existing(path, options.clone(), identity)
        }
    }?;

    let device = if let Some(ref encryption) = config.encryption {
        Device::open_encrypted(device, encryption.clone())
    } else {
        device
    };
    Ok(if let Some(ref compression) = config.compression {
        Device::open_compressed(device, compression.clone())
    } else {
        device
    })
}

fn open_devices_read_only_existing(
    config: &PoolConfig,
    options: &StoreOptions,
    identities: &[BlockStoreIdentity],
) -> Result<Vec<Device>> {
    if identities.len() != config.devices.len() {
        return Err(StoreError::InvalidOptions {
            reason: "read-only Pool Store identity count does not match topology",
        });
    }
    config
        .devices
        .iter()
        .zip(identities)
        .map(|(device_config, identity)| {
            let DeviceKind::Block { path } = &device_config.kind else {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool import supports only DeviceKind::Block members",
                });
            };
            if !device_config.backing.is_byte_addressable_pool_member() {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool import requires block-device or regular-file backing",
                });
            }
            let mut device_options = options.clone();
            device_options.max_segment_bytes = device_config.media_class.default_segment_size();
            let device =
                Device::open_single_block_read_only_existing(path, device_options, *identity)?;
            let device = if let Some(ref encryption) = device_config.encryption {
                Device::open_encrypted(device, encryption.clone())
            } else {
                device
            };
            Ok(if let Some(ref compression) = device_config.compression {
                Device::open_compressed(device, compression.clone())
            } else {
                device
            })
        })
        .collect()
}

fn open_single_device(
    config: &DeviceConfig,
    options: &StoreOptions,
    allow_legacy_directory_shims: bool,
    identity: Option<BlockStoreIdentity>,
) -> Result<Device> {
    let device = match &config.kind {
        DeviceKind::Single { path } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::Single requires directory object-store compatibility backing",
            )?;
            Device::open_single(path, options.clone())
        }
        DeviceKind::Mirror { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::Mirror requires directory object-store compatibility backing",
            )?;
            Device::open_mirror(paths, options)
        }
        DeviceKind::LogDevice { path } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::LogDevice requires directory object-store compatibility backing",
            )?;
            Device::open_log_device(path, options.clone())
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid1 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::ParityRaid1 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid1(paths, options)
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid2 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::ParityRaid2 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid2(paths, options)
        }
        #[cfg(any(feature = "distributed-repair", test))]
        DeviceKind::ParityRaid3 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::ParityRaid3 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid3(paths, options)
        }
        #[cfg(not(any(feature = "distributed-repair", test)))]
        DeviceKind::ParityRaid1 { .. }
        | DeviceKind::ParityRaid2 { .. }
        | DeviceKind::ParityRaid3 { .. } => Err(StoreError::InvalidOptions {
            reason: "PARITY_RAID devices require the distributed-repair feature",
        }),
        DeviceKind::Block { path } => {
            if !config.backing.is_byte_addressable_pool_member() {
                return Err(StoreError::InvalidOptions {
                    reason: "DeviceKind::Block requires block-device or regular-file backing",
                });
            }
            match identity {
                Some(identity) => {
                    Device::open_single_block_writable_existing(path, options.clone(), identity)
                }
                None => Device::open_single_block(path, options.clone()),
            }
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

fn require_legacy_directory_pool_shim(
    backing: DeviceBacking,
    allow_legacy_directory_shims: bool,
    reason: &'static str,
) -> Result<()> {
    if !allow_legacy_directory_shims {
        return Err(StoreError::InvalidOptions {
            reason: "pool device admission requires DeviceKind::Block with block-device or regular-file backing; directory object-store device shims are harness-only",
        });
    }
    if backing == DeviceBacking::DirectoryObjectStoreCompat {
        Ok(())
    } else {
        Err(StoreError::InvalidOptions { reason })
    }
}

fn is_legacy_single_directory_store_bridge(config: &PoolConfig) -> bool {
    let [device] = config.devices.as_slice() else {
        return false;
    };
    if device.backing != DeviceBacking::DirectoryObjectStoreCompat
        || device.class != DeviceClass::Data
    {
        return false;
    }
    match &device.kind {
        DeviceKind::Single { path } => device.path == *path && device.path == config.root_path,
        _ => false,
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

fn normalize_imported_device_layout(
    device_config: &DeviceConfig,
    device: &Device,
    layout: &DeviceLayoutV1,
) -> Result<DeviceLayoutV1> {
    let policy = validate_device_layout_policy_record(layout)?;
    if !device_config.backing.is_byte_addressable_pool_member() {
        return Ok(*layout);
    }

    let usable_capacity = device.store().capacity_bytes();
    if layout.device_size_bytes == usable_capacity {
        return Ok(*layout);
    }

    let raw_capacity = byte_addressable_device_raw_capacity(device_config)?;
    if layout.device_size_bytes == raw_capacity {
        // PoolCreator labels store the raw media length; Pool internals use
        // the object store's usable span with the trailing label excluded.
        return policy
            .compute(usable_capacity)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "pool label DeviceLayoutV1 record is invalid",
            });
    }

    Err(StoreError::InvalidOptions {
        reason: "pool label DeviceLayoutV1 device size mismatch",
    })
}

fn validate_read_only_label_geometry(
    label: &pool_label::PoolLabelV1,
    layout: &DeviceLayoutV1,
) -> Result<()> {
    if label.device_capacity_bytes != layout.device_size_bytes {
        return Err(StoreError::InvalidOptions {
            reason: "read-only pool label capacity disagrees with DeviceLayoutV1",
        });
    }

    let layout_system_end = layout
        .system_area_offset
        .checked_add(layout.system_area_len)
        .ok_or(StoreError::InvalidOptions {
            reason: "read-only pool DeviceLayoutV1 system area overflows",
        })?;
    let label_system_end = label
        .system_area_pointer
        .checked_add(label.system_area_size)
        .ok_or(StoreError::InvalidOptions {
            reason: "read-only pool label committed-root extent overflows",
        })?;
    if label.system_area_size == 0
        || label.system_area_pointer < layout.system_area_offset
        || label_system_end > layout_system_end
    {
        return Err(StoreError::InvalidOptions {
            reason:
                "read-only pool label committed-root extent lies outside DeviceLayoutV1 system area",
        });
    }

    Ok(())
}

fn validate_device_layout_policy_record(layout: &DeviceLayoutV1) -> Result<DeviceLayoutPolicy> {
    let policy = match layout.policy {
        DeviceLayoutPolicyDiscriminant::Slice0Small => DeviceLayoutPolicy::Slice0Small,
        DeviceLayoutPolicyDiscriminant::Auto => DeviceLayoutPolicy::Auto,
        DeviceLayoutPolicyDiscriminant::Custom => DeviceLayoutPolicy::Custom {
            data_segment_size: layout.data_segment_size,
            metadata_segment_size: layout.metadata_segment_size,
            journal_segment_size: layout.poolmap_segment_size,
        },
    };
    let expected =
        policy
            .compute(layout.device_size_bytes)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "pool label DeviceLayoutV1 record is invalid",
            })?;
    if expected != *layout {
        return Err(StoreError::InvalidOptions {
            reason: "pool label DeviceLayoutV1 record does not match layout policy",
        });
    }
    Ok(policy)
}

fn byte_addressable_device_raw_capacity(device_config: &DeviceConfig) -> Result<u64> {
    let device_root = device_root_path(device_config);
    byte_addressable_path_raw_capacity(&device_root)
}

fn byte_addressable_path_raw_capacity(device_root: &Path) -> Result<u64> {
    let mut file = fs::File::open(&device_root).map_err(|source| StoreError::Io {
        operation: "pool_open_device_raw_capacity_open",
        path: device_root.to_path_buf(),
        source,
    })?;
    file.seek(SeekFrom::End(0))
        .map_err(|source| StoreError::Io {
            operation: "pool_open_device_raw_capacity_seek_end",
            path: device_root.to_path_buf(),
            source,
        })
}

fn preflight_blank_block_candidate(
    config: &DeviceConfig,
    minimum_raw_capacity: u64,
) -> Result<Option<(fs::File, crate::store::BlockStoreBootstrapInspection)>> {
    let DeviceKind::Block { path } = &config.kind else {
        return Ok(None);
    };
    if !config.backing.is_byte_addressable_pool_member() {
        return Err(StoreError::InvalidOptions {
            reason: "DeviceKind::Block requires block-device or regular-file backing",
        });
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| StoreError::Io {
            operation: "preflight_replacement_candidate_open",
            path: path.clone(),
            source,
        })?;
    let capacity = file
        .seek(SeekFrom::End(0))
        .map_err(|source| StoreError::Io {
            operation: "preflight_replacement_candidate_capacity",
            path: path.clone(),
            source,
        })?;
    if capacity < minimum_raw_capacity {
        return Err(StoreError::InvalidOptions {
            reason: "replacement device capacity is smaller than the present member",
        });
    }
    let inspection =
        LocalObjectStore::inspect_open_block_device_bootstrap(&mut file, path, capacity)?;
    if inspection.identity.is_some() || inspection.record.is_some() {
        return Err(StoreError::InvalidOptions {
            reason: "replacement candidate is not blank",
        });
    }
    Ok(Some((file, inspection)))
}

fn open_preflighted_block_candidate(
    config: &DeviceConfig,
    options: &StoreOptions,
    identity: BlockStoreIdentity,
    mut file: fs::File,
    inspection: &crate::store::BlockStoreBootstrapInspection,
) -> Result<Device> {
    let DeviceKind::Block { path } = &config.kind else {
        return Err(StoreError::InvalidOptions {
            reason: "preflighted replacement candidate is not byte-addressable",
        });
    };
    LocalObjectStore::initialize_open_block_device_bootstrap_after_inspection(
        &mut file, path, identity, inspection,
    )?;
    let device = Device::open_single_block_writable_existing_file(
        file,
        path.clone(),
        options.clone(),
        identity,
    )?;
    let device = if let Some(ref encryption) = config.encryption {
        Device::open_encrypted(device, encryption.clone())
    } else {
        device
    };
    Ok(if let Some(ref compression) = config.compression {
        Device::open_compressed(device, compression.clone())
    } else {
        device
    })
}

fn open_replacement_resume_candidate(
    config: &DeviceConfig,
    options: &StoreOptions,
    allow_legacy_directory_shims: bool,
    identity: BlockStoreIdentity,
    minimum_raw_capacity: u64,
) -> Result<Device> {
    let DeviceKind::Block { path } = &config.kind else {
        return open_candidate_device(config, options, allow_legacy_directory_shims, identity);
    };
    if !config.backing.is_byte_addressable_pool_member() {
        return Err(StoreError::InvalidOptions {
            reason: "DeviceKind::Block requires block-device or regular-file backing",
        });
    }

    // A resumed candidate normally contains the receipts already rebuilt
    // before interruption, so reopen its complete append-only store instead
    // of applying the blank/bootstrap-only admission scan. If evidence became
    // durable before candidate initialization, admit only an exactly blank
    // candidate through the retained-handle preflight path.
    let device = match Device::open_single_block_writable_existing(path, options.clone(), identity)
    {
        Ok(device) => device,
        Err(existing_error) => {
            let preflight = match preflight_blank_block_candidate(config, minimum_raw_capacity) {
                Ok(preflight) => preflight,
                Err(_) => return Err(existing_error),
            };
            let Some((file, inspection)) = preflight else {
                return Err(existing_error);
            };
            return open_preflighted_block_candidate(config, options, identity, file, &inspection);
        }
    };
    let device = if let Some(ref encryption) = config.encryption {
        Device::open_encrypted(device, encryption.clone())
    } else {
        device
    };
    Ok(if let Some(ref compression) = config.compression {
        Device::open_compressed(device, compression.clone())
    } else {
        device
    })
}

fn open_candidate_device(
    config: &DeviceConfig,
    options: &StoreOptions,
    allow_legacy_directory_shims: bool,
    identity: BlockStoreIdentity,
) -> Result<Device> {
    if let DeviceKind::Block { path } = &config.kind {
        if !config.backing.is_byte_addressable_pool_member() {
            return Err(StoreError::InvalidOptions {
                reason: "DeviceKind::Block requires block-device or regular-file backing",
            });
        }
        let file = LocalObjectStore::initialize_and_retain_block_device_bootstrap(path, identity)?;
        let device = Device::open_single_block_writable_existing_file(
            file,
            path.clone(),
            options.clone(),
            identity,
        )?;
        let device = if let Some(ref encryption) = config.encryption {
            Device::open_encrypted(device, encryption.clone())
        } else {
            device
        };
        return Ok(if let Some(ref compression) = config.compression {
            Device::open_compressed(device, compression.clone())
        } else {
            device
        });
    }
    open_single_device(config, options, allow_legacy_directory_shims, None)
}

fn pool_config_has_label_authority(config: &PoolConfig) -> bool {
    config.devices.iter().any(device_config_has_label_authority)
}

fn device_config_has_label_authority(config: &DeviceConfig) -> bool {
    let device_root = device_root_path(config);
    if config.backing.uses_fixed_offset_pool_labels() {
        let Ok(mut file) = fs::File::open(&device_root) else {
            return false;
        };
        let mut magic = [0u8; 4];
        return file.read_exact(&mut magic).is_ok() && magic == pool_label::POOL_LABEL_MAGIC;
    }

    label_file_path(&device_root).exists()
}

#[cfg(test)]
fn write_pool_label(
    device_config: &DeviceConfig,
    label: PoolLabelV1,
    device_layout: Option<&DeviceLayoutV1>,
    topology_roster: &[[u8; 16]],
    operation: &'static str,
) -> Result<()> {
    write_pool_label_with_lifecycle(
        device_config,
        label,
        device_layout,
        topology_roster,
        None,
        operation,
    )
}

fn write_pool_label_with_lifecycle(
    device_config: &DeviceConfig,
    label: PoolLabelV1,
    device_layout: Option<&DeviceLayoutV1>,
    topology_roster: &[[u8; 16]],
    lifecycle: Option<&PoolLifecycleLabelRecord>,
    operation: &'static str,
) -> Result<()> {
    write_pool_label_copies_with_lifecycle(
        device_config,
        label,
        device_layout,
        topology_roster,
        lifecycle,
        PoolLabelCopyTarget::Both,
        operation,
    )
}

#[derive(Clone, Copy)]
enum PoolLabelCopyTarget {
    Primary,
    Backup,
    Both,
}

fn write_pool_label_copies_with_lifecycle(
    device_config: &DeviceConfig,
    label: PoolLabelV1,
    device_layout: Option<&DeviceLayoutV1>,
    topology_roster: &[[u8; 16]],
    lifecycle: Option<&PoolLifecycleLabelRecord>,
    target: PoolLabelCopyTarget,
    operation: &'static str,
) -> Result<()> {
    let layout_bytes = device_layout.map(|layout| {
        let mut bytes = [0u8; pool_label::POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(layout, &mut bytes);
        bytes
    });
    let lifecycle_record = lifecycle
        .map(|record| {
            pool_label::PoolLifecycleRecordV1::new(
                record.sequence,
                label.topology_generation,
                record.kind,
                &record.payload,
            )
        })
        .transpose()
        .map_err(|_| StoreError::InvalidOptions {
            reason: "Pool lifecycle label record is invalid",
        })?;
    let sealed = pool_label::seal_label_with_all_extensions(
        label,
        layout_bytes.as_ref(),
        Some(topology_roster),
        lifecycle_record,
    )
    .map_err(|_| StoreError::InvalidOptions {
        reason: "label seal failed",
    })?;

    let roster_bytes = topology_roster
        .len()
        .checked_mul(pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_MEMBER_SIZE)
        .and_then(|size| size.checked_add(pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_HEADER_SIZE))
        .and_then(|size| size.checked_add(pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_CHECKSUM_SIZE))
        .ok_or(StoreError::InvalidOptions {
            reason: "pool topology roster is too large",
        })?;
    let mut encoded_size = pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_OFFSET
        .checked_add(roster_bytes)
        .filter(|size| *size <= pool_label::POOL_LABEL_SIZE)
        .ok_or(StoreError::InvalidOptions {
            reason: "pool topology roster does not fit the label envelope",
        })?;
    if let Some(record) = lifecycle_record {
        encoded_size = encoded_size
            .checked_add(
                pool_label::pool_lifecycle_v1_wire_size(record).map_err(|_| {
                    StoreError::InvalidOptions {
                        reason: "Pool lifecycle record does not fit the label envelope",
                    }
                })?,
            )
            .filter(|size| *size <= pool_label::POOL_LABEL_SIZE)
            .ok_or(StoreError::InvalidOptions {
                reason: "Pool lifecycle record does not fit the label envelope",
            })?;
    }
    let mut buf = vec![0u8; encoded_size];
    pool_label::encode_label_with_all_extensions(
        &sealed,
        layout_bytes.as_ref(),
        Some(topology_roster),
        lifecycle_record,
        &mut buf,
    )
    .map_err(|_| StoreError::InvalidOptions {
        reason: "label encode failed",
    })?;

    let device_root = device_root_path(device_config);
    if device_config.backing.uses_fixed_offset_pool_labels() {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(&device_root)
            .map_err(|e| StoreError::Io {
                operation,
                path: device_root.clone(),
                source: e,
            })?;
        let size = file.seek(SeekFrom::End(0)).map_err(|e| StoreError::Io {
            operation,
            path: device_root.clone(),
            source: e,
        })?;
        let label_size = pool_label::POOL_LABEL_SIZE as u64;
        if size < label_size {
            return Err(StoreError::InvalidOptions {
                reason: "pool member is too small for redundant labels",
            });
        }
        let offsets: &[u64] = match target {
            PoolLabelCopyTarget::Primary => &[0],
            PoolLabelCopyTarget::Backup => &[size - label_size],
            PoolLabelCopyTarget::Both if size == label_size => &[0],
            PoolLabelCopyTarget::Both => &[size - label_size, 0],
        };
        for offset in offsets {
            file.seek(SeekFrom::Start(*offset))
                .and_then(|_| file.write_all(&buf))
                .map_err(|e| StoreError::Io {
                    operation,
                    path: device_root.clone(),
                    source: e,
                })?;
        }
        file.sync_all().map_err(|e| StoreError::Io {
            operation,
            path: device_root,
            source: e,
        })?;
        return Ok(());
    }

    fs::create_dir_all(&device_root).map_err(|e| StoreError::Io {
        operation,
        path: device_root.clone(),
        source: e,
    })?;
    let _ = target;
    let label_path = label_file_path(&device_root);
    let mut file = fs::File::create(&label_path).map_err(|e| StoreError::Io {
        operation,
        path: label_path.clone(),
        source: e,
    })?;
    file.write_all(&buf).map_err(|e| StoreError::Io {
        operation,
        path: label_path.clone(),
        source: e,
    })?;
    file.sync_all().map_err(|e| StoreError::Io {
        operation,
        path: label_path,
        source: e,
    })?;
    Ok(())
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

fn object_store_subject_id_from_key(key: ObjectKey) -> u64 {
    let bytes = key.as_bytes32();
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
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

fn pool_pending_deletion_object_key(
    class: IoClass,
    key: ObjectKey,
    receipt_generation: u64,
) -> ObjectKey {
    let mut hasher = blake3::Hasher::new_derive_key(PENDING_DELETION_CONTEXT);
    hasher.update(b"pending-deletion");
    hasher.update(&[io_class_as_u8(class)]);
    hasher.update(&key.as_bytes32());
    hasher.update(&receipt_generation.to_le_bytes());
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[..8].copy_from_slice(&crate::store::POOL_PENDING_DELETION_KEY_PREFIX);
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

    fn single_mirror_device_config(root: &Path) -> PoolConfig {
        let path = root.join("mirror-data");
        PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Mirror { paths: vec![path] },
                encryption: None,
                compression: None,
            }],
        }
    }

    fn two_leg_mirror_device_config(root: &Path) -> PoolConfig {
        let paths = vec![root.join("mirror-0"), root.join("mirror-1")];
        PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: paths[0].clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Mirror { paths },
                encryption: None,
                compression: None,
            }],
        }
    }

    fn create_regular_file_device_with_size(path: &Path, size: u64) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let file = std::fs::File::create(path).unwrap();
        file.set_len(size).unwrap();
    }

    fn create_regular_file_device(path: &Path) {
        create_regular_file_device_with_size(path, 2 * 1024 * 1024);
    }

    fn labelled_pool_bootstrap_config(root: &Path, member_count: usize) -> PoolBootstrapConfig {
        std::fs::create_dir_all(root).expect("create bootstrap fixture root");
        let capacity_bytes = 2 * 1024 * 1024;
        let pool_guid = [0x51; 16];
        let members = (0..member_count)
            .map(|index| {
                let path = root.join(format!("member-{index}.img"));
                create_regular_file_device_with_size(&path, capacity_bytes);
                let device_guid = deterministic_device_guid(index);
                let layout = DeviceLayoutPolicy::Slice0Small
                    .compute(capacity_bytes)
                    .expect("compute bootstrap fixture layout");
                let mut layout_bytes = [0; pool_label::POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
                encode_device_layout_v1(&layout, &mut layout_bytes);
                let mut label = PoolLabelV1::new(pool_guid, device_guid, "bootstrap-fixture");
                label.pool_state = PoolState::Exported;
                label.device_index = index as u32;
                label.device_count = member_count as u32;
                label.device_capacity_bytes = capacity_bytes;
                label.system_area_pointer = layout.system_area_offset;
                label.system_area_size = layout.system_area_len;
                let label = pool_label::seal_label_with_device_layout(label, Some(&layout_bytes))
                    .expect("seal bootstrap fixture label");
                let mut encoded = [0; pool_label::POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
                pool_label::encode_label_with_device_layout(
                    &label,
                    Some(&layout_bytes),
                    &mut encoded,
                )
                .expect("encode bootstrap fixture label");
                let label = pool_label::decode_label(&encoded)
                    .expect("canonicalize bootstrap fixture label");
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .expect("open bootstrap fixture member");
                for offset in [0, capacity_bytes - pool_label::POOL_LABEL_SIZE as u64] {
                    file.seek(SeekFrom::Start(offset))
                        .expect("seek bootstrap fixture label");
                    file.write_all(&encoded)
                        .expect("write bootstrap fixture label");
                }
                file.sync_all().expect("sync bootstrap fixture labels");
                PoolBootstrapMember {
                    file: fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .expect("retain bootstrap fixture member"),
                    path,
                    backing: DeviceBacking::RegularFileDev,
                    device_index: index as u32,
                    capacity_bytes,
                    device_guid,
                    expected_label: label,
                    device_layout_v1: layout_bytes,
                    label_was_present: true,
                }
            })
            .collect();
        PoolBootstrapConfig {
            pool_guid,
            members,
            encryption: None,
        }
    }

    fn reopen_pool_bootstrap_config(config: &PoolBootstrapConfig) -> PoolBootstrapConfig {
        PoolBootstrapConfig {
            pool_guid: config.pool_guid,
            members: config
                .members
                .iter()
                .map(|member| PoolBootstrapMember {
                    file: fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&member.path)
                        .expect("reopen bootstrap fixture member"),
                    path: member.path.clone(),
                    backing: member.backing,
                    device_index: member.device_index,
                    capacity_bytes: member.capacity_bytes,
                    device_guid: member.device_guid,
                    expected_label: member.expected_label.clone(),
                    device_layout_v1: member.device_layout_v1,
                    label_was_present: member.label_was_present,
                })
                .collect(),
            encryption: config.encryption.clone(),
        }
    }

    fn bootstrap_pool_config(config: &PoolBootstrapConfig) -> Result<()> {
        let admission = preflight_labelled_pool_bootstrap(reopen_pool_bootstrap_config(config))?;
        bootstrap_labelled_pool(admission)
    }

    fn seed_pool_bootstrap_record(
        config: &PoolBootstrapConfig,
        member_index: usize,
        key: ObjectKey,
        payload: &[u8],
    ) {
        let member = &config.members[member_index];
        let identity = BlockStoreIdentity {
            pool_guid: config.pool_guid,
            device_guid: member.device_guid,
        };
        LocalObjectStore::initialize_block_device_bootstrap(&member.path, identity)
            .expect("initialize bootstrap fixture Store header");
        let mut store = LocalObjectStore::open_block_device_writable_existing(
            &member.path,
            StoreOptions::test_fast(),
            identity,
        )
        .expect("open bootstrap fixture Store");
        store
            .put_pool_internal(key, payload)
            .expect("seed bootstrap fixture record");
        store.sync_all().expect("sync bootstrap fixture record");
    }

    fn regular_file_device_config(path: PathBuf) -> DeviceConfig {
        create_regular_file_device(&path);
        DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::RegularFileDev,
            class: DeviceClass::Data,
            kind: DeviceKind::Block { path },
            encryption: None,
            compression: None,
        }
    }

    fn single_regular_file_pool_config(root: &Path) -> PoolConfig {
        PoolConfig {
            name: "testpool-file-dev".into(),
            root_path: root.join("metadata"),
            devices: vec![regular_file_device_config(root.join("pool0.img"))],
        }
    }

    fn regular_file_pool_config(root: &Path, name: &str, size: u64) -> PoolConfig {
        let dev_path = root.join("pool.img");
        create_regular_file_device_with_size(&dev_path, size);
        PoolConfig {
            name: name.into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: dev_path.clone(),
                backing: DeviceBacking::RegularFileDev,
                class: DeviceClass::Data,
                kind: DeviceKind::Block { path: dev_path },
                encryption: None,
                compression: None,
            }],
        }
    }

    fn assert_invalid_options_reason_contains<T>(result: Result<T>, needle: &str) {
        match result {
            Err(StoreError::InvalidOptions { reason }) => {
                assert!(
                    reason.contains(needle),
                    "expected InvalidOptions reason containing {needle:?}, got {reason:?}"
                );
            }
            Ok(_) => panic!("expected InvalidOptions containing {needle:?}, got success"),
            Err(other) => panic!("expected InvalidOptions containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn pool_bootstrap_converges_partial_headers_and_markers() {
        let root = temp_dir("bootstrap-partial");
        let _ = std::fs::remove_dir_all(&root);
        let config = labelled_pool_bootstrap_config(&root, 2);
        for member in &config.members {
            LocalObjectStore::initialize_block_device_bootstrap(
                &member.path,
                BlockStoreIdentity {
                    pool_guid: config.pool_guid,
                    device_guid: member.device_guid,
                },
            )
            .expect("seed matching partial Store header");
        }
        let marker = encode_receipt_generation_high_water(ReceiptGenerationHighWater {
            pool_guid: config.pool_guid,
            reserved_through: 0,
        });
        seed_pool_bootstrap_record(&config, 0, receipt_generation_high_water_key(), &marker);

        bootstrap_pool_config(&config).expect("converge partial bootstrap");
        bootstrap_pool_config(&config).expect("retry converged bootstrap");
        for member in &config.members {
            let inspection = LocalObjectStore::inspect_block_device_bootstrap(
                &member.path,
                member.capacity_bytes - pool_label::POOL_LABEL_SIZE as u64,
            )
            .expect("inspect converged member");
            assert_eq!(
                inspection.identity,
                Some(BlockStoreIdentity {
                    pool_guid: config.pool_guid,
                    device_guid: member.device_guid,
                })
            );
            assert!(
                validate_fresh_pool_bootstrap_marker(&inspection, config.pool_guid)
                    .expect("validate converged marker")
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_bootstrap_refuses_unexpected_foreign_and_nonzero_markers() {
        let mut unexpected_key_bytes = *receipt_generation_high_water_key().as_bytes();
        unexpected_key_bytes[8] ^= 0x80;
        for (suffix, key, marker, reason) in [
            (
                "unexpected",
                ObjectKey::from_bytes32(unexpected_key_bytes),
                vec![0x77],
                "unexpected object key",
            ),
            (
                "foreign",
                receipt_generation_high_water_key(),
                encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                    pool_guid: [0x99; 16],
                    reserved_through: 0,
                })
                .to_vec(),
                "foreign or already used",
            ),
            (
                "nonzero",
                receipt_generation_high_water_key(),
                encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                    pool_guid: [0x51; 16],
                    reserved_through: 1,
                })
                .to_vec(),
                "foreign or already used",
            ),
        ] {
            let root = temp_dir(suffix);
            let _ = std::fs::remove_dir_all(&root);
            let config = labelled_pool_bootstrap_config(&root, 1);
            seed_pool_bootstrap_record(&config, 0, key, &marker);
            let before = std::fs::read(&config.members[0].path).expect("snapshot refused member");
            assert_invalid_options_reason_contains(
                preflight_labelled_pool_bootstrap(reopen_pool_bootstrap_config(&config)),
                reason,
            );
            assert_eq!(
                std::fs::read(&config.members[0].path).expect("reread refused member"),
                before,
                "bootstrap preflight changed refused {suffix} media"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn pool_bootstrap_refuses_reordered_topology_without_mutation() {
        let root = temp_dir("bootstrap-reordered");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = labelled_pool_bootstrap_config(&root, 2);
        let before: Vec<_> = config
            .members
            .iter()
            .map(|member| std::fs::read(&member.path).expect("snapshot topology member"))
            .collect();
        config.members.swap(0, 1);
        assert_invalid_options_reason_contains(
            preflight_labelled_pool_bootstrap(reopen_pool_bootstrap_config(&config)),
            "member order is not exact",
        );
        for (member, expected) in config.members.iter().zip(before.iter().rev()) {
            assert_eq!(
                std::fs::read(&member.path).expect("reread topology member"),
                *expected,
                "topology refusal changed media"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_bootstrap_mutates_retained_member_after_path_replacement() {
        let root = temp_dir("bootstrap-retained-handle");
        let _ = std::fs::remove_dir_all(&root);
        let config = labelled_pool_bootstrap_config(&root, 1);
        let original_path = config.members[0].path.clone();
        let renamed_path = root.join("admitted-member.img");
        let capacity_bytes = config.members[0].capacity_bytes;
        let pool_guid = config.pool_guid;
        let device_guid = config.members[0].device_guid;

        let admission = preflight_labelled_pool_bootstrap(config)
            .expect("admit exact retained bootstrap member");
        std::fs::rename(&original_path, &renamed_path)
            .expect("rename admitted member after preflight");
        create_regular_file_device_with_size(&original_path, capacity_bytes);

        bootstrap_labelled_pool(admission).expect("bootstrap retained admitted member");

        let inspection = LocalObjectStore::inspect_block_device_bootstrap(
            &renamed_path,
            capacity_bytes - pool_label::POOL_LABEL_SIZE as u64,
        )
        .expect("inspect renamed admitted member");
        assert_eq!(
            inspection.identity,
            Some(BlockStoreIdentity {
                pool_guid,
                device_guid,
            })
        );
        assert!(validate_fresh_pool_bootstrap_marker(&inspection, pool_guid)
            .expect("validate marker on admitted member"));
        assert!(
            std::fs::read(&original_path)
                .expect("read path replacement")
                .iter()
                .all(|byte| *byte == 0),
            "bootstrap followed the pathname instead of the retained member"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn pending_deletion_for_test(
        pool: &Pool,
        class: IoClass,
        receipt: &PlacementReceipt,
        phase: PendingDeletionPhase,
    ) -> PoolPendingDeletion {
        let indices = pool.class_map.get(class);
        let carriers = pool
            .receipt_carriers(indices, receipt)
            .expect("discover receipt carriers");
        PoolPendingDeletion {
            pool_guid: pool.pool_guid,
            class,
            receipt: receipt.clone(),
            receipt_carrier_guids: carriers
                .into_iter()
                .map(|idx| pool.device_guid_for_index(idx))
                .collect(),
            phase,
        }
    }

    fn stage_pending_deletion_for_test(
        pool: &mut Pool,
        class: IoClass,
        receipt: &PlacementReceipt,
        phase: PendingDeletionPhase,
    ) -> PoolPendingDeletion {
        let mut pending =
            pending_deletion_for_test(pool, class, receipt, PendingDeletionPhase::Prepared);
        pool.persist_pending_deletion_phase(&pending)
            .expect("persist prepared deletion handoff");
        if phase >= PendingDeletionPhase::Committed {
            pending.phase = PendingDeletionPhase::Committed;
            pool.persist_pending_deletion_phase(&pending)
                .expect("persist committed deletion handoff");
        }
        pending
    }

    fn snapshot_tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries: Vec<_> = std::fs::read_dir(current)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    visit(root, &path, snapshot);
                } else {
                    snapshot.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(&path).unwrap(),
                    );
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    fn stage_committed_wal_only(store: &mut LocalObjectStore, entries: &[(ObjectKey, Vec<u8>)]) {
        let cg_id = store.commit_group.current_id().0;
        store
            .intent_log
            .append(crate::intent_log::record::IntentLogRecord::TxBegin { cg_id })
            .unwrap();
        for (key, payload) in entries {
            store
                .intent_log
                .append(crate::intent_log::record::IntentLogRecord::WritePayload {
                    object_id: *key,
                    offset: 0,
                    data: payload.clone(),
                })
                .unwrap();
            store.commit_group.queue_put(*key, payload).unwrap();
        }
        store.intent_log_tx_open = true;
        store.sync_all().unwrap();
    }

    fn assert_generation_high_water_open_refused(label: &str, mutate: impl FnOnce(&mut Pool)) {
        let root = temp_dir(label);
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        mutate(&mut pool);
        sync_receipt_generation_high_water_devices(&mut pool.devices).unwrap();
        drop(pool);

        assert!(matches!(
            Pool::create(config, properties, &test_options()),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn assert_topology_committed(result: &crate::device_removal::EvacuationResult) {
        assert!(result.complete, "{result:?}");
        assert!(!result.topology_commit_pending, "{result:?}");
        assert_eq!(result.objects_failed, 0, "{result:?}");
    }

    fn assert_legacy_device_lifecycle_files_absent(root: &Path) {
        for name in [
            ".tidefs_device_removal_pending",
            ".tidefs_device_removal_pending.tmp",
            ".tidefs_device_replacement_evidence",
            ".tidefs_device_replacement_evidence.tmp",
        ] {
            assert!(
                !root.join(name).exists(),
                "obsolete lifecycle side file {name}"
            );
        }
    }

    fn assert_pool_label_lifecycle(pool: &Pool, kind: pool_label::PoolLifecycleKindV1) {
        let expected = pool
            .label_lifecycle
            .as_ref()
            .expect("Pool has selected lifecycle authority");
        assert_eq!(expected.kind, kind);
        for config in &pool.config.devices {
            let copies = read_pool_label_copies(config).expect("read lifecycle label copies");
            assert!(!copies.is_empty());
            assert!(copies
                .iter()
                .all(|copy| copy.lifecycle.as_ref() == Some(expected)));
        }
    }

    #[test]
    fn lifecycle_counter_exhaustion_fails_closed() {
        assert_eq!(next_pool_lifecycle_sequence(None).unwrap(), 1);
        assert_eq!(next_pool_lifecycle_sequence(Some(41)).unwrap(), 42);
        assert!(matches!(
            next_pool_lifecycle_sequence(Some(u64::MAX)),
            Err(StoreError::InvalidOptions {
                reason: "Pool lifecycle label sequence exhausted"
            })
        ));
        assert_eq!(checked_successor_topology_generation(41), Some(42));
        assert_eq!(checked_successor_topology_generation(u64::MAX), None);
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
        pool.persisted_label_epoch = None;
        pool.persist_active_labels_if_needed()
            .expect("persist deterministic test device GUID labels");
    }

    #[test]
    fn read_only_geometry_accepts_committed_root_extent_inside_layout_system_area() {
        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(300 * 1024 * 1024)
            .expect("device layout");
        let mut label = pool_label::PoolLabelV1::new([0x11; 16], [0x22; 16], "geometry");
        label.device_capacity_bytes = layout.device_size_bytes;
        label.system_area_pointer = 200 * 1024;
        label.system_area_size = 16 * 1024;

        validate_read_only_label_geometry(&label, &layout)
            .expect("committed-root extent within the persisted system region");
    }

    #[test]
    fn read_only_geometry_rejects_committed_root_extent_outside_layout_system_area() {
        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(300 * 1024 * 1024)
            .expect("device layout");
        let mut label = pool_label::PoolLabelV1::new([0x11; 16], [0x22; 16], "geometry");
        label.device_capacity_bytes = layout.device_size_bytes;
        label.system_area_pointer = layout.system_area_len - 8 * 1024;
        label.system_area_size = 16 * 1024;

        assert_invalid_options_reason_contains(
            validate_read_only_label_geometry(&label, &layout),
            "outside DeviceLayoutV1 system area",
        );
    }

    fn replace_planner_replay_receipt(
        receipt: &mut PlacementReceipt,
        device_targets: Vec<u64>,
        failure_domain_separation: bool,
        devices: &[DeviceHealthCapacity],
    ) {
        let (object_id, placement_key) = placement_key_pair(receipt.object_key);
        let decision = PlacementDecision::new(
            device_targets,
            receipt.targets.len(),
            failure_domain_separation,
            0x5eed_cafe,
            object_id,
            receipt.failure_domain_level,
        );
        let request = AllocationRequest::new(object_id, receipt.payload_len, placement_key);
        let replay = decision
            .to_replay_receipt(
                &receipt.policy.layout().unwrap(),
                devices,
                &request,
                receipt.epoch,
            )
            .unwrap();
        assert!(replay.verify_seal());
        receipt.planner_replay_receipt = Some(replay);
    }

    #[test]
    fn read_only_pool_open_preserves_multi_device_state() {
        let root = temp_dir("read-only-existing-multi-device");
        let metadata_root = root.join("metadata");
        let config = PoolConfig {
            name: "read-only-existing".into(),
            root_path: metadata_root.clone(),
            devices: vec![
                regular_file_device_config(root.join("device-0.img")),
                regular_file_device_config(root.join("device-1.img")),
            ],
        };
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create two-device pool");

        let key = ObjectKey::from_name(b"read-only-replicated-object");
        let payload = b"read-only replicated payload".to_vec();
        let (_stored, receipt) = pool
            .put_with_receipt(IoClass::Data, key, &payload)
            .expect("write replicated receipt-backed object");
        assert_eq!(receipt.targets.len(), 2);
        pool.sync_all().expect("sync two-device pool");
        let pool_guid = pool.pool_guid();
        let first_device_guid = pool.device_guid_for_index(0);
        let removal_target_guid = pool.device_guid_for_index(1);
        drop(pool);

        let device_paths: Vec<_> = config
            .devices
            .iter()
            .map(|device| device.path.clone())
            .collect();
        let device_bytes_before: Vec<_> = device_paths
            .iter()
            .map(|path| std::fs::read(path).expect("snapshot device bytes"))
            .collect();
        let mut metadata_entries_before: Vec<_> = std::fs::read_dir(&metadata_root)
            .expect("read metadata directory")
            .map(|entry| entry.expect("read metadata entry").file_name())
            .collect();
        metadata_entries_before.sort();

        let mut read_only =
            Pool::open_read_only_existing(config.clone(), properties.clone(), &options)
                .expect("open complete topology read-only");
        let (read_payload, read_receipt) = read_only
            .get_with_current_receipt(IoClass::Data, key)
            .expect("strict receipt read")
            .expect("receipt-backed object exists");
        assert_eq!(read_payload, payload);
        assert_eq!(read_receipt, receipt);
        assert!(matches!(
            read_only.sync_all(),
            Err(StoreError::ReadOnly { .. })
        ));
        drop(read_only);

        let mut incomplete = config.clone();
        incomplete.devices.remove(0);
        assert_invalid_options_reason_contains(
            Pool::open(incomplete.clone(), properties.clone(), &options),
            "missing or has extra",
        );
        let mut degraded = Pool::open_read_only_existing(incomplete, properties.clone(), &options)
            .expect("open surviving nonzero-index member read-only");
        assert_eq!(degraded.expected_device_count, 2);
        assert_eq!(degraded.device_label_indices, vec![1]);
        assert_eq!(degraded.health(), PoolHealth::Degraded);
        assert_eq!(degraded.device_guid_for_index(0), removal_target_guid);
        assert_eq!(
            degraded.topology_status(),
            PoolTopologyStatus {
                health: PoolHealth::Degraded,
                read_only: true,
                expected_members: 2,
                present_members: 1,
                missing_members: 1,
                members: vec![
                    PoolMemberStatus {
                        device_index: 0,
                        device_guid: first_device_guid,
                        present: false,
                    },
                    PoolMemberStatus {
                        device_index: 1,
                        device_guid: removal_target_guid,
                        present: true,
                    },
                ],
            }
        );
        let (degraded_payload, degraded_receipt) = degraded
            .get_with_current_receipt(IoClass::Data, key)
            .expect("read current receipt through surviving member")
            .expect("receipt-backed object survives on member 1");
        assert_eq!(degraded_payload, payload);
        assert_eq!(degraded_receipt, receipt);
        assert!(matches!(
            degraded.sync_all(),
            Err(StoreError::ReadOnly { .. })
        ));
        drop(degraded);

        let mut mismatched_properties = properties;
        mismatched_properties.redundancy_policy = PoolRedundancyPolicy::replicated(1);
        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(config.clone(), mismatched_properties, &options),
            "redundancy policy does not match",
        );

        let unformatted_path = root.join("unformatted.img");
        create_regular_file_device(&unformatted_path);
        let unformatted_before = std::fs::read(&unformatted_path).expect("snapshot unformatted");
        assert_invalid_options_reason_contains(
            LocalObjectStore::open_block_device_read_only_existing(
                &unformatted_path,
                options.clone(),
                pool_guid,
                first_device_guid,
            ),
            "initialized format header",
        );
        assert_eq!(
            std::fs::read(&unformatted_path).expect("re-read unformatted"),
            unformatted_before,
            "read-only open must not initialize a format header"
        );

        for (path, expected) in device_paths.iter().zip(&device_bytes_before) {
            assert_eq!(
                std::fs::read(path).expect("re-read device bytes"),
                *expected,
                "read-only Pool inspection changed {}",
                path.display()
            );
        }
        let mut metadata_entries_after: Vec<_> = std::fs::read_dir(&metadata_root)
            .expect("re-read metadata directory")
            .map(|entry| entry.expect("read metadata entry").file_name())
            .collect();
        metadata_entries_after.sort();
        assert_eq!(metadata_entries_after, metadata_entries_before);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_open_selects_completed_active_state_over_exported_predecessor() {
        let root = temp_dir("active-lifecycle-state-selection");
        let _ = std::fs::remove_dir_all(&root);
        let config = PoolConfig {
            name: "active-lifecycle-state-selection".into(),
            root_path: root.join("metadata"),
            devices: vec![
                regular_file_device_config(root.join("device-0.img")),
                regular_file_device_config(root.join("device-1.img")),
            ],
        };
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options())
            .expect("create state-selection Pool");
        pool.persist_lifecycle_record_on_current_topology(
            pool_label::PoolLifecycleKindV1::Clear,
            Vec::new(),
            "test-state-selection-lifecycle",
        )
        .expect("publish lifecycle tombstone");
        let lifecycle = pool.label_lifecycle.clone().unwrap();

        // Model the completed import transition: the primary family is
        // ACTIVE while the redundant predecessor family remains EXPORTED at
        // the exact same topology and lifecycle sequence.
        for device_index in 0..pool.devices.len() {
            let label = pool.build_label_with_state(
                device_index,
                &pool.devices[device_index],
                PoolState::Exported,
            );
            write_pool_label_copies_with_lifecycle(
                &pool.config.devices[device_index],
                label,
                pool.device_layouts.get(device_index),
                &pool.device_guids,
                Some(&lifecycle),
                PoolLabelCopyTarget::Backup,
                "test-exported-predecessor-label",
            )
            .expect("write exported predecessor copy");
        }
        drop(pool);

        let reopened = Pool::open(config, properties, &test_options())
            .expect("select completed ACTIVE lifecycle family");
        assert_eq!(reopened.label_lifecycle, Some(lifecycle));
        assert_eq!(reopened.stats().device_count, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_only_pool_open_refuses_conflicting_topology_roster() {
        let root = temp_dir("read-only-conflicting-topology-roster");
        let _ = std::fs::remove_dir_all(&root);
        let config = PoolConfig {
            name: "read-only-conflicting-topology-roster".into(),
            root_path: root.join("metadata"),
            devices: vec![
                regular_file_device_config(root.join("device-0.img")),
                regular_file_device_config(root.join("device-1.img")),
            ],
        };
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create roster-conflict fixture");
        let mut conflicting_roster = pool.device_guids.clone();
        conflicting_roster[0] = [0xEE; 16];
        assert_ne!(conflicting_roster[0], conflicting_roster[1]);
        let layout = pool.device_layouts[1];
        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = fs::File::open(device_root_path(&config.devices[1])).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let label = pool_label::decode_label(&label_bytes).unwrap();
        write_pool_label(
            &config.devices[1],
            label,
            Some(&layout),
            &conflicting_roster,
            "test_write_conflicting_topology_roster",
        )
        .unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(config, properties, &options),
            "topology roster mismatch across labels",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_only_pool_open_refuses_partial_or_missing_topology_roster() {
        let root = temp_dir("read-only-partial-topology-roster");
        let _ = std::fs::remove_dir_all(&root);
        let config = PoolConfig {
            name: "read-only-partial-topology-roster".into(),
            root_path: root.join("metadata"),
            devices: vec![
                regular_file_device_config(root.join("device-0.img")),
                regular_file_device_config(root.join("device-1.img")),
            ],
        };
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create partial-roster fixture");
        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_root_path(&config.devices[0]))
            .unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let label = pool_label::decode_label(&label_bytes).unwrap();
        let mut layout_bytes = [0u8; pool_label::POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&pool.device_layouts[0], &mut layout_bytes);
        let rosterless =
            pool_label::seal_label_with_device_layout(label, Some(&layout_bytes)).unwrap();
        let mut rosterless_bytes = [0u8; pool_label::POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
        pool_label::encode_label_with_device_layout(
            &rosterless,
            Some(&layout_bytes),
            &mut rosterless_bytes,
        )
        .unwrap();
        label_file.seek(SeekFrom::Start(0)).unwrap();
        label_file.write_all(&rosterless_bytes).unwrap();
        label_file.sync_all().unwrap();
        drop(label_file);
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(config.clone(), properties.clone(), &options),
            "feature flags mismatch across devices",
        );

        let mut degraded_without_roster = config;
        degraded_without_roster.devices.truncate(1);
        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(degraded_without_roster, properties, &options),
            "degraded pool import requires a durable topology roster",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_only_pool_open_refuses_receiptless_survivor() {
        let root = temp_dir("read-only-existing-receiptless-survivor");
        let metadata_root = root.join("metadata");
        let config = PoolConfig {
            name: "read-only-receiptless-survivor".into(),
            root_path: metadata_root,
            devices: vec![
                regular_file_device_config(root.join("device-0.img")),
                regular_file_device_config(root.join("device-1.img")),
            ],
        };
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create two-device pool");
        let key = ObjectKey::from_name(b"read-only-receiptless-survivor");
        let payload = b"payload alone cannot authorize a degraded read";
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("write replicated receipt-backed object");
        assert_eq!(receipt.targets.len(), 2);

        let receipt_key = placement_receipt_object_key(key);
        assert!(pool.devices[1]
            .delete_pool_internal(receipt_key)
            .expect("remove surviving member receipt copy"));
        pool.devices[1]
            .sync_strict_pool_authority()
            .expect("sync surviving member receipt loss");
        drop(pool);

        let mut incomplete = config;
        incomplete.devices.remove(0);
        let degraded = Pool::open_read_only_existing(incomplete, properties, &options)
            .expect("open surviving nonzero-index member read-only");
        assert_eq!(degraded.health(), PoolHealth::Degraded);
        assert_invalid_options_reason_contains(
            degraded.get_with_current_receipt(IoClass::Data, key),
            "receiptless raw payload",
        );

        let _ = std::fs::remove_dir_all(&root);
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

        let err = open_single_device(&config, &test_options(), false, None).unwrap_err();
        assert!(matches!(err, StoreError::InvalidOptions { reason } if reason.contains("Block")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn product_pool_refuses_directory_object_store_member() {
        let root = temp_dir("directory-member-refused");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);

        assert_invalid_options_reason_contains(
            Pool::create(config, PoolProperties::default(), &StoreOptions::default()),
            "directory object-store device shims are harness-only",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn harness_options_allow_legacy_directory_object_store_member() {
        let root = temp_dir("directory-member-harness");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);

        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"harness-directory-shim");
        pool.put(IoClass::Data, key, b"compat").unwrap();
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(b"compat".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn product_pool_accepts_regular_file_dev_block_member() {
        let root = temp_dir("regular-file-dev-product");
        let _ = std::fs::remove_dir_all(&root);
        let image = root.join("pool0.img");
        let config = PoolConfig {
            name: "testpool-file-dev".into(),
            root_path: root.join("metadata"),
            devices: vec![regular_file_device_config(image)],
        };

        let mut pool =
            Pool::create(config, PoolProperties::default(), &StoreOptions::default()).unwrap();
        let key = ObjectKey::from_name(b"regular-file-dev-pool-member");
        pool.put(IoClass::Data, key, b"file-dev").unwrap();
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(b"file-dev".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn product_pool_refuses_fixed_directory_layout_kinds() {
        let root = temp_dir("fixed-layout-refused");
        let _ = std::fs::remove_dir_all(&root);

        let mirror_paths = vec![root.join("mirror-a"), root.join("mirror-b")];
        let parity_paths = vec![
            root.join("parity-a"),
            root.join("parity-b"),
            root.join("parity-c"),
            root.join("parity-d"),
            root.join("parity-e"),
        ];
        let log_path = root.join("log");
        let cases = vec![
            DeviceKind::Mirror {
                paths: mirror_paths,
            },
            DeviceKind::ParityRaid1 {
                paths: parity_paths[..3].to_vec(),
            },
            DeviceKind::ParityRaid2 {
                paths: parity_paths[..4].to_vec(),
            },
            DeviceKind::ParityRaid3 {
                paths: parity_paths,
            },
            DeviceKind::LogDevice { path: log_path },
        ];

        for (idx, kind) in cases.into_iter().enumerate() {
            let config = PoolConfig {
                name: format!("testpool-fixed-layout-{idx}"),
                root_path: root.join(format!("metadata-{idx}")),
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: root.join(format!("dev-{idx}")),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind,
                    encryption: None,
                    compression: None,
                }],
            };
            assert_invalid_options_reason_contains(
                Pool::create(config, PoolProperties::default(), &StoreOptions::default()),
                "directory object-store device shims are harness-only",
            );
        }

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
    fn read_cache_fallback_add_reopen_and_dedicated_io() {
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

        let read_cache_path = root.join("read-cache");
        pool.add_device(
            DeviceConfig {
                media_class: DeviceMediaClass::Nvme,
                path: read_cache_path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::ReadCache,
                kind: DeviceKind::Single {
                    path: read_cache_path,
                },
                encryption: None,
                compression: None,
            },
            &test_options(),
        )
        .unwrap();
        let reopen_config = pool.config.clone();
        pool.sync_all().unwrap();
        drop(pool);

        let mut pool =
            Pool::create(reopen_config, PoolProperties::default(), &test_options()).unwrap();
        let dedicated_key = ObjectKey::from_name(b"dedicated-read-cache");
        pool.put(IoClass::ReadCache, dedicated_key, b"dedicated cached data")
            .unwrap();
        assert_eq!(
            pool.get(IoClass::ReadCache, dedicated_key).unwrap(),
            Some(b"dedicated cached data".to_vec())
        );

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
            assert!(receipt.generation > 0);
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
    fn placement_receipt_embeds_planner_replay_authority() {
        let root = temp_dir("receipt-replay-authority");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"replay-authority-erasure");
        let payload = b"planner replay authority payload";
        pool.put(IoClass::Data, key, payload).unwrap();

        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        let replay = receipt
            .planner_replay_receipt
            .as_ref()
            .expect("planner replay receipt");
        let decision = replay.replay_decision().expect("replay decision");
        let receipt_targets: Vec<u64> = receipt
            .targets
            .iter()
            .map(placement_target_device_id)
            .collect();

        assert_eq!(replay.topology_epoch, receipt.epoch);
        assert_eq!(replay.size_hint_bytes, payload.len() as u64);
        assert_eq!(replay.policy, receipt.policy.layout().unwrap().policy);
        let (expected_object_id, expected_placement_key) = placement_key_pair(key);
        assert_eq!(replay.object_id, expected_object_id);
        assert_eq!(replay.placement_key, expected_placement_key);
        assert_eq!(decision.device_targets, receipt_targets);
        assert_eq!(decision.failure_domain_level, receipt.failure_domain_level);
        assert_eq!(replay.targets.len(), receipt.targets.len());
        for (idx, target) in receipt.targets.iter().enumerate() {
            let replay_target = &replay.targets[idx];
            assert_eq!(replay_target.target_index as usize, idx);
            assert_eq!(replay_target.shard_index, target.shard_index);
            assert_eq!(
                placement_role_from_replay(replay_target.shard_role),
                target.role
            );
        }
        let mut mismatched_key_receipt = receipt.clone();
        mismatched_key_receipt.object_key = ObjectKey::from_name(b"wrong-replay-subject");
        assert!(!planner_replay_receipt_matches_receipt(
            &mismatched_key_receipt
        ));
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn planner_replay_receipt_refuses_duplicate_device_ids() {
        let root = temp_dir("receipt-replay-duplicate-device");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"receipt-replay-duplicate-device");
        pool.put(IoClass::Data, key, b"duplicate replay device authority")
            .unwrap();
        let mut receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");

        let duplicate_device_id = placement_target_device_id(&receipt.targets[0]);
        receipt.targets[1].device_guid[..8].copy_from_slice(&duplicate_device_id.to_le_bytes());
        assert_ne!(
            receipt.targets[0].device_guid,
            receipt.targets[1].device_guid
        );
        validate_strict_receipt_structure(&receipt).unwrap();
        replace_planner_replay_receipt(
            &mut receipt,
            vec![duplicate_device_id; 2],
            false,
            &[DeviceHealthCapacity::new(
                duplicate_device_id,
                1,
                1,
                1 << 20,
            )],
        );

        assert!(!planner_replay_receipt_matches_receipt(&receipt));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn planner_replay_receipt_refuses_claimed_separation_with_duplicate_domains() {
        let root = temp_dir("receipt-replay-duplicate-failure-domain");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"receipt-replay-duplicate-failure-domain");
        pool.put(IoClass::Data, key, b"false replay domain separation")
            .unwrap();
        let mut receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        receipt.failure_domain_level = FailureDomainLevel::Node;
        let device_targets: Vec<u64> = receipt
            .targets
            .iter()
            .map(placement_target_device_id)
            .collect();
        assert_ne!(device_targets[0], device_targets[1]);
        let devices = [
            DeviceHealthCapacity::new(device_targets[0], 7, 1, 1 << 20),
            DeviceHealthCapacity::new(device_targets[1], 7, 2, 1 << 20),
        ];
        replace_planner_replay_receipt(&mut receipt, device_targets, true, &devices);
        let replay = receipt.planner_replay_receipt.as_ref().unwrap();
        assert!(replay.failure_domain_separation);
        assert_eq!(
            replay
                .targets
                .iter()
                .map(|target| target.failure_domain_key)
                .collect::<BTreeSet<_>>()
                .len(),
            1
        );

        assert!(!planner_replay_receipt_matches_receipt(&receipt));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_replay_receipt_blocks_topology_fallback_read() {
        let root = temp_dir("receipt-replay-corrupt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"corrupt-replay-seal");
        let payload = b"payload remains on physical targets";
        pool.put(IoClass::Data, key, payload).unwrap();
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let receipt_key = placement_receipt_object_key(key);
        for idx in 0..pool.devices.len() {
            let Some(mut raw) = pool.devices[idx].get(receipt_key).unwrap() else {
                continue;
            };
            let last = raw.len() - 1;
            raw[last] ^= 0x5a;
            pool.devices[idx]
                .put_pool_internal(receipt_key, &raw)
                .expect("replace receipt with bad replay seal");
        }

        assert_invalid_options_reason_contains(
            pool.get(IoClass::Data, key),
            "placement receipt corrupt or unverifiable",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_authority_classifier_excludes_operational_pool_errors() {
        assert!(is_strict_read_authority_error(
            &StoreError::InvalidOptions {
                reason: "strict read refuses a receiptless raw payload",
            }
        ));
        assert!(is_strict_read_authority_error(
            &StoreError::InvalidOptions {
                reason: "conflicting placement receipts share epoch and generation",
            }
        ));
        assert!(!is_strict_read_authority_error(
            &StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O",
            }
        ));
        assert!(!is_strict_read_authority_error(
            &StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            }
        ));
    }

    #[test]
    fn strict_read_classifies_receipt_scan_io_as_object_authority_failure() {
        let root = temp_dir("strict-read-receipt-scan-io");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_mirror_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"strict-read-receipt-scan-io");
        pool.put(IoClass::Data, key, b"receipted payload").unwrap();

        pool.devices[0].set_fail_next_read(true);
        let error = pool
            .get_with_current_receipt(IoClass::Data, key)
            .expect_err("receipt-copy read I/O must invalidate this object's strict authority");
        assert!(is_strict_read_authority_error(&error));
        assert!(matches!(
            error,
            StoreError::InvalidOptions {
                reason: "strict read could not inspect every placement receipt copy"
            }
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_classifies_raw_visibility_io_as_object_authority_failure() {
        let root = temp_dir("strict-read-raw-visibility-io");
        let _ = std::fs::remove_dir_all(&root);
        let pool = Pool::create(
            single_mirror_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"strict-read-raw-visibility-io");
        let indices = pool.class_map.get(IoClass::Data).to_vec();

        pool.devices[0].set_fail_next_read(true);
        let error = map_strict_read_object_io(
            pool.logical_raw_payload_visible(&indices, key),
            "strict read could not establish receiptless raw payload absence",
        )
        .expect_err("raw visibility I/O must leave this object's strict authority unknown");
        assert!(is_strict_read_authority_error(&error));
        assert!(matches!(
            error,
            StoreError::InvalidOptions {
                reason: "strict read could not establish receiptless raw payload absence"
            }
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_refuses_receiptless_raw_payload() {
        let root = temp_dir("strict-read-receiptless-raw");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"strict-read-receiptless-raw");

        pool.devices[0]
            .put(key, b"raw payload without placement authority")
            .unwrap();

        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "receiptless raw payload",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ordinary_replacement_refuses_receiptless_payload_before_mutation() {
        let root = temp_dir("ordinary-replacement-receiptless");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"ordinary-replacement-receiptless");
        let original = b"committed payload";
        pool.put_with_receipt(IoClass::Data, key, original).unwrap();

        let receipt_key = placement_receipt_object_key(key);
        pool.devices[0].delete_pool_internal(receipt_key).unwrap();
        assert_invalid_options_reason_contains(
            pool.put_with_receipt(IoClass::Data, key, b"replacement must not publish"),
            "receiptless raw payload",
        );
        assert_eq!(
            pool.devices[0].get(key).unwrap(),
            Some(original.to_vec()),
            "replacement refusal must precede payload mutation"
        );
        assert!(pool.devices[0].get(receipt_key).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_refuses_receiptless_erasure_shards() {
        let root = temp_dir("strict-read-receiptless-erasure");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-receiptless-erasure");
        pool.put(
            IoClass::Data,
            key,
            b"erasure shards remain without placement authority",
        )
        .unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        for target in &receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            let shard_key = placement_shard_object_key(key, target.shard_index);
            assert!(pool.devices[idx].get(shard_key).unwrap().is_some());
        }

        let receipt_key = placement_receipt_object_key(key);
        for device in &mut pool.devices {
            device.delete_pool_internal(receipt_key).unwrap();
        }
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "receiptless raw payload",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_refuses_replayless_and_zero_version_receipts() {
        let root = temp_dir("strict-read-invalid-receipt-authority");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);

        let replayless_key = ObjectKey::from_name(b"strict-read-replayless");
        pool.put(IoClass::Data, replayless_key, b"replayless payload")
            .unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, replayless_key)
            .unwrap()
            .expect("placement receipt");
        let mut replayless = receipt.encode().unwrap();
        replayless[..PLACEMENT_RECEIPT_MAGIC_V2.len()].copy_from_slice(PLACEMENT_RECEIPT_MAGIC_V2);
        const V2_FIXED_WIRE_LEN: usize = 106;
        const RECEIPT_TARGET_WIRE_LEN: usize = 55;
        replayless.truncate(V2_FIXED_WIRE_LEN + receipt.targets.len() * RECEIPT_TARGET_WIRE_LEN);
        let receipt_key = placement_receipt_object_key(replayless_key);
        for device in &mut pool.devices {
            device.put_pool_internal(receipt_key, &replayless).unwrap();
        }
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, replayless_key),
            "planner replay authority",
        );

        let zero_version_key = ObjectKey::from_name(b"strict-read-zero-version");
        pool.put(IoClass::Data, zero_version_key, b"zero version payload")
            .unwrap();
        let mut zero_version = pool
            .placement_receipt_for_key(IoClass::Data, zero_version_key)
            .unwrap()
            .expect("placement receipt");
        zero_version.generation = 0;
        let encoded = zero_version.encode().unwrap();
        let receipt_key = placement_receipt_object_key(zero_version_key);
        for device in &mut pool.devices {
            device.put_pool_internal(receipt_key, &encoded).unwrap();
        }
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, zero_version_key),
            "nonzero placement receipt epoch and generation",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_refuses_malformed_replicated_receipt_fields() {
        let root = temp_dir("strict-read-malformed-replicated-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"strict-read-malformed-replicated-receipt");
        pool.put(IoClass::Data, key, b"receipt-bound payload")
            .unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        let receipt_key = placement_receipt_object_key(key);

        let mut malformed = receipt.clone();
        malformed.shard_len = 1;
        pool.devices[0]
            .put_pool_internal(receipt_key, &malformed.encode().unwrap())
            .unwrap();
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "malformed replicated placement receipt",
        );

        malformed = receipt.clone();
        malformed.policy = PoolRedundancyPolicy::replicated(2);
        malformed.targets.push(malformed.targets[0].clone());
        assert_invalid_options_reason_contains(
            validate_strict_receipt_structure(&malformed),
            "duplicate physical placement targets",
        );

        malformed = receipt;
        malformed.targets[0].stored_digest = digest32(b"different target bytes");
        pool.devices[0]
            .put_pool_internal(receipt_key, &malformed.encode().unwrap())
            .unwrap();
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "malformed replicated placement receipt",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_finds_same_version_conflict_beneath_newer_receipt() {
        let root = temp_dir("strict-read-hidden-receipt-conflict");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-hidden-receipt-conflict");

        pool.put(IoClass::Data, key, b"older payload").unwrap();
        let older = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("older receipt");
        pool.put(IoClass::Data, key, b"newer payload").unwrap();
        let newer = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("newer receipt");
        assert!((newer.epoch, newer.generation) > (older.epoch, older.generation));

        let mut conflicting_older = older.clone();
        let conflicting_digest = digest32(b"conflicting older authority");
        conflicting_older.payload_digest = conflicting_digest;
        for target in &mut conflicting_older.targets {
            target.stored_digest = conflicting_digest;
        }
        let receipt_key = placement_receipt_object_key(key);
        pool.devices[0]
            .put_pool_internal(receipt_key, &older.encode().unwrap())
            .unwrap();
        pool.devices[1]
            .put_pool_internal(receipt_key, &newer.encode().unwrap())
            .unwrap();
        pool.devices[2]
            .put_pool_internal(receipt_key, &conflicting_older.encode().unwrap())
            .unwrap();

        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "conflicting placement receipts share epoch and generation",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_refuses_heterogeneous_receipt_versions() {
        let root = temp_dir("strict-read-heterogeneous-receipt-versions");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-heterogeneous-receipt-versions");

        pool.put(IoClass::Data, key, b"older receipt payload")
            .unwrap();
        let older = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("older receipt");
        let newer_payload = b"newer receipt payload";
        pool.put(IoClass::Data, key, newer_payload).unwrap();
        let newer = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("newer receipt");
        assert!((newer.epoch, newer.generation) > (older.epoch, older.generation));
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((newer_payload.to_vec(), newer.clone()))
        );

        let current_target_indices: BTreeSet<_> = newer
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();
        let stale_receipt_idx = (0..pool.devices.len())
            .find(|idx| !current_target_indices.contains(idx))
            .expect("replicated(2) on three devices has one non-target receipt carrier");
        let receipt_key = placement_receipt_object_key(key);
        pool.devices[stale_receipt_idx]
            .put_pool_internal(receipt_key, &older.encode().unwrap())
            .unwrap();
        let payloads_before: Vec<_> = pool
            .devices
            .iter()
            .map(|device| device.get(key).unwrap())
            .collect();
        let receipts_before: Vec<_> = pool
            .devices
            .iter()
            .map(|device| device.get(receipt_key).unwrap())
            .collect();
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "heterogeneous placement receipt versions",
        );
        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(key, b"attempted overwrite"),
            "heterogeneous placement receipt versions",
        );
        assert_eq!(
            pool.devices
                .iter()
                .map(|device| device.get(key).unwrap())
                .collect::<Vec<_>>(),
            payloads_before,
            "ambiguous receipt state must not permit payload replacement"
        );
        assert_eq!(
            pool.devices
                .iter()
                .map(|device| device.get(receipt_key).unwrap())
                .collect::<Vec<_>>(),
            receipts_before,
            "ambiguous receipt state must not permit receipt replacement"
        );

        pool.devices[stale_receipt_idx]
            .delete_pool_internal(receipt_key)
            .unwrap();
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((newer_payload.to_vec(), newer))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_read_returns_exact_current_receipt_and_payload() {
        let root = temp_dir("strict-read-exact-current-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-exact-current-receipt");
        let payload = b"payload read only through exact receipt targets";

        pool.put(IoClass::Data, key, payload).unwrap();
        let expected_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");

        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), expected_receipt))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_replicated_read_requires_every_target_receipt_and_payload() {
        let root = temp_dir("strict-read-all-replicated-targets");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-all-replicated-targets");
        let payload = b"strict replicated reads require every recorded copy";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let target_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let receipt_key = placement_receipt_object_key(key);
        let encoded_receipt = receipt.encode().unwrap();

        assert!(pool.devices[target_idx]
            .delete_pool_internal(receipt_key)
            .unwrap());
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "missing target receipt copy",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "degraded Pool::get remains readable from another receipt carrier"
        );
        pool.devices[target_idx]
            .put_pool_internal(receipt_key, &encoded_receipt)
            .unwrap();

        let original = pool.devices[target_idx]
            .get(key)
            .unwrap()
            .expect("recorded replicated target");
        assert!(pool.devices[target_idx].delete(key).unwrap());
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "missing replicated placement target",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "degraded Pool::get remains readable from the surviving replica"
        );
        pool.devices[target_idx].put(key, &original).unwrap();

        let mut corrupt = original;
        corrupt[0] ^= 0x5a;
        pool.devices[target_idx].put(key, &corrupt).unwrap();
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "corrupt replicated placement target",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "degraded Pool::get skips the corrupt replica"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_target_resolution_requires_recorded_device_guid() {
        let root = temp_dir("receipt-guid-authority");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-guid-authority");
        let payload = b"payload remains at same device index";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        assert_eq!(receipt.targets.len(), 1);
        let target_index = receipt.targets[0].device_index as usize;
        assert_eq!(
            pool.devices[target_index].get(key).unwrap(),
            Some(payload.to_vec())
        );

        pool.device_guids[target_index] = deterministic_device_guid(99);

        assert!(
            pool.resolve_receipt_target(&receipt.targets[0]).is_none(),
            "receipt targets are addressed by persistent GUID, not current index"
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            None,
            "read must not fall back to the device currently occupying the old index"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn export_preserves_device_guids_used_by_existing_receipts() {
        let root = temp_dir("receipt-guid-export");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-guid-export");
        let payload = b"receipt survives export import by guid";
        pool.put(IoClass::Data, key, payload).unwrap();
        let before = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before export");
        let before_target_guids: BTreeSet<[u8; 16]> = before
            .targets
            .iter()
            .map(|target| target.device_guid)
            .collect();

        pool.export().unwrap();
        drop(pool);

        let reopened = Pool::open(config, properties, &test_options()).unwrap();
        let after = reopened
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt after import");
        let after_target_guids: BTreeSet<[u8; 16]> = after
            .targets
            .iter()
            .map(|target| target.device_guid)
            .collect();

        assert_eq!(after_target_guids, before_target_guids);
        for target in &after.targets {
            assert!(
                reopened.resolve_receipt_target(target).is_some(),
                "exported labels must preserve receipt target GUIDs"
            );
        }
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_reuses_active_labels_used_by_existing_receipts() {
        let root = temp_dir("receipt-guid-active-labels");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-guid-active-labels");
        let payload = b"receipt survives active create reopen by guid";
        pool.put(IoClass::Data, key, payload).unwrap();
        let pool_guid = pool.pool_guid;
        let before = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before active-label reopen");
        drop(pool);

        let reopened = Pool::create(config, properties, &test_options()).unwrap();
        assert_eq!(reopened.pool_guid, pool_guid);
        for target in &before.targets {
            assert!(
                reopened.resolve_receipt_target(target).is_some(),
                "active labels must preserve receipt target GUIDs"
            );
        }
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_prefers_newer_same_epoch_rewrite() {
        let root = temp_dir("receipt-generation-rewrite");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"same-key-rewrite");
        pool.put(IoClass::Data, key, b"old-payload").unwrap();
        let stale_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("old receipt");
        assert_eq!(stale_receipt.generation, 1);

        pool.put(IoClass::Data, key, b"new-payload").unwrap();
        let fresh_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("fresh receipt");
        assert_eq!(fresh_receipt.epoch, stale_receipt.epoch);
        assert!(fresh_receipt.generation > stale_receipt.generation);

        let stale_key = placement_receipt_object_key(key);
        let stale_encoded = stale_receipt.encode().unwrap();
        let last_idx = pool.devices.len() - 1;
        pool.devices[last_idx]
            .put_pool_internal(stale_key, &stale_encoded)
            .expect("inject stale receipt");

        let selected = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("selected receipt");
        assert_eq!(selected.generation, fresh_receipt.generation);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(b"new-payload".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_epoch_generation_inversion_refuses_selection() {
        let root = temp_dir("receipt-epoch-authority");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"epoch-authority-rewrite");
        pool.put(IoClass::Data, key, b"old-epoch-payload").unwrap();
        let mut stale_epoch_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("old epoch receipt");
        assert_eq!(stale_epoch_receipt.epoch, 1);

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

        pool.put(IoClass::Data, key, b"new-epoch-payload").unwrap();
        let fresh_epoch_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("new epoch receipt");
        assert_eq!(fresh_epoch_receipt.epoch, 2);

        stale_epoch_receipt.generation = fresh_epoch_receipt.generation + 100;
        assert_invalid_options_reason_contains(
            receipt_supersedes(&stale_epoch_receipt, &fresh_epoch_receipt),
            "epoch and generation order conflict",
        );
        assert_invalid_options_reason_contains(
            receipt_supersedes(&fresh_epoch_receipt, &stale_epoch_receipt),
            "epoch and generation order conflict",
        );
        let receipt_key = placement_receipt_object_key(key);
        let stale_encoded = stale_epoch_receipt.encode().unwrap();
        let last_idx = pool.devices.len() - 1;
        pool.devices[last_idx]
            .put_pool_internal(receipt_key, &stale_encoded)
            .expect("inject stale higher-generation receipt");

        assert_invalid_options_reason_contains(
            pool.placement_receipt_for_key(IoClass::Data, key),
            "epoch and generation order conflict",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_reuse_across_objects_refuses_inventory_and_reopen() {
        let root = temp_dir("receipt-generation-cross-object-reuse");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();

        let first_key = ObjectKey::from_name(b"generation-owner-first");
        let second_key = ObjectKey::from_name(b"generation-owner-second");
        pool.put(IoClass::Data, first_key, b"first authority")
            .unwrap();
        pool.put(IoClass::Data, second_key, b"second authority")
            .unwrap();
        let first_receipt = pool
            .placement_receipt_for_key(IoClass::Data, first_key)
            .unwrap()
            .expect("first receipt");
        let mut second_receipt = pool
            .placement_receipt_for_key(IoClass::Data, second_key)
            .unwrap()
            .expect("second receipt");
        assert_ne!(first_receipt.generation, second_receipt.generation);

        second_receipt.generation = first_receipt.generation;
        let second_receipt_key = placement_receipt_object_key(second_key);
        let encoded = second_receipt.encode().unwrap();
        for device in &mut pool.devices {
            device
                .put_pool_internal(second_receipt_key, &encoded)
                .unwrap();
        }

        assert_invalid_options_reason_contains(
            pool.placement_receipts(IoClass::Data),
            "physical placement receipts reuse one pool generation",
        );
        pool.sync_all().unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(config, properties, &test_options()),
            "physical placement receipts reuse one pool generation",
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_rewrite_publishes_receipt_bound_dead_objects() {
        let root = temp_dir("receipt-bound-rewrite-replicated");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-bound-rewrite-replicated");
        pool.put(IoClass::Data, key, b"old replicated payload")
            .unwrap();
        let old_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("old receipt");
        let old_target_indices: BTreeSet<usize> = old_receipt
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();

        pool.put(IoClass::Data, key, b"new replicated payload")
            .unwrap();
        let replacement = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("replacement receipt");
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::create(config, properties, &test_options()).unwrap();
        let held_depth: usize = old_target_indices
            .iter()
            .map(|idx| {
                let stats = reopened.devices[*idx]
                    .store_mut()
                    .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                        replacement.generation.saturating_add(1),
                        replacement.generation.saturating_sub(1),
                        16,
                    )
                    .expect("held drain");
                assert_eq!(stats.entries_processed, 0);
                stats.reclaim_queue_depth
            })
            .sum();
        assert_eq!(held_depth, old_target_indices.len());

        let processed: usize = old_target_indices
            .iter()
            .map(|idx| {
                reopened.devices[*idx]
                    .store_mut()
                    .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                        replacement.generation.saturating_add(1),
                        replacement.generation,
                        16,
                    )
                    .expect("stable drain")
                    .entries_processed
            })
            .sum();
        assert_eq!(processed, old_target_indices.len());
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(b"new replicated payload".to_vec()),
            "receipt-bound drain must not reclaim the replacement placement"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_rewrite_publishes_receipt_bound_dead_shards() {
        let root = temp_dir("receipt-bound-rewrite-erasure");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-bound-rewrite-erasure");
        pool.put(IoClass::Data, key, b"old erasure payload with enough bytes")
            .unwrap();
        let old_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("old erasure receipt");
        let old_physical_targets: BTreeSet<(usize, ObjectKey)> = old_receipt
            .targets
            .iter()
            .map(|target| {
                (
                    pool.resolve_receipt_target(target).unwrap(),
                    placement_shard_object_key(old_receipt.object_key, target.shard_index),
                )
            })
            .collect();
        let old_device_indices: BTreeSet<usize> =
            old_physical_targets.iter().map(|(idx, _)| *idx).collect();

        pool.put(IoClass::Data, key, b"new erasure payload with enough bytes")
            .unwrap();
        let replacement = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("replacement erasure receipt");
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::create(config, properties, &test_options()).unwrap();
        let held_depth: usize = old_device_indices
            .iter()
            .map(|idx| {
                let stats = reopened.devices[*idx]
                    .store_mut()
                    .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                        replacement.generation.saturating_add(1),
                        replacement.generation.saturating_sub(1),
                        16,
                    )
                    .expect("held erasure drain");
                assert_eq!(stats.entries_processed, 0);
                stats.reclaim_queue_depth
            })
            .sum();
        assert_eq!(held_depth, old_physical_targets.len());

        let processed: usize = old_device_indices
            .iter()
            .map(|idx| {
                reopened.devices[*idx]
                    .store_mut()
                    .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                        replacement.generation.saturating_add(1),
                        replacement.generation,
                        16,
                    )
                    .expect("stable erasure drain")
                    .entries_processed
            })
            .sum();
        assert_eq!(processed, old_physical_targets.len());
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(b"new erasure payload with enough bytes".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_enqueues_receipt_bound_dead_objects() {
        let root = temp_dir("receipt-bound-delete-no-synthetic");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"receipt-bound-delete-no-synthetic");
        pool.put(IoClass::Data, key, b"delete payload").unwrap();
        let old_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before delete");
        let old_target_indices: BTreeSet<usize> = old_receipt
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();

        assert!(pool.delete(IoClass::Data, key).unwrap());
        pool.sync_all().unwrap();

        for idx in old_target_indices {
            let stats = pool.devices[idx]
                .store_mut()
                .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                    u64::MAX,
                    u64::MAX,
                    16,
                )
                .expect("delete drain");
            assert_eq!(stats.entries_processed, 1);
            assert_eq!(stats.reclaim_queue_depth, 0);
        }
        for device in &pool.devices {
            assert_eq!(
                require_receipt_generation_high_water(device, pool.pool_guid)
                    .unwrap()
                    .reserved_through,
                pool.reserved_placement_receipt_generation_through
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_preflight_failure_preserves_prior_authority() {
        let root = temp_dir("delete-preflight-preserves-authority");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-preflight-preserves-authority");
        let payload = b"the prior generation remains authoritative";
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("publish prior authority");
        pool.sync_all().expect("sync prior authority");

        pool.fail_pending_deletion_preflight_once = true;
        assert_invalid_options_reason_contains(
            pool.delete(IoClass::Data, key),
            "pending deletion preflight failed",
        );
        assert!(pool.pending_deletions.is_empty());
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key)
                .expect("read prior authority after refused delete"),
            Some((payload.to_vec(), receipt.clone()))
        );
        drop(pool);

        let reopened = Pool::open(config, properties, &test_options()).expect("reopen pool");
        assert!(reopened.pending_deletions.is_empty());
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, key)
                .expect("read prior authority after reopen"),
            Some((payload.to_vec(), receipt))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_refuses_receiptless_raw_payload_before_mutation() {
        let root = temp_dir("delete-receiptless-raw-refusal");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let options = test_options();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        let key = ObjectKey::from_name(b"delete-receiptless-raw-refusal");
        let payload = b"receiptless bytes must remain available for diagnosis";

        for device in &mut pool.devices {
            device.put(key, payload).unwrap();
            device.sync_all().unwrap();
        }

        assert_invalid_options_reason_contains(
            pool.delete(IoClass::Data, key),
            "receiptless raw payload",
        );
        for device in &pool.devices {
            assert_eq!(device.get(key).unwrap(), Some(payload.to_vec()));
        }
        drop(pool);

        let reopened = Pool::open(config, properties, &options).unwrap();
        assert_invalid_options_reason_contains(
            reopened.get_with_current_receipt(IoClass::Data, key),
            "receiptless raw payload",
        );
        for device in &reopened.devices {
            assert_eq!(device.get(key).unwrap(), Some(payload.to_vec()));
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_reopen_rejects_unbound_handoff_authority() {
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };

        let future_root = temp_dir("delete-future-generation-handoff");
        let _ = std::fs::remove_dir_all(&future_root);
        let future_config = multi_data_device_config(&future_root, 2);
        let mut pool = Pool::create(future_config.clone(), properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let future_key = ObjectKey::from_name(b"delete-future-generation-handoff");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, future_key, b"current generation")
            .unwrap();
        let mut pending = pending_deletion_for_test(
            &pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );
        pending.receipt.generation = pool
            .reserved_placement_receipt_generation_through
            .checked_add(1)
            .unwrap();
        let handoff_key = pending.object_key();
        let encoded = pending.encode().unwrap();
        pool.devices[0]
            .put_pool_internal(handoff_key, &encoded)
            .unwrap();
        pool.devices[0].sync_strict_pool_authority().unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(future_config, properties.clone(), &options),
            "exceeds the durable high-water reservation",
        );
        let _ = std::fs::remove_dir_all(&future_root);

        let misplaced_root = temp_dir("delete-misplaced-handoff");
        let _ = std::fs::remove_dir_all(&misplaced_root);
        let misplaced_config = multi_data_device_config(&misplaced_root, 2);
        let mut pool =
            Pool::create(misplaced_config.clone(), properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let misplaced_key = ObjectKey::from_name(b"delete-misplaced-handoff");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, misplaced_key, b"current authority")
            .unwrap();
        let mut pending = pending_deletion_for_test(
            &pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );
        pending.receipt_carrier_guids = vec![pool.device_guids[1]];
        let encoded = pending.encode().unwrap();
        pool.devices[0]
            .put_pool_internal(pending.object_key(), &encoded)
            .unwrap();
        pool.devices[0].sync_strict_pool_authority().unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(misplaced_config, properties, &options),
            "outside its declared receipt carriers",
        );
        let _ = std::fs::remove_dir_all(&misplaced_root);
    }

    #[test]
    fn pool_delete_crash_reopen() {
        let options = test_options();

        // Crash after Prepared: old receipt and payload remain authoritative,
        // and writable reopen removes the non-authoritative handoff.
        let prepared_root = temp_dir("delete-crash-after-prepared");
        let _ = std::fs::remove_dir_all(&prepared_root);
        let prepared_config = single_device_config(&prepared_root);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(prepared_config.clone(), properties.clone(), &options).unwrap();
        let prepared_key = ObjectKey::from_name(b"delete-crash-after-prepared");
        let prepared_payload = b"prepared authority";
        let (_, prepared_receipt) = pool
            .put_with_receipt(IoClass::Data, prepared_key, prepared_payload)
            .unwrap();
        stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &prepared_receipt,
            PendingDeletionPhase::Prepared,
        );
        drop(pool);
        let reopened = Pool::open(prepared_config, properties.clone(), &options)
            .expect("reopen after Prepared");
        assert!(reopened.pending_deletions.is_empty());
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, prepared_key)
                .unwrap(),
            Some((prepared_payload.to_vec(), prepared_receipt))
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(&prepared_root);

        // Crash after Committed: raw payload and receipt may still exist, but
        // reopen must hide them first and reconcile them exactly once.
        let committed_root = temp_dir("delete-crash-after-committed");
        let _ = std::fs::remove_dir_all(&committed_root);
        let committed_config = multi_data_device_config(&committed_root, 2);
        let committed_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            committed_config.clone(),
            committed_properties.clone(),
            &options,
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let committed_key = ObjectKey::from_name(b"delete-crash-after-committed");
        let committed_payload = b"committed authority";
        let (_, committed_receipt) = pool
            .put_with_receipt(IoClass::Data, committed_key, committed_payload)
            .unwrap();
        pool.sync_all().unwrap();
        pool.fail_post_deletion_publication_cleanup_once = true;
        assert!(pool.delete(IoClass::Data, committed_key).unwrap());
        assert_eq!(pool.get(IoClass::Data, committed_key).unwrap(), None);
        assert_eq!(pool.pending_deletions.len(), 1);
        assert!(committed_receipt.targets.iter().all(|target| {
            let idx = pool.resolve_receipt_target(target).unwrap();
            pool.devices[idx].get(committed_key).unwrap().as_deref() == Some(committed_payload)
        }));
        drop(pool);
        let mut reopened = Pool::open(committed_config, committed_properties, &options)
            .expect("reopen after Committed");
        assert_eq!(reopened.get(IoClass::Data, committed_key).unwrap(), None);
        assert!(!reopened.delete(IoClass::Data, committed_key).unwrap());
        assert!(reopened.pending_deletions.is_empty());
        assert!(committed_receipt.targets.iter().all(|target| {
            let idx = reopened.resolve_receipt_target(target).unwrap();
            reopened.devices[idx].get(committed_key).unwrap().is_none()
        }));
        drop(reopened);
        let _ = std::fs::remove_dir_all(&committed_root);

        // Crash after payload removal but before receipt removal.
        let payload_root = temp_dir("delete-crash-after-payload");
        let _ = std::fs::remove_dir_all(&payload_root);
        let payload_config = multi_data_device_config(&payload_root, 2);
        let payload_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool =
            Pool::create(payload_config.clone(), payload_properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let payload_key = ObjectKey::from_name(b"delete-crash-after-payload");
        let (_, payload_receipt) = pool
            .put_with_receipt(IoClass::Data, payload_key, b"payload removal authority")
            .unwrap();
        stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &payload_receipt,
            PendingDeletionPhase::Committed,
        );
        for target in &payload_receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            pool.enqueue_replaced_physical_object(idx, payload_key, &payload_receipt)
                .unwrap();
            assert!(pool.devices[idx].delete(payload_key).unwrap());
            pool.devices[idx].sync_all().unwrap();
        }
        drop(pool);
        let reopened = Pool::open(payload_config, payload_properties, &options)
            .expect("reopen after payload removal");
        assert_eq!(reopened.get(IoClass::Data, payload_key).unwrap(), None);
        assert!(reopened.pending_deletions.is_empty());
        assert!(reopened
            .placement_receipt_for_key(IoClass::Data, payload_key)
            .unwrap()
            .is_none());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&payload_root);

        // Crash after payload and receipt removal but before clearing the
        // handoff. Reopen must finish the tombstone without resurrecting raw
        // fallback bytes or reporting a second successful delete.
        let receipt_root = temp_dir("delete-crash-after-receipt");
        let _ = std::fs::remove_dir_all(&receipt_root);
        let receipt_config = single_device_config(&receipt_root);
        let mut pool = Pool::create(receipt_config.clone(), properties.clone(), &options).unwrap();
        let receipt_key = ObjectKey::from_name(b"delete-crash-after-receipt");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, receipt_key, b"receipt removal authority")
            .unwrap();
        let pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );
        let target_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        pool.enqueue_replaced_physical_object(target_idx, receipt_key, &receipt)
            .unwrap();
        assert!(pool.devices[target_idx].delete(receipt_key).unwrap());
        let receipt_object_key = placement_receipt_object_key(receipt_key);
        for guid in &pending.receipt_carrier_guids {
            let idx = pool.device_index_for_guid(*guid).unwrap();
            assert!(pool.devices[idx]
                .delete_pool_internal(receipt_object_key)
                .unwrap());
            pool.devices[idx].sync_all().unwrap();
        }
        drop(pool);
        let mut reopened =
            Pool::open(receipt_config, properties, &options).expect("reopen after receipt removal");
        assert_eq!(reopened.get(IoClass::Data, receipt_key).unwrap(), None);
        assert!(!reopened.delete(IoClass::Data, receipt_key).unwrap());
        assert!(reopened.pending_deletions.is_empty());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&receipt_root);
    }

    #[test]
    fn pool_delete_reopen_discovers_composite_pending_markers() {
        let options = test_options();
        let properties = PoolProperties::default();

        let mirror_root = temp_dir("delete-reopen-secondary-mirror-marker");
        let _ = std::fs::remove_dir_all(&mirror_root);
        let mirror_config = two_leg_mirror_device_config(&mirror_root);
        let mut pool = Pool::create(mirror_config.clone(), properties.clone(), &options).unwrap();
        let mirror_key = ObjectKey::from_name(b"delete-reopen-secondary-mirror-marker");
        let (_, mirror_receipt) = pool
            .put_with_receipt(IoClass::Data, mirror_key, b"mirror authority")
            .unwrap();
        let mirror_pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &mirror_receipt,
            PendingDeletionPhase::Committed,
        );
        pool.sync_all().unwrap();
        drop(pool);

        let mut primary_leg = LocalObjectStore::open_with_options(
            mirror_root.join("mirror-0"),
            StoreOptions::default(),
        )
        .unwrap();
        assert!(primary_leg
            .delete_pool_internal(mirror_pending.object_key())
            .unwrap());
        primary_leg.sync_all().unwrap();
        drop(primary_leg);

        let mut reopened = Pool::open(mirror_config, properties.clone(), &options)
            .expect("discover committed marker retained only on the secondary mirror leg");
        assert_eq!(reopened.get(IoClass::Data, mirror_key).unwrap(), None);
        assert!(!reopened.delete(IoClass::Data, mirror_key).unwrap());
        assert!(reopened.pending_deletions.is_empty());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&mirror_root);

        let parity_root = temp_dir("delete-reopen-parity-marker");
        let _ = std::fs::remove_dir_all(&parity_root);
        let parity_config = parity_raid1_device_config(&parity_root, 2);
        let mut pool = Pool::create(parity_config.clone(), properties.clone(), &options).unwrap();
        let parity_key = ObjectKey::from_name(b"delete-reopen-parity-marker");
        let (_, parity_receipt) = pool
            .put_with_receipt(IoClass::Data, parity_key, b"parity authority")
            .unwrap();
        stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &parity_receipt,
            PendingDeletionPhase::Committed,
        );
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::open(parity_config, properties, &options)
            .expect("discover and reconstruct committed parity marker");
        assert_eq!(reopened.get(IoClass::Data, parity_key).unwrap(), None);
        assert!(!reopened.delete(IoClass::Data, parity_key).unwrap());
        assert!(reopened.pending_deletions.is_empty());

        let _ = std::fs::remove_dir_all(&parity_root);
    }

    #[test]
    fn pool_delete_refuses_degraded_composite_handoff_publication() {
        let root = temp_dir("delete-degraded-composite-publication");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(
            two_leg_mirror_device_config(&root),
            properties,
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"delete-degraded-composite-publication");
        let payload = b"current authority survives refused tombstone publication";
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("publish current authority");
        pool.sync_all().unwrap();

        let Device::Mirror(mirror) = &mut pool.devices[0] else {
            panic!("expected mirror device");
        };
        let mut failure = crate::FaultInjectionConfig::off();
        failure.write_failure_probability = 1.0;
        mirror
            .member_store_mut_for_test(1)
            .expect("secondary mirror leg")
            .enable_fault_injection(failure);

        assert!(pool.delete(IoClass::Data, key).is_err());
        assert!(pool.pending_deletions.is_empty());
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), receipt))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_partial_commit_publication_converges_forward() {
        let root = temp_dir("delete-partial-commit-publication");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let options = test_options();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-partial-commit-publication");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"phase convergence authority")
            .unwrap();
        let mut pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Prepared,
        );
        pending.phase = PendingDeletionPhase::Committed;
        let committed_copy = pending.encode().unwrap();
        let committed_idx = pool
            .device_index_for_guid(pending.receipt_carrier_guids[0])
            .unwrap();
        pool.devices[committed_idx]
            .put_pool_internal(pending.object_key(), &committed_copy)
            .unwrap();
        pool.devices[committed_idx].sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::open(config, properties, &options)
            .expect("the monotonic committed copy must win over prepared copies");
        assert_eq!(reopened.get(IoClass::Data, key).unwrap(), None);
        assert!(!reopened.delete(IoClass::Data, key).unwrap());
        assert!(reopened.pending_deletions.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn block_device_reopen_reconciles_pending_reclaim() {
        let root = temp_dir("block-device-pending-delete-reclaim");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_regular_file_pool_config(&root);
        let properties = PoolProperties::default();
        let options = test_options();
        let mut pool =
            Pool::create(config.clone(), properties.clone(), &options).expect("create pool");
        let key = ObjectKey::from_name(b"block-device-pending-delete-reclaim");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"durable block reclaim")
            .expect("publish block payload");
        pool.sync_all().expect("sync block payload");

        pool.fail_post_deletion_publication_cleanup_once = true;
        assert!(pool.delete(IoClass::Data, key).unwrap());
        drop(pool);

        let mut reopened = Pool::open(config.clone(), properties.clone(), &options)
            .expect("reconcile committed block deletion");
        assert_eq!(reopened.get(IoClass::Data, key).unwrap(), None);
        assert!(reopened.pending_deletions.is_empty());
        reopened.sync_all().expect("sync reconciled reclaim queue");
        drop(reopened);

        let mut reopened =
            Pool::open(config, properties, &options).expect("reload durable block reclaim queue");
        let target_indices: BTreeSet<_> = receipt
            .targets
            .iter()
            .map(|target| reopened.resolve_receipt_target(target).unwrap())
            .collect();
        let drained = target_indices
            .into_iter()
            .map(|idx| {
                reopened.devices[idx]
                    .store_mut()
                    .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                        u64::MAX,
                        u64::MAX,
                        16,
                    )
                    .expect("drain reloaded block reclaim")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            drained
                .iter()
                .map(|stats| stats.entries_processed)
                .sum::<usize>(),
            receipt.targets.len()
        );
        assert!(drained.iter().all(|stats| stats.reclaim_queue_depth == 0));
        assert!(drained.iter().all(|stats| stats.segments_reclaimed == 0));
        assert!(drained.iter().all(|stats| stats.blocks_freed == 0));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_recreated_key_advances_physical_reclaim_receipt() {
        let root = temp_dir("delete-recreated-key-reclaim-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let properties = PoolProperties::default();
        let options = test_options();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        let key = ObjectKey::from_name(b"delete-recreated-key-reclaim-receipt");

        let (_, first_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"first physical lifetime")
            .unwrap();
        assert!(pool.delete(IoClass::Data, key).unwrap());

        let second_payload = b"second physical lifetime";
        let (_, second_receipt) = pool
            .put_with_receipt(IoClass::Data, key, second_payload)
            .unwrap();
        assert!(second_receipt.generation > first_receipt.generation);
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::open(config.clone(), properties.clone(), &options).unwrap();
        let old_lifetime = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(
                IoClass::Data,
                u64::MAX,
                first_receipt.generation,
                16,
            )
            .expect("first lifetime must be reclaimable after key recreation");
        assert_eq!(old_lifetime.objects_examined, 1);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(second_payload.to_vec()),
            "old-lifetime reclaim must not select the recreated live location"
        );
        assert!(reopened.delete(IoClass::Data, key).unwrap());
        drop(reopened);

        let mut reopened = Pool::open(config, properties, &options).unwrap();
        let held = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(
                IoClass::Data,
                u64::MAX,
                first_receipt.generation,
                16,
            )
            .expect("stale generation must not authorize repeated-key reclaim");
        assert_eq!(held.objects_examined, 0);
        assert_eq!(
            held.reclaim_queue_depth, 1,
            "the latest physical lifetime must remain queued at the stale generation"
        );
        let eligible = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(
                IoClass::Data,
                u64::MAX,
                second_receipt.generation,
                16,
            )
            .expect("latest generation must authorize repeated-key reclaim");
        assert_eq!(eligible.objects_examined, 1);
        assert_eq!(
            eligible.reclaim_queue_depth, 1,
            "segment release may remain queued until every record is dead"
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_cleans_exact_replicated_and_erasure_targets() {
        let options = test_options();

        let replicated_root = temp_dir("delete-exact-replicated-targets");
        let _ = std::fs::remove_dir_all(&replicated_root);
        let replicated_config = multi_data_device_config(&replicated_root, 3);
        let replicated_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            replicated_config.clone(),
            replicated_properties.clone(),
            &options,
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-exact-replicated-targets");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"replicated authority")
            .unwrap();
        let target_indices: BTreeSet<_> = receipt
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();
        let stray_idx = (0..pool.devices.len())
            .find(|idx| !target_indices.contains(idx))
            .expect("non-target device");
        pool.devices[stray_idx]
            .put(key, b"unreceipted stray copy")
            .unwrap();

        assert!(pool.delete(IoClass::Data, key).unwrap());
        assert!(target_indices
            .iter()
            .all(|idx| pool.devices[*idx].get(key).unwrap().is_none()));
        assert_eq!(
            pool.devices[stray_idx].get(key).unwrap(),
            Some(b"unreceipted stray copy".to_vec()),
            "cleanup must not sweep a target absent from the selected receipt"
        );
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        assert_eq!(pool.pending_deletions.len(), 1);
        drop(pool);

        let mut reopened = Pool::open(replicated_config, replicated_properties, &options)
            .expect("reopen with replicated stray");
        assert_eq!(reopened.get(IoClass::Data, key).unwrap(), None);
        assert_eq!(reopened.pending_deletions.len(), 1);
        assert!(reopened.devices[stray_idx].delete(key).unwrap());
        let pending = reopened
            .pending_deletion_for_subject(IoClass::Data, key)
            .expect("retained replicated handoff");
        assert!(reopened.reconcile_one_pending_deletion(&pending).unwrap());
        assert!(reopened.pending_deletions.is_empty());
        assert!(!reopened.delete(IoClass::Data, key).unwrap());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&replicated_root);

        let erasure_root = temp_dir("delete-exact-erasure-targets");
        let _ = std::fs::remove_dir_all(&erasure_root);
        let erasure_config = multi_data_device_config(&erasure_root, 4);
        let erasure_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool =
            Pool::create(erasure_config.clone(), erasure_properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-exact-erasure-targets");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"erasure deletion authority")
            .unwrap();
        let target_indices: BTreeSet<_> = receipt
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();
        let stray_idx = (0..pool.devices.len())
            .find(|idx| !target_indices.contains(idx))
            .expect("non-target erasure device");
        let stray_shard = placement_shard_object_key(key, receipt.targets[0].shard_index);
        pool.devices[stray_idx]
            .put_pool_internal(stray_shard, b"unreceipted stray shard")
            .unwrap();

        assert!(pool.delete(IoClass::Data, key).unwrap());
        for target in &receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            let shard_key = placement_shard_object_key(key, target.shard_index);
            assert!(pool.devices[idx].get(shard_key).unwrap().is_none());
        }
        assert_eq!(
            pool.devices[stray_idx].get(stray_shard).unwrap(),
            Some(b"unreceipted stray shard".to_vec())
        );
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        assert_eq!(pool.pending_deletions.len(), 1);
        drop(pool);

        let mut reopened =
            Pool::open(erasure_config, erasure_properties, &options).expect("reopen erasure pool");
        assert_eq!(reopened.get(IoClass::Data, key).unwrap(), None);
        assert_eq!(reopened.pending_deletions.len(), 1);
        assert!(reopened.devices[stray_idx]
            .delete_pool_internal(stray_shard)
            .unwrap());
        let pending = reopened
            .pending_deletion_for_subject(IoClass::Data, key)
            .expect("retained erasure handoff");
        assert!(reopened.reconcile_one_pending_deletion(&pending).unwrap());
        assert!(reopened.pending_deletions.is_empty());

        let _ = std::fs::remove_dir_all(&erasure_root);
    }

    #[test]
    fn pool_delete_retains_handoff_until_mirror_cleanup_converges() {
        let root = temp_dir("delete-mirror-cleanup-convergence");
        let _ = std::fs::remove_dir_all(&root);
        let config = two_leg_mirror_device_config(&root);
        let properties = PoolProperties::default();
        let options = test_options();
        let mut pool = Pool::create(config, properties, &options).unwrap();
        let key = ObjectKey::from_name(b"delete-mirror-cleanup-convergence");
        let payload = b"committed deletion hides a retained mirror copy";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );

        let Device::Mirror(mirror) = &mut pool.devices[0] else {
            panic!("expected mirror device");
        };
        mirror
            .member_store_mut_for_test(1)
            .unwrap()
            .install_pool_raw_mutation_guard(Arc::new(AtomicBool::new(false)));

        assert!(pool.reconcile_one_pending_deletion(&pending).is_err());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        assert_eq!(pool.pending_deletions.len(), 1);
        let Device::Mirror(mirror) = &mut pool.devices[0] else {
            unreachable!();
        };
        assert_eq!(
            mirror
                .member_store_mut_for_test(0)
                .unwrap()
                .get(key)
                .unwrap(),
            None
        );
        assert_eq!(
            mirror
                .member_store_mut_for_test(1)
                .unwrap()
                .get(key)
                .unwrap(),
            Some(payload.to_vec())
        );
        mirror
            .member_store_mut_for_test(1)
            .unwrap()
            .install_pool_raw_mutation_guard(Arc::new(AtomicBool::new(true)));

        assert!(pool.reconcile_one_pending_deletion(&pending).unwrap());
        assert!(pool.pending_deletions.is_empty());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        let Device::Mirror(mirror) = &mut pool.devices[0] else {
            unreachable!();
        };
        for leg in 0..2 {
            assert_eq!(
                mirror
                    .member_store_mut_for_test(leg)
                    .unwrap()
                    .get(key)
                    .unwrap(),
                None
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_preserves_newer_receipt_hidden_in_store_replica() {
        let root = temp_dir("delete-hidden-newer-store-replica");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = single_device_config(&root);
        config.root_path = config.devices[0].path.clone();
        let properties = PoolProperties::default();
        let mut options = test_options();
        options.mirror_path = Some(root.join("store-replica"));
        let mut pool = Pool::create(config, properties, &options).unwrap();
        let key = ObjectKey::from_name(b"delete-hidden-newer-store-replica");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"old generation")
            .unwrap();
        let pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );

        let mut newer = receipt.clone();
        newer.generation = pool.allocate_placement_receipt_generation().unwrap();
        let receipt_key = placement_receipt_object_key(key);
        let replica = &mut pool.raw_primary_store_mut().replicas[0];
        replica
            .put_pool_internal(receipt_key, &newer.encode().unwrap())
            .unwrap();
        replica.sync_strict_pool_authority().unwrap();

        assert!(pool.reconcile_one_pending_deletion(&pending).is_err());
        assert_eq!(pool.pending_deletions.len(), 1);
        let replica = &pool.raw_primary_store_mut().replicas[0];
        assert_eq!(
            PlacementReceipt::decode(&replica.get(receipt_key).unwrap().unwrap())
                .unwrap()
                .generation,
            newer.generation
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_retains_mixed_pool_device_receipt_generations() {
        let root = temp_dir("delete-mixed-pool-device-receipts");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-mixed-pool-device-receipts");
        let payload = b"old authority remains until replacement publication converges";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );

        let mut newer = receipt.clone();
        newer.generation = pool.allocate_placement_receipt_generation().unwrap();
        let receipt_key = placement_receipt_object_key(key);
        pool.devices[1]
            .put_pool_internal(receipt_key, &newer.encode().unwrap())
            .unwrap();
        pool.devices[1].sync_strict_pool_authority().unwrap();

        assert_invalid_options_reason_contains(
            pool.reconcile_one_pending_deletion(&pending),
            "non-identical receipt copy",
        );
        assert!(!pool.delete(IoClass::Data, key).unwrap());
        assert_eq!(pool.pending_deletions.len(), 1);
        for (idx, expected) in [(0, &receipt), (1, &newer)] {
            let persisted =
                PlacementReceipt::decode(&pool.devices[idx].get(receipt_key).unwrap().unwrap())
                    .unwrap();
            assert_eq!(&persisted, expected);
            assert_eq!(
                pool.devices[idx].get(key).unwrap().as_deref(),
                Some(payload.as_slice())
            );
            assert!(pool.devices[idx]
                .pending_deletion_candidates()
                .unwrap()
                .iter()
                .any(|(candidate_key, _)| *candidate_key == pending.object_key()));
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_retains_missing_targets_and_exposes_newer_generation() {
        let options = test_options();
        let missing_root = temp_dir("delete-missing-target-retention");
        let _ = std::fs::remove_dir_all(&missing_root);
        let missing_config = multi_data_device_config(&missing_root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(missing_config, properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-missing-target-retention");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"missing target authority")
            .unwrap();
        pool.fail_post_deletion_publication_cleanup_once = true;
        assert!(pool.delete(IoClass::Data, key).unwrap());
        let pending = pool
            .pending_deletion_for_subject(IoClass::Data, key)
            .expect("committed handoff");
        let missing_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let original_guid = pool.device_guids[missing_idx];
        pool.device_guids[missing_idx] = [0xEE; 16];
        assert!(!pool.reconcile_one_pending_deletion(&pending).unwrap());
        assert_eq!(pool.pending_deletions.len(), 1);
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        pool.device_guids[missing_idx] = original_guid;
        assert!(pool.reconcile_one_pending_deletion(&pending).unwrap());
        assert!(pool.pending_deletions.is_empty());
        drop(pool);
        let _ = std::fs::remove_dir_all(&missing_root);

        let replacement_root = temp_dir("delete-newer-generation-visible");
        let _ = std::fs::remove_dir_all(&replacement_root);
        let replacement_config = multi_data_device_config(&replacement_root, 2);
        let mut pool = Pool::create(replacement_config, properties, &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-newer-generation-visible");
        let (_, deleted_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"deleted generation")
            .unwrap();
        pool.fail_post_deletion_publication_cleanup_once = true;
        assert!(pool.delete(IoClass::Data, key).unwrap());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);

        let replacement_payload = b"newer generation is current";
        let (_, replacement_receipt) = pool
            .put_with_receipt(IoClass::Data, key, replacement_payload)
            .expect("publish replacement after committed deletion");
        assert!(replacement_receipt.generation > deleted_receipt.generation);
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((replacement_payload.to_vec(), replacement_receipt))
        );
        assert!(pool.pending_deletions.is_empty());

        let _ = std::fs::remove_dir_all(&replacement_root);
    }

    #[test]
    fn pool_delete_retry_refuses_to_abandon_unreachable_prepared_carrier() {
        let root = temp_dir("delete-prepared-carrier-unreachable");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties::default();
        let mut pool =
            Pool::create(single_device_config(&root), properties, &test_options()).unwrap();
        let key = ObjectKey::from_name(b"delete-prepared-carrier-unreachable");
        let payload = b"prepared authority must remain recoverable";
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("publish current authority");
        let pending = stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Prepared,
        );
        pool.device_guids[0] = [0xA5; 16];

        assert_invalid_options_reason_contains(
            pool.delete(IoClass::Data, key),
            "cannot be cleared from every receipt carrier",
        );
        assert_eq!(
            pool.pending_deletion_for_subject(IoClass::Data, key),
            Some(pending)
        );
        assert_eq!(pool.devices[0].get(key).unwrap(), Some(payload.to_vec()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_delete_retry_deletes_newer_generation_after_old_cleanup() {
        let root = temp_dir("delete-retry-newer-generation");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"delete-retry-newer-generation");
        let (_, deleted_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"deleted generation")
            .unwrap();
        pool.fail_post_deletion_publication_cleanup_once = true;
        assert!(pool.delete(IoClass::Data, key).unwrap());

        let replacement_payload = b"replacement generation";
        pool.device_guids[0] = [0xA6; 16];
        let (_, replacement_receipt) = pool
            .put_with_receipt(IoClass::Data, key, replacement_payload)
            .expect("publish replacement while old target is unreachable");
        assert!(replacement_receipt.generation > deleted_receipt.generation);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(replacement_payload.to_vec())
        );
        assert_eq!(pool.pending_deletions.len(), 1);

        assert!(pool.delete(IoClass::Data, key).unwrap());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);
        assert!(!pool.delete(IoClass::Data, key).unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_public_mutation_rejects_pending_deletion_namespace() {
        let root = temp_dir("pending-deletion-namespace-reserved");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let user_key = ObjectKey::from_name(b"pending-deletion-namespace-reserved");
        let reserved_key = pool_pending_deletion_object_key(IoClass::Data, user_key, 1);

        assert_invalid_options_reason_contains(
            pool.put(IoClass::Data, reserved_key, b"raw public payload"),
            "deletion namespaces are reserved",
        );
        assert_invalid_options_reason_contains(
            pool.put_with_receipt(IoClass::Data, reserved_key, b"receipted public payload"),
            "deletion namespaces are reserved",
        );
        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(
                reserved_key,
                b"prepublication public payload",
            ),
            "deletion namespaces are reserved",
        );
        assert_invalid_options_reason_contains(
            pool.delete(IoClass::Data, reserved_key),
            "cannot be deleted directly",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placement_receipts_scan_returns_latest_logical_receipts() {
        let root = temp_dir("receipt-snapshot-latest");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let first_key = ObjectKey::from_name(b"snapshot-first");
        let second_key = ObjectKey::from_name(b"snapshot-second");
        pool.put(IoClass::Data, first_key, b"old-first").unwrap();
        let stale_first = pool
            .placement_receipt_for_key(IoClass::Data, first_key)
            .unwrap()
            .expect("stale first receipt");
        pool.put(IoClass::Data, first_key, b"fresh-first").unwrap();
        pool.put(IoClass::Data, second_key, b"second").unwrap();

        let stale_receipt_key = placement_receipt_object_key(first_key);
        let stale_encoded = stale_first.encode().unwrap();
        let last_idx = pool.devices.len() - 1;
        pool.devices[last_idx]
            .put_pool_internal(stale_receipt_key, &stale_encoded)
            .expect("inject stale receipt");

        let receipts = pool.placement_receipts(IoClass::Data).unwrap();
        assert_eq!(receipts.len(), 2);
        let first = receipts
            .iter()
            .find(|receipt| receipt.object_key == first_key)
            .expect("first receipt");
        assert!(first.generation > stale_first.generation);
        assert_eq!(
            pool.get(IoClass::Data, first_key).unwrap(),
            Some(b"fresh-first".to_vec())
        );
        assert!(receipts
            .iter()
            .any(|receipt| receipt.object_key == second_key));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placement_receipt_projects_replicated_shared_ref() {
        let root = temp_dir("receipt-ref-replicated");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"shared-ref-replicated");
        let payload = b"replicated receipt ref payload";
        pool.put(IoClass::Data, key, payload).unwrap();

        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        let receipt_ref = receipt.shared_receipt_ref().unwrap();

        assert_eq!(receipt_ref.object_id, receipt.object_store_subject_id());
        assert_eq!(receipt_ref.object_key, key.as_bytes32());
        assert_eq!(receipt_ref.receipt_epoch, EpochId::new(receipt.epoch));
        assert_eq!(receipt_ref.receipt_generation, receipt.generation);
        assert_eq!(
            receipt_ref.redundancy_policy,
            ReceiptRedundancyPolicy::Replicated { copies: 2 }
        );
        assert_eq!(receipt_ref.payload_len, payload.len() as u64);
        assert_eq!(receipt_ref.payload_digest, receipt.payload_digest);
        assert_eq!(receipt_ref.target_count, 2);
        assert!(!receipt_ref.is_synthetic());

        let explicit_ref = receipt.shared_receipt_ref_for_subject(0xfeed_f00d).unwrap();
        assert_eq!(explicit_ref.object_id, 0xfeed_f00d);
        assert_eq!(explicit_ref.object_key, receipt_ref.object_key);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_survives_complete_receipt_reclaim() {
        let root = temp_dir("receipt-generation-complete-reclaim");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let properties = PoolProperties::default();
        let key = ObjectKey::from_name(b"receipt-generation-complete-reclaim");

        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        let (_, first_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"first lifetime")
            .unwrap();
        assert_eq!(first_receipt.generation, 1);
        let receipt_key = placement_receipt_object_key(key);
        let marker_key = receipt_generation_high_water_key();
        let shard_key = placement_shard_object_key(key, 0);
        let reserved_keys = [marker_key, receipt_key, shard_key];
        let reserved_before: Vec<_> = reserved_keys
            .iter()
            .map(|reserved_key| pool.devices[0].get(*reserved_key).unwrap())
            .collect();
        assert_invalid_options_reason_contains(
            pool.devices[0].put(marker_key, b"forged pool metadata"),
            "require pool authority",
        );
        for reserved_key in [receipt_key, shard_key] {
            assert!(matches!(
                pool.devices[0].put(reserved_key, b"forged pool metadata"),
                Err(StoreError::InvalidOptions { .. })
            ));
        }
        assert!(matches!(
            pool.devices[0].delete(marker_key),
            Err(StoreError::InvalidOptions { .. })
        ));
        let reserved_after: Vec<_> = reserved_keys
            .iter()
            .map(|reserved_key| pool.devices[0].get(*reserved_key).unwrap())
            .collect();
        assert_eq!(
            reserved_after, reserved_before,
            "public device mutation must leave every reserved namespace unchanged"
        );
        assert_invalid_options_reason_contains(
            pool.delete(IoClass::Data, receipt_generation_high_water_key()),
            "cannot be deleted",
        );
        assert!(pool.delete(IoClass::Data, key).unwrap());

        pool.compact_retaining(&[], &[]).unwrap();
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::create(config, properties, &test_options()).unwrap();
        let (_, recreated_receipt) = reopened
            .put_with_receipt(IoClass::Data, key, b"second lifetime")
            .unwrap();
        assert!(recreated_receipt.generation > first_receipt.generation);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_high_water_survives_composite_compaction_and_burns_unused_range() {
        for (label, mirror) in [("mirror", true), ("parity", false)] {
            let root = temp_dir(&format!("receipt-generation-{label}-compaction"));
            let _ = std::fs::remove_dir_all(&root);
            let config = if mirror {
                two_leg_mirror_device_config(&root)
            } else {
                parity_raid1_device_config(&root, 2)
            };
            let properties = PoolProperties::default();

            let mut pool =
                Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
            assert_eq!(pool.allocate_placement_receipt_generation().unwrap(), 1);
            let burned_through = pool.reserved_placement_receipt_generation_through;
            assert_eq!(burned_through, RECEIPT_GENERATION_RESERVATION_SIZE);
            pool.compact_retaining(&[], &[]).unwrap();
            pool.sync_all().unwrap();
            drop(pool);

            let mut reopened =
                Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
            let key = ObjectKey::from_name(b"receipt-after-composite-compaction");
            let payload = b"first published payload";
            let (_, receipt) = reopened
                .put_with_receipt(IoClass::Data, key, payload)
                .unwrap();
            assert_eq!(receipt.generation, burned_through + 1);
            assert_eq!(
                reopened.get(IoClass::Data, key).unwrap(),
                Some(payload.to_vec())
            );

            let pool_guid = reopened.pool_guid;
            let reserved_through = reopened.reserved_placement_receipt_generation_through;
            if mirror {
                reopened.sync_all().unwrap();
                drop(reopened);

                let mut stale_leg = LocalObjectStore::open_with_options(
                    root.join("mirror-1"),
                    StoreOptions::default(),
                )
                .unwrap();
                stale_leg
                    .put_pool_internal(
                        receipt_generation_high_water_key(),
                        &encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                            pool_guid,
                            reserved_through: 0,
                        }),
                    )
                    .unwrap();
                stale_leg.sync_all().unwrap();
                drop(stale_leg);
            } else {
                let mut failure = crate::FaultInjectionConfig::off();
                failure.write_failure_probability = 1.0;
                let Device::ParityRaid1(parity) = &mut reopened.devices[0] else {
                    panic!("expected PARITY_RAID1 device");
                };
                parity
                    .children
                    .last_mut()
                    .unwrap()
                    .store_mut()
                    .enable_fault_injection(failure);
                assert!(publish_receipt_generation_high_water(
                    &mut reopened.devices,
                    pool_guid,
                    reserved_through,
                    reserved_through + RECEIPT_GENERATION_RESERVATION_SIZE,
                )
                .is_err());
                let Device::ParityRaid1(parity) = &mut reopened.devices[0] else {
                    unreachable!();
                };
                parity
                    .children
                    .last_mut()
                    .unwrap()
                    .store_mut()
                    .disable_fault_injection();
                sync_receipt_generation_high_water_devices(&mut reopened.devices).unwrap();
                drop(reopened);
            }
            assert!(matches!(
                Pool::create(config, properties, &test_options()),
                Err(StoreError::InvalidOptions { .. })
            ));

            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn receipt_generation_high_water_refuses_invalid_topology_authority() {
        assert_generation_high_water_open_refused("receipt-generation-marker-missing", |pool| {
            pool.devices[1]
                .delete_pool_internal(receipt_generation_high_water_key())
                .unwrap();
        });
        assert_generation_high_water_open_refused("receipt-generation-marker-conflict", |pool| {
            let marker = ReceiptGenerationHighWater {
                pool_guid: pool.pool_guid,
                reserved_through: 1,
            };
            pool.devices[1]
                .put_pool_internal(
                    receipt_generation_high_water_key(),
                    &encode_receipt_generation_high_water(marker),
                )
                .unwrap();
        });
        assert_generation_high_water_open_refused("receipt-generation-marker-wrong-pool", |pool| {
            let marker = ReceiptGenerationHighWater {
                pool_guid: [0x5a; 16],
                reserved_through: 0,
            };
            pool.devices[0]
                .put_pool_internal(
                    receipt_generation_high_water_key(),
                    &encode_receipt_generation_high_water(marker),
                )
                .unwrap();
        });
        assert_generation_high_water_open_refused("receipt-generation-marker-malformed", |pool| {
            let marker = ReceiptGenerationHighWater {
                pool_guid: pool.pool_guid,
                reserved_through: 0,
            };
            let mut encoded = encode_receipt_generation_high_water(marker);
            encoded[RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN - 1] ^= 0x5a;
            pool.devices[0]
                .put_pool_internal(receipt_generation_high_water_key(), &encoded)
                .unwrap();
        });
        assert_generation_high_water_open_refused(
            "receipt-generation-marker-below-valid-receipt",
            |pool| {
                for device in &mut pool.devices {
                    device
                        .store_mut()
                        .set_compression(crate::compress::CompressionConfig {
                            algorithm: crate::compress::CompressionAlgorithm::Zstd,
                            level: 3,
                            min_compress_bytes: 0,
                        });
                }
                pool.put_with_receipt(
                    IoClass::Data,
                    ObjectKey::from_name(b"receipt-above-rolled-back-marker"),
                    b"valid payload",
                )
                .unwrap();
                let marker = ReceiptGenerationHighWater {
                    pool_guid: pool.pool_guid,
                    reserved_through: 0,
                };
                let encoded = encode_receipt_generation_high_water(marker);
                for device in &mut pool.devices {
                    device
                        .put_pool_internal(receipt_generation_high_water_key(), &encoded)
                        .unwrap();
                }
            },
        );

        let root = temp_dir("receipt-generation-store-replica-rollback");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = single_device_config(&root);
        config.root_path = config.devices[0].path.clone();
        let properties = PoolProperties::default();
        let replica_path = root.join("store-replica");
        let mut options = test_options();
        options.mirror_path = Some(replica_path.clone());
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        pool.raw_primary_store_mut()
            .set_compression(crate::compress::CompressionConfig {
                algorithm: crate::compress::CompressionAlgorithm::Zstd,
                level: 3,
                min_compress_bytes: 0,
            });
        let key = ObjectKey::from_name(b"store-replica-hidden-newer-receipt");
        let (_, first_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"first payload")
            .unwrap();
        let (_, second_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"second payload")
            .unwrap();
        assert_eq!(first_receipt.generation, 1);
        assert_eq!(second_receipt.generation, 2);
        let receipt_key = placement_receipt_object_key(key);
        let pool_guid = pool.pool_guid;
        pool.sync_all().unwrap();
        drop(pool);

        let rolled_back_marker = encode_receipt_generation_high_water(ReceiptGenerationHighWater {
            pool_guid,
            reserved_through: first_receipt.generation,
        });
        let mut stale_primary = LocalObjectStore::open_with_options(
            config.devices[0].path.clone(),
            StoreOptions::default(),
        )
        .unwrap();
        stale_primary
            .put_pool_internal(receipt_key, &first_receipt.encode().unwrap())
            .unwrap();
        stale_primary
            .put_pool_internal(receipt_generation_high_water_key(), &rolled_back_marker)
            .unwrap();
        stale_primary.sync_all().unwrap();
        drop(stale_primary);

        let mut newer_replica =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::default()).unwrap();
        assert_eq!(
            PlacementReceipt::decode(&newer_replica.get(receipt_key).unwrap().unwrap())
                .unwrap()
                .generation,
            second_receipt.generation
        );
        newer_replica
            .put_pool_internal(receipt_generation_high_water_key(), &rolled_back_marker)
            .unwrap();
        newer_replica.sync_all().unwrap();
        drop(newer_replica);

        assert!(matches!(
            Pool::create(config, properties, &options),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);

        let root = temp_dir("receipt-generation-parity-hidden-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = parity_raid1_device_config(&root, 2);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"parity-hidden-newer-receipt");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"parity payload")
            .unwrap();
        assert_eq!(receipt.generation, 1);
        pool.sync_all().unwrap();
        let rolled_back_marker = encode_receipt_generation_high_water(ReceiptGenerationHighWater {
            pool_guid: pool.pool_guid,
            reserved_through: 0,
        });
        pool.devices[0]
            .put_pool_internal(receipt_generation_high_water_key(), &rolled_back_marker)
            .unwrap();
        let Device::ParityRaid1(parity) = &mut pool.devices[0] else {
            panic!("expected parity device");
        };
        parity.children[0]
            .store_mut()
            .delete_pool_internal(placement_receipt_object_key(key))
            .unwrap();
        pool.devices[0].sync_strict_pool_authority().unwrap();
        drop(pool);

        assert!(matches!(
            Pool::create(config, properties, &test_options()),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);

        let root = temp_dir("receipt-generation-hidden-residual-device");
        let _ = std::fs::remove_dir_all(&root);
        let config = two_leg_mirror_device_config(&root);
        let mut residual =
            LocalObjectStore::open_with_options(root.join("mirror-1"), test_options()).unwrap();
        residual
            .put(
                ObjectKey::from_name(b"hidden-residual"),
                b"must not be relabeled",
            )
            .unwrap();
        residual.sync_all().unwrap();
        drop(residual);
        assert!(matches!(
            Pool::create(config, PoolProperties::default(), &test_options()),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);

        let root = temp_dir("receipt-generation-intent-log-rollback");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        assert_eq!(pool.allocate_placement_receipt_generation().unwrap(), 1);
        let pool_guid = pool.pool_guid;
        let store = pool.raw_primary_store_mut();
        store
            .put(
                ObjectKey::from_name(b"open-receipt-generation-rollback-transaction"),
                b"ordinary payload",
            )
            .unwrap();
        store
            .intent_log
            .append(crate::intent_log::record::IntentLogRecord::WritePayload {
                object_id: receipt_generation_high_water_key(),
                offset: 0,
                data: Vec::new(),
            })
            .unwrap();
        store
            .intent_log
            .append(crate::intent_log::record::IntentLogRecord::WritePayload {
                object_id: receipt_generation_high_water_key(),
                offset: 0,
                data: encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                    pool_guid,
                    reserved_through: 0,
                })
                .to_vec(),
            })
            .unwrap();
        pool.sync_all().unwrap();
        drop(pool);

        assert!(matches!(
            Pool::create(config, properties, &test_options()),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_marker_conflict_refuses_before_committed_wal_replay() {
        let root = temp_dir("receipt-generation-preflight-before-wal");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = single_device_config(&root);
        config.root_path = config.devices[0].path.clone();
        let properties = PoolProperties::default();
        let replica_path = root.join("store-replica");
        let mut options = test_options();
        options.mirror_path = Some(replica_path);

        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        let payload_key = ObjectKey::from_name(b"committed-wal-must-not-replay");
        let payload = b"payload hidden behind invalid marker".to_vec();
        let generation = pool.allocate_placement_receipt_generation().unwrap();
        let mut receipt = pool
            .plan_pool_wide_placement(IoClass::Data, payload_key, payload.len(), &[0])
            .unwrap();
        receipt.generation = generation;
        receipt.payload_digest = digest32(&payload);
        for target in &mut receipt.targets {
            target.stored_digest = receipt.payload_digest;
        }
        let receipt_key = placement_receipt_object_key(payload_key);
        let receipt_payload = receipt.encode().unwrap();
        let pool_guid = pool.pool_guid;

        let replica = &mut pool.raw_primary_store_mut().replicas[0];
        stage_committed_wal_only(
            replica,
            &[(payload_key, payload), (receipt_key, receipt_payload)],
        );
        assert!(replica.get(payload_key).unwrap().is_none());
        assert!(replica.get(receipt_key).unwrap().is_none());
        replica
            .put_pool_internal(
                receipt_generation_high_water_key(),
                &encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                    pool_guid,
                    reserved_through: 0,
                }),
            )
            .unwrap();
        replica.sync_strict_pool_authority().unwrap();
        drop(pool);

        let before = snapshot_tree_bytes(&root);
        assert!(
            before
                .keys()
                .any(|path| path.to_string_lossy().ends_with(".vlos")),
            "fixture must retain a committed WAL segment"
        );
        assert!(
            before
                .keys()
                .all(|path| !path.to_string_lossy().ends_with(".vlos.replayed")),
            "fixture must start with an unapplied WAL segment"
        );

        assert_invalid_options_reason_contains(
            Pool::open(config, properties, &options),
            "conflicts across store replicas",
        );
        assert_eq!(
            snapshot_tree_bytes(&root),
            before,
            "refused import must not apply or mark the committed WAL"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_high_water_partial_reservation_refuses_reopen_before_payload() {
        let root = temp_dir("receipt-generation-partial-reservation");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let key = ObjectKey::from_name(b"must-remain-unwritten");
        let receipt_key = placement_receipt_object_key(key);
        let raw_existing_key = ObjectKey::from_name(b"raw-metadata-before-reservation-poison");

        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        pool.raw_primary_store_mut()
            .put(raw_existing_key, b"stable raw metadata")
            .unwrap();
        assert!(
            pool.raw_primary_store().intent_log_tx_open,
            "ordinary payload transaction should remain pending before reservation"
        );
        let mut failure = crate::FaultInjectionConfig::off();
        failure.write_failure_probability = 1.0;
        pool.devices[1].store_mut().enable_fault_injection(failure);
        assert!(pool
            .put_with_receipt(IoClass::Data, key, b"must not reach payload storage")
            .is_err());
        assert!(
            pool.raw_primary_store().intent_log_tx_open,
            "marker-only durability must not commit an unrelated payload transaction"
        );
        for device in &pool.devices {
            assert!(device.get(key).unwrap().is_none());
            assert!(device.get(receipt_key).unwrap().is_none());
        }
        assert_eq!(
            require_receipt_generation_high_water(&pool.devices[0], pool.pool_guid)
                .unwrap()
                .reserved_through,
            RECEIPT_GENERATION_RESERVATION_SIZE
        );
        assert_eq!(
            require_receipt_generation_high_water(&pool.devices[1], pool.pool_guid)
                .unwrap()
                .reserved_through,
            0
        );
        assert_invalid_options_reason_contains(
            pool.raw_primary_store_mut().delete(raw_existing_key),
            "receipt-generation authority is unavailable",
        );
        assert_eq!(
            pool.raw_primary_store().get(raw_existing_key).unwrap(),
            Some(b"stable raw metadata".to_vec())
        );
        pool.devices[1].store_mut().disable_fault_injection();
        sync_receipt_generation_high_water_devices(&mut pool.devices).unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::create(config, properties, &test_options()),
            "markers conflict",
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_recovery_refuses_receipt_above_ceiling() {
        let root = temp_dir("receipt-generation-recovery-above-ceiling");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"receipt-above-recovery-ceiling");
        pool.put(IoClass::Data, key, b"committed payload").unwrap();
        let mut receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        receipt.generation = pool
            .reserved_placement_receipt_generation_through
            .checked_add(1)
            .unwrap();
        let receipt_key = placement_receipt_object_key(key);
        let encoded = receipt.encode().unwrap();
        for device in &mut pool.devices {
            device.put_pool_internal(receipt_key, &encoded).unwrap();
        }

        pool.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RecoveryRequired,
        );
        assert_invalid_options_reason_contains(
            pool.converge_receipt_generation_authority(),
            "receipt generation exceeds durable high-water authority",
        );
        assert_invalid_options_reason_contains(
            pool.raw_primary_store_mut().put(
                ObjectKey::from_name(b"must-remain-fenced-after-recovery-refusal"),
                b"must not be written",
            ),
            "receipt-generation authority is unavailable",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_exhaustion_refuses_before_payload_mutation() {
        let root = temp_dir("receipt-generation-exhaustion");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = multi_data_device_config(&root, 2);
        let log_dir = root.join("intent-log-device");
        config.devices.push(DeviceConfig {
            media_class: DeviceMediaClass::Ssd,
            path: log_dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::IntentLog,
            kind: DeviceKind::Single {
                path: log_dir.clone(),
            },
            encryption: None,
            compression: None,
        });
        let properties = PoolProperties::default();
        let key = ObjectKey::from_name(b"generation-exhaustion-subject");

        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"committed payload")
            .unwrap();
        publish_receipt_generation_high_water(
            &mut pool.devices,
            pool.pool_guid,
            pool.reserved_placement_receipt_generation_through,
            u64::MAX,
        )
        .unwrap();
        pool.reserved_placement_receipt_generation_through = u64::MAX;
        drop(pool);

        let mut reopened = Pool::create(config, properties, &test_options()).unwrap();
        assert_eq!(reopened.next_placement_receipt_generation, 0);
        assert!(reopened.has_log_device());
        let log_path = log_dir.join(LOG_DEVICE_FILENAME);
        let log_len_before = std::fs::metadata(&log_path).unwrap().len();
        let before: Vec<Option<Vec<u8>>> = reopened
            .devices
            .iter()
            .map(|device| device.get(key).unwrap())
            .collect();
        assert_invalid_options_reason_contains(
            reopened.put_with_receipt(IoClass::Data, key, b"must not be written"),
            "generation exhausted",
        );
        assert_invalid_options_reason_contains(
            reopened.log_device_append(b"must not reach the separate log device"),
            "generation exhausted",
        );
        let after: Vec<Option<Vec<u8>>> = reopened
            .devices
            .iter()
            .map(|device| device.get(key).unwrap())
            .collect();
        assert_eq!(
            after, before,
            "counter exhaustion must precede payload writes"
        );
        assert_eq!(
            reopened
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap(),
            Some(receipt),
            "exhaustion must not mutate current receipt authority"
        );
        assert_eq!(
            std::fs::metadata(&log_path).unwrap().len(),
            log_len_before,
            "exhaustion must precede separate log-device append"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_receipt_refuses_recovered_generation() {
        let root = temp_dir("receipt-generation-wrong-key");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let source_key = ObjectKey::from_name(b"generation-source");
        let wrong_key = ObjectKey::from_name(b"generation-wrong-key");

        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        let (_, mut receipt) = pool
            .put_with_receipt(IoClass::Data, source_key, b"source payload")
            .unwrap();
        receipt.generation = u64::MAX;
        let wrong_receipt_key = placement_receipt_object_key(wrong_key);
        let encoded = receipt.encode().unwrap();
        for device in &mut pool.devices {
            device
                .put_pool_internal(wrong_receipt_key, &encoded)
                .unwrap();
        }
        pool.sync_all().unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::create(config, properties, &test_options()),
            "physical placement receipt is stored under the wrong key",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_publication_ceiling_and_partial_rollback_preserve_prior_authority() {
        let root = temp_dir("partial-receipt-publication");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let options = test_options();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        let key = ObjectKey::from_name(b"partial-receipt-publication");
        let payload = b"stable payload";
        let (_, prior) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let indices = pool.class_map.get(IoClass::Data).to_vec();
        let mut above_reservation = prior.clone();
        above_reservation.generation = pool.reserved_placement_receipt_generation_through + 1;
        assert_invalid_options_reason_contains(
            pool.write_placement_receipt(&indices, &above_reservation),
            "exceeds the durable high-water reservation",
        );
        assert_eq!(
            pool.load_current_placement_receipt_strict(&indices, key)
                .unwrap(),
            Some(prior.clone())
        );

        let mut replacement = prior.clone();
        replacement.generation = pool
            .allocate_placement_receipt_generation()
            .expect("allocate replacement generation");
        let mut failure = crate::FaultInjectionConfig::off();
        failure.write_failure_probability = 1.0;
        pool.devices[indices[1]]
            .store_mut()
            .enable_fault_injection(failure);

        assert!(pool
            .write_placement_receipt(&indices, &replacement)
            .is_err());
        pool.devices[indices[1]]
            .store_mut()
            .disable_fault_injection();
        assert_eq!(
            pool.load_current_placement_receipt_strict(&indices, key)
                .unwrap(),
            Some(prior.clone())
        );
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), prior.clone()))
        );

        pool.fail_placement_receipt_verification_once = true;
        assert_invalid_options_reason_contains(
            pool.put_with_receipt(
                IoClass::Data,
                key,
                b"replacement payload rejected after receipt sync",
            ),
            "test fault: placement receipt verification failed",
        );
        drop(pool);

        let reopened = Pool::open(config, properties, &options).unwrap();
        assert_eq!(
            reopened
                .load_current_placement_receipt_strict(&indices, key)
                .unwrap(),
            Some(prior.clone())
        );
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, key)
                .unwrap(),
            Some((payload.to_vec(), prior))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_publication_verifier_requires_every_write_time_copy() {
        let root = temp_dir("receipt-publication-all-copies");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"receipt-publication-all-copies");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"published payload")
            .unwrap();
        let indices = pool.class_map.get(IoClass::Data).to_vec();
        let target_indices: BTreeSet<_> = receipt
            .targets
            .iter()
            .map(|target| pool.resolve_receipt_target(target).unwrap())
            .collect();
        let non_target_idx = indices
            .iter()
            .copied()
            .find(|idx| !target_indices.contains(idx))
            .expect("replicated(2) on three devices has one non-target receipt carrier");
        let receipt_key = placement_receipt_object_key(key);
        let encoded_receipt = receipt.encode().unwrap();

        assert!(pool.devices[non_target_idx]
            .delete_pool_internal(receipt_key)
            .unwrap());
        assert_invalid_options_reason_contains(
            pool.verify_placement_receipt_publication(&indices, &receipt),
            "missing receipt copy",
        );

        pool.devices[non_target_idx]
            .put_pool_internal(receipt_key, b"corrupt receipt copy")
            .unwrap();
        assert_invalid_options_reason_contains(
            pool.verify_placement_receipt_publication(&indices, &receipt),
            "corrupt receipt copy",
        );

        pool.devices[non_target_idx]
            .put_pool_internal(receipt_key, &encoded_receipt)
            .unwrap();
        pool.verify_placement_receipt_publication(&indices, &receipt)
            .expect("all write-time receipt copies are exact");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pending_reclaim_preflight_failure_preserves_prior_authority_after_reopen() {
        let root = temp_dir("pending-reclaim-preflight-failure");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_regular_file_pool_config(&root);
        let options = StoreOptions::default();
        let key = ObjectKey::from_name(b"pending-reclaim-preflight-failure");
        let original_payload = b"original receipt-authorized payload";

        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let (_, original_receipt) = pool
            .put_with_receipt(IoClass::Data, key, original_payload)
            .unwrap();
        pool.sync_all().unwrap();
        let old_target = pool
            .resolve_receipt_target(&original_receipt.targets[0])
            .expect("old receipt target");
        let mut failure = crate::FaultInjectionConfig::off();
        failure.write_failure_probability = 1.0;
        pool.devices[old_target]
            .store_mut()
            .enable_fault_injection(failure);

        assert!(pool
            .put_with_receipt(
                IoClass::Data,
                key,
                b"replacement must not reach payload publication",
            )
            .is_err());
        pool.devices[old_target]
            .store_mut()
            .disable_fault_injection();
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((original_payload.to_vec(), original_receipt.clone()))
        );
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, key)
                .unwrap(),
            Some((original_payload.to_vec(), original_receipt))
        );
        drop(reopened);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn committed_replacement_does_not_fail_when_reclaim_attachment_is_pending() {
        let root = temp_dir("post-publication-reclaim-attachment-failure");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_regular_file_pool_config(&root);
        let options = StoreOptions::default();
        let key = ObjectKey::from_name(b"post-publication-reclaim-attachment-failure");
        let replacement_payload = b"replacement authority survives cleanup failure";

        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let (_, old_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"old payload")
            .unwrap();
        let old_placements = pool
            .obsolete_physical_placements(&old_receipt)
            .expect("capture old physical placements");
        assert_eq!(old_placements.len(), 1);
        pool.fail_post_publication_reclaim_attachment_once = true;

        let (_, replacement_receipt) = pool
            .put_with_receipt(IoClass::Data, key, replacement_payload)
            .expect("post-commit cleanup failure must not make the write fail");
        assert!(!pool.fail_post_publication_reclaim_attachment_once);
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((replacement_payload.to_vec(), replacement_receipt.clone()))
        );
        for placement in &old_placements {
            let object_id = placement.reclaim_object_id;
            let replacement = dead_object_replacement_receipt_for_object(
                placement.object_key,
                object_id,
                &replacement_receipt,
            )
            .unwrap();
            assert!(
                pool.devices[placement.device_index]
                    .store_mut()
                    .publish_dead_object_replacement_receipt(&object_id, replacement)
                    .unwrap(),
                "pending work must remain available for an idempotent attachment retry"
            );
        }
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, key)
                .unwrap(),
            Some((replacement_payload.to_vec(), replacement_receipt.clone()))
        );
        drop(reopened);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placement_receipt_refs_scan_projects_erasure_shared_refs() {
        let root = temp_dir("receipt-ref-erasure");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"shared-ref-erasure");
        let payload = b"erasure shared receipt ref payload";
        pool.put(IoClass::Data, key, payload).unwrap();

        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        let receipt_refs = pool.placement_receipt_refs(IoClass::Data).unwrap();
        assert_eq!(receipt_refs.len(), 1);
        let receipt_ref = receipt_refs[0];

        assert_eq!(receipt_ref.object_id, receipt.object_store_subject_id());
        assert_eq!(receipt_ref.object_key, key.as_bytes32());
        assert_eq!(receipt_ref.receipt_epoch, EpochId::new(receipt.epoch));
        assert_eq!(receipt_ref.receipt_generation, receipt.generation);
        assert_eq!(
            receipt_ref.redundancy_policy,
            ReceiptRedundancyPolicy::Erasure {
                data_shards: 2,
                parity_shards: 1
            }
        );
        assert_eq!(receipt_ref.payload_len, payload.len() as u64);
        assert_eq!(receipt_ref.payload_digest, receipt.payload_digest);
        assert_eq!(receipt_ref.target_count, 3);
        assert!(!receipt_ref.is_synthetic());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placement_receipts_scan_exposes_erasure_receipts_not_internal_keys() {
        let root = temp_dir("receipt-snapshot-erasure");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"snapshot-erasure-object");
        pool.put(IoClass::Data, key, b"receipt snapshot erasure payload")
            .unwrap();

        let receipts = pool.placement_receipts(IoClass::Data).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.object_key, key);
        assert_eq!(receipt.policy, PoolRedundancyPolicy::erasure(2, 1));
        assert_eq!(receipt.targets.len(), 3);
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
        let public_keys: BTreeSet<ObjectKey> = pool
            .devices
            .iter()
            .flat_map(|device| device.store().list_keys())
            .collect();
        assert!(
            !public_keys.contains(&placement_receipt_object_key(key)),
            "receipt snapshot must not make internal receipt keys public"
        );
        for target in &receipt.targets {
            assert!(
                !public_keys.contains(&placement_shard_object_key(key, target.shard_index)),
                "receipt snapshot must not make internal shard keys public"
            );
        }

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
            pool.get_with_current_receipt(IoClass::Data, old_key)
                .unwrap(),
            Some((b"old-payload".to_vec(), old_receipt.clone())),
            "strict reads must not require an old receipt on a device added after publication"
        );
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
        assert!(pool.devices[victim_idx]
            .delete_pool_internal(victim_key)
            .unwrap());

        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "missing or corrupt erasure placement target",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "receipt-backed erasure read should reconstruct from surviving shards"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_erasure_read_requires_target_receipts_and_uncorrupted_shards() {
        let root = temp_dir("strict-read-all-erasure-targets");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 4),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"strict-read-all-erasure-targets");
        let payload = b"strict erasure reads require every recorded shard";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let target = receipt.targets[0].clone();
        let target_idx = pool.resolve_receipt_target(&target).unwrap();
        let receipt_key = placement_receipt_object_key(key);
        let encoded_receipt = receipt.encode().unwrap();

        assert!(pool.devices[target_idx]
            .delete_pool_internal(receipt_key)
            .unwrap());
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "missing target receipt copy",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "degraded Pool::get remains readable through another receipt copy"
        );
        pool.devices[target_idx]
            .put_pool_internal(receipt_key, &encoded_receipt)
            .unwrap();

        let shard_key = placement_shard_object_key(key, target.shard_index);
        pool.devices[target_idx]
            .put_pool_internal(shard_key, b"corrupt erasure shard")
            .unwrap();
        assert_invalid_options_reason_contains(
            pool.get_with_current_receipt(IoClass::Data, key),
            "missing or corrupt erasure placement target",
        );
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec()),
            "degraded Pool::get reconstructs past one corrupt shard"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_repairing_read_publishes_replacement_receipt() {
        let root = temp_dir("erasure-repairing-read-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-repairing-read-receipt");
        let payload = b"degraded read repair must publish replacement placement evidence";
        let (_, original_receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("initial erasure write");

        let clean_read = pool
            .get_erasure_with_repair_receipt(IoClass::Data, key)
            .expect("clean receipt-aware read")
            .expect("clean erasure payload");
        assert_eq!(clean_read.payload, payload);
        assert_eq!(clean_read.receipt, original_receipt);
        assert_eq!(
            clean_read.repair_status,
            ErasureReadRepairStatus::NotRequired
        );

        let victim = original_receipt.targets[0].clone();
        let victim_idx = pool.resolve_receipt_target(&victim).unwrap();
        let victim_key = placement_shard_object_key(key, victim.shard_index);
        assert!(pool.devices[victim_idx]
            .delete_pool_internal(victim_key)
            .unwrap());

        let repaired_read = pool
            .get_erasure_with_repair_receipt(IoClass::Data, key)
            .expect("degraded receipt-aware read")
            .expect("reconstructed erasure payload");
        assert_eq!(repaired_read.payload, payload);
        assert!(repaired_read.receipt.generation > original_receipt.generation);
        assert_eq!(
            repaired_read.receipt.policy,
            PoolRedundancyPolicy::erasure(2, 1)
        );
        assert_eq!(
            repaired_read.repair_status,
            ErasureReadRepairStatus::ReplacementPublished {
                rebuilt_shard_indices: vec![victim.shard_index],
            }
        );
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("replacement receipt must be current"),
            repaired_read.receipt
        );
        for target in &repaired_read.receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            let shard_key = placement_shard_object_key(key, target.shard_index);
            let shard = pool.devices[idx]
                .get(shard_key)
                .unwrap()
                .expect("replacement receipt target must exist");
            assert_eq!(digest32(&shard), target.stored_digest);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_repairing_read_obeys_committed_deletion() {
        let root = temp_dir("erasure-repairing-read-deleted");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-repairing-read-deleted");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"deleted erasure authority")
            .unwrap();
        stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );

        assert_eq!(
            pool.get_erasure_with_repair_receipt(IoClass::Data, key)
                .expect("committed deletion is a readable absence"),
            None
        );
        assert_eq!(
            pool.load_placement_receipt(pool.class_map.get(IoClass::Data), key)
                .unwrap()
                .expect("physical receipt remains pending")
                .generation,
            receipt.generation,
            "repair must not publish a replacement for deleted authority"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_policy_rejects_malformed_receipt_target_set() {
        let root = temp_dir("erasure-receipt-out-of-range");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-receipt-out-of-range");
        let payload = b"payload large enough to span both data shards";
        pool.put(IoClass::Data, key, payload).unwrap();

        let mut receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("erasure receipt must persist");
        receipt.planner_replay_receipt = None;

        let mut under_width = receipt.clone();
        assert!(under_width.targets.pop().is_some());
        let err = pool.get_erasure_with_receipt(&under_width).unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidOptions {
                reason: "invalid erasure placement receipt availability set"
            }
        ));

        receipt.targets[0].shard_index = receipt.targets.len() as u16;
        let err = pool.get_erasure_with_receipt(&receipt).unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidOptions {
                reason: "invalid erasure placement receipt availability set"
            }
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_policy_rejects_duplicate_receipt_shard() {
        let root = temp_dir("erasure-receipt-duplicate-shard");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"erasure-receipt-duplicate-shard");
        let payload = b"payload large enough to span both data shards";
        pool.put(IoClass::Data, key, payload).unwrap();

        let mut receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("erasure receipt must persist");
        receipt.planner_replay_receipt = None;
        receipt.targets[1].shard_index = receipt.targets[0].shard_index;
        let err = pool.get_erasure_with_receipt(&receipt).unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidOptions {
                reason: "invalid erasure placement receipt availability set"
            }
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn erasure_policy_rejects_receipt_role_mismatch() {
        fn assert_rejects_role_mismatch(
            root_name: &str,
            shard_index: u16,
            role: PlacementTargetRole,
        ) {
            let root = temp_dir(root_name);
            let _ = std::fs::remove_dir_all(&root);
            let config = multi_data_device_config(&root, 4);
            let properties = PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
                ..PoolProperties::default()
            };
            let mut pool = Pool::create(config, properties, &test_options()).unwrap();
            set_deterministic_device_guids(&mut pool);

            let key = ObjectKey::from_name(root_name.as_bytes());
            let payload = b"payload large enough to span both data shards";
            pool.put(IoClass::Data, key, payload).unwrap();

            let mut receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("erasure receipt must persist");
            receipt.planner_replay_receipt = None;
            receipt
                .targets
                .iter_mut()
                .find(|target| target.shard_index == shard_index)
                .expect("target shard")
                .role = role;
            let err = pool.get_erasure_with_receipt(&receipt).unwrap_err();
            assert!(matches!(
                err,
                StoreError::InvalidOptions {
                    reason: "invalid erasure placement receipt availability set"
                }
            ));

            let _ = std::fs::remove_dir_all(&root);
        }

        assert_rejects_role_mismatch(
            "erasure-receipt-data-index-as-parity",
            0,
            PlacementTargetRole::Parity,
        );
        assert_rejects_role_mismatch(
            "erasure-receipt-parity-index-as-data",
            2,
            PlacementTargetRole::Data,
        );
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
        assert_topology_committed(&removal);
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
    fn safe_remove_device_evacuates_target_only_faulted_erasure_receipt() {
        let root = temp_dir("safe-remove-target-only-faulted-erasure-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"target-only-faulted-erasure-receipt");
        let payload = b"faulted target receipt must still drive evacuation";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_guid = pool.device_guid_for_index(victim_idx);
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let receipt_key = placement_receipt_object_key(key);

        for idx in 0..pool.devices.len() {
            if idx != victim_idx {
                assert!(pool.devices[idx].delete_pool_internal(receipt_key).unwrap());
            }
        }
        for _ in 0..3 {
            pool.devices[victim_idx].record_checksum_error();
        }
        assert_eq!(
            pool.devices[victim_idx].status().state,
            DeviceState::Faulted
        );

        let removal = pool.safe_remove_device(&victim_path).unwrap();
        assert_topology_committed(&removal);
        assert_eq!(removal.objects_evacuated, 1);
        assert_eq!(removal.objects_failed, 0);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        let survivor_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("survivor receipt after removal");
        assert!(survivor_receipt
            .targets
            .iter()
            .all(|target| target.device_guid != victim_guid));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_uses_newer_receipt_from_faulted_survivor() {
        let root = temp_dir("safe-remove-faulted-survivor-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"newer-faulted-survivor-receipt");
        let stale_payload = b"stale payload on removal target";
        let current_payload = b"current payload on faulted survivor";
        pool.put(IoClass::Data, key, stale_payload).unwrap();
        let stale_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("initial receipt");
        let target_idx = pool
            .resolve_receipt_target(&stale_receipt.targets[0])
            .unwrap();
        let target_path = pool.devices[target_idx].root().to_path_buf();
        let surviving_indices: Vec<_> = (0..pool.devices.len())
            .filter(|idx| *idx != target_idx)
            .collect();

        let mut current_receipt = pool
            .plan_pool_wide_placement(
                IoClass::Data,
                key,
                current_payload.len(),
                &surviving_indices,
            )
            .unwrap();
        current_receipt.generation = pool
            .allocate_placement_receipt_generation()
            .expect("allocate replacement receipt generation");
        current_receipt.payload_digest = digest32(current_payload);
        pool.put_replicated_with_receipt(
            key,
            current_payload,
            &surviving_indices,
            &mut current_receipt,
        )
        .unwrap();
        assert!(
            (current_receipt.epoch, current_receipt.generation)
                > (stale_receipt.epoch, stale_receipt.generation)
        );
        let current_owner_idx = pool
            .resolve_receipt_target(&current_receipt.targets[0])
            .unwrap();
        assert_ne!(current_owner_idx, target_idx);

        // Leave the newer receipt only on its payload owner, then fault that
        // device. The other readable copies deliberately expose the stale
        // receipt that would roll the payload back if health filtered the
        // removal authority scan.
        let receipt_key = placement_receipt_object_key(key);
        let stale_encoded = stale_receipt.encode().unwrap();
        for idx in 0..pool.devices.len() {
            if idx != current_owner_idx {
                pool.devices[idx]
                    .put_pool_internal(receipt_key, &stale_encoded)
                    .expect("restore stale receipt copy");
            }
        }
        for _ in 0..3 {
            pool.devices[current_owner_idx].record_checksum_error();
        }
        assert_eq!(
            pool.devices[current_owner_idx].status().state,
            DeviceState::Faulted
        );
        assert_eq!(
            pool.devices[target_idx].get(key).unwrap(),
            Some(stale_payload.to_vec())
        );
        assert_eq!(
            pool.devices[current_owner_idx].get(key).unwrap(),
            Some(current_payload.to_vec())
        );

        let removal = pool.safe_remove_device(&target_path).unwrap();
        assert_topology_committed(&removal);
        assert_eq!(removal.objects_evacuated, 1);
        assert_eq!(removal.objects_failed, 0);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(current_payload.to_vec()),
            "removal must not supersede newer faulted-device authority with stale payload"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_uses_newer_receipt_from_metadata_device() {
        let root = temp_dir("safe-remove-metadata-receipt-authority");
        let _ = std::fs::remove_dir_all(&root);
        let metadata_path = root.join("metadata");
        let mut config = multi_data_device_config(&root, 2);
        config.devices.insert(
            0,
            DeviceConfig {
                media_class: DeviceMediaClass::Nvme,
                path: metadata_path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Metadata,
                kind: DeviceKind::Single {
                    path: metadata_path,
                },
                encryption: None,
                compression: None,
            },
        );
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"newer-metadata-device-receipt");
        let stale_payload = b"stale payload on removal target";
        let current_payload = b"current payload on metadata device";
        pool.put(IoClass::Data, key, stale_payload).unwrap();
        let stale_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("initial receipt");
        let target_idx = pool
            .resolve_receipt_target(&stale_receipt.targets[0])
            .unwrap();
        let target_path = pool.devices[target_idx].root().to_path_buf();

        let metadata_indices = [0];
        let mut current_receipt = pool
            .plan_pool_wide_placement(
                IoClass::Metadata,
                key,
                current_payload.len(),
                &metadata_indices,
            )
            .unwrap();
        current_receipt.generation = pool
            .allocate_placement_receipt_generation()
            .expect("allocate replacement receipt generation");
        current_receipt.payload_digest = digest32(current_payload);
        pool.put_replicated_with_receipt(
            key,
            current_payload,
            &metadata_indices,
            &mut current_receipt,
        )
        .unwrap();
        assert!(
            (current_receipt.epoch, current_receipt.generation)
                > (stale_receipt.epoch, stale_receipt.generation)
        );
        assert_eq!(
            pool.devices[target_idx].get(key).unwrap(),
            Some(stale_payload.to_vec())
        );
        assert_eq!(
            pool.devices[0].get(key).unwrap(),
            Some(current_payload.to_vec())
        );

        let removal = pool.safe_remove_device(&target_path).unwrap();
        assert_topology_committed(&removal);
        assert_eq!(removal.objects_evacuated, 1);
        assert_eq!(removal.objects_failed, 0);
        assert_eq!(
            pool.get(IoClass::Metadata, key).unwrap(),
            Some(current_payload.to_vec()),
            "removal must not supersede newer metadata-device authority with stale payload"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_corrupt_target_erasure_receipt() {
        let root = temp_dir("safe-remove-corrupt-target-erasure-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"corrupt-erasure-receipt-before-remove");
        let payload = b"removal must not ignore corrupt erasure placement authority";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let receipt_key = placement_receipt_object_key(key);

        for device in &mut pool.devices {
            let mut raw = device
                .get(receipt_key)
                .unwrap()
                .expect("receipt copy before corruption");
            let last = raw.len() - 1;
            raw[last] ^= 0x5a;
            device
                .put_pool_internal(receipt_key, &raw)
                .expect("replace receipt with bad replay seal");
        }

        let result = pool.safe_remove_device(&victim_path);
        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "placement receipt corrupt or unverifiable"
            })
        ));
        assert_eq!(pool.stats().device_count, 4);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_conflicting_target_and_survivor_receipts() {
        let root = temp_dir("safe-remove-conflicting-receipts");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"conflicting-receipts-before-remove");
        let payload = b"removal must not choose between equal receipt versions";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let receipt_key = placement_receipt_object_key(key);

        let mut conflicting = receipt.clone();
        conflicting.payload_digest = blake3::hash(b"different payload authority").into();
        let encoded = conflicting.encode().unwrap();
        for idx in 0..pool.devices.len() {
            if idx != victim_idx {
                pool.devices[idx]
                    .put_pool_internal(receipt_key, &encoded)
                    .expect("write conflicting survivor receipt");
            }
        }
        for _ in 0..3 {
            pool.devices[victim_idx].record_checksum_error();
        }
        assert_eq!(
            pool.devices[victim_idx].status().state,
            DeviceState::Faulted
        );

        let result = pool.safe_remove_device(&victim_path);
        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "conflicting placement receipts reuse one generation"
            })
        ));
        assert_eq!(pool.stats().device_count, 3);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_orphaned_target_erasure_shard() {
        let root = temp_dir("safe-remove-orphaned-target-erasure-shard");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"orphaned-erasure-shard-before-remove");
        let payload = b"removal must not ignore a shard without receipt authority";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim = &receipt.targets[0];
        let victim_idx = pool.resolve_receipt_target(victim).unwrap();
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let shard_key = placement_shard_object_key(key, victim.shard_index);
        let receipt_key = placement_receipt_object_key(key);

        for device in &mut pool.devices {
            assert!(device.delete_pool_internal(receipt_key).unwrap());
        }
        assert!(pool.devices[victim_idx].get(shard_key).unwrap().is_some());

        let result = pool.safe_remove_device(&victim_path).unwrap();
        assert!(!result.complete);
        assert_eq!(result.objects_failed, 1);
        assert_eq!(result.failed_keys, vec![shard_key]);
        assert_eq!(pool.stats().device_count, 4);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

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
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config, properties.clone(), &test_options()).unwrap();
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
        let key = ObjectKey::from_name(b"after-add-generation-round-trip");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"added topology payload")
            .expect("write through added topology");
        let pool_guid = pool.pool_guid;
        let reserved_through = pool.reserved_placement_receipt_generation_through;
        let reopened_config = pool.config.clone();
        assert!(reserved_through >= receipt.generation);
        for device in &pool.devices {
            assert_eq!(
                require_receipt_generation_high_water(device, pool_guid)
                    .unwrap()
                    .reserved_through,
                reserved_through
            );
        }
        pool.sync_all().unwrap();
        drop(pool);

        let mut reopened = Pool::open(reopened_config, properties, &test_options())
            .expect("reopen added topology");
        assert_eq!(reopened.pool_guid, pool_guid);
        assert_eq!(reopened.stats().device_count, 2);
        assert_eq!(
            reopened.next_placement_receipt_generation,
            reserved_through + 1
        );
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(b"added topology payload".to_vec())
        );
        let (_, after_reopen) = reopened
            .put_with_receipt(
                IoClass::Data,
                ObjectKey::from_name(b"after-added-topology-reopen"),
                b"fresh generation",
            )
            .unwrap();
        assert!(after_reopen.generation > reserved_through);
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
        let key1_receipt = pool
            .placement_receipt_for_key(IoClass::Data, key1)
            .unwrap()
            .expect("key1 receipt before removal");
        let victim_idx = pool
            .resolve_receipt_target(&key1_receipt.targets[0])
            .unwrap();
        let survivor_idx = (0..pool.devices.len())
            .find(|idx| *idx != victim_idx)
            .expect("surviving device");
        let victim_guid = pool.device_guid_for_index(victim_idx);
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let survivor_commit_count_before = pool.devices[survivor_idx]
            .store()
            .txg_manager()
            .commit_count();

        // All objects should be readable now.
        assert!(pool.get(IoClass::Data, key1).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key2).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key3).unwrap().is_some());

        // Remove the device that owns key1 so this test exercises an actual
        // survivor-side rewrite and durability barrier.
        let result = pool.safe_remove_device(&victim_path).unwrap();
        assert_topology_committed(&result);
        assert_eq!(result.objects_failed, 0);

        // Pool now has 1 device.
        assert_eq!(pool.stats().device_count, 1);
        assert_eq!(pool.config.devices.len(), pool.devices.len());
        assert_eq!(pool.device_layouts.len(), pool.devices.len());
        assert_eq!(pool.config.devices[0].path, pool.devices[0].root());
        let survivor_commit_count_after = pool.devices[0].store().txg_manager().commit_count();
        assert!(
            survivor_commit_count_after > survivor_commit_count_before,
            "safe removal must commit survivor data and receipt before detach"
        );

        // All objects should still be readable.
        assert!(pool.get(IoClass::Data, key1).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key2).unwrap().is_some());
        assert!(pool.get(IoClass::Data, key3).unwrap().is_some());
        for key in [key1, key2, key3] {
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt after device removal");
            assert!(
                receipt
                    .targets
                    .iter()
                    .all(|target| target.device_guid != victim_guid),
                "receipt for {key:?} must not target the removed device"
            );
        }

        assert_legacy_device_lifecycle_files_absent(&root);
        assert!(matches!(
            pool.safe_remove_device(&victim_path),
            Err(StoreError::InvalidOptions {
                reason: "device not found for safe removal"
            })
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_rewrites_only_target_owned_receipts() {
        let root = temp_dir("safe-remove-target-owned-receipts");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let victim_key = ObjectKey::from_name(b"target-owned-removal-object");
        let victim_payload = b"only target-owned data needs evacuation";
        pool.put(IoClass::Data, victim_key, victim_payload).unwrap();
        let victim_receipt = pool
            .placement_receipt_for_key(IoClass::Data, victim_key)
            .unwrap()
            .expect("victim receipt before removal");
        let victim_idx = pool
            .resolve_receipt_target(&victim_receipt.targets[0])
            .unwrap();
        let victim_guid = pool.device_guid_for_index(victim_idx);
        let victim_path = pool.devices[victim_idx].root().to_path_buf();

        let unrelated_payload = b"survivor-owned placement must stay unchanged";
        let candidate_indices: Vec<usize> = (0..pool.devices.len()).collect();
        let unrelated_key = (0u64..1024)
            .map(|index| ObjectKey::from_name(format!("survivor-owned-{index}")))
            .find(|key| {
                pool.plan_pool_wide_placement(
                    IoClass::Data,
                    *key,
                    unrelated_payload.len(),
                    &candidate_indices,
                )
                .unwrap()
                .targets
                .iter()
                .all(|target| target.device_guid != victim_guid)
            })
            .expect("key placed away from victim");
        pool.put(IoClass::Data, unrelated_key, unrelated_payload)
            .unwrap();
        let unrelated_receipt_before = pool
            .placement_receipt_for_key(IoClass::Data, unrelated_key)
            .unwrap()
            .expect("unrelated receipt before removal");
        assert!(unrelated_receipt_before
            .targets
            .iter()
            .all(|target| target.device_guid != victim_guid));

        let removal = pool.safe_remove_device(&victim_path).unwrap();
        assert_topology_committed(&removal);
        assert_eq!(removal.objects_evacuated, 1);
        assert_eq!(removal.bytes_evacuated, victim_payload.len() as u64);
        assert_eq!(removal.content_digests.len(), 1);
        assert!(removal.content_digests.contains_key(&victim_key));

        let unrelated_receipt_after = pool
            .placement_receipt_for_key(IoClass::Data, unrelated_key)
            .unwrap()
            .expect("unrelated receipt after removal");
        assert_eq!(unrelated_receipt_after, unrelated_receipt_before);
        assert_eq!(
            pool.get(IoClass::Data, unrelated_key).unwrap(),
            Some(unrelated_payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_unreadable_survivor_owned_payload() {
        let root = temp_dir("safe-remove-unreadable-survivor-owned");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"unreadable-survivor-owned-removal-object");
        let payload = b"only the retiring device still has readable bytes";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt before removal");
        let owner_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_idx = (0..pool.devices.len())
            .find(|idx| *idx != owner_idx)
            .expect("non-owner removal target");
        let victim_path = pool.devices[victim_idx].root().to_path_buf();

        // Leave an untracked payload copy on the retiring device, then remove
        // the receipt-authorized survivor copy. The identical survivor receipt
        // alone must not let removal detach the only readable bytes.
        pool.devices[victim_idx].put(key, payload).unwrap();
        assert!(pool.devices[owner_idx].delete(key).unwrap());
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), None);

        let removal = pool.safe_remove_device(&victim_path).unwrap();

        assert!(!removal.complete);
        assert_eq!(removal.objects_failed, 1);
        assert_eq!(removal.failed_keys, vec![key]);
        assert_eq!(pool.stats().device_count, 2);
        assert!(pool
            .devices
            .iter()
            .any(|device| device.root() == victim_path));
        assert_eq!(
            pool.devices[victim_idx].get(key).unwrap(),
            Some(payload.to_vec())
        );
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_unreceipted_target_logical_data() {
        let root = temp_dir("safe-remove-unreceipted");
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
        let rogue_key = ObjectKey::from_name(b"rogue-unreceipted-object");
        let rogue_payload = b"this object has no placement receipt";
        pool.devices[0].put(rogue_key, rogue_payload).unwrap();

        let result = pool.safe_remove_device(&d1).unwrap();
        assert!(!result.complete);
        assert_eq!(result.objects_failed, 1);
        assert_eq!(result.failed_keys, vec![rogue_key]);
        assert_eq!(pool.stats().device_count, 2);
        assert_eq!(
            pool.devices[0].get(rogue_key).unwrap(),
            Some(rogue_payload.to_vec())
        );
        assert_eq!(
            pool.devices[1].get(rogue_key).unwrap(),
            None,
            "unreceipted data must not be copied to a survivor by key hash"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_unverifiable_survivor_receipts() {
        let root = temp_dir("safe-remove-unverifiable-survivor-receipts");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"survivor-receipt-corrupt-before-remove");
        let payload = b"safe removal requires committed survivor receipt authority";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_path = pool.devices[victim_idx].root().to_path_buf();
        let receipt_key = placement_receipt_object_key(key);

        for idx in 0..pool.devices.len() {
            if idx == victim_idx {
                continue;
            }

            let Some(mut raw) = pool.devices[idx].get(receipt_key).unwrap() else {
                continue;
            };
            let last = raw.len() - 1;
            raw[last] ^= 0x5a;
            pool.devices[idx]
                .put_pool_internal(receipt_key, &raw)
                .expect("replace survivor receipt with bad replay seal");
        }

        let result = pool.safe_remove_device(&victim_path).unwrap();
        assert!(!result.complete);
        assert_eq!(result.objects_failed, 1);
        assert_eq!(result.failed_keys, vec![key]);
        assert_eq!(pool.stats().device_count, 3);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_requires_evacuation_replay_authority() {
        let root = temp_dir("safe-remove-requires-evacuation-replay-authority");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"evacuation-replay-authority");
        let payload = b"evacuation evidence needs a sealed planner replay receipt";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt");
        let removed_device_guid = pool
            .device_guids
            .iter()
            .copied()
            .find(|guid| {
                receipt
                    .targets
                    .iter()
                    .all(|target| target.device_guid != *guid)
            })
            .expect("non-target device");
        let payload_digest = blake3::hash(payload).into();

        assert!(placement_receipt_proves_device_evacuation(
            &pool,
            &receipt,
            payload,
            payload_digest,
            removed_device_guid,
        ));

        let mut receipt_without_replay = receipt.clone();
        receipt_without_replay.planner_replay_receipt = None;
        assert!(!placement_receipt_proves_device_evacuation(
            &pool,
            &receipt_without_replay,
            payload,
            payload_digest,
            removed_device_guid,
        ));

        for target in &receipt.targets {
            let idx = pool.resolve_receipt_target(target).unwrap();
            assert!(pool.devices[idx].delete(key).unwrap());
        }
        assert!(!placement_receipt_proves_device_evacuation(
            &pool,
            &receipt,
            payload,
            payload_digest,
            removed_device_guid,
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_current_receipt_without_replay_authority() {
        let root = temp_dir("safe-remove-refuses-replayless-current-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let key = ObjectKey::from_name(b"replayless-current-removal-receipt");
        let payload = b"source retirement requires sealed locator authority";
        pool.put(IoClass::Data, key, payload).unwrap();
        let receipt = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt before removal");
        let victim_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let victim_path = pool.devices[victim_idx].root().to_path_buf();

        // Re-encode the current receipt as the replayless V2 format still
        // accepted for older in-tree harness data. Every receipt copy is V2,
        // so no sealed locator authority remains for source retirement.
        let mut replayless = receipt.encode().unwrap();
        replayless[..PLACEMENT_RECEIPT_MAGIC_V2.len()].copy_from_slice(PLACEMENT_RECEIPT_MAGIC_V2);
        const V2_FIXED_WIRE_LEN: usize = 106;
        const RECEIPT_TARGET_WIRE_LEN: usize = 55;
        let v2_len = V2_FIXED_WIRE_LEN + receipt.targets.len() * RECEIPT_TARGET_WIRE_LEN;
        replayless.truncate(v2_len);
        let decoded = PlacementReceipt::decode(&replayless).expect("V2 placement receipt");
        assert!(decoded.planner_replay_receipt.is_none());

        let receipt_key = placement_receipt_object_key(key);
        for device in &mut pool.devices {
            device.put_pool_internal(receipt_key, &replayless).unwrap();
        }

        let removal = pool.safe_remove_device(&victim_path).unwrap();

        assert!(!removal.complete);
        assert_eq!(removal.objects_failed, 1);
        assert_eq!(removal.failed_keys, vec![key]);
        assert_eq!(pool.stats().device_count, 3);
        assert!(pool
            .devices
            .iter()
            .any(|device| device.root() == victim_path));
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

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
    fn safe_remove_device_refuses_ambiguous_target_guid() {
        let root = temp_dir("safe-remove-ambiguous-target-guid");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[1].root().to_path_buf();
        pool.device_guids[1] = pool.device_guids[0];

        let result = pool.safe_remove_device(&target_path);

        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "device removal target GUID is missing or ambiguous"
            })
        ));
        assert_eq!(pool.stats().device_count, 2);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_misaligned_topology_tables() {
        let root = temp_dir("safe-remove-misaligned-topology-tables");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        let device_roots_before: Vec<_> = pool
            .devices
            .iter()
            .map(|device| device.root().to_path_buf())
            .collect();
        pool.config.devices.swap(0, 1);

        let result = pool.safe_remove_device(&target_path);

        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "device removal topology tables are incomplete or misaligned"
            })
        ));
        assert_eq!(pool.stats().device_count, 2);
        assert_eq!(
            pool.devices
                .iter()
                .map(|device| device.root().to_path_buf())
                .collect::<Vec<_>>(),
            device_roots_before
        );
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_ambiguous_survivor_guid() {
        let root = temp_dir("safe-remove-ambiguous-survivor-guid");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        pool.device_guids[2] = pool.device_guids[1];

        let result = pool.safe_remove_device(&target_path);

        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "device removal topology GUID table is incomplete or ambiguous"
            })
        ));
        assert_eq!(pool.stats().device_count, 3);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_ambiguous_replay_device_id() {
        let root = temp_dir("safe-remove-ambiguous-replay-device-id");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        pool.device_guids[2] = pool.device_guids[1];
        pool.device_guids[2][15] ^= 1;
        assert_ne!(pool.device_guids[2], pool.device_guids[1]);

        let result = pool.safe_remove_device(&target_path);

        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "device removal placement replay IDs are ambiguous"
            })
        ));
        assert_eq!(pool.stats().device_count, 3);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_without_usable_survivor() {
        let root = temp_dir("safe-remove-no-usable-survivor");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();

        for _ in 0..3 {
            pool.devices[1].record_checksum_error();
        }
        assert_eq!(pool.devices[1].status().state, DeviceState::Faulted);

        let result = pool.safe_remove_device(&target_path);
        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "safe removal requires at least one usable surviving device"
            })
        ));
        assert_eq!(pool.stats().device_count, 2);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_non_data_survivor_for_data() {
        let root = temp_dir("safe-remove-non-data-survivor");
        let _ = std::fs::remove_dir_all(&root);
        let data_path = root.join("data");
        let log_path = root.join("log");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![
                DeviceConfig {
                    media_class: Default::default(),
                    path: data_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single {
                        path: data_path.clone(),
                    },
                    encryption: None,
                    compression: None,
                },
                DeviceConfig {
                    media_class: Default::default(),
                    path: log_path.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::IntentLog,
                    kind: DeviceKind::Single { path: log_path },
                    encryption: None,
                    compression: None,
                },
            ],
        };
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"data-must-not-evacuate-to-log-device");
        let payload = b"data needs a surviving data-class placement target";
        pool.put(IoClass::Data, key, payload).unwrap();

        let result = pool.safe_remove_device(&data_path);
        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "safe removal requires at least one usable surviving device"
            })
        ));
        assert_eq!(pool.stats().device_count, 2);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_different_pending_target() {
        let root = temp_dir("safe-remove-different-pending-target");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let first_target = pool.devices[0].root().to_path_buf();
        let first_target_guid = pool.device_guid_for_index(0);
        let second_target = pool.devices[1].root().to_path_buf();
        let rogue_key = ObjectKey::from_name(b"first-removal-must-remain-pending");
        pool.devices[0]
            .put(rogue_key, b"unreceipted removal blocker")
            .unwrap();

        let first_result = pool.safe_remove_device(&first_target).unwrap();
        assert!(!first_result.complete);
        assert_eq!(first_result.failed_keys, vec![rogue_key]);

        let second_result = pool.safe_remove_device(&second_target);
        assert!(matches!(
            second_result,
            Err(StoreError::InvalidOptions {
                reason: "another device removal is already pending"
            })
        ));
        assert_eq!(pool.stats().device_count, 3);
        let marker = pool
            .device_removal_marker
            .as_ref()
            .expect("first removal label intent remains selected");
        assert_eq!(marker.target_path, first_target);
        assert_eq!(marker.target_guid, first_target_guid);
        assert_eq!(marker.target_index, 0);
        assert_eq!(
            marker.successor_topology_generation,
            checked_successor_topology_generation(pool.placement_epoch()).unwrap()
        );
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_allows_sequential_removal_after_topology_commit() {
        let root = temp_dir("safe-remove-sequential-topology-commit");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let first_target = pool.devices[0].root().to_path_buf();
        let first_target_guid = pool.device_guid_for_index(0);
        let second_target = pool.devices[1].root().to_path_buf();

        let first_result = pool.safe_remove_device(&first_target).unwrap();
        assert_topology_committed(&first_result);
        assert_eq!(pool.stats().device_count, 2);
        assert!(!pool.device_guids.contains(&first_target_guid));

        assert_legacy_device_lifecycle_files_absent(&root);

        let second_result = pool.safe_remove_device(&second_target).unwrap();
        assert_topology_committed(&second_result);
        assert_eq!(pool.stats().device_count, 1);
        assert_legacy_device_lifecycle_files_absent(&root);

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
        assert_topology_committed(&result);
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
        // 2. Publish and use device-authoritative lifecycle intent, then drop
        //    the runtime metadata owner.
        // 3. Re-open the pool, then let the raw owner explicitly resume and
        //    remove the device.

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

        let prepared = pool.prepare_safe_remove_device(&d1).unwrap();
        assert!(!prepared.complete);
        assert!(prepared.topology_commit_pending);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        // Drop the pool (simulating crash / process exit).
        drop(pool);

        // Re-open with the original topology. Generic Pool open preserves the
        // marker and fences the target because only a mounted owner can know
        // whether higher layers embed receipt generations. This raw-Pool test
        // explicitly retries the operation to declare that no such references
        // exist.
        let mut pool2 =
            Pool::open(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        assert_pool_label_lifecycle(&pool2, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);
        assert_eq!(pool2.stats().device_count, 2);
        let resumed = pool2.safe_remove_device(&d1).unwrap();
        assert_topology_committed(&resumed);
        assert_pool_label_lifecycle(&pool2, pool_label::PoolLifecycleKindV1::Clear);
        assert_legacy_device_lifecycle_files_absent(&root);
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

        let reduced_config = pool2.config.clone();
        drop(pool2);

        let reduced =
            Pool::open(reduced_config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(reduced.stats().device_count, 1);
        assert_eq!(
            reduced.get(IoClass::Data, key1).unwrap(),
            Some(data1.clone())
        );
        assert_eq!(
            reduced.get(IoClass::Data, key2).unwrap(),
            Some(data2.clone())
        );
        assert_eq!(
            reduced.get(IoClass::Data, key3).unwrap(),
            Some(data3.clone())
        );
        drop(reduced);

        // A caller may still supply the pre-removal device list. Complete
        // higher-generation label authority filters out the stale target.
        let pool3 = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert_pool_label_lifecycle(&pool3, pool_label::PoolLifecycleKindV1::Clear);
        assert_legacy_device_lifecycle_files_absent(&root);
        assert_eq!(pool3.stats().device_count, 1);
        assert_eq!(pool3.get(IoClass::Data, key1).unwrap(), Some(data1));
        assert_eq!(pool3.get(IoClass::Data, key2).unwrap(), Some(data2));
        assert_eq!(pool3.get(IoClass::Data, key3).unwrap(), Some(data3));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_resolves_target_by_guid() {
        let root = temp_dir("safe-remove-resume-guid");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = multi_data_device_config(&root, 2);
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"resume-guid-object");
        let payload = b"resume follows stable device identity";
        pool.put(IoClass::Data, key, payload).unwrap();
        pool.sync_all().unwrap();

        let old_target_path = config.devices[0].path.clone();
        let prepared = pool.prepare_safe_remove_device(&old_target_path).unwrap();
        assert_eq!(prepared.objects_failed, 0);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        drop(pool);

        let renamed_target_path = root.join("renamed-device-0");
        std::fs::rename(&old_target_path, &renamed_target_path).unwrap();
        config.devices[0].path = renamed_target_path.clone();
        config.devices[0].kind = DeviceKind::Single {
            path: renamed_target_path.clone(),
        };
        let mut reopened =
            Pool::open(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let resolved_target = reopened
            .pending_device_removal_path()
            .unwrap()
            .expect("label intent resolves target index/GUID to its attached path");
        assert_eq!(resolved_target, renamed_target_path);
        let resumed = reopened.safe_remove_device(&resolved_target).unwrap();
        assert_topology_committed(&resumed);
        assert_pool_label_lifecycle(&reopened, pool_label::PoolLifecycleKindV1::Clear);
        assert_legacy_device_lifecycle_files_absent(&root);
        assert_eq!(reopened.stats().device_count, 1);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let reduced_config = reopened.config.clone();
        drop(reopened);
        let reduced =
            Pool::open(reduced_config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(reduced.stats().device_count, 1);
        assert_eq!(
            reduced.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        drop(reduced);
        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert_pool_label_lifecycle(&reopened, pool_label::PoolLifecycleKindV1::Clear);
        assert_eq!(reopened.stats().device_count, 1);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn device_removal_label_intent_wrong_target_fails_pool_open() {
        let root = temp_dir("device-removal-label-wrong-target");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        let payload = encode_device_removal_marker(
            pool.pool_guid,
            0,
            &target_path,
            pool.device_guid_for_index(1),
            checked_successor_topology_generation(pool.placement_epoch()).unwrap(),
        )
        .unwrap();
        pool.persist_lifecycle_record_on_current_topology(
            pool_label::PoolLifecycleKindV1::DeviceRemoval,
            payload,
            "test-wrong-removal-target",
        )
        .unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(config, PoolProperties::default(), &test_options()),
            "does not match the durable topology",
        );
        assert_legacy_device_lifecycle_files_absent(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn device_removal_label_intent_corruption_fails_pool_open() {
        let root = temp_dir("device-removal-label-corrupt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        pool.prepare_safe_remove_device(&target_path).unwrap();
        drop(pool);

        for device in &config.devices {
            let label_path = label_file_path(&device_root_path(device));
            let mut encoded = std::fs::read(&label_path).unwrap();
            let roster_size = pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_HEADER_SIZE
                + config.devices.len() * pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_MEMBER_SIZE
                + pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_CHECKSUM_SIZE;
            let lifecycle_offset = pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_OFFSET + roster_size;
            encoded[lifecycle_offset + pool_label::POOL_LABEL_LIFECYCLE_V1_HEADER_SIZE] ^= 0x80;
            std::fs::write(label_path, encoded).unwrap();
        }

        assert_invalid_options_reason_contains(
            Pool::open(config, PoolProperties::default(), &test_options()),
            "pool label corrupt or unreadable",
        );
        assert_legacy_device_lifecycle_files_absent(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_label_intent_after_refusal() {
        let root = temp_dir("safe-remove-resume-refusal");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        let rogue_key = ObjectKey::from_name(b"resume-rogue-unreceipted-object");
        let rogue_payload = b"resume refusal keeps label intent";
        pool.devices[0].put(rogue_key, rogue_payload).unwrap();

        let refused = pool.prepare_safe_remove_device(&target_path).unwrap();
        assert_eq!(refused.objects_failed, 1);
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert_pool_label_lifecycle(&reopened, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_eq!(
            reopened.pending_device_removal_path().unwrap(),
            Some(target_path)
        );
        assert_eq!(
            reopened.devices[0].get(rogue_key).unwrap(),
            Some(rogue_payload.to_vec())
        );
        assert_legacy_device_lifecycle_files_absent(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Device replacement
    // ------------------------------------------------------------------

    #[test]
    fn safe_replace_device_rebuilds_receipts_and_reopens_without_old_member() {
        let root = temp_dir("safe-replace-device-reopen");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool =
            Pool::create(config, properties.clone(), &test_options()).expect("create Pool");
        set_deterministic_device_guids(&mut pool);
        let old_path = pool.devices[0].root().to_path_buf();
        let old_guid = pool.device_guid_for_index(0);
        let key = ObjectKey::from_name(b"safe-replacement-payload");
        let payload = b"receipt-backed replacement bytes";
        let (_, predecessor) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("write predecessor placement");
        let replacement_path = root.join("replacement-data");
        let replacement_config = DeviceConfig {
            media_class: pool.config.devices[0].media_class,
            path: replacement_path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: replacement_path.clone(),
            },
            encryption: None,
            compression: None,
        };

        let result = pool
            .safe_replace_device(&old_path, replacement_config, &test_options())
            .expect("complete safe replacement");
        assert!(result.complete);
        assert_eq!(result.objects_total, 1);
        assert_eq!(result.objects_rebuilt, 1);
        assert_eq!(result.objects_failed, 0);
        assert_eq!(result.verified_receipt_count, 1);
        assert_eq!(result.bytes_rebuilt, payload.len() as u64);
        assert_eq!(
            result.detach_decision,
            ReplacementDetachDecision::SafeToDetach
        );
        assert!(!result.remanence_treatment.media_privacy_claimed);
        assert_eq!(pool.devices.len(), 2);
        assert!(!pool.device_guids.contains(&old_guid));
        assert_eq!(pool.devices[0].root(), replacement_path);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        let replacement_receipt = pool
            .load_placement_receipt(pool.class_map.get(IoClass::Data), key)
            .unwrap()
            .expect("replacement receipt");
        assert!(replacement_receipt.generation > predecessor.generation);
        assert!(replacement_receipt
            .targets
            .iter()
            .all(|target| target.device_guid != old_guid));
        assert!(replacement_receipt
            .targets
            .iter()
            .any(|target| target.device_guid == result.new_device_guid));

        let reopened_config = pool.config().clone();
        drop(pool);
        let reopened = Pool::open(reopened_config, properties, &test_options())
            .expect("reopen replacement topology");
        assert_eq!(reopened.devices.len(), 2);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        assert!(reopened
            .device_replacement_result()
            .is_some_and(|status| status.complete));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_replace_device_resumes_receipts_before_progress_marker() {
        let root = temp_dir("safe-replace-device-resume");
        let _ = std::fs::remove_dir_all(&root);
        let original_config = multi_data_device_config(&root, 2);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(original_config.clone(), properties.clone(), &test_options())
            .expect("create Pool");
        set_deterministic_device_guids(&mut pool);
        let old_path = pool.devices[0].root().to_path_buf();
        let key = ObjectKey::from_name(b"safe-replacement-resume-payload");
        let payload = b"resume exact replacement bytes";
        pool.put_with_receipt(IoClass::Data, key, payload)
            .expect("write predecessor placement");
        let replacement_path = root.join("replacement-resume-data");
        let replacement_config = DeviceConfig {
            media_class: pool.config.devices[0].media_class,
            path: replacement_path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: replacement_path,
            },
            encryption: None,
            compression: None,
        };

        let prepared = pool
            .replace_device(&old_path, replacement_config.clone(), &test_options())
            .expect("prepare replacement");
        assert!(!prepared.complete);
        assert_eq!(prepared.objects_rebuilt, 1);
        assert_eq!(pool.devices.len(), 3, "old member remains attached");

        // Model the crash cut after the per-object successor receipt and
        // payload are durable but before the later aggregate progress marker
        // rename. Reopen must trust neither the missing candidate nor the
        // stale aggregate counts; it verifies the survivor's exact receipt
        // and payload, then resumes the recorded candidate identity.
        let mut crash_cut = pool
            .replacement_evidence
            .clone()
            .expect("replacement evidence before crash cut");
        assert!(crash_cut.evidence_stable);
        crash_cut.subjects_completed = 0;
        crash_cut.verified_receipt_count = 0;
        crash_cut.bytes_rebuilt = 0;
        crash_cut.evidence_stable = false;
        crash_cut.state = ReplacementRebuildStatusState::Pending;
        pool.persist_replacement_evidence_in_labels(&crash_cut)
            .expect("persist pre-progress replacement crash cut in member labels");
        assert_legacy_device_lifecycle_files_absent(&root);
        drop(pool);

        let mut reopened = Pool::open(original_config, properties.clone(), &test_options())
            .expect("reopen old durable topology");
        let resuming = reopened
            .device_replacement_result()
            .expect("durable replacement result");
        assert_eq!(resuming.state, ReplacementRebuildStatusState::Resuming);
        assert!(!resuming.complete);
        assert_eq!(resuming.objects_rebuilt, 0);
        assert!(reopened.has_device_replacement_predecessor_resume());
        assert_eq!(
            reopened
                .get_with_current_receipt(IoClass::Data, key)
                .expect("verify successor receipt through survivor before candidate reopen")
                .map(|(bytes, _receipt)| bytes),
            Some(payload.to_vec())
        );
        let prepared_again = reopened
            .replace_device(&old_path, replacement_config, &test_options())
            .expect("resume replacement idempotently");
        assert_eq!(prepared_again.objects_rebuilt, 1);
        let completed = reopened
            .finish_safe_replace_device(&old_path)
            .expect("publish replacement topology");
        assert!(completed.complete);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );
        let final_config = reopened.config().clone();
        drop(reopened);
        let reopened = Pool::open(final_config, properties, &test_options())
            .expect("reopen completed replacement topology");
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_replace_device_finishes_evidence_after_topology_publication() {
        let (root, old_path, _config, properties, replacement_config, mut pool) =
            replacement_replay_test_pool("safe-replace-post-label-resume");
        let key = ObjectKey::from_name(b"post-label-replacement-payload");
        let payload = b"published replacement topology remains exact";
        pool.put_with_receipt(IoClass::Data, key, payload)
            .expect("write replacement crash-cut payload");
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .expect("prepare replacement before label crash cut");
        pool.finish_safe_replace_device(&old_path)
            .expect("publish replacement labels");
        let final_config = pool.config().clone();

        // Model a crash after both replacement label families are durable but
        // before the terminal evidence rename. The next import selects the new
        // topology and must let the exact command finish evidence without an
        // ordinary generation-allocating write first.
        let mut crash_cut = pool
            .replacement_evidence
            .clone()
            .expect("completed replacement evidence");
        assert!(crash_cut.evidence_stable);
        crash_cut.state = ReplacementRebuildStatusState::Pending;
        pool.persist_replacement_evidence_in_labels(&crash_cut)
            .expect("persist pre-terminal replacement crash cut in member labels");
        assert_legacy_device_lifecycle_files_absent(&root);
        drop(pool);

        let mut reopened = Pool::open(final_config, properties, &test_options())
            .expect("reopen published replacement topology");
        assert!(reopened.has_device_replacement_resume());
        assert!(!reopened.has_device_replacement_predecessor_resume());
        assert_eq!(
            reopened.get(IoClass::Data, key).expect("read new topology"),
            Some(payload.to_vec())
        );
        let resumed = reopened
            .replace_device(&old_path, replacement_config, &test_options())
            .expect("resume terminal replacement evidence");
        assert!(!resumed.complete);
        let completed = reopened
            .finish_safe_replace_device(&old_path)
            .expect("finish terminal replacement evidence");
        assert!(completed.complete);
        assert!(reopened
            .device_replacement_result()
            .is_some_and(|status| status.complete));

        let _ = std::fs::remove_dir_all(&root);
    }

    fn replacement_replay_test_pool(
        name: &str,
    ) -> (
        PathBuf,
        PathBuf,
        PoolConfig,
        PoolProperties,
        DeviceConfig,
        Pool,
    ) {
        let root = temp_dir(name);
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let old_path = config.devices[0].path.clone();
        let replacement_path = root.join("replacement-data");
        let replacement_config = DeviceConfig {
            media_class: config.devices[0].media_class,
            path: replacement_path.clone(),
            backing: config.devices[0].backing,
            class: config.devices[0].class,
            kind: DeviceKind::Single {
                path: replacement_path,
            },
            encryption: None,
            compression: None,
        };
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let pool = Pool::create(config.clone(), properties.clone(), &test_options())
            .expect("create replacement replay Pool");
        (root, old_path, config, properties, replacement_config, pool)
    }

    #[test]
    fn replace_device_refuses_concurrent_replacement() {
        let (root, old_path, _config, _properties, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-concurrent");
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .expect("prepare first replacement");
        let retried = pool
            .replace_device(&old_path, replacement_config.clone(), &test_options())
            .expect("retry exact in-memory replacement");
        assert_eq!(retried.objects_failed, 0);
        assert_eq!(pool.devices.len(), 3);

        let second_path = root.join("second-replacement-data");
        let mut second_config = replacement_config;
        second_config.path = second_path.clone();
        second_config.kind = DeviceKind::Single { path: second_path };
        let second_config_after_completion = second_config.clone();
        assert_invalid_options_reason_contains(
            pool.replace_device(
                &root.join("replacement-data"),
                second_config,
                &test_options(),
            ),
            "already in progress",
        );
        assert_eq!(pool.devices.len(), 3);
        assert!(pool.devices.iter().any(|device| device.root() == old_path));

        pool.finish_safe_replace_device(&old_path)
            .expect("complete first replacement");
        let next_old_path = pool.devices[1].root().to_path_buf();
        let next = pool
            .replace_device(
                &next_old_path,
                second_config_after_completion,
                &test_options(),
            )
            .expect("start a new replacement after terminal evidence");
        assert_eq!(next.objects_failed, 0);
        assert_eq!(pool.devices.len(), 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_reopens_resuming_and_reuses_identity_on_resume() {
        let (root, old_path, config, properties, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-reopen-resume");
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .expect("prepare replacement");
        let before_reopen = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence before reopen");
        assert_eq!(before_reopen.state, ReplacementRebuildStatusState::Pending);
        assert!(before_reopen.evidence_stable);
        assert!(before_reopen.evidence_replayable_after_reopen);
        let new_device_guid = before_reopen.new_device_guid;
        drop(pool);

        let mut reopened =
            Pool::open(config, properties, &test_options()).expect("reopen old topology");
        let replayed = reopened
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence after reopen");
        assert_eq!(replayed.state, ReplacementRebuildStatusState::Resuming);
        assert_eq!(replayed.new_device_guid, new_device_guid);
        assert_eq!(replayed.topology_epoch, before_reopen.topology_epoch);
        assert!(replayed.evidence_stable);
        assert_eq!(
            replayed.detach_decision,
            ReplacementDetachDecision::UnsafeToDetach
        );

        let refused_key = ObjectKey::from_name(b"stale-old-topology-must-not-write");
        assert_invalid_options_reason_contains(
            reopened.put_with_receipt(
                IoClass::Data,
                refused_key,
                b"must not reach stale old topology",
            ),
            "explicit replacement resume",
        );
        reopened
            .replace_device(&old_path, replacement_config, &test_options())
            .expect("resume with the recorded replacement");
        let resumed = reopened
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence after resume");
        assert_eq!(resumed.state, ReplacementRebuildStatusState::Pending);
        assert_eq!(resumed.new_device_guid, new_device_guid);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_corruption_refuses_reopen() {
        let (root, old_path, config, properties, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-corrupt");
        pool.replace_device(&old_path, replacement_config, &test_options())
            .expect("prepare replacement");
        drop(pool);

        for device in &config.devices {
            let label_path = label_file_path(&device_root_path(device));
            let mut encoded = std::fs::read(&label_path).unwrap();
            let roster_size = pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_HEADER_SIZE
                + config.devices.len() * pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_MEMBER_SIZE
                + pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_CHECKSUM_SIZE;
            let lifecycle_offset = pool_label::POOL_LABEL_TOPOLOGY_ROSTER_V1_OFFSET + roster_size;
            encoded[lifecycle_offset + pool_label::POOL_LABEL_LIFECYCLE_V1_HEADER_SIZE] ^= 0x80;
            std::fs::write(label_path, encoded).unwrap();
        }

        assert_invalid_options_reason_contains(
            Pool::open(config, properties, &test_options()),
            "pool label corrupt or unreadable",
        );
        assert_legacy_device_lifecycle_files_absent(&root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_device_refuses_unknown_member_without_mutation() {
        let (root, old_path, _config, _properties, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-unknown");
        let old_device_guids = pool.device_guids.clone();
        let old_topology_epoch = pool.placement_epoch();

        assert_invalid_options_reason_contains(
            pool.replace_device(
                &root.join("not-a-current-member"),
                replacement_config.clone(),
                &test_options(),
            ),
            "not found",
        );
        let mut mismatched_config = replacement_config;
        mismatched_config.compression = Some(crate::CompressionConfig::speed());
        assert_invalid_options_reason_contains(
            pool.replace_device(&old_path, mismatched_config, &test_options()),
            "same-backing member configuration",
        );
        assert_eq!(pool.devices.len(), 2);
        assert_eq!(pool.device_guids, old_device_guids);
        assert_eq!(pool.placement_epoch(), old_topology_epoch);
        assert!(pool.replacement_status().is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

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
    fn open_restores_pool_label_redundancy_policy_over_caller_default() {
        let root = temp_dir("import-label-policy");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 4);
        let options = test_options();
        let persisted_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };

        let pool = Pool::create(config.clone(), persisted_properties, &options).unwrap();
        pool.export().unwrap();
        drop(pool);

        let caller_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut reopened = Pool::open(config, caller_properties, &options).unwrap();
        assert_eq!(
            reopened.redundancy_policy(),
            PoolRedundancyPolicy::erasure(2, 1),
            "pool label policy must be the authority for new allocations"
        );

        let key = ObjectKey::from_name(b"label-policy-erasure-write");
        let payload = b"label policy survives exported pool import";
        reopened.put(IoClass::Data, key, payload).unwrap();
        let receipt = reopened
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("placement receipt after label-authoritative import");
        assert_eq!(receipt.policy, PoolRedundancyPolicy::erasure(2, 1));
        assert_eq!(receipt.targets.len(), 3);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_reuses_active_label_redundancy_policy_over_caller_default() {
        let root = temp_dir("active-label-policy");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let options = test_options();
        let persisted_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };

        let mut pool = Pool::create(config.clone(), persisted_properties, &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let first_key = ObjectKey::from_name(b"active-label-policy-before-reopen");
        pool.put(IoClass::Data, first_key, b"first").unwrap();
        drop(pool);

        let caller_properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut reopened = Pool::create(config, caller_properties, &options).unwrap();
        assert_eq!(
            reopened.redundancy_policy(),
            PoolRedundancyPolicy::replicated(2),
            "active labels must keep the persisted pool-wide policy"
        );

        let second_key = ObjectKey::from_name(b"active-label-policy-after-reopen");
        reopened.put(IoClass::Data, second_key, b"second").unwrap();
        let receipt = reopened
            .placement_receipt_for_key(IoClass::Data, second_key)
            .unwrap()
            .expect("placement receipt after active-label reopen");
        assert_eq!(receipt.policy, PoolRedundancyPolicy::replicated(2));
        assert_eq!(receipt.targets.len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_persists_device_layout_and_open_uses_label_record() {
        let root = temp_dir("layout-label-reopen");
        let _ = std::fs::remove_dir_all(&root);
        let config = regular_file_pool_config(&root, "layout-label-reopen", 300 * 1024 * 1024);
        let mut options = test_options();
        options.max_segment_bytes = 16 * 1024;
        let custom_policy = DeviceLayoutPolicy::Custom {
            data_segment_size: 1024 * 1024,
            metadata_segment_size: 1024 * 1024,
            journal_segment_size: 1024 * 1024,
        };
        let properties = PoolProperties {
            layout_policy: custom_policy,
            ..PoolProperties::default()
        };

        let pool = Pool::create(config.clone(), properties, &options).unwrap();
        let created_layout = pool.device_layouts()[0];
        assert_eq!(
            created_layout.policy,
            crate::device_layout::DeviceLayoutPolicyDiscriminant::Custom
        );

        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = fs::File::open(device_root_path(&config.devices[0])).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let label = pool_label::decode_label(&label_bytes).unwrap();
        assert!(label.features_compat & features::DEVICE_LAYOUT_V1 != 0);
        let layout_bytes = pool_label::decode_device_layout_v1_bytes(&label_bytes)
            .unwrap()
            .expect("layout sidecar");
        let label_layout = decode_device_layout_v1(&layout_bytes).unwrap();
        assert_eq!(label_layout, created_layout);
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(reopened.device_layouts()[0], created_layout);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn directory_pool_reopens_when_layout_size_differs_from_current_capacity() {
        let root = temp_dir("directory-layout-capacity-drift");
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let options = test_options();

        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let current_capacity = pool.devices[0].store().capacity_bytes();
        let persisted_layout = DeviceLayoutPolicy::Auto
            .compute(current_capacity / 2)
            .expect("alternate directory layout");
        assert_ne!(persisted_layout.device_size_bytes, current_capacity);

        let device_root = device_root_path(&config.devices[0]);
        let label_path = label_file_path(&device_root);
        let mut label = pool_label::decode_label(&fs::read(&label_path).unwrap()).unwrap();
        label.device_capacity_bytes = persisted_layout.device_size_bytes;
        write_pool_label(
            &config.devices[0],
            label,
            Some(&persisted_layout),
            &pool.device_guids,
            "test_write_directory_layout_capacity_drift_label",
        )
        .unwrap();
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert_eq!(reopened.device_layouts()[0], persisted_layout);
        assert_ne!(
            reopened.devices[0].store().capacity_bytes(),
            persisted_layout.device_size_bytes,
            "directory shim capacity is not a pool-label authority boundary"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn byte_addressable_pool_opens_raw_capacity_creator_layout() {
        let root = temp_dir("byte-layout-raw-creator-capacity");
        let _ = std::fs::remove_dir_all(&root);
        let raw_device_bytes = 300 * 1024 * 1024;
        let config = regular_file_pool_config(&root, "byte-layout-raw-creator", raw_device_bytes);
        let options = test_options();

        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let usable_device_bytes = pool.devices[0].store().capacity_bytes();
        assert_ne!(usable_device_bytes, raw_device_bytes);
        let raw_layout = DeviceLayoutPolicy::Slice0Small
            .compute(raw_device_bytes)
            .expect("raw-capacity creator layout");

        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = fs::File::open(device_root_path(&config.devices[0])).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let mut label = pool_label::decode_label(&label_bytes).unwrap();
        label.device_capacity_bytes = raw_device_bytes;
        write_pool_label(
            &config.devices[0],
            label,
            Some(&raw_layout),
            &pool.device_guids,
            "test_write_raw_capacity_creator_layout_label",
        )
        .unwrap();
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &options).unwrap();
        let expected_layout = DeviceLayoutPolicy::Slice0Small
            .compute(usable_device_bytes)
            .expect("usable-capacity pool layout");
        assert_eq!(reopened.device_layouts()[0], expected_layout);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn byte_addressable_pool_rejects_mismatched_label_layout_size() {
        let root = temp_dir("byte-layout-capacity-mismatch");
        let _ = std::fs::remove_dir_all(&root);
        let config =
            regular_file_pool_config(&root, "byte-layout-capacity-mismatch", 300 * 1024 * 1024);
        let options = test_options();

        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        let created_size = pool.device_layouts()[0].device_size_bytes;
        let mismatched_layout = DeviceLayoutPolicy::Auto
            .compute(created_size - 64 * 1024 * 1024)
            .expect("mismatched byte-addressable layout");

        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = fs::File::open(device_root_path(&config.devices[0])).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let mut label = pool_label::decode_label(&label_bytes).unwrap();
        label.device_capacity_bytes = mismatched_layout.device_size_bytes;
        write_pool_label(
            &config.devices[0],
            label,
            Some(&mismatched_layout),
            &pool.device_guids,
            "test_write_byte_layout_capacity_mismatch_label",
        )
        .unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(config, PoolProperties::default(), &options),
            "DeviceLayoutV1 device size mismatch",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_rejects_mismatched_label_redundancy_policy() {
        let root = temp_dir("label-policy-mismatch");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let options = test_options();
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };

        let pool = Pool::create(config.clone(), properties, &options).unwrap();
        let device_layout = pool.device_layouts()[1];
        let topology_roster = pool.device_guids.clone();
        pool.export().unwrap();
        drop(pool);

        let device_root = device_root_path(&config.devices[1]);
        let label_path = label_file_path(&device_root);
        let mut label = pool_label::decode_label(&fs::read(&label_path).unwrap()).unwrap();
        label.redundancy_policy = pool_label::PoolRedundancyPolicy::erasure(2, 1);
        write_pool_label(
            &config.devices[1],
            label,
            Some(&device_layout),
            &topology_roster,
            "test_write_mismatched_redundancy_label",
        )
        .unwrap();

        assert_invalid_options_reason_contains(
            Pool::open(config, PoolProperties::default(), &options),
            "redundancy policy mismatch",
        );

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
        let pool1_guid = pool1.pool_guid;
        drop(pool1);
        let _ = std::fs::remove_dir_all(&root);
        let config = single_device_config(&root);
        let pool2 = Pool::create(config, PoolProperties::default(), &options).unwrap();
        assert_ne!(pool1_guid, pool2.pool_guid);
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
    fn log_device_removal_commits_topology_before_mutation_resumes() {
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

        // Write via log device.
        let key = ObjectKey::from_name(b"lifecycle-test");
        pool.log_device_append(b"before-remove").unwrap();
        let log_path = log_dir.join(LOG_DEVICE_FILENAME);
        let log_len_before_remove = std::fs::metadata(&log_path).unwrap().len();

        // A committed log record is crash-replay authority. Refuse detach
        // until a higher layer has drained it into committed pool state.
        let removal = pool.safe_remove_device(&log_dir);
        assert!(matches!(
            removal,
            Err(StoreError::InvalidOptions {
                reason: "cannot remove active intent-log device with undrained records"
            })
        ));
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.has_log_device());
        assert_eq!(
            std::fs::metadata(&log_path).unwrap().len(),
            log_len_before_remove
        );
        assert_pool_label_lifecycle(&pool, pool_label::PoolLifecycleKindV1::DeviceRemoval);
        assert_legacy_device_lifecycle_files_absent(&root);

        // Simulate the owning commit/replay layer draining the records. Safe
        // removal must still refuse truncated or corrupt drain authority.
        pool.log_device.as_mut().unwrap().truncate().unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&log_path)
            .unwrap()
            .set_len(0)
            .unwrap();
        let removal = pool.safe_remove_device(&log_dir);
        assert!(matches!(
            removal,
            Err(StoreError::InvalidOptions {
                reason: "cannot remove active intent-log device with truncated header"
            })
        ));
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.has_log_device());

        let mut valid_header = Vec::with_capacity(LOG_DEVICE_HEADER_SIZE as usize);
        valid_header.extend_from_slice(crate::log_device::LOG_DEVICE_MAGIC);
        valid_header.extend_from_slice(&crate::log_device::LOG_DEVICE_VERSION.to_le_bytes());
        valid_header.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(valid_header.len(), LOG_DEVICE_HEADER_SIZE as usize);
        let mut corrupt_header = valid_header.clone();
        corrupt_header[0] ^= 0xff;
        std::fs::write(&log_path, &corrupt_header).unwrap();
        let removal = pool.safe_remove_device(&log_dir);
        assert!(matches!(
            removal,
            Err(StoreError::InvalidOptions {
                reason: "log_device file has wrong magic"
            })
        ));
        assert_eq!(pool.log_device_count(), 1);
        assert!(pool.has_log_device());

        // A valid header-only log is drained, so removal may close the
        // dedicated writer before detach.
        std::fs::write(&log_path, &valid_header).unwrap();
        let drained_log_len = std::fs::metadata(&log_path).unwrap().len();
        let removal = pool.safe_remove_device(&log_dir).unwrap();
        assert_topology_committed(&removal);
        assert_eq!(pool.log_device_count(), 0);
        assert!(!pool.log_device_healthy());
        assert!(!pool.has_log_device());
        assert_legacy_device_lifecycle_files_absent(&root);
        assert_eq!(std::fs::metadata(&log_path).unwrap().len(), drained_log_len);

        // Mutation resumes only after both label copies have committed. With
        // no dedicated log member, intent-log-class writes use the retained
        // pool fallback.
        pool.put(IoClass::IntentLog, key, b"after-remove").unwrap();

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
        assert!(pool.has_log_device());

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
        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options)
            .expect("create encrypted pool");
        assert!(!pool.is_locked(), "freshly created pool must not be locked");
        let data_key = ObjectKey::from_name(b"locked-import-encrypted-payload");
        let data_payload = b"encrypted payload must not become raw marker metadata";
        pool.put(IoClass::Data, data_key, data_payload).unwrap();
        let stored_frame = pool.devices[0]
            .store()
            .get(data_key)
            .unwrap()
            .expect("encrypted raw frame");
        assert_ne!(stored_frame, data_payload);
        let pool_guid = pool.pool_guid;
        let device_guid = pool.device_guids[0];
        let reserved_through = pool.reserved_placement_receipt_generation_through;
        pool.export().expect("export encrypted pool");
        drop(pool);

        // Re-open without encryption key — should be locked.
        let config_no_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config.clone()
        };
        let mut imported = Pool::open(config_no_key.clone(), PoolProperties::default(), &options)
            .expect("open encrypted pool without key");
        assert!(
            imported.is_locked(),
            "pool opened without encryption key must be locked"
        );
        assert_eq!(
            imported.next_placement_receipt_generation, 0,
            "locked import must not expose a receipt-generation allocator"
        );
        assert_eq!(
            require_receipt_generation_high_water(&imported.devices[0], imported.pool_guid)
                .unwrap()
                .reserved_through,
            reserved_through,
            "locked import must validate the raw-only generation marker"
        );
        assert!(
            imported
                .put(IoClass::Data, ObjectKey::from_name(b"data"), b"test")
                .is_err(),
            "locked pool must refuse put"
        );
        let raw_key = ObjectKey::from_name(b"locked-import-raw-mutation");
        assert_invalid_options_reason_contains(
            imported
                .raw_primary_store_mut()
                .put(raw_key, b"must not reach raw storage"),
            "receipt-generation authority is unavailable",
        );
        assert!(imported.raw_primary_store().get(raw_key).unwrap().is_none());
        drop(imported);

        let mut marker_device = open_single_device(
            &config.devices[0],
            &options,
            true,
            Some(BlockStoreIdentity {
                pool_guid,
                device_guid,
            }),
        )
        .expect("open marker device");
        let mut corrupt = encode_receipt_generation_high_water(ReceiptGenerationHighWater {
            pool_guid,
            reserved_through,
        });
        corrupt[RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN - 1] ^= 0x5a;
        marker_device
            .put_pool_internal(receipt_generation_high_water_key(), &corrupt)
            .unwrap();
        marker_device.sync_all().unwrap();
        drop(marker_device);
        assert_invalid_options_reason_contains(
            Pool::open(config_no_key, PoolProperties::default(), &options),
            "checksum mismatch",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_pool_detects_encrypted_device_behind_compression() {
        let root = temp_dir("locked-detect-compressed");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();

        let (config, _key) = encrypted_compressed_device_config(&root);
        let mut pool = Pool::create(config.clone(), PoolProperties::default(), &options)
            .expect("create encrypted compressed pool");
        assert!(!pool.is_locked(), "freshly created pool must not be locked");
        let data_key = ObjectKey::from_name(b"locked-import-encrypted-compressed-payload");
        let data_payload = vec![0x5a; 4096];
        pool.put(IoClass::Data, data_key, &data_payload).unwrap();
        assert_ne!(
            pool.devices[0]
                .store()
                .get(data_key)
                .unwrap()
                .expect("encrypted compressed raw frame"),
            data_payload,
            "ordinary objects must remain transformed while the marker stays raw-only"
        );
        let reserved_through = pool.reserved_placement_receipt_generation_through;
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
        assert_eq!(
            require_receipt_generation_high_water(&imported.devices[0], imported.pool_guid)
                .unwrap()
                .reserved_through,
            reserved_through,
            "locked encrypted+compressed import must validate the raw-only marker"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_pool_defers_pending_deletion_until_keyed_reopen() {
        let root = temp_dir("locked-pending-deletion");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();
        let properties = PoolProperties::default();
        let (config, _key) = encrypted_device_config(&root);

        let mut pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create encrypted pool");
        let key = ObjectKey::from_name(b"locked-pending-deletion");
        let (_, receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"encrypted deleted authority")
            .unwrap();
        stage_pending_deletion_for_test(
            &mut pool,
            IoClass::Data,
            &receipt,
            PendingDeletionPhase::Committed,
        );
        drop(pool);

        let config_without_key = PoolConfig {
            devices: vec![DeviceConfig {
                encryption: None,
                ..config.devices[0].clone()
            }],
            ..config.clone()
        };
        let locked = Pool::open(config_without_key, properties.clone(), &options)
            .expect("locked import defers encrypted deletion discovery");
        assert!(locked.is_locked());
        assert!(locked.pending_deletions.is_empty());
        assert_invalid_options_reason_contains(
            locked.get(IoClass::Data, key),
            "encryption key required",
        );
        drop(locked);

        let reopened = Pool::open(config, properties, &options)
            .expect("key-bearing reopen discovers committed deletion");
        assert!(!reopened.is_locked());
        assert_eq!(reopened.get(IoClass::Data, key).unwrap(), None);
        assert!(reopened.pending_deletions.is_empty());
        assert!(reopened
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .is_none());

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
    fn locked_pool_refuses_safe_device_removal() {
        let root = temp_dir("locked-safe-remove");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();
        let encryption =
            crate::encrypt::EncryptionConfig::new(crate::encrypt::StoreEncryptionKey::generate());
        let mut config = multi_data_device_config(&root, 2);
        for device in &mut config.devices {
            device.encryption = Some(encryption.clone());
        }

        let pool = Pool::create(config.clone(), PoolProperties::default(), &options).unwrap();
        pool.export().unwrap();
        drop(pool);

        let target_path = config.devices[0].path.clone();
        for device in &mut config.devices {
            device.encryption = None;
        }
        let mut locked_pool = Pool::open(config, PoolProperties::default(), &options).unwrap();
        assert!(locked_pool.is_locked());

        let err = locked_pool.safe_remove_device(&target_path).unwrap_err();

        assert!(matches!(
            err,
            StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O"
            }
        ));
        assert_eq!(locked_pool.stats().device_count, 2);
        assert_legacy_device_lifecycle_files_absent(&root);

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

    #[test]
    fn put_with_receipt_returns_placement_receipt() {
        let root = temp_dir("put-with-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();

        let key = ObjectKey::from_name(b"receipt-test");
        let payload = b"placement receipt authority test";
        let (stored, receipt) = pool
            .put_with_receipt(IoClass::Data, key, payload)
            .expect("put_with_receipt succeeds");

        assert_eq!(stored.key, key);
        assert_eq!(receipt.object_key, key);
        assert!(!receipt.targets.is_empty());
        assert!(receipt.generation > 0);

        // Verify receipt is persisted and retrievable.
        let loaded = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .expect("load succeeds")
            .expect("receipt present");
        assert_eq!(loaded.generation, receipt.generation);
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), receipt))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uncommitted_replay_ensure_reuses_exact_receipt() {
        let root = temp_dir("uncommitted-replay-exact-reuse");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"uncommitted-replay-exact-reuse");
        let payload = b"deterministic replay payload";

        let first = pool
            .ensure_prepublication_data_object_with_receipt(key, payload)
            .expect("publish replay object");
        let generation_after_first = pool.next_placement_receipt_generation;
        let second = pool
            .ensure_prepublication_data_object_with_receipt(key, payload)
            .expect("reuse replay object");

        assert_eq!(second, first);
        assert_eq!(
            pool.next_placement_receipt_generation, generation_after_first,
            "an exact replay retry must not allocate a new receipt generation"
        );
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), first))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uncommitted_replay_ensure_refuses_receiptless_or_corrupt_state() {
        let root = temp_dir("uncommitted-replay-orphan-convergence");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();

        let receiptless_key = ObjectKey::from_name(b"uncommitted-replay-receiptless");
        pool.devices[0]
            .put(receiptless_key, b"orphan bytes")
            .unwrap();
        let expected = b"intent-authoritative bytes";
        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(receiptless_key, expected),
            "receiptless raw payload",
        );
        assert_eq!(
            pool.devices[0].get(receiptless_key).unwrap(),
            Some(b"orphan bytes".to_vec()),
            "receiptless state must remain untouched for explicit recovery"
        );

        let corrupt_key = ObjectKey::from_name(b"uncommitted-replay-corrupt-receipt");
        pool.devices[0].put(corrupt_key, b"orphan bytes").unwrap();
        pool.devices[0]
            .put_pool_internal(placement_receipt_object_key(corrupt_key), b"corrupt")
            .unwrap();
        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(corrupt_key, expected),
            "corrupt or unverifiable placement receipt",
        );
        assert_eq!(
            pool.devices[0].get(corrupt_key).unwrap(),
            Some(b"orphan bytes".to_vec()),
            "corrupt receipt state must remain untouched for explicit recovery"
        );
        assert_eq!(
            pool.devices[0]
                .get(placement_receipt_object_key(corrupt_key))
                .unwrap(),
            Some(b"corrupt".to_vec())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uncommitted_replay_ensure_refuses_different_valid_current_payload() {
        let root = temp_dir("uncommitted-replay-different-valid-payload");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = Pool::create(
            single_device_config(&root),
            PoolProperties::default(),
            &test_options(),
        )
        .unwrap();
        let key = ObjectKey::from_name(b"uncommitted-replay-different-valid-payload");
        let (_, old_receipt) = pool
            .put_with_receipt(IoClass::Data, key, b"orphan attempt")
            .unwrap();
        let expected = b"durable intent result";

        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(key, expected),
            "different current receipt-backed payload",
        );
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((b"orphan attempt".to_vec(), old_receipt))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uncommitted_replay_ensure_refuses_receiptless_erasure_shards() {
        let root = temp_dir("uncommitted-replay-receiptless-erasure");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"uncommitted-replay-receiptless-erasure");
        pool.put(IoClass::Data, key, b"orphan erasure attempt")
            .unwrap();
        let receipt_key = placement_receipt_object_key(key);
        for device in &mut pool.devices {
            device.delete_pool_internal(receipt_key).unwrap();
        }
        let expected = b"intent-authoritative erasure payload";
        let payloads_before: Vec<_> = pool
            .devices
            .iter()
            .map(|device| device.get(key).unwrap())
            .collect();

        assert_invalid_options_reason_contains(
            pool.ensure_prepublication_data_object_with_receipt(key, expected),
            "receiptless raw payload",
        );
        assert_eq!(
            pool.devices
                .iter()
                .map(|device| device.get(key).unwrap())
                .collect::<Vec<_>>(),
            payloads_before,
            "receiptless erasure state must not be overwritten"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn put_with_receipt_rejects_receiptless_intent_log() {
        let root = temp_dir("put-with-receipt-intent-log");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();
        let data_dir = root.join("data");
        let log_dir = root.join("log");
        let config = PoolConfig {
            name: "testpool-intent-log-receipt".into(),
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
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();
        let key = ObjectKey::from_name(b"intent-log-receiptless");

        assert_invalid_options_reason_contains(
            pool.put_with_receipt(IoClass::IntentLog, key, b"log payload"),
            "IntentLog writes do not publish placement receipts",
        );
        assert_eq!(pool.get(IoClass::IntentLog, key).unwrap(), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repair_with_receipt_supersedes_original() {
        let root = temp_dir("repair-with-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let options = test_options();
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &options).unwrap();

        let key = ObjectKey::from_name(b"repair-test");
        let original = b"original data";
        let repaired = b"repaired data";

        let (_stored, orig) = pool
            .put_with_receipt(IoClass::Data, key, original)
            .expect("original put");

        let (_rep, repair) = pool
            .repair_with_receipt(
                IoClass::Data,
                key,
                repaired,
                RepairSource::Replica {
                    source_device_index: 0,
                },
            )
            .expect("repair succeeds");

        assert!(repair.generation > orig.generation);
        let read_back = pool.get(IoClass::Data, key).expect("get succeeds");
        assert_eq!(read_back.as_deref(), Some(&repaired[..]));

        let _ = std::fs::remove_dir_all(&root);
    }

    // -- pool-wide placement: all eligible devices used --------------------

    #[test]
    fn pool_wide_placement_uses_all_eligible_devices_over_many_allocations() {
        let root = temp_dir("pool-wide-device-usage");
        let _ = std::fs::remove_dir_all(&root);
        let device_count: usize = 8;
        let config = multi_data_device_config(&root, device_count);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let mut used_devices = std::collections::BTreeSet::new();
        for i in 0..1024u64 {
            let key = ObjectKey::from_name(format!("usage-{i}").as_bytes());
            pool.put(IoClass::Data, key, format!("payload-{i}").as_bytes())
                .unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt must persist");
            assert_eq!(
                receipt.targets.len(),
                2,
                "replicated(2) must place exactly 2 targets per allocation"
            );
            for target in &receipt.targets {
                used_devices.insert(target.device_index);
            }
            if used_devices.len() == device_count {
                break;
            }
        }

        assert_eq!(
            used_devices.len(),
            device_count,
            "pool-wide placement must use all {} eligible devices, used {:?}",
            device_count,
            used_devices
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pool_wide_placement_erasure_uses_all_eligible_devices() {
        let root = temp_dir("pool-wide-erasure-usage");
        let _ = std::fs::remove_dir_all(&root);
        let device_count: usize = 10;
        let config = multi_data_device_config(&root, device_count);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::erasure(4, 2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let mut used_devices = std::collections::BTreeSet::new();
        for i in 0..2048u64 {
            let key = ObjectKey::from_name(format!("erasure-usage-{i}").as_bytes());
            pool.put(IoClass::Data, key, format!("payload-{i}").as_bytes())
                .unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt must persist");
            assert_eq!(
                receipt.targets.len(),
                6,
                "erasure(4,2) must place exactly 6 targets per allocation"
            );
            for target in &receipt.targets {
                used_devices.insert(target.device_index);
            }
            if used_devices.len() == device_count {
                break;
            }
        }

        assert_eq!(
            used_devices.len(),
            device_count,
            "pool-wide erasure placement must use all {} devices, used {:?}",
            device_count,
            used_devices
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // -- pool-wide placement: no fixed vdev subset owns all stripes ---------

    #[test]
    fn pool_wide_placement_no_fixed_device_subset_owns_all_stripes() {
        let root = temp_dir("no-fixed-vdev-subset");
        let _ = std::fs::remove_dir_all(&root);
        let device_count: usize = 8;
        let config = multi_data_device_config(&root, device_count);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(3),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(config, properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        // Track per-device allocation counts.
        let mut device_alloc_count: Vec<u64> = vec![0; device_count];
        let total_allocations: usize = 512;

        for i in 0..total_allocations {
            let key = ObjectKey::from_name(format!("stripe-{i}").as_bytes());
            pool.put(IoClass::Data, key, format!("payload-{i}").as_bytes())
                .unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt must persist");
            for target in &receipt.targets {
                let idx = target.device_index as usize;
                device_alloc_count[idx] = device_alloc_count[idx].saturating_add(1);
            }
        }

        // Every device must have received at least some allocations.
        let min_allocations = device_alloc_count.iter().min().copied().unwrap_or(0);
        assert!(
            min_allocations > 0,
            "no device should be left with zero allocations: {:?}",
            device_alloc_count
        );

        // No single device should dominate -- each device gets a roughly fair share.
        let max_allocations = device_alloc_count.iter().max().copied().unwrap_or(0);
        let expected_avg = (total_allocations * 3) as u64 / device_count as u64;
        // Allow generous headroom; the point is to detect fixed-subset
        // behaviour where 1-2 devices get everything.
        let cap = expected_avg.saturating_mul(4).max(10);
        assert!(
            max_allocations <= cap,
            "no device should dominate: max {} vs expected-avg {}, counts {:?}",
            max_allocations,
            expected_avg,
            device_alloc_count
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // -- pool-wide placement: redundancy determines target width ------------

    #[test]
    fn redundancy_policy_determines_placement_target_width() {
        let root = temp_dir("redundancy-target-width");
        let _ = std::fs::remove_dir_all(&root);

        // Replicated(1) --> 1 target
        {
            let config = multi_data_device_config(&root.join("rep1"), 4);
            let props = PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::replicated(1),
                ..PoolProperties::default()
            };
            let mut pool = Pool::create(config, props, &test_options()).unwrap();
            set_deterministic_device_guids(&mut pool);
            let key = ObjectKey::from_name(b"rep1-obj");
            pool.put(IoClass::Data, key, b"a").unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt");
            assert_eq!(receipt.targets.len(), 1);
            let _ = std::fs::remove_dir_all(&root.join("rep1"));
        }

        // Replicated(3) --> 3 targets
        {
            let config = multi_data_device_config(&root.join("rep3"), 5);
            let props = PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::replicated(3),
                ..PoolProperties::default()
            };
            let mut pool = Pool::create(config, props, &test_options()).unwrap();
            set_deterministic_device_guids(&mut pool);
            let key = ObjectKey::from_name(b"rep3-obj");
            pool.put(IoClass::Data, key, b"abc").unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt");
            assert_eq!(receipt.targets.len(), 3);
            let _ = std::fs::remove_dir_all(&root.join("rep3"));
        }

        // Erasure(2,1) --> 3 targets (2 data + 1 parity)
        {
            let config = multi_data_device_config(&root.join("ec21"), 5);
            let props = PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::erasure(2, 1),
                ..PoolProperties::default()
            };
            let mut pool = Pool::create(config, props, &test_options()).unwrap();
            set_deterministic_device_guids(&mut pool);
            let key = ObjectKey::from_name(b"ec21-obj");
            pool.put(IoClass::Data, key, b"erasure data").unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt");
            assert_eq!(receipt.targets.len(), 3);
            let _ = std::fs::remove_dir_all(&root.join("ec21"));
        }

        // Erasure(4,2) --> 6 targets (4 data + 2 parity)
        {
            let config = multi_data_device_config(&root.join("ec42"), 8);
            let props = PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::erasure(4, 2),
                ..PoolProperties::default()
            };
            let mut pool = Pool::create(config, props, &test_options()).unwrap();
            set_deterministic_device_guids(&mut pool);
            let key = ObjectKey::from_name(b"ec42-obj");
            pool.put(IoClass::Data, key, b"four data shards payload")
                .unwrap();
            let receipt = pool
                .placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .expect("receipt");
            assert_eq!(receipt.targets.len(), 6);
            let _ = std::fs::remove_dir_all(&root.join("ec42"));
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    struct PendingReplicatedRepairFixture {
        root: PathBuf,
        pool: Pool,
        key: ObjectKey,
        payload: Vec<u8>,
        predecessor: PlacementReceipt,
        replacement: PlacementReceipt,
        source_index: usize,
        repaired_index: usize,
    }

    fn replicated_repair_pending_prepublication_fixture(
        label: &str,
    ) -> PendingReplicatedRepairFixture {
        let root = temp_dir(label);
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(label.as_bytes());
        let payload = format!("pending replicated repair fixture: {label}").into_bytes();
        let (_, predecessor) = pool
            .put_with_receipt(IoClass::Data, key, &payload)
            .expect("publish predecessor repair receipt");
        let source_index = pool
            .resolve_receipt_target(&predecessor.targets[0])
            .expect("resolve repair source");
        let repaired_index = pool
            .resolve_receipt_target(&predecessor.targets[1])
            .expect("resolve repair target");
        let mut corrupt = payload.clone();
        corrupt[0] ^= 0x5a;
        pool.devices[repaired_index]
            .put(key, &corrupt)
            .expect("corrupt pending repair target");
        pool.devices[repaired_index]
            .sync_strict_pool_authority()
            .expect("sync pending repair corruption");
        pool.fail_replicated_repair_after_reclaim_intent_once = true;
        let failure = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &predecessor,
                predecessor.targets[0].device_index,
                predecessor.targets[1].device_index,
            )
            .expect_err("fixture stops after the durable reclaim intent");
        assert_eq!(
            failure.receipt_publication,
            ReplicatedRepairReceiptPublicationState::NotAttempted
        );
        let mut replacement = predecessor.clone();
        replacement.generation = failure
            .replacement_generation
            .expect("pending repair owns a burned replacement generation");
        assert!(replacement.generation > predecessor.generation);
        assert_replicated_repair_receipt_copies(&pool, &predecessor);
        PendingReplicatedRepairFixture {
            root,
            pool,
            key,
            payload,
            predecessor,
            replacement,
            source_index,
            repaired_index,
        }
    }

    fn replicated_repair_pending_postpublication_fixture(
        label: &str,
    ) -> PendingReplicatedRepairFixture {
        let root = temp_dir(label);
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(label.as_bytes());
        let payload = format!("published pending replicated repair: {label}").into_bytes();
        let (_, predecessor) = pool
            .put_with_receipt(IoClass::Data, key, &payload)
            .expect("publish predecessor repair receipt");
        let source_index = pool
            .resolve_receipt_target(&predecessor.targets[0])
            .expect("resolve repair source");
        let repaired_index = pool
            .resolve_receipt_target(&predecessor.targets[1])
            .expect("resolve repair target");
        let mut corrupt = payload.clone();
        corrupt[0] ^= 0x5a;
        pool.devices[repaired_index]
            .put(key, &corrupt)
            .expect("corrupt repair target before publication");
        pool.devices[repaired_index]
            .sync_strict_pool_authority()
            .expect("sync repair target corruption");
        pool.fail_replicated_repair_after_receipt_publication_once = true;
        let failure = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &predecessor,
                predecessor.targets[0].device_index,
                predecessor.targets[1].device_index,
            )
            .expect_err("fixture stops after replacement receipt publication");
        assert_eq!(
            failure.receipt_publication,
            ReplicatedRepairReceiptPublicationState::Completed
        );
        let mut replacement = predecessor.clone();
        replacement.generation = failure
            .replacement_generation
            .expect("published repair reports its replacement generation");
        assert_replicated_repair_receipt_copies(&pool, &replacement);
        PendingReplicatedRepairFixture {
            root,
            pool,
            key,
            payload,
            predecessor,
            replacement,
            source_index,
            repaired_index,
        }
    }

    fn assert_replicated_repair_receipt_copies(pool: &Pool, expected: &PlacementReceipt) {
        let receipt_key = placement_receipt_object_key(expected.object_key);
        let encoded = expected.encode().expect("encode expected repair receipt");
        for &index in pool.class_map.get(IoClass::Data) {
            let visible = pool.devices[index]
                .get(receipt_key)
                .expect("read visible repair receipt")
                .expect("repair receipt remains visible");
            assert_eq!(
                visible, encoded,
                "visible receipt differs on carrier {index}"
            );
            let physical = pool.devices[index]
                .placement_receipt_candidates()
                .expect("scan physical repair receipt copies")
                .into_iter()
                .filter(|(key, _)| *key == receipt_key)
                .map(|(_, payload)| payload)
                .collect::<Vec<_>>();
            assert!(
                !physical.is_empty(),
                "carrier {index} must retain a physical receipt copy"
            );
            assert!(
                physical.iter().all(|payload| payload == &encoded),
                "carrier {index} has a non-converged physical receipt copy"
            );
        }
    }

    fn replicated_repair_payload_locations(
        pool: &Pool,
        key: ObjectKey,
    ) -> Vec<Option<ObjectLocation>> {
        pool.devices
            .iter()
            .map(|device| device.store().location_of(key))
            .collect()
    }

    fn assert_completed_pending_replicated_repair(
        fixture: &PendingReplicatedRepairFixture,
        completed: &ReplicatedRepairReconciliationEvidence,
    ) {
        assert_eq!(
            completed.embedded_predecessor_generation,
            fixture.predecessor.generation
        );
        assert_eq!(completed.current_receipt, fixture.replacement);
        assert_eq!(completed.repaired_target, fixture.predecessor.targets[1]);
        assert!(completed.replacement_receipt_attached);
        assert_eq!(
            fixture
                .pool
                .replicated_repair_reconciliation_evidence(
                    IoClass::Data,
                    fixture.key,
                    fixture.predecessor.generation,
                )
                .expect("read completed repair reconciliation evidence"),
            Some(completed.clone())
        );
        assert_replicated_repair_receipt_copies(&fixture.pool, &fixture.replacement);
        let targets = fixture
            .pool
            .replicated_receipt_evidence(IoClass::Data, fixture.key)
            .expect("read completed repair target evidence")
            .expect("completed repair receipt exists");
        assert_eq!(targets.receipt, fixture.replacement);
        assert!(targets
            .targets
            .iter()
            .all(|target| matches!(target.outcome, ReplicatedTargetReadOutcome::Clean)));
        assert!(fixture
            .pool
            .pending_replicated_repair_recovery_evidence(IoClass::Data)
            .expect("rescan completed pending repairs")
            .is_none());
    }

    #[test]
    fn replicated_repair_recovery_completes_all_predecessor_copies_with_bad_target() {
        let mut fixture = replicated_repair_pending_prepublication_fixture(
            "replicated-repair-recovery-all-predecessor-bad",
        );
        let discovered = fixture
            .pool
            .pending_replicated_repair_recovery_evidence(IoClass::Data)
            .expect("discover all-predecessor pending repair")
            .expect("pending repair evidence");
        assert_eq!(
            discovered.receipt_copies,
            PendingReplicatedRepairReceiptCopies::Predecessor
        );
        assert_eq!(
            discovered.target_state,
            PendingReplicatedRepairTargetState::NeedsRewrite
        );
        assert_eq!(discovered.predecessor_receipt, fixture.predecessor);
        assert_eq!(discovered.replacement_receipt, fixture.replacement);
        assert_eq!(discovered.clean_source, fixture.predecessor.targets[0]);
        assert_eq!(discovered.repaired_target, fixture.predecessor.targets[1]);
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        let completed = fixture
            .pool
            .complete_pending_replicated_repair_before_owner(IoClass::Data, &discovered)
            .expect("complete bad pending repair target");

        let locations_after = replicated_repair_payload_locations(&fixture.pool, fixture.key);
        for (index, before) in locations_before.iter().enumerate() {
            if index == fixture.repaired_index {
                assert_ne!(
                    &locations_after[index], before,
                    "bad pending target must be rewritten exactly once"
                );
            } else {
                assert_eq!(
                    &locations_after[index], before,
                    "completion must not rewrite an unrelated target"
                );
            }
        }
        assert_eq!(
            fixture.pool.devices[fixture.source_index]
                .get(fixture.key)
                .unwrap(),
            Some(fixture.payload.clone())
        );
        assert_completed_pending_replicated_repair(&fixture, &completed);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_recovery_publishes_all_predecessor_copies_with_clean_target() {
        let mut fixture = replicated_repair_pending_prepublication_fixture(
            "replicated-repair-recovery-all-predecessor-clean",
        );
        fixture.pool.devices[fixture.repaired_index]
            .put(fixture.key, &fixture.payload)
            .expect("simulate completed target write before crash");
        fixture.pool.devices[fixture.repaired_index]
            .sync_strict_pool_authority()
            .expect("sync simulated completed target write");
        let discovered = fixture
            .pool
            .pending_replicated_repair_recovery_evidence(IoClass::Data)
            .expect("discover clean all-predecessor repair")
            .expect("pending repair evidence");
        assert_eq!(
            discovered.receipt_copies,
            PendingReplicatedRepairReceiptCopies::Predecessor
        );
        assert_eq!(
            discovered.target_state,
            PendingReplicatedRepairTargetState::Clean
        );
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        let completed = fixture
            .pool
            .complete_pending_replicated_repair_before_owner(IoClass::Data, &discovered)
            .expect("publish burned generation for already-clean target");

        assert_eq!(
            replicated_repair_payload_locations(&fixture.pool, fixture.key),
            locations_before,
            "already-clean completion must not rewrite either target"
        );
        assert_completed_pending_replicated_repair(&fixture, &completed);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_recovery_converges_mixed_receipt_copies_without_payload_rewrite() {
        let mut fixture = replicated_repair_pending_prepublication_fixture(
            "replicated-repair-recovery-mixed-copies",
        );
        fixture.pool.devices[fixture.repaired_index]
            .put(fixture.key, &fixture.payload)
            .expect("simulate completed target write before partial publication");
        fixture.pool.devices[fixture.repaired_index]
            .sync_strict_pool_authority()
            .expect("sync simulated completed target write");
        let receipt_key = placement_receipt_object_key(fixture.key);
        fixture.pool.devices[fixture.source_index]
            .put_pool_internal(receipt_key, &fixture.replacement.encode().unwrap())
            .expect("publish one replacement receipt carrier");
        fixture.pool.devices[fixture.source_index]
            .sync_strict_pool_authority()
            .expect("sync one replacement receipt carrier");
        let discovered = fixture
            .pool
            .pending_replicated_repair_recovery_evidence(IoClass::Data)
            .expect("discover mixed repair receipt copies")
            .expect("mixed pending repair evidence");
        assert_eq!(
            discovered.receipt_copies,
            PendingReplicatedRepairReceiptCopies::Mixed
        );
        assert_eq!(
            discovered.target_state,
            PendingReplicatedRepairTargetState::Clean
        );
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        let completed = fixture
            .pool
            .complete_pending_replicated_repair_before_owner(IoClass::Data, &discovered)
            .expect("converge mixed repair receipt copies");

        assert_eq!(
            replicated_repair_payload_locations(&fixture.pool, fixture.key),
            locations_before,
            "mixed receipt convergence must not rewrite either clean target"
        );
        assert_completed_pending_replicated_repair(&fixture, &completed);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_recovery_attaches_all_replacement_copies_without_payload_rewrite() {
        let mut fixture = replicated_repair_pending_postpublication_fixture(
            "replicated-repair-recovery-all-replacement-clean",
        );
        let discovered = fixture
            .pool
            .pending_replicated_repair_recovery_evidence(IoClass::Data)
            .expect("discover fully published pending repair")
            .expect("published pending repair evidence");
        assert_eq!(
            discovered.receipt_copies,
            PendingReplicatedRepairReceiptCopies::Replacement
        );
        assert_eq!(
            discovered.target_state,
            PendingReplicatedRepairTargetState::Clean
        );
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        let completed = fixture
            .pool
            .complete_pending_replicated_repair_before_owner(IoClass::Data, &discovered)
            .expect("attach fully published pending repair");

        assert_eq!(
            replicated_repair_payload_locations(&fixture.pool, fixture.key),
            locations_before,
            "attachment-only completion must not rewrite either target"
        );
        assert_completed_pending_replicated_repair(&fixture, &completed);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_recovery_refuses_new_corruption_after_full_publication() {
        let mut fixture = replicated_repair_pending_postpublication_fixture(
            "replicated-repair-recovery-all-replacement-corrupt",
        );
        let mut corrupt = fixture.payload.clone();
        corrupt[0] ^= 0xa5;
        fixture.pool.devices[fixture.repaired_index]
            .put(fixture.key, &corrupt)
            .expect("inject new corruption after full receipt publication");
        fixture.pool.devices[fixture.repaired_index]
            .sync_strict_pool_authority()
            .expect("sync post-publication corruption");
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        assert_invalid_options_reason_contains(
            fixture
                .pool
                .pending_replicated_repair_recovery_evidence(IoClass::Data),
            "fully published repair receipt has new target corruption",
        );

        assert_eq!(
            replicated_repair_payload_locations(&fixture.pool, fixture.key),
            locations_before,
            "post-publication refusal must not mutate either target"
        );
        assert_replicated_repair_receipt_copies(&fixture.pool, &fixture.replacement);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_recovery_refuses_opposite_target_failure() {
        let mut fixture = replicated_repair_pending_prepublication_fixture(
            "replicated-repair-recovery-opposite-target-failure",
        );
        fixture.pool.devices[fixture.repaired_index]
            .put(fixture.key, &fixture.payload)
            .expect("simulate clean pending target before source failure");
        fixture.pool.devices[fixture.repaired_index]
            .sync_strict_pool_authority()
            .expect("sync clean pending target");
        let mut corrupt_source = fixture.payload.clone();
        corrupt_source[0] ^= 0x3c;
        fixture.pool.devices[fixture.source_index]
            .put(fixture.key, &corrupt_source)
            .expect("inject opposite-target failure");
        fixture.pool.devices[fixture.source_index]
            .sync_strict_pool_authority()
            .expect("sync opposite-target failure");
        let locations_before = replicated_repair_payload_locations(&fixture.pool, fixture.key);

        assert_invalid_options_reason_contains(
            fixture
                .pool
                .pending_replicated_repair_recovery_evidence(IoClass::Data),
            "pending replicated repair has a second failed target",
        );

        assert_eq!(
            replicated_repair_payload_locations(&fixture.pool, fixture.key),
            locations_before,
            "opposite-target refusal must not mutate either target"
        );
        assert_replicated_repair_receipt_copies(&fixture.pool, &fixture.predecessor);
        let root = fixture.root.clone();
        drop(fixture);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replicated_repair_requires_current_two_copy_pool_policy() {
        let root = temp_dir("replicated-repair-current-pool-policy");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(3),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-current-pool-policy");
        pool.put(IoClass::Data, key, b"three-copy policy payload")
            .unwrap();

        assert_invalid_options_reason_contains(
            pool.replicated_receipt_evidence(IoClass::Data, key),
            "exact two-copy current pool policy",
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_in_three_member_pool_changes_only_corrupt_target() {
        let root = temp_dir("replicated-repair-current-receipt");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        pool.put_with_receipt(
            IoClass::Data,
            ObjectKey::from_name(b"replicated-repair-predecessor-generation-primer"),
            b"advance the global receipt allocator before the repair fixture",
        )
        .unwrap();
        let key = ObjectKey::from_name(b"replicated-repair-current-receipt");
        let payload = b"receipt-authorized repair payload";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        assert_eq!(pool.class_map.get(IoClass::Data).len(), 3);
        assert_eq!(receipt.targets.len(), 2);
        let source_device_index = receipt.targets[0].device_index;
        let corrupt_device_index = receipt.targets[1].device_index;
        let corrupt_idx = pool.resolve_receipt_target(&receipt.targets[1]).unwrap();
        let source_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let non_target_idx = (0..pool.devices.len())
            .find(|idx| *idx != source_idx && *idx != corrupt_idx)
            .expect("three-member pool has one non-target receipt carrier");
        assert_eq!(pool.devices[non_target_idx].get(key).unwrap(), None);
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();
        let locations_before_repair = pool
            .devices
            .iter()
            .map(|device| device.store().location_of(key))
            .collect::<Vec<_>>();

        let before = pool
            .replicated_receipt_evidence(IoClass::Data, key)
            .unwrap()
            .expect("current receipt evidence");
        assert_eq!(before.receipt, receipt);
        assert!(matches!(
            before
                .targets
                .iter()
                .find(|target| target.target.device_index == source_device_index)
                .unwrap()
                .outcome,
            ReplicatedTargetReadOutcome::Clean
        ));
        assert!(matches!(
            before
                .targets
                .iter()
                .find(|target| target.target.device_index == corrupt_device_index)
                .unwrap()
                .outcome,
            ReplicatedTargetReadOutcome::Corrupt { .. }
        ));

        let repaired = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                source_device_index,
                corrupt_device_index,
            )
            .unwrap();
        assert_eq!(repaired.previous_receipt, receipt);
        assert!(repaired.replacement_receipt.generation > receipt.generation);
        assert_eq!(
            repaired.replacement_receipt.targets, receipt.targets,
            "target-only repair must retain the exact physical target set"
        );
        assert_eq!(repaired.source_device_index, source_device_index);
        assert_eq!(repaired.repaired_device_index, corrupt_device_index);
        for (idx, location_before) in locations_before_repair.iter().enumerate() {
            let location_after = pool.devices[idx].store().location_of(key);
            if idx == corrupt_idx {
                assert_ne!(
                    &location_after, location_before,
                    "targeted repair must replace the post-corruption target location"
                );
            } else {
                assert_eq!(
                    &location_after, location_before,
                    "targeted repair must not rewrite a clean or non-target payload"
                );
            }
        }
        assert_eq!(pool.devices[non_target_idx].get(key).unwrap(), None);
        let reconciliation = pool
            .replicated_repair_reconciliation_evidence(IoClass::Data, key, receipt.generation)
            .unwrap()
            .expect("successful target-only repair retains reconciliation evidence");
        assert_eq!(
            reconciliation.embedded_predecessor_generation,
            receipt.generation
        );
        assert_eq!(
            pool.replicated_repair_reconciliation_evidence(
                IoClass::Data,
                key,
                receipt.generation - 1,
            )
            .unwrap(),
            None,
            "durable target-only evidence must reject any other lower generation"
        );
        assert_eq!(reconciliation.current_receipt, repaired.replacement_receipt);
        assert_eq!(
            reconciliation.repaired_target.device_index,
            corrupt_device_index
        );
        assert!(reconciliation.replacement_receipt_attached);
        for idx in 0..pool.devices.len() {
            let reclaim = pool.devices[idx]
                .store_mut()
                .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                    u64::MAX,
                    repaired.replacement_receipt.generation,
                    0,
                )
                .unwrap();
            assert_eq!(
                reclaim.reclaim_queue_depth,
                if idx == corrupt_idx { 1 } else { 0 },
                "only the corrupt payload target may enter receipt-bound reclaim"
            );
        }
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key)
                .unwrap()
                .map(|(payload, _)| payload),
            Some(payload.to_vec())
        );
        let after = pool
            .replicated_receipt_evidence(IoClass::Data, key)
            .unwrap()
            .expect("replacement receipt evidence");
        assert!(after
            .targets
            .iter()
            .all(|target| matches!(target.outcome, ReplicatedTargetReadOutcome::Clean)));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_refuses_without_one_clean_target() {
        let root = temp_dir("replicated-repair-no-clean-target");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-no-clean-target");
        let payload = b"both replicas lose source authority";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        for (position, target) in receipt.targets.iter().enumerate() {
            let idx = pool.resolve_receipt_target(target).unwrap();
            let mut corrupt = payload.to_vec();
            corrupt[0] ^= (position as u8) + 1;
            pool.devices[idx].put(key, &corrupt).unwrap();
        }
        let payloads_before = pool
            .devices
            .iter()
            .map(|device| device.get(key).unwrap())
            .collect::<Vec<_>>();
        let error = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .unwrap_err();
        assert!(!error.writeback_started);
        assert_eq!(error.replacement_generation, None);
        assert_eq!(
            error.receipt_publication,
            ReplicatedRepairReceiptPublicationState::NotAttempted
        );
        assert!(matches!(
            &error.error,
            StoreError::InvalidOptions {
                reason: "replicated repair selected source is not receipt-clean"
            }
        ));
        assert_eq!(
            pool.devices
                .iter()
                .map(|device| device.get(key).unwrap())
                .collect::<Vec<_>>(),
            payloads_before,
            "refused repair must not mutate either target"
        );
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key).unwrap(),
            Some(receipt)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_can_repair_the_same_target_again() {
        let root = temp_dir("replicated-repair-same-target-again");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-same-target-again");
        let payload = b"one physical target may fail more than once";
        let (_, first_receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let source_device_index = first_receipt.targets[0].device_index;
        let corrupt_device_index = first_receipt.targets[1].device_index;
        let corrupt_idx = pool
            .resolve_receipt_target(&first_receipt.targets[1])
            .unwrap();

        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();
        let first_repair = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &first_receipt,
                source_device_index,
                corrupt_device_index,
            )
            .expect("first target repair");

        let mut corrupt_again = payload.to_vec();
        corrupt_again[0] ^= 0xa5;
        pool.devices[corrupt_idx].put(key, &corrupt_again).unwrap();
        let second_repair = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &first_repair.replacement_receipt,
                source_device_index,
                corrupt_device_index,
            )
            .expect("second repair preserves a second exact target lifetime");

        assert!(
            second_repair.replacement_receipt.generation
                > first_repair.replacement_receipt.generation
        );
        assert_eq!(
            pool.devices[corrupt_idx].get(key).unwrap(),
            Some(payload.to_vec())
        );
        assert_eq!(
            pool.replicated_repair_reconciliation_evidence(
                IoClass::Data,
                key,
                first_repair.replacement_receipt.generation,
            )
            .unwrap()
            .map(|evidence| evidence.current_receipt),
            Some(second_repair.replacement_receipt.clone())
        );
        assert_eq!(
            pool.replicated_repair_reconciliation_evidence(
                IoClass::Data,
                key,
                first_receipt.generation,
            )
            .unwrap(),
            None,
            "newer transition evidence must not impersonate the retired transition"
        );
        let reclaim_rows = pool.devices[corrupt_idx]
            .store()
            .receipt_bound_dead_object_lifetimes_for_logical_key_pool_internal(key)
            .expect("resolve same-key repair lifetimes");
        assert_eq!(reclaim_rows.len(), 2);
        assert_ne!(reclaim_rows[0].0.object_id, reclaim_rows[1].0.object_id);
        assert_ne!(reclaim_rows[0].1.location, reclaim_rows[1].1.location);
        assert!(reclaim_rows
            .iter()
            .all(|(entry, _)| entry.replacement_receipt.is_some()));
        let reclaim = pool.devices[corrupt_idx]
            .store_mut()
            .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                u64::MAX,
                second_repair.replacement_receipt.generation,
                0,
            )
            .unwrap();
        assert_eq!(reclaim.reclaim_queue_depth, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_generation_reservation_failure_reports_writeback() {
        let root = temp_dir("replicated-repair-generation-reservation-writeback");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-generation-reservation-writeback");
        let payload = b"generation reservation is durable repair writeback";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let corrupt_idx = pool.resolve_receipt_target(&receipt.targets[1]).unwrap();
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();

        let reserved_before = pool.reserved_placement_receipt_generation_through;
        pool.next_placement_receipt_generation = reserved_before + 1;
        pool.fail_replicated_repair_after_generation_allocation_once = true;
        let error = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .unwrap_err();

        assert!(error.writeback_started);
        assert_eq!(error.replacement_generation, Some(reserved_before + 1));
        assert!(pool.reserved_placement_receipt_generation_through > reserved_before);
        assert_eq!(
            error.receipt_publication,
            ReplicatedRepairReceiptPublicationState::NotAttempted
        );
        assert!(matches!(
            error.error,
            StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after generation allocation"
            }
        ));
        assert_eq!(pool.devices[corrupt_idx].get(key).unwrap(), Some(corrupt));
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key).unwrap(),
            Some(receipt)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_failure_after_reclaim_intent_reports_writeback_started() {
        let root = temp_dir("replicated-repair-after-reclaim-intent");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-after-reclaim-intent");
        let payload = b"reclaim intent is persistent repair writeback";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let source_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let corrupt_idx = pool.resolve_receipt_target(&receipt.targets[1]).unwrap();
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();
        let locations_before_repair = pool
            .devices
            .iter()
            .map(|device| device.store().location_of(key))
            .collect::<Vec<_>>();
        pool.fail_replicated_repair_after_reclaim_intent_once = true;

        let error = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .unwrap_err();
        let replacement_generation = error
            .replacement_generation
            .expect("replacement generation allocated before reclaim intent");
        assert!(error.writeback_started);
        assert!(replacement_generation > receipt.generation);
        assert_eq!(
            error.receipt_publication,
            ReplicatedRepairReceiptPublicationState::NotAttempted
        );
        assert!(matches!(
            &error.error,
            StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after reclaim intent"
            }
        ));
        for (idx, location_before) in locations_before_repair.iter().enumerate() {
            assert_eq!(
                &pool.devices[idx].store().location_of(key),
                location_before,
                "reclaim-intent failure must precede payload replacement"
            );
        }
        assert_eq!(
            pool.devices[source_idx].get(key).unwrap(),
            Some(payload.to_vec())
        );
        assert_eq!(pool.devices[corrupt_idx].get(key).unwrap(), Some(corrupt));
        let reclaim = pool.devices[corrupt_idx]
            .store_mut()
            .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                u64::MAX,
                replacement_generation,
                0,
            )
            .unwrap();
        assert_eq!(reclaim.reclaim_queue_depth, 1);
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key).unwrap(),
            Some(receipt.clone())
        );

        let repaired = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .expect("retry resumes the exact durable reclaim intent");
        assert_eq!(
            repaired.replacement_receipt.generation, replacement_generation,
            "retry must reuse the generation owned by the pending transition"
        );
        assert_eq!(
            pool.devices[source_idx].get(key).unwrap(),
            Some(payload.to_vec())
        );
        assert_eq!(
            pool.devices[corrupt_idx].get(key).unwrap(),
            Some(payload.to_vec())
        );
        let reconciliation = pool
            .replicated_repair_reconciliation_evidence(IoClass::Data, key, receipt.generation)
            .unwrap()
            .expect("resumed target repair retains exact reconciliation evidence");
        assert_eq!(reconciliation.current_receipt, repaired.replacement_receipt);
        assert!(reconciliation.replacement_receipt_attached);
        let reclaim = pool.devices[corrupt_idx]
            .store_mut()
            .drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
                u64::MAX,
                replacement_generation,
                0,
            )
            .unwrap();
        assert_eq!(
            reclaim.reclaim_queue_depth, 1,
            "resume must not allocate a second object-key reclaim row"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_receipt_publication_error_reports_uncertain() {
        let root = temp_dir("replicated-repair-publication-uncertain");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 2),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-publication-uncertain");
        let payload = b"target bytes can change before publication fails";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let source_idx = pool.resolve_receipt_target(&receipt.targets[0]).unwrap();
        let corrupt_idx = pool.resolve_receipt_target(&receipt.targets[1]).unwrap();
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();
        let source_location_before = pool.devices[source_idx].store().location_of(key);
        let corrupt_location_before = pool.devices[corrupt_idx].store().location_of(key);
        pool.fail_placement_receipt_verification_once = true;

        let error = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .unwrap_err();
        let replacement_generation = error
            .replacement_generation
            .expect("replacement generation allocated before target writeback");
        assert!(error.writeback_started);
        assert!(replacement_generation > receipt.generation);
        assert_eq!(
            error.receipt_publication,
            ReplicatedRepairReceiptPublicationState::Uncertain
        );
        assert!(matches!(
            &error.error,
            StoreError::InvalidOptions {
                reason: "test fault: placement receipt verification failed"
            }
        ));
        assert_eq!(
            pool.devices[source_idx].store().location_of(key),
            source_location_before
        );
        assert_ne!(
            pool.devices[corrupt_idx].store().location_of(key),
            corrupt_location_before,
            "target writeback must remain visible even though publication returned an error"
        );
        assert_eq!(
            pool.get_with_current_receipt(IoClass::Data, key).unwrap(),
            Some((payload.to_vec(), receipt.clone()))
        );
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key).unwrap(),
            Some(receipt)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_post_publication_error_reports_completed() {
        let root = temp_dir("replicated-repair-publication-completed");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let config = multi_data_device_config(&root, 2);
        let options = test_options();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options).unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-publication-completed");
        let payload = b"published receipt remains authoritative after later failure";
        let (_, receipt) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let corrupt_idx = pool.resolve_receipt_target(&receipt.targets[1]).unwrap();
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0x5a;
        pool.devices[corrupt_idx].put(key, &corrupt).unwrap();
        pool.fail_replicated_repair_after_receipt_publication_once = true;

        let error = pool
            .repair_current_replicated_target(
                IoClass::Data,
                key,
                &receipt,
                receipt.targets[0].device_index,
                receipt.targets[1].device_index,
            )
            .unwrap_err();
        let replacement_generation = error
            .replacement_generation
            .expect("published repair carries its replacement generation");
        assert!(error.writeback_started);
        assert!(replacement_generation > receipt.generation);
        assert_eq!(
            error.receipt_publication,
            ReplicatedRepairReceiptPublicationState::Completed
        );
        assert!(matches!(
            &error.error,
            StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after receipt publication"
            }
        ));
        let (repaired_payload, current_receipt) = pool
            .get_with_current_receipt(IoClass::Data, key)
            .unwrap()
            .expect("published replacement receipt remains current");
        assert_eq!(repaired_payload, payload);
        assert_eq!(current_receipt.generation, replacement_generation);
        assert_eq!(
            pool.placement_receipt_for_key(IoClass::Data, key)
                .unwrap()
                .map(|current| current.generation),
            Some(replacement_generation)
        );
        let reconciliation = pool
            .replicated_repair_reconciliation_evidence(IoClass::Data, key, receipt.generation)
            .unwrap()
            .expect("published repair with pending attachment is resumable");
        assert_eq!(
            reconciliation.current_receipt.generation,
            replacement_generation
        );
        assert_eq!(
            reconciliation.repaired_target.device_index,
            receipt.targets[1].device_index
        );
        assert!(!reconciliation.replacement_receipt_attached);
        drop(pool);

        let mut pool = Pool::open(config, properties, &options)
            .expect("reopen published repair with pending reclaim attachment");
        let reopened = pool
            .replicated_repair_reconciliation_evidence(IoClass::Data, key, receipt.generation)
            .unwrap()
            .expect("pending repair attachment survives reopen");
        assert_eq!(reopened, reconciliation);
        let completed = pool
            .complete_replicated_repair_reclaim_attachment(IoClass::Data, key, receipt.generation)
            .unwrap()
            .expect("exact published repair can complete pending reclaim attachment");
        assert!(completed.replacement_receipt_attached);
        assert_eq!(completed.current_receipt.generation, replacement_generation);
        assert_eq!(
            pool.complete_replicated_repair_reclaim_attachment(
                IoClass::Data,
                key,
                receipt.generation,
            )
            .unwrap(),
            Some(completed),
            "reclaim attachment completion must be idempotent"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replicated_repair_reconciliation_refuses_ordinary_rewrite() {
        let root = temp_dir("replicated-repair-reconciliation-ordinary-rewrite");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
            ..PoolProperties::default()
        };
        let mut pool = Pool::create(
            multi_data_device_config(&root, 3),
            properties,
            &test_options(),
        )
        .unwrap();
        set_deterministic_device_guids(&mut pool);
        let key = ObjectKey::from_name(b"replicated-repair-reconciliation-ordinary-rewrite");
        let payload = b"ordinary rewrite is not target-only repair evidence";
        let (_, predecessor) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        let (_, current) = pool.put_with_receipt(IoClass::Data, key, payload).unwrap();
        assert!(current.generation > predecessor.generation);

        assert_eq!(
            pool.replicated_repair_reconciliation_evidence(
                IoClass::Data,
                key,
                predecessor.generation,
            )
            .unwrap(),
            None,
            "two-target ordinary rewrite reclaim evidence must not authorize repair retry"
        );
        assert_invalid_options_reason_contains(
            pool.replicated_repair_reconciliation_evidence(IoClass::Data, key, 0),
            "nonzero embedded predecessor generation",
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}

// ---------------------------------------------------------------------------
// Exact replicated-target repair and interrupted-transition recovery
// ---------------------------------------------------------------------------

impl Pool {
    /// Read every target of one exact current two-copy replicated receipt.
    ///
    /// This is the local Pool evidence boundary used before mounted repair.
    /// It never falls back to receiptless device scanning and it keeps missing,
    /// unreadable, and digest-mismatched targets distinct.
    pub fn replicated_receipt_evidence(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<ReplicatedReceiptEvidence>> {
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair evidence requires an unlocked pool",
            });
        }
        if self.allocation_fenced_device_guid.is_some() {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair evidence refuses an active device lifecycle fence",
            });
        }
        let exact_policy = PoolRedundancyPolicy::Replicated { copies: 2 };
        if self.properties.redundancy_policy != exact_policy {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair requires an exact two-copy current pool policy",
            });
        }
        let indices = self.class_map.get(class).to_vec();
        if indices.len() < 2 {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair requires at least two current class members",
            });
        }
        let Some(receipt) = self.load_current_placement_receipt_strict(&indices, key)? else {
            return Ok(None);
        };
        if receipt.policy != exact_policy || receipt.targets.len() != 2 {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair requires an exact two-copy current receipt",
            });
        }
        self.verify_strict_receipt_target_copies(&receipt)?;

        self.replicated_receipt_evidence_for_exact_receipt(class, receipt)
            .map(Some)
    }

    fn replicated_receipt_evidence_for_exact_receipt(
        &self,
        class: IoClass,
        receipt: PlacementReceipt,
    ) -> Result<ReplicatedReceiptEvidence> {
        let exact_policy = PoolRedundancyPolicy::Replicated { copies: 2 };
        if receipt.policy != exact_policy || receipt.targets.len() != 2 {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair recovery requires an exact two-copy receipt",
            });
        }
        let indices = self.class_map.get(class).to_vec();
        let mut targets = Vec::with_capacity(receipt.targets.len());
        for target in &receipt.targets {
            let Some(idx) = self.resolve_receipt_target(target) else {
                targets.push(ReplicatedTargetEvidence {
                    target: target.clone(),
                    outcome: ReplicatedTargetReadOutcome::Missing,
                    payload: None,
                });
                continue;
            };
            if !indices.contains(&idx) {
                return Err(StoreError::InvalidOptions {
                    reason: "replicated repair receipt target is outside the current class members",
                });
            }
            let (outcome, payload) = match self.devices[idx].get(receipt.object_key) {
                Ok(Some(payload)) => {
                    let actual_digest = digest32(&payload);
                    let actual_len = payload.len() as u64;
                    let clean = actual_len == receipt.payload_len
                        && actual_digest == receipt.payload_digest
                        && actual_digest == target.stored_digest;
                    if clean {
                        (ReplicatedTargetReadOutcome::Clean, Some(payload))
                    } else {
                        (
                            ReplicatedTargetReadOutcome::Corrupt {
                                actual_len,
                                actual_digest,
                            },
                            Some(payload),
                        )
                    }
                }
                Ok(None) => (ReplicatedTargetReadOutcome::Missing, None),
                Err(_) => (ReplicatedTargetReadOutcome::Unreadable, None),
            };
            targets.push(ReplicatedTargetEvidence {
                target: target.clone(),
                outcome,
                payload,
            });
        }
        targets.sort_by_key(|target| target.target.device_index);
        Ok(ReplicatedReceiptEvidence { receipt, targets })
    }

    /// Prove that a newer current receipt is the durable result of exactly one
    /// target-only replicated repair whose filesystem root is not reconciled.
    ///
    /// General rewrites and receipt states without exact one-target reclaim
    /// evidence return `None`; higher layers still authenticate the embedded
    /// predecessor root whose generation they supply.
    pub fn replicated_repair_reconciliation_evidence(
        &self,
        class: IoClass,
        key: ObjectKey,
        embedded_predecessor_generation: u64,
    ) -> Result<Option<ReplicatedRepairReconciliationEvidence>> {
        if embedded_predecessor_generation == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "replicated repair reconciliation requires a nonzero embedded predecessor generation",
            });
        }
        let Some(evidence) = self.replicated_receipt_evidence(class, key)? else {
            return Ok(None);
        };
        if evidence.receipt.generation <= embedded_predecessor_generation
            || evidence.targets.len() != 2
            || !evidence
                .targets
                .iter()
                .all(|target| matches!(target.outcome, ReplicatedTargetReadOutcome::Clean))
        {
            return Ok(None);
        }

        let mut entries = Vec::new();
        for &idx in self.class_map.get(class) {
            for (entry, lifetime) in self.devices[idx]
                .store()
                .receipt_bound_dead_object_lifetimes_for_logical_key_pool_internal(key)?
            {
                if entry.dataset_uuid == self.pool_guid
                    && entry.eligible
                    && entry.death_commit_group == evidence.receipt.generation
                    && entry.enqueued_at_txg == embedded_predecessor_generation
                {
                    entries.push((idx, entry, lifetime));
                }
            }
        }
        let [(repaired_runtime_index, entry, lifetime)] = entries.as_slice() else {
            return Ok(None);
        };

        let Some(repaired_target) = evidence
            .receipt
            .targets
            .iter()
            .find(|target| self.resolve_receipt_target(target) == Some(*repaired_runtime_index))
            .cloned()
        else {
            return Ok(None);
        };
        let replacement_receipt_attached = match entry.replacement_receipt {
            None => false,
            Some(attached)
                if attached
                    == dead_object_replacement_receipt_for_object(
                        key,
                        lifetime.reclaim_object_id,
                        &evidence.receipt,
                    )? =>
            {
                true
            }
            Some(_) => return Ok(None),
        };

        Ok(Some(ReplicatedRepairReconciliationEvidence {
            embedded_predecessor_generation,
            current_receipt: evidence.receipt,
            repaired_target,
            replacement_receipt_attached,
            reclaim_object_id: entry.object_id,
        }))
    }

    /// Discover every completed current-receipt repair transition that may
    /// still be referenced by a predecessor filesystem root.
    ///
    /// Older attached rows remain ordinary reclaim history. Only a row whose
    /// replacement generation is the exact current receipt can become
    /// reconciliation work.
    pub fn replicated_repair_reconciliation_evidence_all(
        &self,
        class: IoClass,
    ) -> Result<Vec<(ObjectKey, ReplicatedRepairReconciliationEvidence)>> {
        let mut pending_keys = BTreeSet::new();
        for device in &self.devices {
            for (entry, lifetime) in device
                .store()
                .receipt_bound_dead_object_physical_lifetimes_pool_internal()?
            {
                if entry.dataset_uuid == self.pool_guid
                    && entry.eligible
                    && entry.replacement_receipt.is_none()
                    && entry.enqueued_at_txg < entry.death_commit_group
                {
                    pending_keys.insert(lifetime.logical_object_key);
                }
            }
        }

        let mut subjects = BTreeSet::new();
        for &idx in self.class_map.get(class) {
            for (entry, lifetime) in self.devices[idx]
                .store()
                .receipt_bound_dead_object_physical_lifetimes_pool_internal()?
            {
                if entry.dataset_uuid == self.pool_guid
                    && entry.eligible
                    && entry.replacement_receipt.is_some()
                    && entry.enqueued_at_txg > 0
                    && entry.enqueued_at_txg < entry.death_commit_group
                    && !pending_keys.contains(&lifetime.logical_object_key)
                {
                    subjects.insert((lifetime.logical_object_key, entry.enqueued_at_txg));
                }
            }
        }

        let mut evidence = Vec::new();
        for (object_key, embedded_generation) in subjects {
            if let Some(candidate) = self.replicated_repair_reconciliation_evidence(
                class,
                object_key,
                embedded_generation,
            )? {
                evidence.push((object_key, candidate));
            }
        }
        evidence.sort_by_key(|(object_key, candidate)| {
            (
                *object_key,
                candidate.embedded_predecessor_generation,
                candidate.current_receipt.generation,
            )
        });
        Ok(evidence)
    }

    /// Idempotently attach the current replacement receipt to the exact
    /// target-only repair reclaim entry used for reconciliation-only retry.
    ///
    /// This never rewrites payload data or publishes a placement receipt.  It
    /// succeeds only when [`Self::replicated_repair_reconciliation_evidence`]
    /// first proves the exact predecessor-to-current transition and rechecks
    /// that same evidence after the durable queue update.
    pub fn complete_replicated_repair_reclaim_attachment(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        embedded_predecessor_generation: u64,
    ) -> Result<Option<ReplicatedRepairReconciliationEvidence>> {
        self.ensure_writable("complete replicated repair reclaim attachment")?;
        let Some(evidence) = self.replicated_repair_reconciliation_evidence(
            class,
            key,
            embedded_predecessor_generation,
        )?
        else {
            return Ok(None);
        };
        if evidence.replacement_receipt_attached {
            return Ok(Some(evidence));
        }

        let repaired_index = self
            .resolve_receipt_target(&evidence.repaired_target)
            .ok_or(StoreError::InvalidOptions {
                reason: "replicated repair reconciliation target is no longer attached",
            })?;
        let obsolete_target = ObsoletePhysicalPlacement {
            device_index: repaired_index,
            object_key: key,
            reclaim_object_id: evidence.reclaim_object_id,
        };
        self.attach_obsolete_placement_receipt(
            std::slice::from_ref(&obsolete_target),
            &evidence.current_receipt,
        )?;

        let Some(refreshed) = self.replicated_repair_reconciliation_evidence(
            class,
            key,
            embedded_predecessor_generation,
        )?
        else {
            return Err(StoreError::InvalidOptions {
                reason:
                    "replicated repair reconciliation evidence disappeared after reclaim attachment",
            });
        };
        if !refreshed.replacement_receipt_attached
            || refreshed.current_receipt != evidence.current_receipt
            || refreshed.repaired_target != evidence.repaired_target
            || refreshed.reclaim_object_id != evidence.reclaim_object_id
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "replicated repair reclaim attachment did not preserve exact repair evidence",
            });
        }
        Ok(Some(refreshed))
    }

    /// Discover one interrupted target-only repair without changing media.
    ///
    /// The pending reclaim row binds predecessor generation `G`, burned
    /// replacement generation `G2`, and one exact physical target. Receipt
    /// carriers may all contain `G`, be split between `G` and `G2`, or all
    /// contain `G2`; no other candidate is admitted. The returned evidence is
    /// intentionally not mutation authority. A higher layer must authenticate
    /// an exact predecessor filesystem root and object reference first.
    pub fn pending_replicated_repair_recovery_evidence(
        &self,
        class: IoClass,
    ) -> Result<Option<PendingReplicatedRepairRecoveryEvidence>> {
        Ok(self
            .pending_replicated_repair_recovery_evidence_all(class)?
            .into_iter()
            .next())
    }

    /// Discover every interrupted target-only repair in deterministic logical
    /// object and exact physical-lifetime order without changing media.
    pub fn pending_replicated_repair_recovery_evidence_all(
        &self,
        class: IoClass,
    ) -> Result<Vec<PendingReplicatedRepairRecoveryEvidence>> {
        if self.pending_device_removal_path()?.is_some()
            || self.has_device_replacement_predecessor_resume()
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "pending replicated repair cannot recover during a device lifecycle transition",
            });
        }

        let mut pending = Vec::new();
        for (device_index, device) in self.devices.iter().enumerate() {
            for (entry, lifetime) in device
                .store()
                .receipt_bound_dead_object_physical_lifetimes_pool_internal()?
            {
                if entry.dataset_uuid == self.pool_guid
                    && entry.eligible
                    && entry.replacement_receipt.is_none()
                    && entry.enqueued_at_txg < entry.death_commit_group
                {
                    pending.push((device_index, entry, lifetime));
                }
            }
        }
        pending.sort_by_key(|(device_index, entry, lifetime)| {
            (
                lifetime.logical_object_key,
                lifetime.reclaim_object_id,
                entry.enqueued_at_txg,
                entry.death_commit_group,
                *device_index,
            )
        });
        pending
            .into_iter()
            .map(|(pending_index, entry, lifetime)| {
                self.pending_replicated_repair_recovery_evidence_for_row(
                    class,
                    pending_index,
                    entry,
                    lifetime,
                )
            })
            .collect()
    }

    /// Stage one exact interrupted target-only repair for cross-crate crash
    /// recovery tests.
    ///
    /// This is a fault-cut helper, not repair authority: it deliberately
    /// stops before reclaim attachment and leaves the filesystem root
    /// unreconciled. The caller must first corrupt `repaired_device_index`
    /// under the exact current two-copy receipt. `Predecessor` leaves that
    /// target corrupt and every receipt copy unchanged. `Mixed` rewrites the
    /// target and publishes the replacement receipt on that carrier only.
    /// `Replacement` rewrites the target and publishes the replacement on
    /// every receipt carrier. All three forms durably enqueue the exact
    /// predecessor physical lifetime first.
    #[doc(hidden)]
    pub fn stage_pending_replicated_repair_for_recovery_test(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        source_device_index: u32,
        repaired_device_index: u32,
        receipt_copies: PendingReplicatedRepairReceiptCopies,
    ) -> Result<PendingReplicatedRepairRecoveryEvidence> {
        self.ensure_writable("stage pending replicated repair fault cut")?;
        let evidence =
            self.replicated_receipt_evidence(class, key)?
                .ok_or(StoreError::InvalidOptions {
                    reason: "pending repair fault cut requires a current placement receipt",
                })?;
        let predecessor_receipt = evidence.receipt.clone();
        if predecessor_receipt.policy != (PoolRedundancyPolicy::Replicated { copies: 2 })
            || predecessor_receipt.targets.len() != 2
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut requires an exact two-copy receipt",
            });
        }

        let source = evidence
            .targets
            .iter()
            .find(|target| target.target.device_index == source_device_index)
            .ok_or(StoreError::InvalidOptions {
                reason: "pending repair fault cut source is absent from the current receipt",
            })?;
        if !matches!(source.outcome, ReplicatedTargetReadOutcome::Clean) {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut source is not receipt-clean",
            });
        }
        let source_payload = source.payload.clone().ok_or(StoreError::InvalidOptions {
            reason: "pending repair fault cut source payload is absent",
        })?;
        let repaired = evidence
            .targets
            .iter()
            .find(|target| target.target.device_index == repaired_device_index)
            .ok_or(StoreError::InvalidOptions {
                reason: "pending repair fault cut target is absent from the current receipt",
            })?;
        if !matches!(
            repaired.outcome,
            ReplicatedTargetReadOutcome::Corrupt { .. } | ReplicatedTargetReadOutcome::Unreadable
        ) {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut target is not corrupt or unreadable",
            });
        }

        let source_index =
            self.resolve_receipt_target(&source.target)
                .ok_or(StoreError::InvalidOptions {
                    reason: "pending repair fault cut source is no longer attached",
                })?;
        let repaired_index =
            self.resolve_receipt_target(&repaired.target)
                .ok_or(StoreError::InvalidOptions {
                    reason: "pending repair fault cut target is no longer attached",
                })?;
        let indices = self.class_map.get(class).to_vec();
        if source_index == repaired_index
            || !indices.contains(&source_index)
            || !indices.contains(&repaired_index)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut source or target is outside class authority",
            });
        }
        if self
            .pending_replicated_repair_recovery_evidence_all(class)?
            .iter()
            .any(|pending| pending.predecessor_receipt.object_key == key)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut found an unfinished transition for this object",
            });
        }

        let lifetime = self.devices[repaired_index]
            .store()
            .current_receipt_bound_physical_lifetime_pool_internal(key)?;
        let mut writeback_started = false;
        let replacement_generation =
            self.allocate_placement_receipt_generation_reporting_writeback(&mut writeback_started)?;
        let mut replacement_receipt = predecessor_receipt.clone();
        replacement_receipt.generation = replacement_generation;
        self.ensure_receipt_replay_authority(&replacement_receipt)?;
        validate_strict_receipt_structure(&replacement_receipt)?;
        let pending_entry = DeadObjectEntry::new(
            lifetime.reclaim_object_id,
            self.pool_guid,
            replacement_generation,
            true,
            predecessor_receipt.generation,
        );
        if !self.devices[repaired_index]
            .store_mut()
            .enqueue_pending_receipt_bound_dead_object_pool_internal(pending_entry)?
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut collided with existing physical lifetime state",
            });
        }

        if receipt_copies != PendingReplicatedRepairReceiptCopies::Predecessor {
            self.devices[repaired_index].put(key, &source_payload)?;
            self.devices[repaired_index].sync_strict_pool_authority()?;
            match self.devices[repaired_index].get(key)? {
                Some(payload)
                    if payload == source_payload
                        && payload.len() as u64 == replacement_receipt.payload_len
                        && digest32(&payload) == replacement_receipt.payload_digest => {}
                _ => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending repair fault cut target rewrite did not verify",
                    })
                }
            }
        }

        match receipt_copies {
            PendingReplicatedRepairReceiptCopies::Predecessor => {}
            PendingReplicatedRepairReceiptCopies::Mixed => {
                let receipt_key = placement_receipt_object_key(key);
                let encoded = replacement_receipt.encode()?;
                self.devices[repaired_index].put_pool_internal(receipt_key, &encoded)?;
                self.devices[repaired_index].sync_strict_pool_authority()?;
            }
            PendingReplicatedRepairReceiptCopies::Replacement => {
                self.write_placement_receipt(&indices, &replacement_receipt)?;
            }
        }
        self.sync_all()?;

        let staged = self
            .pending_replicated_repair_recovery_evidence_all(class)?
            .into_iter()
            .find(|pending| {
                pending.predecessor_receipt.object_key == key
                    && pending.predecessor_receipt.generation == predecessor_receipt.generation
                    && pending.replacement_receipt.generation == replacement_generation
            })
            .ok_or(StoreError::InvalidOptions {
                reason: "pending repair fault cut did not produce discoverable exact evidence",
            })?;
        if staged.receipt_copies != receipt_copies {
            return Err(StoreError::InvalidOptions {
                reason: "pending repair fault cut did not preserve requested receipt-copy state",
            });
        }
        Ok(staged)
    }

    fn pending_replicated_repair_recovery_evidence_for_row(
        &self,
        class: IoClass,
        pending_index: usize,
        entry: DeadObjectEntry,
        lifetime: crate::store::ReceiptBoundPhysicalLifetime,
    ) -> Result<PendingReplicatedRepairRecoveryEvidence> {
        if entry.enqueued_at_txg == 0 || entry.death_commit_group == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair has a zero receipt generation",
            });
        }

        self.validate_loaded_receipt_generation_high_water()?;
        if entry.death_commit_group > self.reserved_placement_receipt_generation_through {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair exceeds durable receipt generation authority",
            });
        }

        if lifetime.reclaim_object_id != entry.object_id
            || lifetime.location.key != lifetime.logical_object_key
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair has inconsistent physical lifetime identity",
            });
        }
        let object_key = lifetime.logical_object_key;
        let receipt_key = placement_receipt_object_key(object_key);
        let indices = self.class_map.get(class).to_vec();
        if indices.len() < 2 || !indices.contains(&pending_index) {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair target is outside current class authority",
            });
        }

        let mut predecessor = None;
        let mut replacement = None;
        let mut saw_predecessor = false;
        let mut saw_replacement = false;
        for &idx in &indices {
            let physical = self.devices[idx]
                .placement_receipt_candidates()?
                .into_iter()
                .filter(|(candidate_key, _)| *candidate_key == receipt_key)
                .map(|(_, raw)| raw)
                .collect::<Vec<_>>();
            if physical.is_empty() {
                return Err(StoreError::InvalidOptions {
                    reason: "pending replicated repair has no physical receipt copy on a carrier",
                });
            }
            for raw in physical {
                let receipt = PlacementReceipt::decode(&raw).ok_or(StoreError::InvalidOptions {
                    reason: "pending replicated repair has a corrupt physical receipt copy",
                })?;
                if receipt.object_key != object_key
                    || placement_receipt_object_key(receipt.object_key) != receipt_key
                    || (receipt.generation != entry.enqueued_at_txg
                        && receipt.generation != entry.death_commit_group)
                {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending replicated repair found unrelated receipt authority",
                    });
                }
                self.ensure_receipt_replay_authority(&receipt)?;
                validate_strict_receipt_structure(&receipt)?;
                let slot = if receipt.generation == entry.enqueued_at_txg {
                    saw_predecessor = true;
                    &mut predecessor
                } else {
                    saw_replacement = true;
                    &mut replacement
                };
                if slot.as_ref().is_some_and(|known| known != &receipt) {
                    return Err(StoreError::InvalidOptions {
                        reason:
                            "pending replicated repair receipt generation is internally conflicting",
                    });
                }
                slot.get_or_insert(receipt);
            }
        }

        let (predecessor_receipt, replacement_receipt) = match (predecessor, replacement) {
            (Some(predecessor), Some(replacement)) => (predecessor, replacement),
            (Some(predecessor), None) => {
                let mut replacement = predecessor.clone();
                replacement.generation = entry.death_commit_group;
                (predecessor, replacement)
            }
            (None, Some(replacement)) => {
                let mut predecessor = replacement.clone();
                predecessor.generation = entry.enqueued_at_txg;
                (predecessor, replacement)
            }
            (None, None) => {
                return Err(StoreError::InvalidOptions {
                    reason: "pending replicated repair has no exact receipt authority",
                })
            }
        };
        let mut normalized_predecessor = predecessor_receipt.clone();
        normalized_predecessor.generation = replacement_receipt.generation;
        if normalized_predecessor != replacement_receipt
            || predecessor_receipt.generation != entry.enqueued_at_txg
            || replacement_receipt.generation != entry.death_commit_group
            || replacement_receipt.generation <= predecessor_receipt.generation
            || predecessor_receipt.policy != (PoolRedundancyPolicy::Replicated { copies: 2 })
            || predecessor_receipt.targets.len() != 2
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair receipts do not form one exact two-copy generation transition",
            });
        }
        self.ensure_receipt_replay_authority(&predecessor_receipt)?;
        self.ensure_receipt_replay_authority(&replacement_receipt)?;
        validate_strict_receipt_structure(&predecessor_receipt)?;
        validate_strict_receipt_structure(&replacement_receipt)?;

        let receipt_copies = match (saw_predecessor, saw_replacement) {
            (true, false) => PendingReplicatedRepairReceiptCopies::Predecessor,
            (true, true) => PendingReplicatedRepairReceiptCopies::Mixed,
            (false, true) => PendingReplicatedRepairReceiptCopies::Replacement,
            (false, false) => unreachable!("receipt candidates were required above"),
        };
        let repaired_target = predecessor_receipt
            .targets
            .iter()
            .find(|target| self.resolve_receipt_target(target) == Some(pending_index))
            .cloned()
            .ok_or(StoreError::InvalidOptions {
                reason: "pending replicated repair row does not bind one receipt target",
            })?;

        let mut target_evidence = Vec::with_capacity(2);
        for target in &predecessor_receipt.targets {
            let idx = self
                .resolve_receipt_target(target)
                .ok_or(StoreError::InvalidOptions {
                    reason: "pending replicated repair receipt target is no longer attached",
                })?;
            if !indices.contains(&idx) {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "pending replicated repair receipt target is outside current class members",
                });
            }
            let (outcome, payload) = match self.devices[idx].get(object_key) {
                Ok(Some(payload)) => {
                    let actual_digest = digest32(&payload);
                    let actual_len = payload.len() as u64;
                    if actual_len == predecessor_receipt.payload_len
                        && actual_digest == predecessor_receipt.payload_digest
                        && actual_digest == target.stored_digest
                    {
                        (ReplicatedTargetReadOutcome::Clean, Some(payload))
                    } else {
                        (
                            ReplicatedTargetReadOutcome::Corrupt {
                                actual_len,
                                actual_digest,
                            },
                            Some(payload),
                        )
                    }
                }
                Ok(None) => (ReplicatedTargetReadOutcome::Missing, None),
                Err(_) => (ReplicatedTargetReadOutcome::Unreadable, None),
            };
            target_evidence.push(ReplicatedTargetEvidence {
                target: target.clone(),
                outcome,
                payload,
            });
        }
        let repaired = target_evidence
            .iter()
            .find(|target| target.target == repaired_target)
            .ok_or(StoreError::InvalidOptions {
                reason: "pending replicated repair target evidence is absent",
            })?;
        let source = target_evidence
            .iter()
            .find(|target| target.target != repaired_target)
            .ok_or(StoreError::InvalidOptions {
                reason: "pending replicated repair clean source target is absent",
            })?;
        if !matches!(source.outcome, ReplicatedTargetReadOutcome::Clean) {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair has a second failed target",
            });
        }
        let clean_source_payload = source.payload.clone().ok_or(StoreError::InvalidOptions {
            reason: "pending replicated repair clean source payload is absent",
        })?;
        let target_state = match repaired.outcome {
            ReplicatedTargetReadOutcome::Clean => PendingReplicatedRepairTargetState::Clean,
            ReplicatedTargetReadOutcome::Corrupt { .. }
            | ReplicatedTargetReadOutcome::Unreadable
                if receipt_copies != PendingReplicatedRepairReceiptCopies::Replacement =>
            {
                PendingReplicatedRepairTargetState::NeedsRewrite
            }
            ReplicatedTargetReadOutcome::Corrupt { .. }
            | ReplicatedTargetReadOutcome::Unreadable => {
                return Err(StoreError::InvalidOptions {
                    reason: "fully published repair receipt has new target corruption",
                })
            }
            ReplicatedTargetReadOutcome::Missing => {
                return Err(StoreError::InvalidOptions {
                    reason: "pending replicated repair target is missing rather than repairable",
                })
            }
        };

        Ok(PendingReplicatedRepairRecoveryEvidence {
            predecessor_receipt,
            replacement_receipt,
            repaired_target,
            clean_source: source.target.clone(),
            receipt_copies,
            target_state,
            reclaim_object_id: entry.object_id,
            clean_source_payload,
        })
    }

    /// Complete one previously discovered repair transition after the caller
    /// authenticates the exact predecessor filesystem root and object
    /// reference. The discovery evidence is refreshed byte-for-byte before
    /// any write. Receipt convergence always verifies every carrier.
    pub fn complete_pending_replicated_repair_before_owner(
        &mut self,
        class: IoClass,
        expected: &PendingReplicatedRepairRecoveryEvidence,
    ) -> Result<ReplicatedRepairReconciliationEvidence> {
        self.ensure_writable("complete pending replicated repair")?;
        let current = self
            .pending_replicated_repair_recovery_evidence(class)?
            .ok_or(StoreError::InvalidOptions {
                reason: "pending replicated repair disappeared after root authentication",
            })?;
        if &current != expected {
            return Err(StoreError::InvalidOptions {
                reason: "pending replicated repair changed after root authentication",
            });
        }

        let indices = self.class_map.get(class).to_vec();
        let repaired_index = self
            .resolve_receipt_target(&current.repaired_target)
            .ok_or(StoreError::InvalidOptions {
                reason: "pending replicated repair target detached before completion",
            })?;
        if current.target_state == PendingReplicatedRepairTargetState::NeedsRewrite {
            let target_write = self.devices[repaired_index].put(
                current.predecessor_receipt.object_key,
                current.clean_source_payload(),
            );
            self.record_device_write_result(
                repaired_index,
                current.clean_source_payload().len(),
                &target_write,
            );
            target_write?;
            self.devices[repaired_index].sync_strict_pool_authority()?;
            match self.devices[repaired_index].get(current.predecessor_receipt.object_key)? {
                Some(payload)
                    if payload == current.clean_source_payload()
                        && payload.len() as u64 == current.replacement_receipt.payload_len
                        && digest32(&payload) == current.replacement_receipt.payload_digest => {}
                _ => {
                    return Err(StoreError::InvalidOptions {
                        reason: "pending replicated repair target failed recovery verification",
                    })
                }
            }
        }

        if current.receipt_copies == PendingReplicatedRepairReceiptCopies::Replacement {
            self.verify_placement_receipt_publication(&indices, &current.replacement_receipt)?;
        } else {
            self.write_placement_receipt(&indices, &current.replacement_receipt)?;
        }
        self.verify_placement_receipt_publication(&indices, &current.replacement_receipt)?;

        let obsolete_target = ObsoletePhysicalPlacement {
            device_index: repaired_index,
            object_key: current.predecessor_receipt.object_key,
            reclaim_object_id: current.reclaim_object_id,
        };
        self.attach_obsolete_placement_receipt(
            std::slice::from_ref(&obsolete_target),
            &current.replacement_receipt,
        )?;

        let evidence = self
            .replicated_repair_reconciliation_evidence(
                class,
                current.predecessor_receipt.object_key,
                current.predecessor_receipt.generation,
            )?
            .ok_or(StoreError::InvalidOptions {
                reason: "completed pending repair has no exact reconciliation evidence",
            })?;
        if evidence.current_receipt != current.replacement_receipt
            || evidence.repaired_target != current.repaired_target
            || evidence.reclaim_object_id != current.reclaim_object_id
            || !evidence.replacement_receipt_attached
        {
            return Err(StoreError::InvalidOptions {
                reason: "completed pending repair evidence changed during convergence",
            });
        }
        Ok(evidence)
    }

    /// Repair one corrupt target from the other clean target under an exact
    /// current two-copy receipt and publish a replacement receipt.
    ///
    /// The caller supplies the comparison-selected source and target, but this
    /// method rechecks the complete current receipt evidence immediately before
    /// writeback. Missing evidence, a stale receipt, and anything other than one
    /// clean plus one corrupt/unreadable target fail closed.
    pub fn repair_current_replicated_target(
        &mut self,
        class: IoClass,
        key: ObjectKey,
        expected_receipt: &PlacementReceipt,
        source_device_index: u32,
        corrupt_device_index: u32,
    ) -> std::result::Result<ReplicatedRepairResult, ReplicatedRepairFailure> {
        let mut progress = ReplicatedRepairProgress::new();
        self.ensure_writable("pool replicated repair")
            .map_err(|error| progress.failure(error))?;
        let evidence = self
            .replicated_receipt_evidence(class, key)
            .map_err(|error| progress.failure(error))?
            .ok_or_else(|| {
                progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair requires a current placement receipt",
                })
            })?;
        if evidence.receipt != *expected_receipt {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair evidence is stale relative to current receipt authority",
            }));
        }
        if source_device_index == corrupt_device_index {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair source and corrupt target must be distinct",
            }));
        }

        let mut source = None;
        let mut corrupt_target = None;
        for target in &evidence.targets {
            if target.target.device_index == source_device_index {
                if !matches!(target.outcome, ReplicatedTargetReadOutcome::Clean) {
                    return Err(progress.failure(StoreError::InvalidOptions {
                        reason: "replicated repair selected source is not receipt-clean",
                    }));
                }
                let payload = target.payload.clone().ok_or_else(|| {
                    progress.failure(StoreError::InvalidOptions {
                        reason: "replicated repair clean source payload is missing",
                    })
                })?;
                source = Some((target.target.clone(), payload));
            } else if target.target.device_index == corrupt_device_index {
                if matches!(
                    target.outcome,
                    ReplicatedTargetReadOutcome::Corrupt { .. }
                        | ReplicatedTargetReadOutcome::Unreadable
                ) {
                    corrupt_target = Some(target.target.clone());
                } else {
                    return Err(progress.failure(StoreError::InvalidOptions {
                        reason: "replicated repair selected target is not corrupt",
                    }));
                }
            } else {
                return Err(progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair evidence contains an unexpected third target",
                }));
            }
        }
        let (source_target, source_payload) = source.ok_or_else(|| {
            progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair clean source evidence is missing",
            })
        })?;
        let corrupt_target = corrupt_target.ok_or_else(|| {
            progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair corrupt target evidence is missing",
            })
        })?;
        if source_payload.len() as u64 != expected_receipt.payload_len
            || digest32(&source_payload) != expected_receipt.payload_digest
        {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason:
                    "replicated repair clean source no longer matches receipt payload authority",
            }));
        }

        let indices = self.class_map.get(class).to_vec();
        let source_index = self.resolve_receipt_target(&source_target).ok_or_else(|| {
            progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair source GUID is no longer attached",
            })
        })?;
        let corrupt_index = self
            .resolve_receipt_target(&corrupt_target)
            .ok_or_else(|| {
                progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair target GUID is no longer attached",
                })
            })?;
        if source_index == corrupt_index {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair source and target resolve to the same device",
            }));
        }
        if !indices.contains(&source_index) || !indices.contains(&corrupt_index) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair source or target is outside current class members",
            }));
        }

        self.check_write_admission(class, source_payload.len() as u64)
            .map_err(|error| progress.failure(error))?;
        let target_lifetime = self.devices[corrupt_index]
            .store()
            .current_receipt_bound_physical_lifetime_pool_internal(key)
            .map_err(|error| progress.failure(error))?;
        let reclaim_object_id = target_lifetime.reclaim_object_id;
        let mut existing_reclaim_entries = Vec::new();
        for &idx in &indices {
            for (entry, lifetime) in self.devices[idx]
                .store()
                .receipt_bound_dead_object_lifetimes_for_logical_key_pool_internal(key)
                .map_err(|error| progress.failure(error))?
            {
                existing_reclaim_entries.push((idx, entry, lifetime));
            }
        }
        let pending_repair_entries = existing_reclaim_entries
            .iter()
            .copied()
            .filter(|(_, entry, _)| {
                entry.dataset_uuid == self.pool_guid
                    && entry.eligible
                    && entry.replacement_receipt.is_none()
                    && entry.enqueued_at_txg == expected_receipt.generation
                    && entry.death_commit_group > expected_receipt.generation
            })
            .collect::<Vec<_>>();
        if pending_repair_entries.len() > 1 {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair found multiple pending transitions for one predecessor receipt",
            }));
        }
        let pending_repair_entry = pending_repair_entries.first().copied();
        if pending_repair_entry.is_some_and(|(idx, entry, _)| {
            idx != corrupt_index || entry.object_id != reclaim_object_id
        }) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair pending transition targets a different current member",
            }));
        }
        if existing_reclaim_entries.iter().any(|(_, entry, _)| {
            entry.replacement_receipt.is_none()
                && entry.enqueued_at_txg < entry.death_commit_group
                && Some(*entry) != pending_repair_entry.map(|(_, entry, _)| entry)
        }) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair found an unrelated unfinished target transition",
            }));
        }

        let mut replacement_receipt = expected_receipt.clone();
        let replacement_generation = if let Some((_, pending, _)) = pending_repair_entry {
            // The durable pending entry exclusively owns this already-burned
            // generation. Reusing it resumes the exact enqueue-before-publish
            // transition instead of allocating a second generation that can
            // never match the idempotent object-key queue row.
            progress.writeback_started = true;
            pending.death_commit_group
        } else {
            self.allocate_placement_receipt_generation_reporting_writeback(
                &mut progress.writeback_started,
            )
            .map_err(|error| progress.failure(error))?
        };
        progress.replacement_generation = Some(replacement_generation);
        #[cfg(test)]
        if std::mem::take(&mut self.fail_replicated_repair_after_generation_allocation_once) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after generation allocation",
            }));
        }
        replacement_receipt.generation = replacement_generation;
        self.ensure_receipt_replay_authority(&replacement_receipt)
            .map_err(|error| progress.failure(error))?;
        validate_strict_receipt_structure(&replacement_receipt)
            .map_err(|error| progress.failure(error))?;
        if replacement_receipt.generation <= expected_receipt.generation
            || replacement_receipt.payload_digest != expected_receipt.payload_digest
            || replacement_receipt.payload_len != expected_receipt.payload_len
        {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason:
                    "replicated repair replacement receipt did not advance exact payload authority",
            }));
        }

        // Only the corrupt target's old physical record is superseded.  The
        // clean source remains the same physical authority under the advanced
        // receipt and must neither be rewritten nor queued for reclaim.
        let obsolete_target = ObsoletePhysicalPlacement {
            device_index: corrupt_index,
            object_key: key,
            reclaim_object_id,
        };
        let pending_entry = DeadObjectEntry::new(
            reclaim_object_id,
            self.pool_guid,
            replacement_receipt.generation,
            true,
            expected_receipt.generation,
        );
        // The durable reclaim-intent enqueue is the first repair writeback
        // unless generation-reservation publication already crossed that
        // boundary. A retry reuses the exact durable row. A later repair of
        // the same logical target receives a different physical-lifetime ID,
        // so every completed predecessor remains independently reclaimable.
        // It is enqueued while the predecessor receipt is still current, so
        // `enqueued_at_txg` binds that exact predecessor generation; the death
        // generation binds the replacement receipt under which this target's
        // old physical record becomes obsolete.  The pair is the durable
        // transition evidence used by reconciliation-only retry.
        if let Some((_, existing, lifetime)) = pending_repair_entry {
            if existing != pending_entry || lifetime != target_lifetime {
                return Err(progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair pending transition changed before resume",
                }));
            }
        } else {
            progress.writeback_started = true;
            let target_store = self.devices[corrupt_index].store_mut();
            if !target_store
                .enqueue_pending_receipt_bound_dead_object_pool_internal(pending_entry)
                .map_err(|error| progress.failure(error))?
            {
                return Err(progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair reclaim intent collided with existing target state",
                }));
            }
        }
        let repair_reclaim_entries = indices
            .iter()
            .filter_map(|idx| {
                self.devices[*idx]
                    .store()
                    .receipt_bound_dead_object_entry_pool_internal(&reclaim_object_id)
                    .map(|entry| (*idx, entry))
            })
            .filter(|(_, entry)| {
                entry.dataset_uuid == self.pool_guid
                    && entry.death_commit_group == replacement_receipt.generation
                    && entry.enqueued_at_txg == expected_receipt.generation
                    && entry.eligible
                    && entry.replacement_receipt.is_none()
            })
            .collect::<Vec<_>>();
        let [(queued_index, queued_entry)] = repair_reclaim_entries.as_slice() else {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair could not establish unique target-only reclaim evidence",
            }));
        };
        if *queued_index != corrupt_index || *queued_entry != pending_entry {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "replicated repair reclaim evidence does not bind the exact target and receipt transition",
            }));
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_replicated_repair_after_reclaim_intent_once) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after reclaim intent",
            }));
        }
        self.persist_active_labels_if_needed()
            .map_err(|error| progress.failure(error))?;

        let target_write = self.devices[corrupt_index].put(key, &source_payload);
        self.record_device_write_result(corrupt_index, source_payload.len(), &target_write);
        target_write.map_err(|error| progress.failure(error))?;
        self.devices[corrupt_index]
            .sync_strict_pool_authority()
            .map_err(|error| progress.failure(error))?;
        match self.devices[corrupt_index]
            .get(key)
            .map_err(|error| progress.failure(error))?
        {
            Some(payload)
                if payload == source_payload
                    && payload.len() as u64 == replacement_receipt.payload_len
                    && digest32(&payload) == replacement_receipt.payload_digest => {}
            _ => {
                return Err(progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair target failed pre-publication verification",
                }))
            }
        }

        progress.receipt_publication = ReplicatedRepairReceiptPublicationState::Uncertain;
        self.write_placement_receipt(&indices, &replacement_receipt)
            .map_err(|error| progress.failure(error))?;
        progress.receipt_publication = ReplicatedRepairReceiptPublicationState::Completed;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_replicated_repair_after_receipt_publication_once) {
            return Err(progress.failure(StoreError::InvalidOptions {
                reason: "test fault: replicated repair failed after receipt publication",
            }));
        }
        if let Err(error) = self.attach_obsolete_placement_receipt(
            std::slice::from_ref(&obsolete_target),
            &replacement_receipt,
        ) {
            eprintln!(
                "tidefs: targeted repair receipt generation {} committed for {key:?}; obsolete target reclaim remains pending: {error}",
                replacement_receipt.generation
            );
        }

        let prior_deletions = self
            .pending_deletions
            .values()
            .filter(|pending| {
                pending.class == class
                    && pending.receipt.object_key == key
                    && pending.receipt.generation < replacement_receipt.generation
            })
            .cloned()
            .collect::<Vec<_>>();
        for pending in prior_deletions {
            if let Err(error) = self.reconcile_one_pending_deletion(&pending) {
                eprintln!(
                    "tidefs: targeted repair generation {} is current for {key:?}; prior deletion cleanup remains pending: {error}",
                    replacement_receipt.generation
                );
            }
        }
        self.health = compute_health(&self.devices);
        self.record_health_transitions();

        match self
            .get_with_current_receipt(class, key)
            .map_err(|error| progress.failure(error))?
        {
            Some((payload, current))
                if payload == source_payload && current == replacement_receipt => {}
            _ => {
                return Err(progress.failure(StoreError::InvalidOptions {
                    reason: "replicated repair replacement receipt failed strict verification",
                }))
            }
        }

        Ok(ReplicatedRepairResult {
            previous_receipt: expected_receipt.clone(),
            replacement_receipt,
            source_device_index,
            repaired_device_index: corrupt_device_index,
        })
    }
}
