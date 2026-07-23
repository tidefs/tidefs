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

use tidefs_membership_epoch::{EpochId, MemberId};
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
    LocalObjectStore, ObjectKey, ObjectLocation, Result, ScrubStats, StoreError, StoreOptions,
    StoreRetentionCompactionReport, StoreStats, StoredObject,
};
use tidefs_block_allocator::{BlockAllocator, BlockId, TrimRequest};
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};
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

    fn to_label_policy(self) -> pool_label::PoolRedundancyPolicy {
        match self {
            Self::Replicated { copies } => pool_label::PoolRedundancyPolicy::replicated(copies),
            Self::Erasure {
                data_shards,
                parity_shards,
            } => pool_label::PoolRedundancyPolicy::erasure(data_shards, parity_shards),
        }
    }

    fn from_label_policy(policy: pool_label::PoolRedundancyPolicy) -> Self {
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

    /// Project this local pool policy into the shared distributed receipt
    /// policy identity.
    #[must_use]
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
    /// Original stable device GUID for receipts that still target the old media.
    pub old_device_guid: [u8; 16],
    /// Path of the new replacement device.
    pub new_path: PathBuf,
    /// Current replacement state.
    pub state: ReplacementState,
    /// Index of the device in the pool's device list during replacement.
    pub device_index: usize,
}

/// Local replacement/rebuild status projected from pool replacement state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementRebuildStatusState {
    Pending,
    Resuming,
    Completed,
    Canceled,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementRebuildEvidenceStatus {
    pub old_member: MemberId,
    pub new_member: MemberId,
    pub topology_epoch: u64,
    pub total_subjects: u64,
    pub subjects_completed: u64,
    pub subjects_failed: u64,
    pub verified_receipt_count: u64,
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
    pub fn shared_receipt_ref(&self) -> Result<PlacementReceiptRef> {
        self.shared_receipt_ref_for_subject(self.object_store_subject_id())
    }

    /// Project this local placement receipt into the shared distributed receipt
    /// reference with an explicit caller-supplied subject id.
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

fn reclaim_object_key(key: ObjectKey) -> ReclaimObjectKey {
    ReclaimObjectKey(key.as_bytes32())
}

fn dead_object_replacement_receipt_for_object(
    object_key: ObjectKey,
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
        reclaim_object_key(object_key),
        receipt.epoch,
        receipt.generation,
        redundancy_policy,
        receipt.payload_len,
        receipt.payload_digest,
        target_count,
    ))
}

fn receipt_supersedes(candidate: &PlacementReceipt, current: &PlacementReceipt) -> Result<bool> {
    let candidate_version = (candidate.epoch, candidate.generation);
    let current_version = (current.epoch, current.generation);
    if candidate_version == current_version {
        if candidate != current {
            return Err(StoreError::InvalidOptions {
                reason: "conflicting placement receipts share epoch and generation",
            });
        }
        return Ok(false);
    }
    Ok(candidate_version > current_version)
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum OldReceiptPolicy {
    RequireValid,
    UseValidated(PlacementReceipt),
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
    /// Pending removal result established only after this Pool instance
    /// actually detached the target. A marker plus a caller-supplied reduced
    /// configuration is not enough to populate this state.
    pending_device_removal: Option<(PathBuf, [u8; 16], crate::device_removal::EvacuationResult)>,
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
    #[cfg(test)]
    fail_post_publication_reclaim_attachment_once: bool,
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
    evidence_stable: bool,
    state: ReplacementRebuildStatusState,
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
}

const DEVICE_REPLACEMENT_EVIDENCE_FILE: &str = ".tidefs_device_replacement_evidence";
const DEVICE_REPLACEMENT_EVIDENCE_TMP_FILE: &str = ".tidefs_device_replacement_evidence.tmp";
const DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1: &[u8; 8] = b"TFSDRP1\0";
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
        ReplacementRebuildStatusState::Canceled => 2,
        ReplacementRebuildStatusState::Completed => 3,
        ReplacementRebuildStatusState::Refused => 4,
    }
}

fn replacement_evidence_state_from_code(code: u8) -> Option<ReplacementRebuildStatusState> {
    match code {
        0 => Some(ReplacementRebuildStatusState::Pending),
        1 => Some(ReplacementRebuildStatusState::Resuming),
        2 => Some(ReplacementRebuildStatusState::Canceled),
        3 => Some(ReplacementRebuildStatusState::Completed),
        4 => Some(ReplacementRebuildStatusState::Refused),
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
    {
        return Err(invalid_device_replacement_evidence());
    }

    let mut encoded = Vec::with_capacity(
        DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1.len()
            + 16 * 3
            + std::mem::size_of::<u64>() * 5
            + std::mem::size_of::<u32>() * 3
            + 2
            + old_path.len()
            + new_path.len()
            + DEVICE_REPLACEMENT_EVIDENCE_CHECKSUM_LEN,
    );
    encoded.extend_from_slice(DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1);
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
        if cursor.take(DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1.len())?
            != DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1
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
            evidence_stable: flags & DEVICE_REPLACEMENT_EVIDENCE_STABLE_FLAG != 0,
            state,
        })
    })()
    .ok_or_else(invalid_device_replacement_evidence)?;

    // Reuse the encoder's semantic checks, not only its byte-shape checks.
    encode_device_replacement_evidence(&decoded)?;
    Ok(decoded)
}

fn persist_device_replacement_evidence(
    pool_root: &Path,
    evidence: &DeviceReplacementEvidenceMarker,
) -> Result<()> {
    let evidence_path = pool_root.join(DEVICE_REPLACEMENT_EVIDENCE_FILE);
    let tmp_path = pool_root.join(DEVICE_REPLACEMENT_EVIDENCE_TMP_FILE);
    let encoded = encode_device_replacement_evidence(evidence)?;
    let persist_result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, &evidence_path)?;
        fs::File::open(pool_root)?.sync_all()
    })();

    if let Err(source) = persist_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(StoreError::Io {
            operation: "persist_device_replacement_evidence",
            path: evidence_path,
            source,
        });
    }
    Ok(())
}

fn read_device_replacement_evidence(
    evidence_path: &Path,
) -> Result<DeviceReplacementEvidenceMarker> {
    let encoded = fs::read(evidence_path).map_err(|source| StoreError::Io {
        operation: "read_device_replacement_evidence",
        path: evidence_path.to_path_buf(),
        source,
    })?;
    decode_device_replacement_evidence(&encoded)
}

fn restore_device_replacement_evidence(pool: &mut Pool) -> Result<()> {
    let evidence_path = pool.config.root_path.join(DEVICE_REPLACEMENT_EVIDENCE_FILE);
    if !evidence_path.exists() {
        return Ok(());
    }

    let mut evidence = read_device_replacement_evidence(&evidence_path)?;
    if evidence.pool_guid != pool.pool_guid {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence belongs to a different pool",
        });
    }
    let loaded_path = pool
        .devices
        .get(evidence.device_index)
        .map(|device| device.root());
    let loaded_guid = pool.device_guids.get(evidence.device_index).copied();
    let old_topology_loaded = loaded_path == Some(evidence.old_path.as_path())
        && loaded_guid == Some(evidence.old_device_guid);
    let new_topology_loaded = loaded_path == Some(evidence.new_path.as_path())
        && loaded_guid == Some(evidence.new_device_guid);
    if !old_topology_loaded && !new_topology_loaded {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence does not match the loaded topology",
        });
    }
    match evidence.state {
        ReplacementRebuildStatusState::Pending | ReplacementRebuildStatusState::Resuming => {
            if new_topology_loaded && pool.placement_epoch == evidence.topology_epoch {
                // The replacement member and its labels are the admitted
                // topology. Ordinary writes may continue while rebuild
                // evidence remains fail-closed for old-device detach.
            } else if old_topology_loaded
                && pool.placement_epoch.saturating_add(1).max(1) == evidence.topology_epoch
            {
                pool.set_receipt_generation_authority_state(
                    ReceiptGenerationAuthorityState::ReplacementResumeRequired,
                );
            } else {
                return Err(StoreError::InvalidOptions {
                    reason:
                        "active device replacement evidence has no complete matching label topology",
                });
            }
            evidence.state = ReplacementRebuildStatusState::Resuming;
        }
        ReplacementRebuildStatusState::Canceled => {
            if pool.placement_epoch != evidence.topology_epoch
                || (!old_topology_loaded && !new_topology_loaded)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "canceled device replacement evidence is ahead of its final labels",
                });
            }
        }
        ReplacementRebuildStatusState::Completed => {
            if !new_topology_loaded || pool.placement_epoch != evidence.topology_epoch {
                return Err(StoreError::InvalidOptions {
                    reason: "completed device replacement evidence does not match the new topology",
                });
            }
        }
        ReplacementRebuildStatusState::Refused => {
            return Err(StoreError::InvalidOptions {
                reason: "refused device replacement evidence has no writable final topology",
            });
        }
    }
    pool.replacement_evidence = Some(evidence);
    Ok(())
}

/// File written to pool root during device removal to enable
/// crash-safe resume on next pool open.
const DEVICE_REMOVAL_MARKER_FILE: &str = ".tidefs_device_removal_pending";
const DEVICE_REMOVAL_MARKER_TMP_FILE: &str = ".tidefs_device_removal_pending.tmp";
const DEVICE_REMOVAL_MARKER_MAGIC_V2: &[u8; 8] = b"TFSDRM2\0";
const DEVICE_REMOVAL_MARKER_CHECKSUM_LEN: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceRemovalMarker {
    pool_guid: [u8; 16],
    target_path: PathBuf,
    target_guid: [u8; 16],
}

fn invalid_device_removal_marker() -> StoreError {
    StoreError::InvalidOptions {
        reason: "device removal marker is corrupt or unverifiable",
    }
}

fn encode_device_removal_marker(
    pool_guid: [u8; 16],
    target_path: &Path,
    target_guid: [u8; 16],
) -> Result<Vec<u8>> {
    let path = target_path.as_os_str().as_bytes();
    if path.is_empty() {
        return Err(invalid_device_removal_marker());
    }
    let path_len = u32::try_from(path.len()).map_err(|_| invalid_device_removal_marker())?;
    let mut encoded = Vec::with_capacity(
        DEVICE_REMOVAL_MARKER_MAGIC_V2.len()
            + pool_guid.len()
            + target_guid.len()
            + std::mem::size_of::<u32>()
            + path.len()
            + DEVICE_REMOVAL_MARKER_CHECKSUM_LEN,
    );
    encoded.extend_from_slice(DEVICE_REMOVAL_MARKER_MAGIC_V2);
    encoded.extend_from_slice(&pool_guid);
    encoded.extend_from_slice(&target_guid);
    encoded.extend_from_slice(&path_len.to_le_bytes());
    encoded.extend_from_slice(path);
    let checksum = blake3::hash(&encoded);
    encoded.extend_from_slice(checksum.as_bytes());
    Ok(encoded)
}

fn decode_device_removal_marker(encoded: &[u8]) -> Result<DeviceRemovalMarker> {
    let decoded = (|| -> Option<DeviceRemovalMarker> {
        let mut cursor = ReceiptCursor::new(encoded);
        if cursor.take(DEVICE_REMOVAL_MARKER_MAGIC_V2.len())? != DEVICE_REMOVAL_MARKER_MAGIC_V2 {
            return None;
        }
        let pool_guid = cursor.array()?;
        let target_guid = cursor.array()?;
        let path_len = u32::from_le_bytes(cursor.array()?) as usize;
        if path_len == 0 {
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
            target_path,
            target_guid,
        })
    })();

    decoded.ok_or_else(invalid_device_removal_marker)
}

fn persist_device_removal_marker(
    pool_root: &Path,
    pool_guid: [u8; 16],
    target_path: &Path,
    target_guid: [u8; 16],
) -> Result<()> {
    let marker_path = pool_root.join(DEVICE_REMOVAL_MARKER_FILE);
    let tmp_path = pool_root.join(DEVICE_REMOVAL_MARKER_TMP_FILE);
    let encoded = encode_device_removal_marker(pool_guid, target_path, target_guid)?;
    let persist_result = (|| -> std::io::Result<()> {
        let mut marker = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        marker.write_all(&encoded)?;
        marker.sync_all()?;
        drop(marker);

        fs::rename(&tmp_path, &marker_path)?;
        fs::File::open(pool_root)?.sync_all()
    })();

    if let Err(source) = persist_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(StoreError::Io {
            operation: "persist_device_removal_marker",
            path: marker_path,
            source,
        });
    }
    Ok(())
}

fn read_device_removal_marker(marker_path: &Path) -> Result<DeviceRemovalMarker> {
    let encoded = fs::read(marker_path).map_err(|source| StoreError::Io {
        operation: "read_device_removal_marker",
        path: marker_path.to_path_buf(),
        source,
    })?;
    decode_device_removal_marker(&encoded)
}

fn read_device_removal_marker_if_present(
    marker_path: &Path,
) -> Result<Option<DeviceRemovalMarker>> {
    match read_device_removal_marker(marker_path) {
        Ok(marker) => Ok(Some(marker)),
        Err(StoreError::Io {
            operation,
            path,
            source,
        }) if source.kind() == std::io::ErrorKind::NotFound => {
            match fs::symlink_metadata(marker_path) {
                Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(None)
                }
                Ok(_) => Err(StoreError::Io {
                    operation,
                    path,
                    source,
                }),
                Err(source) => Err(StoreError::Io {
                    operation: "inspect_device_removal_marker",
                    path: marker_path.to_path_buf(),
                    source,
                }),
            }
        }
        Err(err) => Err(err),
    }
}

fn validate_read_only_lifecycle_state(
    config: &PoolConfig,
    pool_guid: [u8; 16],
    device_guids: &[[u8; 16]],
    topology_generation: u64,
) -> Result<()> {
    let removal_marker_path = config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
    if read_device_removal_marker_if_present(&removal_marker_path)?
        .is_some_and(|marker| marker.pool_guid == pool_guid)
    {
        return Err(StoreError::InvalidOptions {
            reason: "read-only pool import refuses pending device removal",
        });
    }

    let evidence_path = config.root_path.join(DEVICE_REPLACEMENT_EVIDENCE_FILE);
    let evidence = match fs::symlink_metadata(&evidence_path) {
        Ok(_) => Some(read_device_replacement_evidence(&evidence_path)?),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(StoreError::Io {
                operation: "inspect_device_replacement_evidence",
                path: evidence_path,
                source,
            })
        }
    };
    let Some(evidence) = evidence else {
        return Ok(());
    };
    if evidence.pool_guid != pool_guid {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence belongs to a different pool",
        });
    }
    let loaded_path = config
        .devices
        .get(evidence.device_index)
        .map(device_root_path);
    let loaded_guid = device_guids.get(evidence.device_index).copied();
    let old_topology_loaded = loaded_path.as_deref() == Some(evidence.old_path.as_path())
        && loaded_guid == Some(evidence.old_device_guid);
    let new_topology_loaded = loaded_path.as_deref() == Some(evidence.new_path.as_path())
        && loaded_guid == Some(evidence.new_device_guid);
    if !old_topology_loaded && !new_topology_loaded {
        return Err(StoreError::InvalidOptions {
            reason: "device replacement evidence does not match the loaded topology",
        });
    }
    if evidence.state == ReplacementRebuildStatusState::Canceled
        && (old_topology_loaded || new_topology_loaded)
        && evidence.topology_epoch == topology_generation
    {
        return Ok(());
    }
    if evidence.state == ReplacementRebuildStatusState::Completed
        && new_topology_loaded
        && evidence.topology_epoch == topology_generation
    {
        return Ok(());
    }
    Err(StoreError::InvalidOptions {
        reason: "read-only pool import refuses unresolved device replacement",
    })
}

/// Check for a pending device removal marker and resume evacuation if found.
fn resume_device_removal_if_pending(pool: &mut Pool) -> Result<()> {
    let marker_path = pool.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
    if let Some(marker) = read_device_removal_marker_if_present(&marker_path)? {
        if marker.pool_guid != pool.pool_guid {
            // A marker copied from another pool cannot authorize automatic
            // evacuation or detach in this pool, even if a device GUID
            // happens to be reused.
            return Ok(());
        }
        let mut unique_device_guids = BTreeSet::new();
        if pool.device_guids.len() != pool.devices.len()
            || !pool
                .device_guids
                .iter()
                .copied()
                .all(|guid| unique_device_guids.insert(guid))
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending device removal has incomplete topology identity",
            });
        }
        let target_path = pool
            .device_guids
            .iter()
            .position(|guid| *guid == marker.target_guid)
            .and_then(|idx| pool.devices.get(idx))
            .map(|device| device.root().to_path_buf());
        let target_path = target_path.ok_or(StoreError::InvalidOptions {
            reason: "pending device removal target is absent from the labeled topology",
        })?;
        // A successful retry removes the target only from this Pool
        // instance. Keep the marker because neither that detach nor GUID
        // absence from a caller-supplied configuration proves a durable
        // topology commit.
        let result = pool.safe_remove_device(&target_path)?;
        if result.objects_failed != 0 || !result.topology_commit_pending {
            return Err(StoreError::InvalidOptions {
                reason: "pending device removal could not reach topology-commit-pending state",
            });
        }
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
    let mut max_generation = 0;
    for device in devices {
        for receipt_key in device.store().list_keys_including_internal() {
            if !crate::is_pool_placement_receipt_key(receipt_key) {
                continue;
            }
            let Some(raw) = device.get(receipt_key)? else {
                continue;
            };
            let Some(receipt) = PlacementReceipt::decode(&raw) else {
                continue;
            };
            if placement_receipt_object_key(receipt.object_key) != receipt_key
                || receipt.epoch == 0
                || receipt.generation == 0
                || receipt.planner_replay_receipt.is_none()
                || !planner_replay_receipt_matches_receipt(&receipt)
                || validate_strict_receipt_structure(&receipt).is_err()
            {
                continue;
            }
            max_generation = max_generation.max(receipt.generation);
        }
    }
    Ok(max_generation)
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

fn initialize_receipt_generation_high_water(
    devices: &mut [Device],
    pool_guid: [u8; 16],
) -> Result<u64> {
    if devices.is_empty() {
        return Err(StoreError::InvalidOptions {
            reason: "pool receipt generation authority requires at least one device",
        });
    }
    if devices
        .iter()
        .any(|device| !device.store().list_keys_including_internal().is_empty())
    {
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
    for device in devices.iter_mut() {
        device.sync_all()?;
    }
    for device in devices.iter() {
        verify_receipt_generation_high_water_copy(device, marker)?;
    }
    Ok(marker.reserved_through)
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
    for device in devices.iter_mut() {
        device.sync_all()?;
    }
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
    device.sync_all()?;
    verify_receipt_generation_high_water_copy(device, marker)
}

fn retire_receipt_generation_high_water_on_device(
    device: &mut Device,
    pool_guid: [u8; 16],
) -> Result<()> {
    require_receipt_generation_high_water(device, pool_guid)?;
    let marker = ReceiptGenerationHighWater {
        pool_guid,
        reserved_through: u64::MAX,
    };
    device.put_pool_internal(
        receipt_generation_high_water_key(),
        &encode_receipt_generation_high_water(marker),
    )?;
    device.sync_all()?;
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
        self.refresh_raw_store_mutation_gate();
    }

    /// Create a new pool from a configuration.
    ///
    /// Creates the root directory and initializes every device.
    pub fn create(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
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

        let mut devices = open_devices(&config, options)?;
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
            device_guids,
            placement_epoch: 1,
            persisted_label_epoch: None,
            next_placement_receipt_generation,
            reserved_placement_receipt_generation_through,
            receipt_generation_authority_state: ReceiptGenerationAuthorityState::Converged,
            raw_store_mutation_allowed,
            pending_device_removal: None,
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            replacement_evidence: None,
            allocator: None,
            locked: false,
            #[cfg(test)]
            fail_post_publication_reclaim_attachment_once: false,
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

    /// Open a complete existing Pool topology for side-effect-free inspection.
    ///
    /// This import refuses missing, unlabelled, reordered, or inconsistent
    /// members and supports only byte-addressable block/regular-file devices.
    /// It never creates storage, opens an intent-log writer, or resumes device
    /// lifecycle work.
    pub fn open_read_only_existing(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Self> {
        Self::open_with_mode(config, properties, options, PoolOpenMode::ReadOnlyExisting)
    }

    fn open_with_mode(
        config: PoolConfig,
        properties: PoolProperties,
        options: &StoreOptions,
        mode: PoolOpenMode,
    ) -> Result<Self> {
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

        // Attempt to read a label from each configured device path.
        for (configured_index, vc) in config.devices.iter().enumerate() {
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
            labeled_device_count += 1;
            if label.device_count as usize != config.devices.len() {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology is missing or has extra configured members",
                });
            }
            if label.device_index as usize != configured_index {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology device order does not match labels",
                });
            }
            if !read_only_device_guids.insert(label.device_guid) {
                return Err(StoreError::InvalidOptions {
                    reason: "pool topology contains duplicate device GUIDs",
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
            if mode == PoolOpenMode::ReadOnlyExisting
                && (label.device_capacity_bytes != device_layout.device_size_bytes
                    || label.system_area_pointer != device_layout.system_area_offset
                    || label.system_area_size != device_layout.system_area_len)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "read-only pool label geometry disagrees with DeviceLayoutV1",
                });
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
                    label.device_index as usize,
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
        if mode == PoolOpenMode::ReadOnlyExisting {
            validate_read_only_lifecycle_state(
                &config,
                pg,
                &device_guids,
                topology_generation.unwrap_or(1).max(1),
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

        let classes: Vec<DeviceClass> = config.devices.iter().map(|vc| vc.class).collect();
        let class_map = build_class_map(&classes);
        let mut devices = match mode {
            PoolOpenMode::Writable => open_devices(&config, options)?,
            PoolOpenMode::ReadOnlyExisting => open_devices_read_only_existing(&config, options)?,
        };
        let reserved_placement_receipt_generation_through =
            receipt_generation_high_water_for_devices(&devices, pg)?;
        validate_receipts_within_generation_high_water(
            &devices,
            reserved_placement_receipt_generation_through,
        )?;
        let next_placement_receipt_generation = match mode {
            PoolOpenMode::Writable => reserved_placement_receipt_generation_through
                .checked_add(1)
                .unwrap_or(0),
            PoolOpenMode::ReadOnlyExisting => 0,
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
        let health = compute_health(&devices);

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
            device_guids,
            placement_epoch: topology_generation.unwrap_or(1).max(1),
            persisted_label_epoch: Some(topology_generation.unwrap_or(1).max(1)),
            next_placement_receipt_generation,
            reserved_placement_receipt_generation_through,
            receipt_generation_authority_state: ReceiptGenerationAuthorityState::Converged,
            raw_store_mutation_allowed,
            pending_device_removal: None,
            spare_policy: SparePolicy::Manual,
            health_transitions: Vec::new(),
            replacement: None,
            replacement_evidence: None,
            allocator: None,
            locked,
            #[cfg(test)]
            fail_post_publication_reclaim_attachment_once: false,
        };

        if mode == PoolOpenMode::Writable {
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
            write_pool_label(
                config,
                label,
                self.device_layouts.get(i),
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
            features_compat: features::DEVICE_HEALTH_STATE | features::DEVICE_LAYOUT_V1,
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

    fn persist_active_labels_if_needed(&mut self) -> Result<()> {
        if self.persisted_label_epoch == Some(self.placement_epoch) {
            return Ok(());
        }

        let removal_marker_path = self.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
        if let Some(marker) = read_device_removal_marker_if_present(&removal_marker_path)? {
            if marker.pool_guid == self.pool_guid {
                // The current device list and placement epoch are in-memory
                // state until removal has one durable topology commit. Do not
                // let a later data write publish that reduced topology through
                // the ordinary active-label refresh path.
                return Ok(());
            }
        }

        for (device_index, device) in self.devices.iter().enumerate() {
            let config =
                self.config
                    .devices
                    .get(device_index)
                    .ok_or(StoreError::InvalidOptions {
                        reason: "pool device label persistence missing device config",
                    })?;
            let label = self.build_label_with_state(device_index, device, PoolState::Active);
            write_pool_label(
                config,
                label,
                self.device_layouts.get(device_index),
                "pool_active_write_label",
            )?;
        }

        self.persisted_label_epoch = Some(self.placement_epoch);
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
        let result = if self.next_placement_receipt_generation == 0 {
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
        };
        self.refresh_raw_store_mutation_gate();
        result
    }

    fn validate_loaded_receipt_generation_high_water(&self) -> Result<()> {
        let reserved_through =
            receipt_generation_high_water_for_devices(&self.devices, self.pool_guid)?;
        if reserved_through != self.reserved_placement_receipt_generation_through {
            return Err(StoreError::InvalidOptions {
                reason: "placement receipt generation high-water differs from loaded authority",
            });
        }
        Ok(())
    }

    fn validate_receipt_generation_high_water(&self) -> Result<()> {
        self.ensure_receipt_generation_authority_converged()?;
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
            publish_receipt_generation_high_water(
                &mut self.devices,
                self.pool_guid,
                self.reserved_placement_receipt_generation_through,
                new_reserved_through,
            )?;
            self.reserved_placement_receipt_generation_through = new_reserved_through;
            self.set_receipt_generation_authority_state(ReceiptGenerationAuthorityState::Converged);
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
        self.load_placement_receipt(&indices, key)
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

        let mut receipts: BTreeMap<ObjectKey, PlacementReceipt> = BTreeMap::new();
        for idx in self.usable_candidates(&indices) {
            for key in self.devices[idx].store().list_keys_including_internal() {
                if !crate::is_pool_placement_receipt_key(key) {
                    continue;
                }
                let Ok(Some(raw)) = self.devices[idx].get(key) else {
                    continue;
                };
                let Some(receipt) = PlacementReceipt::decode(&raw) else {
                    continue;
                };
                if placement_receipt_object_key(receipt.object_key) != key {
                    continue;
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

        Ok(receipts.into_values().collect())
    }

    /// Return the latest local placement receipts projected into the shared
    /// distributed receipt reference model.
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
            let Some(raw) = self.devices[idx].get(receipt_key)? else {
                continue;
            };
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
                    reason: "strict read requires nonzero placement receipt epoch and generation",
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

        if receipts.len() > 1 {
            return Err(StoreError::InvalidOptions {
                reason: "strict read found heterogeneous placement receipt versions",
            });
        }

        Ok(receipts.into_iter().next().map(|(_, receipt)| receipt))
    }

    fn logical_raw_payload_visible(&self, indices: &[usize], key: ObjectKey) -> Result<bool> {
        let mut visible = false;
        for &idx in indices {
            visible |= self.devices[idx].get(key)?.is_some();
        }
        if let PoolRedundancyPolicy::Erasure { .. } = self.properties.redundancy_policy {
            let width = self.properties.redundancy_policy.total_targets()?;
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

    fn restore_device_objects(&mut self, previous: &[(usize, ObjectKey, Option<Vec<u8>>)]) -> bool {
        let mut restored = true;
        for (idx, key, payload) in previous {
            let pool_internal = crate::is_pool_placement_scan_internal_key(*key);
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
        }
        Ok(())
    }

    fn write_placement_receipt(
        &mut self,
        indices: &[usize],
        receipt: &PlacementReceipt,
    ) -> Result<()> {
        self.ensure_receipt_generation_authority_converged()?;
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
                if !self.restore_device_objects(&previous[..=position]) {
                    return Err(StoreError::InvalidOptions {
                        reason: "placement receipt publication failed and rollback was incomplete",
                    });
                }
                return Err(error);
            }
        }

        match self.verify_placement_receipt_publication(indices, receipt) {
            Ok(()) => Ok(()),
            Err(error) => {
                if !self.restore_device_objects(&previous) {
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
        old_receipt_policy: OldReceiptPolicy,
    ) -> Result<(StoredObject, PlacementReceipt)> {
        if crate::is_pool_placement_scan_internal_key(key) {
            return Err(StoreError::InvalidOptions {
                reason: "pool receipt, shard, and generation namespaces are reserved",
            });
        }
        let old_receipt = match old_receipt_policy {
            OldReceiptPolicy::RequireValid => {
                match self.load_current_placement_receipt_strict(indices, key)? {
                    Some(receipt) => Some(receipt),
                    None if self.logical_raw_payload_visible(indices, key)? => {
                        return Err(StoreError::InvalidOptions {
                            reason: "strict read refuses a receiptless raw payload",
                        });
                    }
                    None => None,
                }
            }
            OldReceiptPolicy::UseValidated(receipt) => {
                if receipt.object_key != key {
                    return Err(StoreError::InvalidOptions {
                        reason: "replacement receipt does not match the logical object",
                    });
                }
                validate_strict_receipt_structure(&receipt)?;
                self.ensure_receipt_replay_authority(&receipt)?;
                Some(receipt)
            }
        };
        let mut receipt = self.plan_pool_wide_placement(class, key, payload.len(), indices)?;
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
                self.put_replicated_with_receipt(key, payload, indices, &mut receipt)
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                self.put_erasure_with_receipt(key, payload, indices, &mut receipt)
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
                    if !self.restore_device_objects(&previous_payloads) {
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
            if !self.restore_device_objects(&previous_payloads) {
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
                let _ = self.restore_device_objects(&previous_shards);
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
                    if !self.restore_device_objects(&previous_shards) {
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
            if !self.restore_device_objects(&previous_shards) {
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

    fn obsolete_physical_placements(
        &self,
        receipt: &PlacementReceipt,
    ) -> Vec<ObsoletePhysicalPlacement> {
        let mut placements = BTreeSet::new();
        match receipt.policy {
            PoolRedundancyPolicy::Replicated { .. } => {
                for target in &receipt.targets {
                    let Some(device_index) = self.resolve_receipt_target(target) else {
                        continue;
                    };
                    placements.insert(ObsoletePhysicalPlacement {
                        device_index,
                        object_key: receipt.object_key,
                    });
                }
            }
            PoolRedundancyPolicy::Erasure { .. } => {
                for target in &receipt.targets {
                    let Some(device_index) = self.resolve_receipt_target(target) else {
                        continue;
                    };
                    placements.insert(ObsoletePhysicalPlacement {
                        device_index,
                        object_key: placement_shard_object_key(
                            receipt.object_key,
                            target.shard_index,
                        ),
                    });
                }
            }
        }
        placements.into_iter().collect()
    }

    fn persist_pending_obsolete_placements(
        &mut self,
        old_receipt: &PlacementReceipt,
        replacement_generation: u64,
    ) -> Result<Vec<ObsoletePhysicalPlacement>> {
        let placements = self.obsolete_physical_placements(old_receipt);
        for placement in &placements {
            let entry = DeadObjectEntry::new(
                reclaim_object_key(placement.object_key),
                self.pool_guid,
                replacement_generation,
                true,
                replacement_generation,
            );
            self.devices[placement.device_index]
                .store_mut()
                .enqueue_pending_receipt_bound_dead_object_pool_internal(entry)?;
        }
        Ok(placements)
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
            let object_id = reclaim_object_key(placement.object_key);
            let replacement = dead_object_replacement_receipt_for_object(
                placement.object_key,
                replacement_receipt,
            )?;
            let _updated = self.devices[placement.device_index]
                .store_mut()
                .publish_dead_object_replacement_receipt_pool_internal(&object_id, replacement)?;
        }
        Ok(())
    }

    fn enqueue_committed_deleted_placement(&mut self, receipt: &PlacementReceipt) -> Result<()> {
        self.enqueue_obsolete_placement_with_clearance(receipt, receipt)
    }

    fn enqueue_obsolete_placement_with_clearance(
        &mut self,
        old_receipt: &PlacementReceipt,
        replacement_receipt: &PlacementReceipt,
    ) -> Result<()> {
        let placements = self.obsolete_physical_placements(old_receipt);
        for placement in placements {
            self.enqueue_replaced_physical_object(
                placement.device_index,
                placement.object_key,
                replacement_receipt,
            )?;
        }
        Ok(())
    }

    fn enqueue_replaced_physical_object(
        &mut self,
        device_index: usize,
        object_key: ObjectKey,
        replacement_receipt: &PlacementReceipt,
    ) -> Result<()> {
        let replacement =
            dead_object_replacement_receipt_for_object(object_key, replacement_receipt)?;
        let death_txg = replacement.receipt_generation;
        let entry = DeadObjectEntry::new(
            reclaim_object_key(object_key),
            self.pool_guid,
            death_txg,
            true,
            death_txg,
        )
        .with_replacement_receipt(replacement);
        self.devices[device_index]
            .store_mut()
            .enqueue_receipt_bound_dead_object_pool_internal(entry)?;
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
        if crate::is_pool_placement_scan_internal_key(key) {
            return Err(StoreError::InvalidOptions {
                reason: "pool receipt, shard, and generation namespaces are reserved",
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
                self.ensure_receipt_generation_authority_converged()?;
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

    fn verify_strict_receipt_target_copies(&self, receipt: &PlacementReceipt) -> Result<()> {
        let receipt_key = placement_receipt_object_key(receipt.object_key);
        for target in &receipt.targets {
            let idx = self
                .resolve_receipt_target(target)
                .ok_or(StoreError::InvalidOptions {
                    reason: "strict read could not resolve every receipt target",
                })?;
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
        Ok(())
    }

    /// Read only through one current, internally consistent placement receipt.
    ///
    /// Unlike [`Pool::get`], this entry point rejects receiptless raw payloads
    /// and any malformed, replayless, zero-version, or conflicting receipt.
    /// Every encoded target must retain the exact receipt copy and exact
    /// payload or shard named by it; degraded reconstruction remains on the
    /// explicitly non-strict read and repair paths. The selected receipt is
    /// scanned again after the exact-receipt read so callers never receive
    /// bytes under authority that changed in flight.
    pub fn get_with_current_receipt(
        &self,
        class: IoClass,
        key: ObjectKey,
    ) -> Result<Option<(Vec<u8>, PlacementReceipt)>> {
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

        let Some(receipt) = map_strict_read_object_io(
            self.load_current_placement_receipt_strict(&indices, key),
            "strict read could not inspect every placement receipt copy",
        )?
        else {
            if map_strict_read_object_io(
                self.logical_raw_payload_visible(&indices, key),
                "strict read could not establish receiptless raw payload absence",
            )? {
                return Err(StoreError::InvalidOptions {
                    reason: "strict read refuses a receiptless raw payload",
                });
            }
            return Ok(None);
        };

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
            self.load_current_placement_receipt_strict(&indices, key),
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
        let expected_len =
            usize::try_from(receipt.payload_len).map_err(|_| StoreError::InvalidOptions {
                reason: "placement receipt payload length exceeds platform usize",
            })?;
        let mut canonical = None;
        for target in &receipt.targets {
            let idx = self
                .resolve_receipt_target(target)
                .ok_or(StoreError::InvalidOptions {
                    reason: "strict read could not resolve every replicated placement target",
                })?;
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

    /// Delete an object from every device that can hold this I/O class.
    pub fn delete(&mut self, class: IoClass, key: ObjectKey) -> Result<bool> {
        self.ensure_writable("pool delete")?;
        if crate::is_pool_placement_scan_internal_key(key) {
            return Err(StoreError::InvalidOptions {
                reason: "pool receipt, shard, and generation metadata cannot be deleted directly",
            });
        }
        self.ensure_receipt_generation_authority_converged()?;
        let indices: Vec<usize> = self.class_map.get(class).to_vec();
        if indices.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "pool has no devices for this I/O class",
            });
        }

        if let Some(receipt) = self.load_placement_receipt(&indices, key)? {
            let deleted = self.delete_with_receipt(&receipt, &indices)?;
            if deleted {
                self.enqueue_committed_deleted_placement(&receipt)?;
            }
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
                        deleted |= self.devices[idx]
                            .delete_pool_internal(shard_key)
                            .unwrap_or(false);
                    }
                    deleted |= self.devices[idx]
                        .delete(receipt.object_key)
                        .unwrap_or(false);
                }
            }
        }

        let receipt_key = placement_receipt_object_key(receipt.object_key);
        for idx in self.usable_candidates(indices) {
            deleted |= self.devices[idx]
                .delete_pool_internal(receipt_key)
                .unwrap_or(false);
        }
        Ok(deleted)
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
        if let Err(error) = self.ensure_receipt_generation_authority_converged() {
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
        let mut device =
            open_single_device(&config, &dev_opts, options.is_test_fast_harness_fixture())?;
        device.install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
        seed_receipt_generation_high_water_on_candidate(
            &mut device,
            self.pool_guid,
            self.reserved_placement_receipt_generation_through,
        )?;
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
        self.device_guids.push(rand::random());
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
        self.bump_placement_epoch();
        self.persist_active_labels_if_needed()?;
        self.set_receipt_generation_authority_state(ReceiptGenerationAuthorityState::Converged);
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
        // Find the faulted device's index.
        let faulted_index = self
            .device_guids
            .iter()
            .position(|g| g == &faulted_device_guid)
            .ok_or(StoreError::InvalidOptions {
                reason: "faulted device GUID not found in pool",
            })?;

        let existing_configs = self.config.devices.clone();

        self.validate_receipt_generation_high_water()?;
        let mut dev_opts = options.clone();
        dev_opts.max_segment_bytes = spare_config.media_class.default_segment_size();
        let mut new_device = open_single_device(
            &spare_config,
            &dev_opts,
            options.is_test_fast_harness_fixture(),
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
        // A spare activation has no cancellation path. Exhaust the detached
        // member's generation authority before its labels can describe a
        // competing complete topology.
        retire_receipt_generation_high_water_on_device(
            &mut self.devices[faulted_index],
            self.pool_guid,
        )?;

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

        // Update in-memory device at the faulted index only after its receipt
        // generation authority is durable and pool labels have admitted it.
        self.devices[faulted_index] = new_device;
        self.device_guids[faulted_index] = spare_device_guid;
        self.config.devices[faulted_index] = spare_config.clone();
        self.classes[faulted_index] = spare_config.class;
        self.class_map = build_class_map(&self.classes);

        // Update media class and layout stats.
        if faulted_index < self.media_classes.len() {
            self.media_classes[faulted_index] = spare_config.media_class;
        }
        if faulted_index < self.device_layout_stats.len() {
            self.device_layout_stats[faulted_index] = DeviceLayoutStats::with_segment_size(
                spare_config.media_class.default_segment_size(),
            );
        }
        let replacement_capacity = self.devices[faulted_index].store().capacity_bytes();
        self.device_layouts[faulted_index] = self
            .properties
            .layout_policy
            .compute(replacement_capacity)
            .unwrap_or_else(|_| {
                DeviceLayoutPolicy::Slice0Small
                    .compute(replacement_capacity)
                    .expect("Slice0Small must succeed for non-zero device")
            });
        let total_bytes: Vec<u64> = self
            .devices
            .iter()
            .map(|d| d.store().capacity_bytes())
            .collect();
        self.write_allocator = WriteAllocator::new(self.media_classes.clone(), total_bytes);

        self.health = compute_health(&self.devices);
        self.bump_placement_epoch();
        self.set_receipt_generation_authority_state(ReceiptGenerationAuthorityState::Converged);
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

    /// Return a pending removal result established by this Pool instance.
    ///
    /// This is ephemeral operator-status state, not durable detach proof. It
    /// is available only after this instance actually removed the target and
    /// while the bound recovery marker remains valid and the target absent.
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

        let marker_path = self.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
        let marker = read_device_removal_marker_if_present(&marker_path)?.ok_or(
            StoreError::InvalidOptions {
                reason: "device removal marker is missing while topology commit is pending",
            },
        )?;
        if marker.pool_guid != self.pool_guid
            || marker.target_guid != *pending_guid
            || marker.target_path != *pending_path
        {
            return Err(StoreError::InvalidOptions {
                reason: "device removal marker does not match pending in-memory detach",
            });
        }
        if self
            .devices
            .iter()
            .any(|device| device.root() == pending_path)
            || self.device_guids.contains(pending_guid)
        {
            return Err(StoreError::InvalidOptions {
                reason: "pending device removal target is still attached",
            });
        }

        Ok(Some(result.clone()))
    }

    /// Safely evacuate and detach a device from the current Pool instance.
    ///
    /// This is the preferred removal path. It enumerates current placement
    /// receipts, rewrites each receipt-backed logical object through the
    /// pool-wide redundancy policy on surviving devices, and finally removes
    /// the device only after no unreceipted logical objects remain on the
    /// target. Because the current label format has no durable topology commit
    /// point, a successful in-memory detach returns `complete = false` with
    /// `topology_commit_pending = true` and retains the recovery marker.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOptions`] when the pool is locked, the
    /// target device is not found, or it is the last remaining device in the
    /// pool. Returns [`StoreError::Io`] when object read/write/delete fails.
    pub fn safe_remove_device(
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
            return Ok(result);
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
        let marker_path = self.config.root_path.join(DEVICE_REMOVAL_MARKER_FILE);
        if let Some(pending_marker) = read_device_removal_marker_if_present(&marker_path)? {
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
        // Publish the marker atomically and sync both the file and pool root
        // before evacuation starts. A crash during a retry therefore leaves
        // either the previous complete marker or the new complete marker.
        persist_device_removal_marker(&self.config.root_path, self.pool_guid, path, target_guid)?;

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
                OldReceiptPolicy::UseValidated(receipt.clone()),
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
            return Ok(result);
        }

        // All objects evacuated -- remove the device.
        self.remove_device(path)?;
        self.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RemovalTopologyCommitRequired,
        );

        // Keep the pending-removal marker until a later implementation can
        // prove one durable topology commit. Neither the in-memory detach nor
        // GUID absence from a caller-supplied configuration is that proof.

        result.complete = false;
        result.topology_commit_pending = true;
        self.pending_device_removal = Some((path.to_path_buf(), target_guid, result.clone()));
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
        self.ensure_writable("pool replace device")?;
        // Refuse if a replacement is already active.
        if self.replacement.as_ref().is_some_and(|r| r.is_active()) {
            return Err(StoreError::InvalidOptions {
                reason: "a device replacement is already in progress",
            });
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
            if old_path != evidence.old_path
                || new_config.path != evidence.new_path
                || self
                    .devices
                    .get(evidence.device_index)
                    .map(|device| device.root())
                    != Some(old_path)
                || self.device_guids.get(evidence.device_index).copied()
                    != Some(evidence.old_device_guid)
                || evidence.topology_epoch != self.placement_epoch.saturating_add(1).max(1)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "device replacement resume does not match durable evidence",
                });
            }
            if self.receipt_generation_authority_state
                != ReceiptGenerationAuthorityState::ReplacementResumeRequired
            {
                return Err(StoreError::InvalidOptions {
                    reason: "device replacement resume requires the recorded old-topology recovery state",
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
            (
                evidence.device_index,
                old_config,
                evidence.old_device_guid,
                evidence,
                true,
            )
        } else {
            // Find the device to replace.
            let idx = self
                .devices
                .iter()
                .position(|v| v.root() == old_path)
                .ok_or(StoreError::InvalidOptions {
                    reason: "device to replace not found in pool",
                })?;
            let old_config =
                self.config
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
            let old_device_guid = self.device_guid_for_index(idx);
            let total_subjects = discover_replacement_rebuild_subject_count(self, old_device_guid)?;
            let evidence = DeviceReplacementEvidenceMarker {
                pool_guid: self.pool_guid,
                old_device_guid,
                new_device_guid: rand::random(),
                topology_epoch: self.placement_epoch.saturating_add(1).max(1),
                device_index: idx,
                old_path: old_path.to_path_buf(),
                new_path: new_config.path.clone(),
                total_subjects,
                subjects_completed: 0,
                subjects_failed: 0,
                verified_receipt_count: 0,
                evidence_stable: false,
                state: ReplacementRebuildStatusState::Pending,
            };
            (idx, old_config, old_device_guid, evidence, false)
        };

        if resuming {
            self.validate_loaded_receipt_generation_high_water()?;
        } else {
            self.validate_receipt_generation_high_water()?;
        }

        // Open and seed the replacement before it can enter the admitted
        // topology. A stale removed member may advance to the active ceiling,
        // but it may never make that ceiling move backward.
        let mut new_device =
            open_single_device(&new_config, options, options.is_test_fast_harness_fixture())?;
        new_device.install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
        if resuming {
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
        persist_device_replacement_evidence(&self.config.root_path, &replacement_evidence)?;
        self.replacement_evidence = Some(replacement_evidence.clone());

        // Swap the device in the pool list (old out, new in).
        let _old_device = std::mem::replace(&mut self.devices[idx], new_device);
        if idx < self.config.devices.len() {
            self.config.devices[idx] = new_config.clone();
        }
        // Update device GUID for the replacement.
        if idx < self.device_guids.len() {
            self.device_guids[idx] = replacement_evidence.new_device_guid;
        }

        // Update the media class and layout stats for the replaced device.
        if idx < self.media_classes.len() {
            self.media_classes[idx] = new_config.media_class;
        }
        if idx < self.device_layout_stats.len() {
            self.device_layout_stats[idx] =
                DeviceLayoutStats::with_segment_size(new_config.media_class.default_segment_size());
        }
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
        self.health = compute_health(&self.devices);
        self.record_health_transitions();

        // The durable marker must precede this topology update. Persist the
        // replacement labels now rather than waiting for a later data write,
        // so a reopen against the new topology can resume from the marker.
        // Pending evidence still does not authorize old-device detach.
        self.persist_active_labels_if_needed()?;
        self.set_receipt_generation_authority_state(ReceiptGenerationAuthorityState::Converged);

        Ok(())
    }

    /// Current replacement status, if a replacement is in progress or was
    /// recently completed.
    pub fn replacement_status(&self) -> Option<&DeviceReplacement> {
        self.replacement.as_ref()
    }

    /// Current local replacement/rebuild evidence projection.
    ///
    /// Durable marker replay can establish identity/state replayability, but
    /// old-device detach remains fail-closed until receipt-backed progress is
    /// complete and stable.
    pub fn replacement_rebuild_evidence_status(&self) -> Option<ReplacementRebuildEvidenceStatus> {
        let replacement = self.replacement.as_ref();
        let live_state = replacement.map(|replacement| match &replacement.state {
            ReplacementState::InProgress { .. } => ReplacementRebuildStatusState::Pending,
            ReplacementState::CopyComplete => ReplacementRebuildStatusState::Completed,
            ReplacementState::Cancelled => ReplacementRebuildStatusState::Canceled,
            ReplacementState::Failed { .. } => ReplacementRebuildStatusState::Refused,
        });

        let (
            old_member,
            new_member,
            topology_epoch,
            total_subjects,
            subjects_completed,
            subjects_failed,
            verified_receipt_count,
            evidence_stable,
            evidence_replayable_after_reopen,
            state,
        ) = if let Some(evidence) = self.replacement_evidence.as_ref() {
            let state = live_state.unwrap_or(evidence.state);
            let replayable = evidence.covers_state(state);
            (
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
                evidence.evidence_stable && replayable,
                replayable,
                state,
            )
        } else {
            let replacement = replacement?;
            (
                MemberId::new(u64::from_le_bytes(
                    replacement.old_device_guid[..8].try_into().unwrap(),
                )),
                MemberId::new(self.device_id_for_index(replacement.device_index)),
                self.placement_epoch(),
                0,
                0,
                0,
                0,
                false,
                false,
                live_state.unwrap(),
            )
        };

        let detach_decision = ReplacementDetachDecision::UnsafeToDetach;
        Some(ReplacementRebuildEvidenceStatus {
            old_member,
            new_member,
            topology_epoch,
            total_subjects,
            subjects_completed,
            subjects_failed,
            verified_receipt_count,
            evidence_stable,
            evidence_replayable_after_reopen,
            state,
            detach_decision,
            remanence_treatment: ReplacementRemanenceTreatment::from_detach_decision(
                detach_decision,
            ),
        })
    }

    /// Cancel an in-progress device replacement.
    ///
    /// Restores the old device to the pool and detaches the new device.
    /// This is a best-effort operation; if the old device was already
    /// removed or is no longer accessible, the pool continues with the
    /// new device in place.
    pub fn cancel_replacement(&mut self, options: &StoreOptions) -> Result<()> {
        self.ensure_writable("pool cancel device replacement")?;
        self.validate_receipt_generation_high_water()?;
        let live_replacement_active = self.replacement.as_ref().is_some_and(|r| r.is_active());
        if !live_replacement_active {
            let Some(mut evidence) = self
                .replacement_evidence
                .as_ref()
                .filter(|evidence| evidence.state.is_active())
                .cloned()
            else {
                return Ok(());
            };
            if self
                .devices
                .get(evidence.device_index)
                .map(|device| device.root())
                != Some(evidence.old_path.as_path())
                || self.device_guids.get(evidence.device_index).copied()
                    != Some(evidence.old_device_guid)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "replayed device replacement cancel requires the recorded old topology",
                });
            }
            evidence.state = ReplacementRebuildStatusState::Canceled;
            evidence.topology_epoch = self.placement_epoch.saturating_add(1).max(1);
            persist_device_replacement_evidence(&self.config.root_path, &evidence)?;
            let canceled_topology_epoch = evidence.topology_epoch;
            self.replacement_evidence = Some(evidence);

            // Commit the restored old topology only after cancellation is durable.
            self.placement_epoch = canceled_topology_epoch;
            self.persist_active_labels_if_needed()?;
            return Ok(());
        }

        // Publish cancellation before swapping the old device back. If the
        // host crashes after this point, reopen can report the canceled state
        // without interpreting the live topology as stable detach evidence.
        let replacement = self.replacement.as_ref().unwrap(); // safe: checked above
        let mut evidence =
            self.replacement_evidence
                .as_ref()
                .cloned()
                .ok_or(StoreError::InvalidOptions {
                    reason: "active device replacement is missing durable evidence",
                })?;
        if evidence.pool_guid != self.pool_guid
            || evidence.device_index != replacement.device_index
            || evidence.old_path != replacement.old_path
            || evidence.old_device_guid != replacement.old_device_guid
            || evidence.new_path != replacement.new_path
            || self.device_guids.get(evidence.device_index).copied()
                != Some(evidence.new_device_guid)
        {
            return Err(StoreError::InvalidOptions {
                reason: "active device replacement does not match durable evidence",
            });
        }

        // Seed a readable old member before publishing cancellation. If it is
        // unavailable, cancellation retains the current replacement device;
        // if it is readable but carries incompatible authority, fail before
        // changing either topology or replacement evidence.
        let restored_old_device = match open_single_device(
            &replacement.old_config,
            options,
            options.is_test_fast_harness_fixture(),
        ) {
            Ok(mut old_device) => {
                old_device
                    .install_pool_raw_mutation_guard(Arc::clone(&self.raw_store_mutation_allowed));
                seed_receipt_generation_high_water_on_candidate(
                    &mut old_device,
                    self.pool_guid,
                    self.reserved_placement_receipt_generation_through,
                )?;
                Some(old_device)
            }
            Err(_) => None,
        };
        self.set_receipt_generation_authority_state(
            ReceiptGenerationAuthorityState::RecoveryRequired,
        );
        evidence.state = ReplacementRebuildStatusState::Canceled;
        evidence.topology_epoch = self.placement_epoch.saturating_add(1).max(1);
        persist_device_replacement_evidence(&self.config.root_path, &evidence)?;
        self.replacement_evidence = Some(evidence.clone());

        let replacement = self.replacement.take().unwrap(); // safe: checked above

        // If the old device can still be opened, swap it back using the exact
        // media configuration captured before replacement.
        if let Some(old_device) = restored_old_device {
            self.devices[replacement.device_index] = old_device;
            if replacement.device_index < self.config.devices.len() {
                self.config.devices[replacement.device_index] = replacement.old_config.clone();
            }
            if replacement.device_index < self.device_guids.len() {
                self.device_guids[replacement.device_index] = replacement.old_device_guid;
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
            let restored_capacity = self.devices[replacement.device_index]
                .store()
                .capacity_bytes();
            self.device_layouts[replacement.device_index] = self
                .properties
                .layout_policy
                .compute(restored_capacity)
                .unwrap_or_else(|_| {
                    DeviceLayoutPolicy::Slice0Small
                        .compute(restored_capacity)
                        .expect("Slice0Small must succeed for non-zero device")
                });
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
        self.placement_epoch = evidence.topology_epoch;
        self.health = compute_health(&self.devices);
        self.record_health_transitions();

        // The canceled evidence is durable before this label update restores
        // the old topology. Cancellation still leaves old-device detach
        // unsafe until a later replacement has stable rebuild evidence.
        self.persist_active_labels_if_needed()?;
        self.set_receipt_generation_authority_state(ReceiptGenerationAuthorityState::Converged);
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
        self.ensure_writable("pool mirror repair scrub")?;
        if self.locked {
            return Err(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for mirror repair scrub",
            });
        }
        self.ensure_receipt_generation_authority_converged()?;
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
        if self.read_only {
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
        if self.read_only {
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
        self.refresh_raw_store_mutation_gate();
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
        self.ensure_receipt_generation_authority_converged()?;
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

fn open_devices(config: &PoolConfig, options: &StoreOptions) -> Result<Vec<Device>> {
    let allow_legacy_directory_shims =
        options.is_test_fast_harness_fixture() || is_legacy_single_directory_store_bridge(config);
    config
        .devices
        .iter()
        .map(|vc| {
            let mut dev_opts = options.clone();
            dev_opts.max_segment_bytes = vc.media_class.default_segment_size();
            open_single_device(vc, &dev_opts, allow_legacy_directory_shims)
        })
        .collect()
}

fn open_devices_read_only_existing(
    config: &PoolConfig,
    options: &StoreOptions,
) -> Result<Vec<Device>> {
    config
        .devices
        .iter()
        .map(|device_config| {
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
            let device = Device::open_single_block_read_only_existing(path, device_options)?;
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
        DeviceKind::ParityRaid1 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::ParityRaid1 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid1(paths, options)
        }
        DeviceKind::ParityRaid2 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
                "DeviceKind::ParityRaid2 requires directory object-store compatibility backing",
            )?;
            Device::open_parity_raid2(paths, options)
        }
        DeviceKind::ParityRaid3 { paths } => {
            require_legacy_directory_pool_shim(
                config.backing,
                allow_legacy_directory_shims,
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
    let mut file = fs::File::open(&device_root).map_err(|source| StoreError::Io {
        operation: "pool_open_device_raw_capacity_open",
        path: device_root.clone(),
        source,
    })?;
    file.seek(SeekFrom::End(0))
        .map_err(|source| StoreError::Io {
            operation: "pool_open_device_raw_capacity_seek_end",
            path: device_root,
            source,
        })
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

fn write_pool_label(
    device_config: &DeviceConfig,
    label: PoolLabelV1,
    device_layout: Option<&DeviceLayoutV1>,
    operation: &'static str,
) -> Result<()> {
    let layout_bytes = device_layout.map(|layout| {
        let mut bytes = [0u8; pool_label::POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(layout, &mut bytes);
        bytes
    });
    let sealed =
        pool_label::seal_label_with_device_layout(label, layout_bytes.as_ref()).map_err(|_| {
            StoreError::InvalidOptions {
                reason: "label seal failed",
            }
        })?;

    let mut buf = [0u8; pool_label::POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
    pool_label::encode_label_with_device_layout(&sealed, layout_bytes.as_ref(), &mut buf).map_err(
        |_| StoreError::InvalidOptions {
            reason: "label encode failed",
        },
    )?;

    let device_root = device_root_path(device_config);
    if device_config.backing.uses_fixed_offset_pool_labels() {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&device_root)
            .map_err(|e| StoreError::Io {
                operation,
                path: device_root.clone(),
                source: e,
            })?;
        file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::Io {
            operation,
            path: device_root.clone(),
            source: e,
        })?;
        file.write_all(&buf).map_err(|e| StoreError::Io {
            operation,
            path: device_root.clone(),
            source: e,
        })?;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceClass;
    use crate::ObjectKey;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
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

    fn assert_generation_high_water_open_refused(label: &str, mutate: impl FnOnce(&mut Pool)) {
        let root = temp_dir(label);
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &test_options()).unwrap();
        mutate(&mut pool);
        pool.sync_all().unwrap();
        drop(pool);

        assert!(matches!(
            Pool::create(config, properties, &test_options()),
            Err(StoreError::InvalidOptions { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn assert_topology_commit_pending(result: &crate::device_removal::EvacuationResult) {
        assert!(!result.complete, "{result:?}");
        assert!(result.topology_commit_pending, "{result:?}");
        assert_eq!(result.objects_failed, 0, "{result:?}");
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
        let properties = PoolProperties::default();
        let mut pool = Pool::create(config.clone(), properties.clone(), &options)
            .expect("create two-device pool");

        let (key, payload, receipt) = (0..128_u64)
            .find_map(|attempt| {
                let key = ObjectKey::from_name(format!("read-only-object-{attempt}").as_bytes());
                let payload = format!("read-only payload {attempt}").into_bytes();
                let (_stored, receipt) = pool
                    .put_with_receipt(IoClass::Data, key, &payload)
                    .expect("write receipt-backed object");
                receipt
                    .targets
                    .iter()
                    .all(|target| target.device_index == 1)
                    .then_some((key, payload, receipt))
            })
            .expect("deterministic placement reaches the secondary device");
        pool.sync_all().expect("sync two-device pool");
        let pool_guid = pool.pool_guid();
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

        persist_device_removal_marker(
            &metadata_root,
            pool_guid,
            &config.devices[1].path,
            removal_target_guid,
        )
        .expect("persist pending-removal fixture");
        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(config.clone(), properties.clone(), &options),
            "pending device removal",
        );
        std::fs::remove_file(metadata_root.join(DEVICE_REMOVAL_MARKER_FILE))
            .expect("remove pending-removal fixture");

        let mut incomplete = config.clone();
        incomplete.devices.pop();
        assert_invalid_options_reason_contains(
            Pool::open(incomplete.clone(), properties.clone(), &options),
            "missing or has extra",
        );
        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(incomplete, properties.clone(), &options),
            "missing or has extra",
        );

        let mut mismatched_properties = properties;
        mismatched_properties.redundancy_policy = PoolRedundancyPolicy::replicated(2);
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
            ),
            "existing valid format header",
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
    fn read_only_pool_open_accepts_canceled_replacement_new_topology() {
        let root = temp_dir("read-only-existing-canceled-replacement");
        let options = test_options();
        let properties = PoolProperties::default();
        let config = regular_file_pool_config(&root, "read-only-canceled", 2 * 1024 * 1024);
        let old_path = config.devices[0].path.clone();
        let replacement_path = root.join("replacement.img");
        let replacement_config = regular_file_device_config(replacement_path.clone());
        let mut pool = Pool::create(config, properties.clone(), &options)
            .expect("create replacement fixture pool");

        pool.replace_device(&old_path, replacement_config, &options)
            .expect("start replacement");
        assert_invalid_options_reason_contains(
            Pool::open_read_only_existing(pool.config().clone(), properties.clone(), &options),
            "unresolved device replacement",
        );
        std::fs::remove_file(&old_path).expect("make old device unavailable");
        pool.cancel_replacement(&options)
            .expect("cancel while retaining new topology");
        assert_eq!(pool.config().devices[0].path, replacement_path);
        let reopened_config = pool.config().clone();
        let replacement_bytes_before =
            std::fs::read(&replacement_path).expect("snapshot replacement device");
        drop(pool);

        let reopened = Pool::open_read_only_existing(reopened_config, properties, &options)
            .expect("open canceled replacement new topology read-only");
        assert_eq!(reopened.config().devices[0].path, replacement_path);
        drop(reopened);
        assert_eq!(
            std::fs::read(&replacement_path).expect("re-read replacement device"),
            replacement_bytes_before,
            "read-only open changed the canceled replacement topology"
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

        let err = open_single_device(&config, &test_options(), false).unwrap_err();
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
    fn receipt_epoch_prefers_newer_topology_over_higher_old_generation() {
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
        let receipt_key = placement_receipt_object_key(key);
        let stale_encoded = stale_epoch_receipt.encode().unwrap();
        let last_idx = pool.devices.len() - 1;
        pool.devices[last_idx]
            .put_pool_internal(receipt_key, &stale_encoded)
            .expect("inject stale higher-generation receipt");

        let selected = pool
            .placement_receipt_for_key(IoClass::Data, key)
            .unwrap()
            .expect("selected receipt");
        assert_eq!(selected.epoch, fresh_epoch_receipt.epoch);
        assert_eq!(selected.generation, fresh_epoch_receipt.generation);
        assert_eq!(
            pool.get(IoClass::Data, key).unwrap(),
            Some(b"new-epoch-payload".to_vec())
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
                reopened.sync_all().unwrap();
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
        assert_eq!(pool.allocate_placement_receipt_generation().unwrap(), 1);
        let pool_guid = pool.pool_guid;
        pool.sync_all().unwrap();
        drop(pool);

        let mut stale_replica =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::default()).unwrap();
        stale_replica
            .put_pool_internal(
                receipt_generation_high_water_key(),
                &encode_receipt_generation_high_water(ReceiptGenerationHighWater {
                    pool_guid,
                    reserved_through: 0,
                }),
            )
            .unwrap();
        stale_replica.sync_all().unwrap();
        drop(stale_replica);

        assert!(matches!(
            Pool::create(config, properties, &options),
            Err(StoreError::InvalidOptions { .. })
        ));
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
        pool.compact_retaining(&[raw_existing_key], &[]).unwrap();
        let mut failure = crate::FaultInjectionConfig::off();
        failure.write_failure_probability = 1.0;
        pool.devices[1].store_mut().enable_fault_injection(failure);
        assert!(pool
            .put_with_receipt(IoClass::Data, key, b"must not reach payload storage")
            .is_err());
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
        pool.sync_all().unwrap();
        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::create(config, properties, &test_options()),
            "markers conflict",
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
    fn wrong_key_receipt_cannot_steer_recovered_generation() {
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

        let mut reopened = Pool::create(config, properties, &test_options()).unwrap();
        assert_eq!(
            reopened.next_placement_receipt_generation,
            RECEIPT_GENERATION_RESERVATION_SIZE + 1
        );
        let fresh_key = ObjectKey::from_name(b"generation-after-wrong-key");
        let (_, fresh) = reopened
            .put_with_receipt(IoClass::Data, fresh_key, b"fresh payload")
            .unwrap();
        assert_eq!(fresh.generation, RECEIPT_GENERATION_RESERVATION_SIZE + 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_generation_publication_ceiling_and_partial_rollback_preserve_prior_authority() {
        let root = temp_dir("partial-receipt-publication");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
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
        let old_placements = pool.obsolete_physical_placements(&old_receipt);
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
            let object_id = reclaim_object_key(placement.object_key);
            let replacement = dead_object_replacement_receipt_for_object(
                placement.object_key,
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
        assert_topology_commit_pending(&removal);
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
        assert_topology_commit_pending(&removal);
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
        assert_topology_commit_pending(&removal);
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
        assert_topology_commit_pending(&removal);
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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
                reason: "conflicting placement receipts share epoch and generation"
            })
        ));
        assert_eq!(pool.stats().device_count, 3);
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert_topology_commit_pending(&result);
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

        std::fs::remove_file(root.join(DEVICE_REMOVAL_MARKER_FILE)).unwrap();
        assert!(matches!(
            pool.safe_remove_device(&victim_path),
            Err(StoreError::InvalidOptions {
                reason: "device removal marker is missing while topology commit is pending"
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
        assert_topology_commit_pending(&removal);
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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(!root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(!root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(!root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(!root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        let marker = read_device_removal_marker(&root.join(DEVICE_REMOVAL_MARKER_FILE)).unwrap();
        assert_eq!(marker.target_path, first_target);
        assert_eq!(marker.target_guid, first_target_guid);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_refuses_new_target_while_topology_commit_pending() {
        let root = temp_dir("safe-remove-awaits-topology-commit");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 3);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let first_target = pool.devices[0].root().to_path_buf();
        let first_target_guid = pool.device_guid_for_index(0);
        let second_target = pool.devices[1].root().to_path_buf();

        let first_result = pool.safe_remove_device(&first_target).unwrap();
        assert_topology_commit_pending(&first_result);
        assert_eq!(pool.stats().device_count, 2);
        assert!(!pool.device_guids.contains(&first_target_guid));

        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(marker.target_guid, first_target_guid);

        let second_result = pool.safe_remove_device(&second_target);
        assert_invalid_options_reason_contains(
            second_result,
            "awaits durable removal topology commit",
        );
        assert_eq!(pool.stats().device_count, 2);
        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(marker.target_guid, first_target_guid);

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
        assert_topology_commit_pending(&result);
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

        // Simulate crash: publish the marker file manually.
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        let pool_guid = pool.pool_guid;
        let target_guid = pool.device_guid_for_index(0);
        persist_device_removal_marker(&root, pool_guid, &d1, target_guid).unwrap();
        assert!(marker_path.exists());

        // Drop the pool (simulating crash / process exit).
        drop(pool);

        // Re-open with the original topology. Resume evacuates objects from
        // d1 to d2 and detaches d1 only from this Pool instance.
        let pool2 = Pool::open(config.clone(), PoolProperties::default(), &test_options()).unwrap();

        // The retry did not publish durable topology, so the marker remains.
        assert!(marker_path.exists());

        // This Pool instance now has one device; durable topology is pending.
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

        assert_invalid_options_reason_contains(
            Pool::open(reduced_config, PoolProperties::default(), &test_options()),
            "missing or has extra",
        );
        assert!(marker_path.exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_resolves_target_by_guid() {
        let root = temp_dir("safe-remove-resume-guid");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let key = ObjectKey::from_name(b"resume-guid-object");
        let payload = b"resume follows stable device identity";
        pool.put(IoClass::Data, key, payload).unwrap();
        pool.sync_all().unwrap();

        let target_guid = pool.device_guid_for_index(0);
        let stale_target_path = root.join("previous-device-path");
        persist_device_removal_marker(&root, pool.pool_guid, &stale_target_path, target_guid)
            .unwrap();
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);

        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert!(marker_path.exists());
        assert_eq!(reopened.stats().device_count, 1);
        assert_eq!(
            reopened.get(IoClass::Data, key).unwrap(),
            Some(payload.to_vec())
        );

        drop(reopened);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_marker_for_reduced_config() {
        let root = temp_dir("safe-remove-resume-reduced-config");
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
        let key = ObjectKey::from_name(b"resume-preserves-marker-after-detach");
        let data = b"in-memory detach does not clear removal marker".to_vec();
        pool.put(IoClass::Data, key, &data).unwrap();
        pool.sync_all().unwrap();

        let target_guid = pool.device_guid_for_index(0);
        let result = pool.safe_remove_device(&d1).unwrap();
        assert_topology_commit_pending(&result);
        assert_eq!(pool.stats().device_count, 1);
        assert!(d1.exists());
        let refused_key = ObjectKey::from_name(b"post-detach-mutation-must-wait");
        assert_invalid_options_reason_contains(
            pool.put(
                IoClass::Data,
                refused_key,
                b"must not enter an uncommitted removal topology",
            ),
            "awaits durable removal topology commit",
        );
        assert!(pool.devices[0].get(refused_key).unwrap().is_none());

        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        persist_device_removal_marker(&root, pool.pool_guid, &d1, target_guid).unwrap();

        assert_invalid_options_reason_contains(
            resume_device_removal_if_pending(&mut pool),
            "target is absent from the labeled topology",
        );

        assert!(marker_path.exists());
        assert_eq!(pool.stats().device_count, 1);
        assert_eq!(pool.get(IoClass::Data, key).unwrap(), Some(data));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_marker_for_incomplete_guid_table() {
        let root = temp_dir("safe-remove-resume-incomplete-guid-table");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[1].root().to_path_buf();
        let target_guid = pool.device_guid_for_index(1);
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        persist_device_removal_marker(&root, pool.pool_guid, &target_path, target_guid).unwrap();

        pool.device_guids.pop();
        assert_invalid_options_reason_contains(
            resume_device_removal_if_pending(&mut pool),
            "incomplete topology identity",
        );

        assert!(marker_path.exists());
        assert_eq!(pool.stats().device_count, 2);
        assert!(pool
            .devices
            .iter()
            .any(|device| device.root() == target_path));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_marker_for_different_pool() {
        let root = temp_dir("safe-remove-resume-different-pool");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[1].root().to_path_buf();
        let target_guid = pool.device_guid_for_index(1);
        let mut marker_pool_guid = pool.pool_guid;
        marker_pool_guid[0] ^= 0xff;
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        persist_device_removal_marker(&root, marker_pool_guid, &target_path, target_guid).unwrap();

        resume_device_removal_if_pending(&mut pool).unwrap();

        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(marker.pool_guid, marker_pool_guid);
        assert_eq!(marker.target_guid, target_guid);
        assert_eq!(pool.stats().device_count, 2);
        assert!(matches!(
            pool.safe_remove_device(&target_path),
            Err(StoreError::InvalidOptions {
                reason: "device removal marker belongs to a different pool"
            })
        ));
        assert_eq!(pool.stats().device_count, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_marker_for_rebound_target_path() {
        let root = temp_dir("safe-remove-resume-rebound-target-path");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config, PoolProperties::default(), &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);
        let target_path = pool.devices[1].root().to_path_buf();
        let target_guid = pool.device_guid_for_index(1);
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        persist_device_removal_marker(&root, pool.pool_guid, &target_path, target_guid).unwrap();

        pool.device_guids[1] = deterministic_device_guid(2);
        assert_invalid_options_reason_contains(
            resume_device_removal_if_pending(&mut pool),
            "target is absent from the labeled topology",
        );

        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(marker.pool_guid, pool.pool_guid);
        assert_eq!(marker.target_path, target_path);
        assert_eq!(marker.target_guid, target_guid);
        assert_eq!(pool.stats().device_count, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_round_trips_target_path_bytes() {
        let root = temp_dir("safe-remove-resume-exact-target-path");
        let _ = std::fs::remove_dir_all(&root);
        let target_path = root.join(OsString::from_vec(b"data-\xff ".to_vec()));
        let mut config = multi_data_device_config(&root, 2);
        config.devices[0].path = target_path.clone();
        config.devices[0].kind = DeviceKind::Single {
            path: target_path.clone(),
        };

        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let rogue_key = ObjectKey::from_name(b"exact-target-path-removal-blocker");
        let rogue_payload = b"resume must not lose a byte-exact target path";
        pool.devices[0].put(rogue_key, rogue_payload).unwrap();

        let result = pool.safe_remove_device(&target_path).unwrap();
        assert!(!result.complete);
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(
            marker.target_path.as_os_str().as_bytes(),
            target_path.as_os_str().as_bytes()
        );

        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(config, PoolProperties::default(), &test_options()),
            "could not reach topology-commit-pending state",
        );
        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(
            marker.target_path.as_os_str().as_bytes(),
            target_path.as_os_str().as_bytes()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn device_removal_marker_corrupt_bytes_fail_pool_open() {
        let root = temp_dir("device-removal-marker-corrupt");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        let mut encoded = encode_device_removal_marker(
            pool.pool_guid,
            &target_path,
            pool.device_guid_for_index(0),
        )
        .unwrap();
        let checksum_byte = encoded.last_mut().unwrap();
        *checksum_byte ^= 0x80;
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        drop(pool);
        std::fs::write(&marker_path, &encoded).unwrap();

        assert!(matches!(
            Pool::open(config, PoolProperties::default(), &test_options()),
            Err(StoreError::InvalidOptions {
                reason: "device removal marker is corrupt or unverifiable"
            })
        ));
        assert_eq!(std::fs::read(&marker_path).unwrap(), encoded);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn device_removal_marker_truncated_bytes_fail_pool_open() {
        let root = temp_dir("device-removal-marker-truncated");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let target_path = pool.devices[0].root().to_path_buf();
        let mut encoded = encode_device_removal_marker(
            pool.pool_guid,
            &target_path,
            pool.device_guid_for_index(0),
        )
        .unwrap();
        encoded.truncate(encoded.len() - 1);
        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        drop(pool);
        std::fs::write(&marker_path, &encoded).unwrap();

        assert!(matches!(
            Pool::open(config, PoolProperties::default(), &test_options()),
            Err(StoreError::InvalidOptions {
                reason: "device removal marker is corrupt or unverifiable"
            })
        ));
        assert_eq!(std::fs::read(&marker_path).unwrap(), encoded);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn device_removal_marker_lookup_error_fails_pool_open() {
        let root = temp_dir("device-removal-marker-lookup-error");
        let _ = std::fs::remove_dir_all(&root);
        let config = multi_data_device_config(&root, 2);
        let pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        drop(pool);

        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        std::os::unix::fs::symlink(root.join("missing-marker-target"), &marker_path).unwrap();

        let error = match Pool::open(config, PoolProperties::default(), &test_options()) {
            Ok(_) => panic!("marker lookup failure must fail pool open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::Io {
                operation: "read_device_removal_marker",
                ..
            }
        ));

        std::fs::remove_file(&marker_path).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_remove_device_resume_preserves_marker_after_refusal() {
        let root = temp_dir("safe-remove-resume-refusal");
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

        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        let rogue_key = ObjectKey::from_name(b"resume-rogue-unreceipted-object");
        let rogue_payload = b"resume refusal keeps marker";
        pool.devices[0].put(rogue_key, rogue_payload).unwrap();

        let marker_path = root.join(DEVICE_REMOVAL_MARKER_FILE);
        let target_guid = pool.device_guid_for_index(0);
        persist_device_removal_marker(&root, pool.pool_guid, &d1, target_guid).unwrap();
        let marker_tmp_path = root.join(DEVICE_REMOVAL_MARKER_TMP_FILE);
        std::fs::write(
            &marker_tmp_path,
            b"partial marker from interrupted publication",
        )
        .unwrap();

        drop(pool);

        assert_invalid_options_reason_contains(
            Pool::open(config.clone(), PoolProperties::default(), &test_options()),
            "could not reach topology-commit-pending state",
        );

        assert!(marker_path.exists());
        assert!(!marker_tmp_path.exists());
        let marker = read_device_removal_marker(&marker_path).unwrap();
        assert_eq!(marker.target_path, d1);
        assert_eq!(marker.target_guid, target_guid);
        std::fs::remove_file(&marker_path).unwrap();
        let pool2 = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert_eq!(pool2.stats().device_count, 2);
        assert_eq!(
            pool2.devices[0].get(rogue_key).unwrap(),
            Some(rogue_payload.to_vec())
        );
        assert_eq!(pool2.devices[1].get(rogue_key).unwrap(), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // Device replacement
    // ------------------------------------------------------------------

    fn replacement_evidence_test_pool(
        name: &str,
    ) -> (PathBuf, PathBuf, Pool, MemberId, MemberId, u64) {
        let root = temp_dir(name);
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
        let old_device_guid = pool.device_guid_for_index(0);
        let old_member =
            MemberId::new(u64::from_le_bytes(old_device_guid[..8].try_into().unwrap()));

        pool.replace_device(
            &d1,
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
        )
        .unwrap();

        let new_member = MemberId::new(pool.device_id_for_index(0));
        let topology_epoch = pool.placement_epoch();
        (root, d1, pool, old_member, new_member, topology_epoch)
    }

    fn replacement_replay_test_pool(
        name: &str,
    ) -> (PathBuf, PathBuf, PoolConfig, DeviceConfig, Pool) {
        let root = temp_dir(name);
        let _ = std::fs::remove_dir_all(&root);
        let old_path = root.join("data1");
        let new_path = root.join("data2");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.clone(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: old_path.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single {
                    path: old_path.clone(),
                },
                encryption: None,
                compression: None,
            }],
        };
        let replacement_config = DeviceConfig {
            media_class: Default::default(),
            path: new_path,
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: root.join("data2"),
            },
            encryption: None,
            compression: None,
        };
        let pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        (root, old_path, config, replacement_config, pool)
    }

    fn assert_replacement_evidence_fail_closed(
        evidence: &ReplacementRebuildEvidenceStatus,
        old_member: MemberId,
        new_member: MemberId,
        topology_epoch: u64,
    ) {
        assert_eq!(evidence.old_member, old_member);
        assert_eq!(evidence.new_member, new_member);
        assert_eq!(evidence.topology_epoch, topology_epoch);
        assert_eq!(
            evidence.detach_decision,
            ReplacementDetachDecision::UnsafeToDetach
        );
        assert_eq!(evidence.verified_receipt_count, 0);
        assert!(!evidence.evidence_stable);
        assert!(!evidence.remanence_treatment.old_device_detach_allowed);
        assert!(!evidence.remanence_treatment.media_privacy_claimed);
        assert!(!evidence.remanence_treatment.secure_erase_claimed);
        assert!(!evidence.remanence_treatment.sanitization_claimed);
        assert!(!evidence.remanence_treatment.decommissioning_claimed);
    }

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
    fn replacement_evidence_discovers_old_device_receipt_subjects() {
        let root = temp_dir("replace-evidence-receipt-subjects");
        let _ = std::fs::remove_dir_all(&root);
        let properties = PoolProperties {
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            ..PoolProperties::default()
        };
        let mut config = multi_data_device_config(&root, 2);
        let mut pool = Pool::create(config.clone(), properties, &test_options()).unwrap();
        set_deterministic_device_guids(&mut pool);

        let old_index = 0;
        let old_path = pool.devices[old_index].root().to_path_buf();
        let old_device_guid = pool.device_guid_for_index(old_index);
        let payload = b"replacement receipt subject";
        let candidates = vec![0, 1];
        let keys: Vec<_> = (0u64..1024)
            .map(|index| ObjectKey::from_name(format!("replacement-subject-{index}")))
            .filter(|key| {
                pool.plan_pool_wide_placement(IoClass::Data, *key, payload.len(), &candidates)
                    .unwrap()
                    .targets
                    .iter()
                    .any(|target| target.device_guid == old_device_guid)
            })
            .take(2)
            .collect();
        assert_eq!(keys.len(), 2, "test pool must find old-device subjects");
        for key in keys {
            pool.put(IoClass::Data, key, payload).unwrap();
        }

        let replacement_path = root.join("replacement-data");
        let replacement_config = DeviceConfig {
            media_class: Default::default(),
            path: replacement_path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: replacement_path,
            },
            encryption: None,
            compression: None,
        };
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .unwrap();

        config.devices[old_index] = replacement_config;
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        let replayed = reopened
            .replacement_rebuild_evidence_status()
            .expect("reopened replacement evidence status");
        assert_eq!(replayed.state, ReplacementRebuildStatusState::Resuming);
        assert_eq!(replayed.total_subjects, 2);
        assert_eq!(replayed.subjects_completed, 0);
        assert_eq!(replayed.verified_receipt_count, 0);
        assert!(!replayed.evidence_stable);
        assert_eq!(
            replayed.detach_decision,
            ReplacementDetachDecision::UnsafeToDetach
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_rebuild_evidence_status_projects_in_progress_fail_closed() {
        let (root, _old_path, mut pool, old_member, new_member, topology_epoch) =
            replacement_evidence_test_pool("replace-evidence-pending");
        pool.replacement.as_mut().unwrap().state = ReplacementState::InProgress {
            bytes_copied: 15,
            total_bytes: 10,
        };

        let evidence = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence status");
        assert_replacement_evidence_fail_closed(&evidence, old_member, new_member, topology_epoch);
        assert_eq!(evidence.state, ReplacementRebuildStatusState::Pending);
        assert_eq!(evidence.total_subjects, 0);
        assert_eq!(evidence.subjects_completed, 0);
        assert_eq!(evidence.subjects_failed, 0);
        assert!(evidence.evidence_replayable_after_reopen);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_rebuild_evidence_status_projects_completed_fail_closed() {
        let (root, _old_path, mut pool, old_member, new_member, topology_epoch) =
            replacement_evidence_test_pool("replace-evidence-completed");
        pool.replacement.as_mut().unwrap().state = ReplacementState::CopyComplete;

        let evidence = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence status");
        assert_replacement_evidence_fail_closed(&evidence, old_member, new_member, topology_epoch);
        assert_eq!(evidence.state, ReplacementRebuildStatusState::Completed);
        assert_eq!(evidence.total_subjects, 0);
        assert_eq!(evidence.subjects_completed, 0);
        assert_eq!(evidence.subjects_failed, 0);
        assert!(!evidence.evidence_replayable_after_reopen);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_rebuild_evidence_status_projects_cancelled_fail_closed() {
        let (root, _old_path, mut pool, old_member, new_member, topology_epoch) =
            replacement_evidence_test_pool("replace-evidence-cancelled");
        pool.replacement.as_mut().unwrap().state = ReplacementState::Cancelled;

        let evidence = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence status");
        assert_replacement_evidence_fail_closed(&evidence, old_member, new_member, topology_epoch);
        assert_eq!(evidence.state, ReplacementRebuildStatusState::Canceled);
        assert_eq!(evidence.total_subjects, 0);
        assert_eq!(evidence.subjects_completed, 0);
        assert_eq!(evidence.subjects_failed, 0);
        assert!(!evidence.evidence_replayable_after_reopen);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_rebuild_evidence_status_projects_failed_fail_closed() {
        let (root, _old_path, mut pool, old_member, new_member, topology_epoch) =
            replacement_evidence_test_pool("replace-evidence-failed");
        pool.replacement.as_mut().unwrap().state = ReplacementState::Failed {
            reason: "copy failed".into(),
        };

        let evidence = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence status");
        assert_replacement_evidence_fail_closed(&evidence, old_member, new_member, topology_epoch);
        assert_eq!(evidence.state, ReplacementRebuildStatusState::Refused);
        assert_eq!(evidence.total_subjects, 0);
        assert_eq!(evidence.subjects_completed, 0);
        assert_eq!(evidence.subjects_failed, 0);
        assert!(!evidence.evidence_replayable_after_reopen);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_reopens_resuming_and_reuses_identity_on_resume() {
        let (root, old_path, config, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-reopen-resume");
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .unwrap();
        let candidate_key = ObjectKey::from_name(b"candidate-high-water-before-stale-reopen");
        let (_, candidate_receipt) = pool
            .put_with_receipt(
                IoClass::Data,
                candidate_key,
                b"candidate generation authority",
            )
            .unwrap();
        let candidate_ceiling = pool.reserved_placement_receipt_generation_through;
        assert!(candidate_ceiling >= candidate_receipt.generation);
        let before_reopen = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence before reopen");
        assert_eq!(before_reopen.state, ReplacementRebuildStatusState::Pending);
        assert!(before_reopen.evidence_replayable_after_reopen);
        drop(pool);

        let mut reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        assert!(reopened.replacement_status().is_none());
        let replayed = reopened
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence after reopen");
        assert_eq!(replayed.state, ReplacementRebuildStatusState::Resuming);
        assert_eq!(replayed.old_member, before_reopen.old_member);
        assert_eq!(replayed.new_member, before_reopen.new_member);
        assert_eq!(replayed.topology_epoch, before_reopen.topology_epoch);
        assert!(replayed.evidence_replayable_after_reopen);
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
        assert!(reopened.devices[0].get(refused_key).unwrap().is_none());
        assert!(reopened.devices[0]
            .get(placement_receipt_object_key(refused_key))
            .unwrap()
            .is_none());

        reopened
            .replace_device(&old_path, replacement_config, &test_options())
            .unwrap();
        let resumed = reopened
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence after resume");
        assert_eq!(resumed.state, ReplacementRebuildStatusState::Pending);
        assert_eq!(resumed.old_member, before_reopen.old_member);
        assert_eq!(resumed.new_member, before_reopen.new_member);
        assert_eq!(resumed.topology_epoch, before_reopen.topology_epoch);
        assert!(resumed.evidence_replayable_after_reopen);
        let (_, after_resume) = reopened
            .put_with_receipt(
                IoClass::Data,
                ObjectKey::from_name(b"generation-after-explicit-resume"),
                b"new authority",
            )
            .unwrap();
        assert!(after_resume.generation > candidate_ceiling);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_reopens_new_topology_from_persisted_labels() {
        let root = temp_dir("replace-evidence-reopen-new-topology");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let old_path = root.join("pool0.img");
        let new_path = root.join("pool1.img");
        for (path, size) in [(&old_path, 2 * 1024 * 1024), (&new_path, 4 * 1024 * 1024)] {
            let file = std::fs::File::create(path).unwrap();
            file.set_len(size).unwrap();
        }
        let mut config = PoolConfig {
            name: "testpool".into(),
            root_path: root.join("metadata"),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: old_path.clone(),
                backing: DeviceBacking::RegularFileDev,
                class: DeviceClass::Data,
                kind: DeviceKind::Block {
                    path: old_path.clone(),
                },
                encryption: None,
                compression: None,
            }],
        };
        let replacement_config = DeviceConfig {
            media_class: Default::default(),
            path: new_path.clone(),
            backing: DeviceBacking::RegularFileDev,
            class: DeviceClass::Data,
            kind: DeviceKind::Block {
                path: new_path.clone(),
            },
            encryption: None,
            compression: None,
        };
        let mut pool =
            Pool::create(config.clone(), PoolProperties::default(), &test_options()).unwrap();

        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .unwrap();
        let before_reopen = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence before reopen");

        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = std::fs::File::open(&new_path).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let label = pool_label::decode_label(&label_bytes).expect("replacement label");
        let layout_bytes = pool_label::decode_device_layout_v1_bytes(&label_bytes)
            .unwrap()
            .expect("replacement label layout");
        let layout = decode_device_layout_v1(&layout_bytes).expect("replacement device layout");
        assert_eq!(label.pool_guid, pool.pool_guid());
        assert_eq!(label.device_guid, pool.device_guid_for_index(0));
        assert_eq!(label.topology_generation, before_reopen.topology_epoch);
        assert_eq!(label.pool_state, PoolState::Active);
        assert_eq!(
            layout.device_size_bytes,
            pool.devices[0].store().capacity_bytes()
        );

        config.devices[0] = replacement_config;
        drop(pool);

        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        let replayed = reopened
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence after new-topology reopen");
        assert_eq!(replayed.state, ReplacementRebuildStatusState::Resuming);
        assert_eq!(replayed.old_member, before_reopen.old_member);
        assert_eq!(replayed.new_member, before_reopen.new_member);
        assert_eq!(replayed.topology_epoch, before_reopen.topology_epoch);
        assert!(replayed.evidence_replayable_after_reopen);
        assert_eq!(
            replayed.detach_decision,
            ReplacementDetachDecision::UnsafeToDetach
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replayed_replacement_cancel_persists_terminal_evidence() {
        let (root, old_path, config, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-reopen-cancel");
        pool.replace_device(&old_path, replacement_config.clone(), &test_options())
            .unwrap();
        let replacement_identity = pool
            .replacement_rebuild_evidence_status()
            .expect("replacement evidence before cancel");
        drop(pool);

        let mut reopened =
            Pool::open(config.clone(), PoolProperties::default(), &test_options()).unwrap();
        reopened
            .replace_device(&old_path, replacement_config, &test_options())
            .unwrap();
        reopened.cancel_replacement(&test_options()).unwrap();
        let canceled = reopened
            .replacement_rebuild_evidence_status()
            .expect("canceled replacement evidence");
        assert_eq!(canceled.state, ReplacementRebuildStatusState::Canceled);
        assert_eq!(canceled.old_member, replacement_identity.old_member);
        assert_eq!(canceled.new_member, replacement_identity.new_member);
        assert!(canceled.evidence_replayable_after_reopen);
        assert_eq!(
            canceled.detach_decision,
            ReplacementDetachDecision::UnsafeToDetach
        );
        assert_eq!(reopened.placement_epoch(), canceled.topology_epoch);
        drop(reopened);

        let reopened = Pool::open(config, PoolProperties::default(), &test_options()).unwrap();
        let canceled = reopened
            .replacement_rebuild_evidence_status()
            .expect("replayed canceled replacement evidence");
        assert_eq!(canceled.state, ReplacementRebuildStatusState::Canceled);
        assert!(canceled.evidence_replayable_after_reopen);
        assert_eq!(reopened.placement_epoch(), canceled.topology_epoch);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_corruption_refuses_reopen() {
        let (root, old_path, config, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-corrupt");
        pool.replace_device(&old_path, replacement_config, &test_options())
            .unwrap();
        drop(pool);

        let evidence_path = root.join(DEVICE_REPLACEMENT_EVIDENCE_FILE);
        let mut encoded = std::fs::read(&evidence_path).unwrap();
        encoded[DEVICE_REPLACEMENT_EVIDENCE_MAGIC_V1.len()] ^= 0x80;
        std::fs::write(&evidence_path, encoded).unwrap();

        let result = Pool::open(config, PoolProperties::default(), &test_options());
        assert!(matches!(
            result,
            Err(StoreError::InvalidOptions {
                reason: "device replacement evidence is corrupt or unverifiable"
            })
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replacement_evidence_publish_failure_keeps_old_topology() {
        let (root, old_path, _config, replacement_config, mut pool) =
            replacement_replay_test_pool("replace-evidence-publish-failure");
        let old_device_guid = pool.device_guid_for_index(0);
        let old_topology_epoch = pool.placement_epoch();
        std::fs::create_dir(root.join(DEVICE_REPLACEMENT_EVIDENCE_TMP_FILE)).unwrap();

        let result = pool.replace_device(&old_path, replacement_config, &test_options());
        assert!(result.is_err());
        assert_eq!(pool.devices[0].root(), old_path);
        assert_eq!(pool.device_guid_for_index(0), old_device_guid);
        assert_eq!(pool.placement_epoch(), old_topology_epoch);
        assert!(pool.replacement_status().is_none());
        assert!(pool.replacement_rebuild_evidence_status().is_none());
        assert!(!root.join(DEVICE_REPLACEMENT_EVIDENCE_FILE).exists());

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
        for (path, size) in [(&d1, 2 * 1024 * 1024), (&d2, 4 * 1024 * 1024)] {
            let file = std::fs::File::create(path).unwrap();
            file.set_len(size).unwrap();
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
        assert_eq!(
            pool.device_layouts[0].device_size_bytes,
            pool.devices[0].store().capacity_bytes()
        );
        let mut label_bytes = vec![0u8; pool_label::POOL_LABEL_SIZE];
        let mut label_file = std::fs::File::open(&d1).unwrap();
        label_file.read_exact(&mut label_bytes).unwrap();
        let label = pool_label::decode_label(&label_bytes).unwrap();
        assert_eq!(label.device_guid, pool.device_guid_for_index(0));
        assert_eq!(label.topology_generation, pool.placement_epoch());
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
        assert!(root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
        assert_topology_commit_pending(&removal);
        assert_eq!(pool.log_device_count(), 0);
        assert!(!pool.log_device_healthy());
        assert!(!pool.has_log_device());
        pool.log_device_append(b"after-remove").unwrap();
        assert_eq!(std::fs::metadata(&log_path).unwrap().len(), drained_log_len);

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

        let mut marker_device =
            open_single_device(&config.devices[0], &options, true).expect("open marker device");
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
        assert!(!root.join(DEVICE_REMOVAL_MARKER_FILE).exists());

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
}
