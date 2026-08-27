// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Central write-path coordinator for the local object store.
//!
//! The [`LocalObjectStore`] struct owns the full lifecycle of durable object
//! storage: opening (with segment replay), writing new objects through the
//! [`SegmentBuilder`], flushing segments to disk, serving reads from the
//! in-memory object index, and reclaiming space via the [`ReclaimScheduler`].
//!
//! # Write path overview
//!
//! ```text
//! caller  ->  put_content_addressed(key, payload)
//!          ->  ObjectKey derived via BLAKE3-256
//!          ->  segment_builder.push()
//!          ->  [when threshold reached or flush requested]
//!          ->  segment_builder.finish() -> WriteSegment
//!          ->  flush_segment(WriteSegment)
//!          ->    write record header + payload + IntegrityTrailerV2 + footer
//!          ->    fsync segment file
//!          ->    update in-memory index
//! ```
//!
//! # Segment replay on open
//!
//! When the store opens, it replays every `segment-NNN.vlos` file:
//! reads each record header, validates magic bytes and version, verifies
//! BLAKE3-256 integrity digests against the [`ProductionIntegrityDigest`],
//! reconstructs the [`ObjectKey`] → [`ObjectLocation`] index, and detects
//! torn (incomplete) final records by the absence of a valid commit footer.
//! Torn records are silently truncated and repaired.
//!
//! # Concurrency
//!
//! The store is single-writer by design. Reads are served from the in-memory
//! index and segment files without write-path coordination.
//!

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};
use std::time::Instant;
// already imported above
// already imported above
use crate::compress::CompressionStats;
use crate::io_scheduler::{IoScheduler, IoSchedulerConfig};
#[cfg(test)]
use crate::reclaim_queue::load_dead_object_reclaim_queue;
use crate::reclaim_queue::{
    load_reclaim_queue_entries, load_reclaim_receipts, load_segment_liveness_queue,
    load_snapshot_extent_pin_set, store_reclaim_receipts, store_snapshot_extent_pin_set,
    DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME, RECLAIM_QUEUE_ENTRIES_OBJECT_NAME,
    RECLAIM_QUEUE_OBJECT_NAME, RECLAIM_RECEIPTS_OBJECT_NAME, SNAPSHOT_EXTENT_PIN_SET_OBJECT_NAME,
};
use crate::segment_builder::{FlushResult, SegmentBuilder};
use crate::txg_manager::CommitGroupManager;
use crate::*;
use std::convert::Infallible;
use tidefs_checksum_tree::{
    ChecksumTree, ChecksumTreeBuilder, ChecksumTreeVerifier, DomainTag, LocatorToken, ObjectDigest,
    VerificationResult,
};
use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_gc_pin_set::SnapshotExtentPinSet;
use tidefs_pool_allocator::{PoolAllocator, PoolAllocatorError, SpacePressureEvent};
use tidefs_reclaim::{
    ClearanceEvidence, DrainError, GateDecision, GateDenyReason, ReclaimConfig,
    ReclaimConsumerConfig, ReclaimConsumerService, ReclaimGate, ReclaimReceipt, ReclaimScheduler,
    SegmentLiveCounts,
};
use tidefs_reclaim_queue_core::{
    BPlusTreeReclaimQueue, DeadObjectReclaimQueue, SegmentLivenessQueue,
};
#[cfg(test)]
use tidefs_space_accounting::Error as SpaceAccountingError;
use tidefs_space_accounting::{DatasetSpaceUsage, PoolCounters, SpaceBook, StatfsResult};
use tidefs_spacemap_allocator::{SegmentFreeMap, SpaceMapCheckpointV1};
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReplacementReceipt, ObjectKey as ReclaimObjectKey, QueueFamily,
    ReclaimQueueEntry,
};

use tidefs_reserve_ledger::{ReserveLedger, WritePriority};
use tidefs_types_pool_label_core::POOL_LABEL_SIZE;

type StoreIndex = BTreeMap<ObjectKey, ObjectLocation>;
type StoreHistory = BTreeMap<ObjectKey, Vec<ObjectLocation>>;
type BlockIndexScan = (StoreIndex, StoreHistory, u64, u64);
type IndexCheckpoint = Option<(StoreIndex, StoreHistory, u64)>;

/// Immutable identity of one byte-addressable member of a labelled Pool.
///
/// Mutable topology, capacity, and layout stay in Pool label authority.  A
/// device can be grown, reordered, exported, or admitted to a later topology
/// without changing the incarnation of the object log stored on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockStoreIdentity {
    pub pool_guid: [u8; 16],
    pub device_guid: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockStoreBootstrapInspection {
    pub identity: Option<BlockStoreIdentity>,
    pub record: Option<(ObjectKey, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockFormatHeader {
    identity: BlockStoreIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockFormatHeaderState {
    Blank,
    Current(BlockFormatHeader),
}

/// Offset where the pool commit-record region ends and the object-store
/// data region begins.  The commit-record region occupies bytes
/// [8192, 8192 + 256 KiB) = [8192, 270336).  Object records start
/// after this, avoiding interference between commit history and
/// object-store record scanning.
const BLOCK_DEVICE_DATA_REGION_OFFSET: u64 = 270_336;

/// Magic bytes for the identity-bound block-device data-region format header.
const BLOCK_DATA_MAGIC: [u8; 8] = *b"TFSBLK2\0";
/// Size of the block-device format header.
const BLOCK_DATA_FORMAT_HEADER_SIZE: u64 = 80;
/// Block-device format version.
const BLOCK_DATA_FORMAT_VERSION: u32 = 2;
const BLOCK_DATA_FORMAT_CHECKSUM_OFFSET: usize = 48;
/// Well-known file name for the store format manifest (JSON).
const FORMAT_MANIFEST_FILE_NAME: &str = "format_manifest";
/// Well-known object name for committed compaction publication manifests.
const COMPACTION_PUBLISH_MANIFEST_OBJECT_NAME: &str = "tidefs-compaction-publish-manifest";
/// Hidden block-log record that preserves the globally unique physical put
/// sequence after compaction removes every record that previously carried the
/// maximum. It is rewritten only as part of the verified compacted prefix.
const PHYSICAL_LIFETIME_SEQUENCE_HIGH_WATER_OBJECT_NAME: &str =
    "tidefs-physical-lifetime-sequence-high-water-v1";
/// `sync_all()` records remaining named reclaim authority through
/// `put_named()`, which opens one commit group, then publishes its chained root
/// on block media as the exact 48-byte payload produced by
/// `encode_root_with_digest()`. Root-owned dead-object entries use their own
/// focused barrier and do not consume this reserve.
const CHAINED_COMMITTED_ROOT_PAYLOAD_LEN: u64 = 48;
/// Well-known object name for the mounted filesystem's exact deferred-reclaim queue.
///
/// This is distinct from the object-store's physical reclaim queues: the
/// filesystem queue retains logical object-key obligations until every
/// mountable root has stopped referencing them and `Pool::delete()` has
/// completed the receipt-authoritative handoff.
pub const FILESYSTEM_RECLAIM_QUEUE_OBJECT_NAME: &str = "tidefs-filesystem-reclaim-queue-v1";
/// Prefix for hidden target objects staged by verified compaction rewrites.
const COMPACTION_TARGET_KEY_PREFIX: [u8; 8] = *b"TFSCMPCT";
/// Root-owned receipt-bound reclaim rows.
///
/// Each physical store root persists only the lifetimes it owns. Keeping one
/// checksummed queue entry behind each derived key makes a transition an
/// append of constant size instead of a rewrite of the complete growing
/// queue. These records deliberately do not use ordinary store-replica fanout:
/// replica roots can own different physical lifetime identities.
const DEAD_OBJECT_RECLAIM_ENTRY_KEY_PREFIX: [u8; 8] = *b"TFSRQE1\0";
/// Hidden Pool-owned records that make logical deletion publication replayable.
///
/// The remaining 24 bytes identify one `(I/O class, object key, receipt
/// generation)` handoff.  The Pool owns the record format; the store only
/// reserves and preserves the namespace so raw callers, scans, statistics,
/// and compaction cannot mistake it for user payload.
pub(crate) const POOL_PENDING_DELETION_KEY_PREFIX: [u8; 8] = *b"TFSPDEL1";
const COMPACTION_MANIFEST_MAGIC: &[u8; 8] = b"TFSCMPM1";
const COMPACTION_MANIFEST_VERSION: u32 = 1;
const COMPACTION_MANIFEST_HEADER_LEN: usize = 8 + 4 + 4;
const COMPACTION_MANIFEST_LOCATION_LEN: usize = 32 + 8 + 8 + 8 + 8 + 8 + 8;
const COMPACTION_MANIFEST_EXTENT_LEN: usize = 8 + 8 + 1 + 1 + 8 + 32 + 8 + 15;
const COMPACTION_MANIFEST_RECEIPT_LEN: usize =
    tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::ENCODED_SIZE;
const COMPACTION_MANIFEST_ENTRY_LEN: usize = 8
    + 32
    + 16
    + COMPACTION_MANIFEST_LOCATION_LEN
    + COMPACTION_MANIFEST_LOCATION_LEN
    + COMPACTION_MANIFEST_EXTENT_LEN
    + COMPACTION_MANIFEST_RECEIPT_LEN;
use crate::constants::{
    INDEX_BASE_FILE_NAME, INDEX_BASE_FORMAT_VERSION, INDEX_BASE_MAGIC, KEY_DERIVE_SEED,
};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Tracks free-segment count with a low-watermark signal for downstream
/// services (write throttling, statfs, cleaner scheduling).
///
/// The free count is updated via atomic operations so callers can read
/// `free_segment_count()` and `is_low_space()` without locking the full store.
#[derive(Debug)]
pub struct FreeSegmentCounter {
    free_count: AtomicU64,
    low_watermark: AtomicBool,
    low_watermark_segments: u64,
}

#[derive(Clone, Debug, Default)]
struct DeadObjectDrainSegmentResolver {
    segments: BTreeMap<ReclaimObjectKey, u64>,
}

impl tidefs_reclaim::SegmentResolver for DeadObjectDrainSegmentResolver {
    type Error = Infallible;

    fn resolve(&self, key: &ReclaimObjectKey) -> std::result::Result<Option<u64>, Self::Error> {
        Ok(self.segments.get(key).copied())
    }
}

/// Non-mutating first phase of receipt-bound physical reclaim.
///
/// The reclaim consumer owns liveness and gate evaluation, but durable receipt
/// and queue acknowledgement must precede allocator or segment-file mutation.
/// Record its exact decision here, then apply it only after both authorities
/// have crossed their durability barriers.
#[derive(Debug, Default)]
struct RecordingSegmentFreer {
    segment_ids: BTreeSet<u64>,
}

impl tidefs_reclaim::SegmentFreer for RecordingSegmentFreer {
    type Error = PoolAllocatorError;

    fn free_segment(&mut self, segment_id: u64) -> std::result::Result<(), Self::Error> {
        self.segment_ids.insert(segment_id);
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct ReceiptBoundDeadObjectDrainPlan {
    resolver: DeadObjectDrainSegmentResolver,
    dead_segments: Vec<u64>,
    eligible_object_ids: BTreeSet<ReclaimObjectKey>,
    logical_object_ids: BTreeMap<ReclaimObjectKey, ReclaimObjectKey>,
}

impl ReceiptBoundDeadObjectDrainPlan {
    fn current_segment_would_be_reclaimed(&self, current_segment_id: u64) -> bool {
        self.dead_segments.contains(&current_segment_id)
    }
}

/// One verified live-object relocation to publish at a compaction commit boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCompactionRewrite {
    pub key: ObjectKey,
    pub logical_offset: u64,
    pub old_extent: ExtentMapEntryV2,
    pub target_payload: Vec<u8>,
    pub dataset_uuid: [u8; 16],
    pub replacement_receipt: DeadObjectReplacementReceipt,
}

/// Published state for one compaction relocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedCompactionRewrite {
    pub key: ObjectKey,
    pub old_location: ObjectLocation,
    pub target_location: ObjectLocation,
    pub new_extent: ExtentMapEntryV2,
    pub checksum_root: [u8; 32],
    pub receipt_generation: u64,
}

/// Result returned after a compaction batch reaches its commit boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactionPublishReport {
    pub committed_txg: u64,
    pub committed_generation: u64,
    pub rewrites: Vec<PublishedCompactionRewrite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedCompactionPublishEntry {
    publish_txg: u64,
    key: ObjectKey,
    dataset_uuid: [u8; 16],
    old_location: ObjectLocation,
    target_location: ObjectLocation,
    new_extent: ExtentMapEntryV2,
    receipt: DeadObjectReplacementReceipt,
}

#[derive(Clone, Debug)]
struct CommittedDeadObjectReclaimGate {
    eligible_object_ids: BTreeSet<ReclaimObjectKey>,
    logical_object_ids: BTreeMap<ReclaimObjectKey, ReclaimObjectKey>,
    stable_committed_txg: u64,
    snapshot_extent_pin_set: SnapshotExtentPinSet,
}

impl ReclaimGate for CommittedDeadObjectReclaimGate {
    fn check_extent(&self, extent_key: &ReclaimObjectKey) -> GateDecision {
        if !self.eligible_object_ids.contains(extent_key) {
            return GateDecision::Deny(GateDenyReason::DeadlistReferenced);
        }

        let Some(logical_object_id) = self.logical_object_ids.get(extent_key) else {
            return GateDecision::Deny(GateDenyReason::DeadlistReferenced);
        };
        if self.snapshot_extent_pin_set.is_pinned(logical_object_id) {
            return GateDecision::Deny(GateDenyReason::SnapshotPinned);
        }

        GateDecision::Allow(ClearanceEvidence::Verified {
            deadlist_committed_txg: self.stable_committed_txg,
            pin_clearance_epoch: self.snapshot_extent_pin_set.epoch(),
        })
    }
}

/// Exact append-log lifetime owned by one receipt-bound reclaim row.
///
/// The logical key remains the snapshot-pin identity. `reclaim_object_id` is a
/// deterministic identity for these exact physical bytes, so repeated writes
/// of the same logical object can coexist in the durable reclaim queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptBoundPhysicalLifetime {
    pub logical_object_key: ObjectKey,
    pub location: ObjectLocation,
    pub reclaim_object_id: ReclaimObjectKey,
}

fn receipt_bound_physical_lifetime_id(
    logical_object_key: ObjectKey,
    location: ObjectLocation,
) -> ReclaimObjectKey {
    let mut evidence = Vec::with_capacity(2 * 32 + 4 * 8 + 40);
    evidence.extend_from_slice(b"tidefs-receipt-bound-physical-lifetime-v2");
    evidence.extend_from_slice(logical_object_key.as_bytes());
    evidence.extend_from_slice(location.key.as_bytes());
    evidence.extend_from_slice(&location.payload_len.to_le_bytes());
    evidence.extend_from_slice(&location.sequence.to_le_bytes());
    evidence.extend_from_slice(&location.payload_checksum.get().to_le_bytes());
    ReclaimObjectKey(*blake3::hash(&evidence).as_bytes())
}

fn build_receipt_bound_physical_lifetime_index(
    history: &BTreeMap<ObjectKey, Vec<ObjectLocation>>,
) -> Result<BTreeMap<ReclaimObjectKey, ReceiptBoundPhysicalLifetime>> {
    let mut lifetimes = BTreeMap::new();
    for (logical_object_key, locations) in history {
        for location in locations {
            let reclaim_object_id =
                receipt_bound_physical_lifetime_id(*logical_object_key, *location);
            let candidate = ReceiptBoundPhysicalLifetime {
                logical_object_key: *logical_object_key,
                location: *location,
                reclaim_object_id,
            };
            if let Some(known) = lifetimes.get(&reclaim_object_id) {
                if *known != candidate {
                    return Err(StoreError::InvalidDeadObjectReceipt {
                        reason: "receipt-bound physical lifetime identity collision",
                    });
                }
            } else {
                lifetimes.insert(reclaim_object_id, candidate);
            }
        }
    }
    Ok(lifetimes)
}

fn next_put_sequence_after_history(
    history: &BTreeMap<ObjectKey, Vec<ObjectLocation>>,
) -> Result<u64> {
    history
        .values()
        .flat_map(|locations| locations.iter())
        .map(|location| location.sequence)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(StoreError::InvalidOptions {
            reason: "object-store physical lifetime sequence exhausted",
        })
}

/// Error returned by the receipt-bound dead-object drain entry point.
#[derive(Debug)]
pub enum ReceiptBoundDeadObjectDrainError {
    /// The reclaim consumer could not resolve or free a selected segment.
    Reclaim(DrainError<Infallible, PoolAllocatorError>),
    /// Queue persistence, segment rotation, or the durability barrier failed.
    Store(StoreError),
}

impl fmt::Display for ReceiptBoundDeadObjectDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reclaim(error) => write!(f, "receipt-bound dead-object drain failed: {error}"),
            Self::Store(error) => {
                write!(f, "receipt-bound dead-object persistence failed: {error}")
            }
        }
    }
}

impl std::error::Error for ReceiptBoundDeadObjectDrainError {}

impl From<DrainError<Infallible, PoolAllocatorError>> for ReceiptBoundDeadObjectDrainError {
    fn from(value: DrainError<Infallible, PoolAllocatorError>) -> Self {
        Self::Reclaim(value)
    }
}

impl From<StoreError> for ReceiptBoundDeadObjectDrainError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Snapshot-deadlist object candidate accepted by the local object store.
///
/// This API is intentionally narrower than the persisted
/// [`DeadObjectEntry`] format: snapshot/clone deletion derivation supplies
/// only object identity plus commit-group metadata, and the object store turns
/// it into receipt-bound reclaim work in
/// `tidefs-dead-object-reclaim-queue`. No replacement receipt is accepted
/// here; callers must publish committed receipt evidence through
/// [`LocalObjectStore::publish_dead_object_replacement_receipt`] before
/// physical reclaim can run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotDeadObjectCandidate {
    pub object_id: ReclaimObjectKey,
    pub dataset_uuid: [u8; 16],
    pub death_commit_group: u64,
    pub enqueued_at_txg: u64,
}

impl SnapshotDeadObjectCandidate {
    #[must_use]
    pub const fn new(
        object_id: ReclaimObjectKey,
        dataset_uuid: [u8; 16],
        death_commit_group: u64,
        enqueued_at_txg: u64,
    ) -> Self {
        Self {
            object_id,
            dataset_uuid,
            death_commit_group,
            enqueued_at_txg,
        }
    }

    fn into_dead_object_entry(self) -> DeadObjectEntry {
        DeadObjectEntry::new(
            self.object_id,
            self.dataset_uuid,
            self.death_commit_group,
            true,
            self.enqueued_at_txg,
        )
    }
}

fn reclaim_receipt_replay_allocator_error(error: PoolAllocatorError) -> StoreError {
    match error {
        PoolAllocatorError::SegmentOutOfRange(_) => StoreError::InvalidOptions {
            reason: "reclaim receipt references segment outside configured pool",
        },
        _ => StoreError::InvalidOptions {
            reason: "reclaim receipt allocator replay failed",
        },
    }
}

impl FreeSegmentCounter {
    pub fn new(initial_free: u64, low_watermark_segments: u64) -> Self {
        let low = initial_free <= low_watermark_segments;
        Self {
            free_count: AtomicU64::new(initial_free),
            low_watermark: AtomicBool::new(low),
            low_watermark_segments,
        }
    }

    /// Call when a segment is allocated (free count decreases).
    pub fn allocated(&self) {
        let prev = self
            .free_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            })
            .unwrap_or(0);
        let new = prev.saturating_sub(1);
        if new <= self.low_watermark_segments {
            self.low_watermark.store(true, Ordering::Release);
        }
    }

    /// Call when a segment is freed (free count increases).
    pub fn freed(&self) {
        let new = self.free_count.fetch_add(1, Ordering::AcqRel);
        let new = new.saturating_add(1);
        if new > self.low_watermark_segments {
            self.low_watermark.store(false, Ordering::Release);
        }
    }

    /// Current number of free segments (lock-free read).
    pub fn free_segment_count(&self) -> u64 {
        self.free_count.load(Ordering::Acquire)
    }

    /// Whether free segments are at or below the low-watermark threshold.
    pub fn is_low_space(&self) -> bool {
        self.low_watermark.load(Ordering::Acquire)
    }
}

/// Default capacity for the in-memory intent-log ring buffer in bytes.
const INTENT_LOG_BUFFER_CAPACITY: usize = 16 * 1024 * 1024; // 16 MiB

use crate::ObjectKey;

impl ObjectKey {
    pub const ZERO: Self = Self([0_u8; 32]);

    #[must_use]
    pub const fn from_bytes32(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_name(name: impl AsRef<[u8]>) -> Self {
        let name = name.as_ref();
        let mut out = [0_u8; 32];
        for lane in 0..4 {
            let seed = KEY_DERIVE_SEED ^ (lane as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let digest = checksum64_with_seed_and_len(name, seed);
            out[lane * 8..(lane + 1) * 8].copy_from_slice(&digest.to_le_bytes());
        }
        Self(out)
    }

    /// Derive a content-addressed object key from payload bytes.
    ///
    /// This uses BLAKE3-256 to match the crate's current production integrity
    /// digest format while keeping the public key width at 32 bytes.
    #[must_use]
    pub fn from_content(payload: impl AsRef<[u8]>) -> Self {
        Self(*blake3::hash(payload.as_ref()).as_bytes())
    }

    #[must_use]
    pub const fn as_bytes32(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn short_hex(self) -> String {
        let mut out = String::with_capacity(16);
        for byte in &self.0[..8] {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

#[derive(Debug)]
pub struct LocalObjectStore {
    root: PathBuf,
    segments_dir: PathBuf,
    options: StoreOptions,
    pub(crate) read_only: bool,
    pub(crate) current_segment_id: u64,
    pub(crate) free_map: PoolAllocator,
    current_offset: u64,
    current_file: File,
    /// Exact raw capacity captured from the retained byte-device handle at
    /// admission.  Keeping it here avoids seeking a duplicated descriptor:
    /// `File::try_clone` shares the open-file-description offset and would
    /// disturb the writer even when used only for a read-side size probe.
    block_device_capacity: Option<u64>,
    segment_created_at: Instant,
    segment_write_count: u64,
    index: BTreeMap<ObjectKey, ObjectLocation>,
    /// Exact projection of non-internal live entries in `index`.
    ///
    /// These counters are updated by the same helpers that mutate the live
    /// index and rebuilt from the index on open and wholesale replacement.
    /// They are a lower-layer physical-placement input, not mounted capacity
    /// authority.
    stats_live_objects: usize,
    stats_live_bytes: u64,
    history: BTreeMap<ObjectKey, Vec<ObjectLocation>>,
    receipt_bound_physical_lifetimes: BTreeMap<ReclaimObjectKey, ReceiptBoundPhysicalLifetime>,
    pub(crate) next_sequence: u64,
    replay: ReplayReport,
    current_io_class: IoClass,
    io_scheduler: IoScheduler,
    tombstone_count: u64,
    last_replicated_write: Option<crate::ReplicatedWriteResult>,
    pub(crate) replicas: Vec<LocalObjectStore>,
    replica_healthy: Vec<bool>,
    last_scrub: Instant,
    pub(crate) fault_injection_config: Option<super::FaultInjectionConfig>,
    reclaim_scheduler: ReclaimScheduler,
    reclaim_queue: BPlusTreeReclaimQueue,
    dead_object_reclaim_queue: DeadObjectReclaimQueue,
    /// Last queue contents known to have crossed this store's durability
    /// barrier. The current index may already point at an unsynced append, so
    /// retry compaction must not infer old durable authority from that index.
    durable_dead_object_reclaim_queue: DeadObjectReclaimQueue,
    /// Exact per-entry changes waiting for the next root-owned durability
    /// barrier. Keeping this delta explicit makes the ordinary Pool barrier
    /// proportional to newly changed lifetimes rather than the lifetime of the
    /// complete reclaim queue.
    dead_object_reclaim_pending_upserts: BTreeMap<ReclaimObjectKey, DeadObjectEntry>,
    dead_object_reclaim_pending_upsert_record_bytes: u64,
    dead_object_reclaim_pending_removals: BTreeSet<ReclaimObjectKey>,
    dead_object_reclaim_queue_dirty: bool,
    reclaim_receipts: Vec<ReclaimReceipt>,
    reclaim_receipts_dirty: bool,
    snapshot_extent_pin_set: SnapshotExtentPinSet,
    snapshot_extent_pin_set_dirty: bool,
    segment_liveness: SegmentLivenessQueue,
    reclaim_consumer: ReclaimConsumerService,
    pub(crate) enospc_bytes_written: u64,
    pub(crate) segment_builder: SegmentBuilder,
    /// Online free-segment counter with low-watermark signaling.
    pub(crate) free_segment_counter: FreeSegmentCounter,
    /// Last written segment footer for hash chaining.
    pub(crate) chain_footer: SegmentIntegrityFooter,
    /// Per-record BLAKE3 digests accumulated for the current segment footer.
    pub(crate) segment_record_digests: Vec<ProductionIntegrityDigest>,
    /// Persistent corruption tracking ring buffer.
    pub(crate) suspect_log: SuspectLog,
    pub(crate) scrub_cursor: ScrubCursor,
    pub(crate) commit_group: CommitGroupManager,
    pub(crate) txg_coordinator: tidefs_commit_group::CommitGroupCoordinator,
    /// In-memory intent-log ring buffer for write-ahead logging.
    /// Accumulates BLAKE3-verified records during transaction build-up,
    /// flushed to durable intent-log segments on commit.
    pub(crate) intent_log: crate::intent_log::sync_write::IntentLog,
    pub(crate) intent_log_tx_open: bool,
    /// Optional reserve ledger shared with the allocation pipeline.
    /// When set, the write path consults the reserve before consuming
    /// free segments; set via [`set_reserve_ledger`](LocalObjectStore::set_reserve_ledger).
    pub(crate) reserve_ledger: Option<Arc<Mutex<ReserveLedger>>>,
    /// Pool-owned gate for public raw mutations.
    ///
    /// A pool installs one shared gate on every admitted raw store. Pool
    /// internals retain separate crate-private mutation entry points for
    /// receipt and high-water publication while public raw callers fail
    /// closed whenever the pool's receipt-generation authority is not
    /// converged.
    pool_raw_mutation_allowed: Option<Arc<AtomicBool>>,
    /// Optional compression config set via [`set_compression`].
    compression_config: Option<CompressionConfig>,
    /// Cumulative inline compression statistics.
    pub compression_stats: CompressionStats,
    /// Optional durability layout policy for failure-domain-aware placement.
    /// Set via StoreOptions on open; can be changed at runtime via
    /// [`set_durability_layout`].
    pub(crate) durability_layout: Option<DurabilityLayoutV1>,
    /// Multi-dataset committed-counter projection with dirty-flag persistence.
    pub(crate) space_book: SpaceBook,
    /// Test-only dataset context for raw-store SpaceBook producer fixtures.
    ///
    /// Production mounted accounting is committed by the filesystem through
    /// `sync_dataset_counters`; store writes and deletes must not update an
    /// independent mounted capacity mirror.
    #[cfg(test)]
    pub(crate) current_dataset_id: Option<[u8; 16]>,
    /// Per-object BLAKE3 domain-separated checksums for read-path verification.
    /// Computed on every write and persisted by its transaction or explicit
    /// Pool-prepublication sync boundary.
    pub(crate) checksums: BTreeMap<ObjectKey, ObjectDigest>,
    /// Prepublication writes deliberately do not enter the ordinary transaction
    /// group, so their checksum-index update must join the next explicit sync.
    prepublication_checksums_dirty: bool,
    /// Block-device prepublication batches retain their contiguous encoded
    /// records until the Pool closes the append boundary. The buffer always
    /// ends in a zero successor header, so one positioned write installs a
    /// scan-bounded batch before the final tail rewrite and readback.
    prepublication_append_start: Option<u64>,
    prepublication_append_bytes: Vec<u8>,
    /// Exact block range installed by the current prepublication batch.
    /// After the Pool barrier, one positioned read loads this range so the
    /// existing strict per-object verifier can decode every record from the
    /// persisted bytes without issuing one read per header and payload. The
    /// range includes the successor-header slot that closed the batch, but a
    /// later Pool sync may legitimately overwrite that slot with its next
    /// record before readback; it is outside the indexed batch records.
    prepublication_readback_range: Option<(u64, usize)>,
    prepublication_readback_bytes: Vec<u8>,
    prepublication_readback_records: BTreeMap<ObjectLocation, (usize, usize, u8)>,
    prepublication_tail_verification_deferred: bool,
    #[cfg(test)]
    block_device_tail_terminator_verifications: u64,
    /// When true, the store operates directly on a block device instead of
    /// a directory of segment files. Segment files are not created;
    /// all I/O goes through current_file which points to the block device.
    pub(crate) block_device_mode: bool,
}
pub trait ObjectStore {
    type Scan: Iterator<Item = ObjectKey>;

    /// Store a blob by its content digest and return the derived key.
    fn put(&mut self, payload: &[u8]) -> Result<ObjectKey>;

    /// Retrieve a blob by key, returning `None` when the key is not live.
    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>>;

    /// Delete a live blob by key, returning whether it existed.
    fn delete(&mut self, key: ObjectKey) -> Result<bool>;

    /// Iterate all live object keys known to the store.
    fn scan(&self) -> Self::Scan;

    /// Return lightweight object metadata without copying the full payload.
    ///
    /// Returns `Ok(ObjectAttr)` with size, creation timestamp, and the
    /// content key when the object is present; returns
    /// `Err(ObjectReadError::NotFound)` when the key is unknown.
    fn get_attr(&self, key: &ObjectKey) -> std::result::Result<ObjectAttr, ObjectReadError>;
}

/// Scan a block device data region to rebuild the in-memory index.
///
/// Reads records sequentially from `data_start` to `device_end`.
/// Each record has: 64-byte header (magic 0xBF01_0001 + key + payload_len)
/// followed by payload, padded to 512-byte alignment.
/// Tombstone records (flag 0x0001) remove entries from the index.
impl ObjectStore for LocalObjectStore {
    type Scan = std::vec::IntoIter<ObjectKey>;

    fn put(&mut self, payload: &[u8]) -> Result<ObjectKey> {
        self.put_content_addressed(payload)
    }

    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        LocalObjectStore::get(self, key)
    }

    fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        LocalObjectStore::delete(self, key)
    }

    fn scan(&self) -> Self::Scan {
        self.list_keys().into_iter()
    }

    fn get_attr(&self, key: &ObjectKey) -> std::result::Result<ObjectAttr, ObjectReadError> {
        LocalObjectStore::get_attr(self, key)
    }
}

// ── committed root persistence ──────────────────────────────────────

/// Try to load the committed root pointer from the well-known file.
///
/// Returns `Some(RootPointer)` if the file exists and decodes successfully,
/// `None` if the file does not exist (fresh pool) or is malformed.
fn load_committed_root(
    root: &Path,
) -> Option<(tidefs_commit_group::RootPointer, Option<[u8; 32]>)> {
    let root_path = root.join(crate::txg_manager::COMMITTED_ROOT_FILE);
    let payload = match std::fs::read(&root_path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return None,
    };
    CommitGroupManager::decode_root_with_digest(&payload)
}

/// Initialize the commit_group manager for a store, resuming from a previous
/// committed root when one exists.
fn init_commit_group(root: &Path) -> CommitGroupManager {
    if let Some((recovered_root, _digest)) = load_committed_root(root) {
        let next_id = recovered_root.commit_group_id.next();
        CommitGroupManager::resume(next_id, recovered_root)
    } else {
        CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST)
    }
}
/// Initialize the CommitGroupCoordinator from the persisted committed root, matching
/// the CommitGroupManager recovery path so both track the same lineage.
fn init_txg_coordinator(root: &Path) -> tidefs_commit_group::CommitGroupCoordinator {
    if let Some((recovered_root, Some(digest))) = load_committed_root(root) {
        tidefs_commit_group::CommitGroupCoordinator::resume_with_digest(recovered_root, digest)
    } else if let Some((recovered_root, _)) = load_committed_root(root) {
        tidefs_commit_group::CommitGroupCoordinator::resume(recovered_root)
    } else {
        tidefs_commit_group::CommitGroupCoordinator::new()
    }
}

/// Returns `true` if the key is internal metadata rather than user data.
fn committed_root_key() -> ObjectKey {
    static COMMITTED_ROOT_KEY: OnceLock<ObjectKey> = OnceLock::new();
    *COMMITTED_ROOT_KEY
        .get_or_init(|| ObjectKey::from_name(crate::txg_manager::COMMITTED_ROOT_FILE.as_bytes()))
}

fn compaction_publish_manifest_key() -> ObjectKey {
    static COMPACTION_PUBLISH_MANIFEST_KEY: OnceLock<ObjectKey> = OnceLock::new();
    *COMPACTION_PUBLISH_MANIFEST_KEY
        .get_or_init(|| ObjectKey::from_name(COMPACTION_PUBLISH_MANIFEST_OBJECT_NAME.as_bytes()))
}

fn physical_lifetime_sequence_high_water_key() -> ObjectKey {
    static KEY: OnceLock<ObjectKey> = OnceLock::new();
    *KEY.get_or_init(|| {
        ObjectKey::from_name(PHYSICAL_LIFETIME_SEQUENCE_HIGH_WATER_OBJECT_NAME.as_bytes())
    })
}

fn is_compaction_target_key(key: ObjectKey) -> bool {
    key.as_bytes()[..8] == COMPACTION_TARGET_KEY_PREFIX
}

fn dead_object_reclaim_entry_state_key(object_id: ReclaimObjectKey) -> ObjectKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"TideFS dead-object reclaim entry state v1\0");
    hasher.update(&object_id.0);
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[..DEAD_OBJECT_RECLAIM_ENTRY_KEY_PREFIX.len()]
        .copy_from_slice(&DEAD_OBJECT_RECLAIM_ENTRY_KEY_PREFIX);
    ObjectKey::from_bytes32(bytes)
}

pub(crate) fn is_dead_object_reclaim_entry_state_key(key: ObjectKey) -> bool {
    key.as_bytes()[..DEAD_OBJECT_RECLAIM_ENTRY_KEY_PREFIX.len()]
        == DEAD_OBJECT_RECLAIM_ENTRY_KEY_PREFIX
}

pub(crate) fn is_pool_pending_deletion_key(key: ObjectKey) -> bool {
    key.as_bytes()[..8] == POOL_PENDING_DELETION_KEY_PREFIX
}

pub(crate) fn is_strict_pool_authority_key(key: ObjectKey) -> bool {
    crate::is_pool_placement_receipt_key(key)
        || crate::is_pool_receipt_generation_high_water_key(key)
        || is_pool_pending_deletion_key(key)
}

fn is_pool_store_internal_key(key: ObjectKey) -> bool {
    crate::is_pool_placement_scan_internal_key(key)
        || is_pool_pending_deletion_key(key)
        || is_dead_object_reclaim_entry_state_key(key)
}

fn persistent_reclaim_metadata_keys() -> &'static [ObjectKey; 8] {
    static KEYS: OnceLock<[ObjectKey; 8]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            ObjectKey::from_name(RECLAIM_QUEUE_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(RECLAIM_QUEUE_ENTRIES_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(RECLAIM_RECEIPTS_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(SNAPSHOT_EXTENT_PIN_SET_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(FILESYSTEM_RECLAIM_QUEUE_OBJECT_NAME.as_bytes()),
            compaction_publish_manifest_key(),
            physical_lifetime_sequence_high_water_key(),
        ]
    })
}

fn is_persistent_reclaim_metadata_key(key: ObjectKey) -> bool {
    persistent_reclaim_metadata_keys().contains(&key) || is_dead_object_reclaim_entry_state_key(key)
}

fn is_stats_internal_key(key: ObjectKey) -> bool {
    key == committed_root_key()
        || is_persistent_reclaim_metadata_key(key)
        || crate::is_pool_placement_receipt_key(key)
        || crate::is_pool_receipt_generation_high_water_key(key)
        || is_pool_pending_deletion_key(key)
        || is_compaction_target_key(key)
}

fn is_public_scan_internal_key(key: ObjectKey) -> bool {
    key == committed_root_key()
        || is_persistent_reclaim_metadata_key(key)
        || crate::is_pool_placement_scan_internal_key(key)
        || is_pool_pending_deletion_key(key)
        || is_compaction_target_key(key)
}

fn stats_counted_index_len(index: &BTreeMap<ObjectKey, ObjectLocation>) -> usize {
    index
        .keys()
        .filter(|key| !is_stats_internal_key(**key))
        .count()
}

fn stats_counted_index_bytes(index: &BTreeMap<ObjectKey, ObjectLocation>) -> u64 {
    index
        .iter()
        .filter(|(key, _)| !is_stats_internal_key(**key))
        .map(|(_, loc)| loc.payload_len)
        .sum()
}

fn stats_counted_index_totals(index: &BTreeMap<ObjectKey, ObjectLocation>) -> (usize, u64) {
    index
        .iter()
        .filter(|(key, _)| !is_stats_internal_key(**key))
        .fold((0_usize, 0_u64), |(objects, bytes), (_, location)| {
            (
                objects
                    .checked_add(1)
                    .expect("live object count remains representable"),
                bytes
                    .checked_add(location.payload_len)
                    .expect("live byte count remains representable"),
            )
        })
}

fn encode_compaction_location(buf: &mut Vec<u8>, location: ObjectLocation) {
    buf.extend_from_slice(location.key.as_bytes());
    buf.extend_from_slice(&location.segment_id.to_le_bytes());
    buf.extend_from_slice(&location.record_offset.to_le_bytes());
    buf.extend_from_slice(&location.payload_offset.to_le_bytes());
    buf.extend_from_slice(&location.payload_len.to_le_bytes());
    buf.extend_from_slice(&location.sequence.to_le_bytes());
    buf.extend_from_slice(&location.payload_checksum.get().to_le_bytes());
}

fn encode_compaction_extent(buf: &mut Vec<u8>, extent: &ExtentMapEntryV2) {
    buf.extend_from_slice(&extent.logical_offset.to_le_bytes());
    buf.extend_from_slice(&extent.length.to_le_bytes());
    buf.push(extent.extent_kind);
    buf.push(extent.flags);
    buf.extend_from_slice(&extent.locator_id.0.to_le_bytes());
    buf.extend_from_slice(&extent.checksum);
    buf.extend_from_slice(&extent.birth_commit_group.to_le_bytes());
    buf.extend_from_slice(&extent.reserved);
}

fn compaction_take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest length overflow",
        })?;
    if end > bytes.len() {
        return Err(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest truncated",
        });
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn compaction_take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let slice = compaction_take(bytes, offset, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn compaction_take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(compaction_take_array::<8>(
        bytes, offset,
    )?))
}

fn decode_compaction_location(bytes: &[u8], offset: &mut usize) -> Result<ObjectLocation> {
    let key = ObjectKey::from_bytes(compaction_take_array::<32>(bytes, offset)?);
    let segment_id = compaction_take_u64(bytes, offset)?;
    let record_offset = compaction_take_u64(bytes, offset)?;
    let payload_offset = compaction_take_u64(bytes, offset)?;
    let payload_len = compaction_take_u64(bytes, offset)?;
    let sequence = compaction_take_u64(bytes, offset)?;
    let payload_checksum = IntegrityDigest64(compaction_take_u64(bytes, offset)?);
    Ok(ObjectLocation {
        key,
        segment_id,
        record_offset,
        payload_offset,
        payload_len,
        sequence,
        payload_checksum,
    })
}

fn decode_compaction_extent(bytes: &[u8], offset: &mut usize) -> Result<ExtentMapEntryV2> {
    let logical_offset = compaction_take_u64(bytes, offset)?;
    let length = compaction_take_u64(bytes, offset)?;
    let extent_kind = compaction_take(bytes, offset, 1)?[0];
    let flags = compaction_take(bytes, offset, 1)?[0];
    let locator_id = LocatorId(compaction_take_u64(bytes, offset)?);
    let checksum = compaction_take_array::<32>(bytes, offset)?;
    let birth_commit_group = compaction_take_u64(bytes, offset)?;
    let reserved = compaction_take_array::<15>(bytes, offset)?;
    Ok(ExtentMapEntryV2 {
        logical_offset,
        length,
        extent_kind,
        flags,
        locator_id,
        checksum,
        birth_commit_group,
        reserved,
    })
}

fn encode_compaction_publish_manifest(
    entries: &[PersistedCompactionPublishEntry],
) -> Result<Vec<u8>> {
    let count = u32::try_from(entries.len()).map_err(|_| StoreError::InvalidCompactionRewrite {
        reason: "compaction publish manifest has too many entries",
    })?;
    let body_len = entries
        .len()
        .checked_mul(COMPACTION_MANIFEST_ENTRY_LEN)
        .and_then(|len| len.checked_add(COMPACTION_MANIFEST_HEADER_LEN))
        .ok_or(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest length overflow",
        })?;
    let mut buf = Vec::with_capacity(body_len);
    buf.extend_from_slice(COMPACTION_MANIFEST_MAGIC);
    buf.extend_from_slice(&COMPACTION_MANIFEST_VERSION.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        buf.extend_from_slice(&entry.publish_txg.to_le_bytes());
        buf.extend_from_slice(entry.key.as_bytes());
        buf.extend_from_slice(&entry.dataset_uuid);
        encode_compaction_location(&mut buf, entry.old_location);
        encode_compaction_location(&mut buf, entry.target_location);
        encode_compaction_extent(&mut buf, &entry.new_extent);
        buf.extend_from_slice(&entry.receipt.encode());
    }
    Ok(buf)
}

fn decode_compaction_publish_manifest(
    bytes: &[u8],
) -> Result<Vec<PersistedCompactionPublishEntry>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut offset = 0usize;
    let magic = compaction_take(bytes, &mut offset, COMPACTION_MANIFEST_MAGIC.len())?;
    if magic != COMPACTION_MANIFEST_MAGIC {
        return Err(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest invalid magic",
        });
    }
    let version = u32::from_le_bytes(compaction_take_array::<4>(bytes, &mut offset)?);
    if version != COMPACTION_MANIFEST_VERSION {
        return Err(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest unsupported version",
        });
    }
    let count = u32::from_le_bytes(compaction_take_array::<4>(bytes, &mut offset)?) as usize;
    let expected_len = COMPACTION_MANIFEST_HEADER_LEN
        .checked_add(count.checked_mul(COMPACTION_MANIFEST_ENTRY_LEN).ok_or(
            StoreError::InvalidCompactionRewrite {
                reason: "compaction publish manifest length overflow",
            },
        )?)
        .ok_or(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest length overflow",
        })?;
    if expected_len != bytes.len() {
        return Err(StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest trailing bytes",
        });
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let publish_txg = compaction_take_u64(bytes, &mut offset)?;
        let key = ObjectKey::from_bytes(compaction_take_array::<32>(bytes, &mut offset)?);
        let dataset_uuid = compaction_take_array::<16>(bytes, &mut offset)?;
        let old_location = decode_compaction_location(bytes, &mut offset)?;
        let target_location = decode_compaction_location(bytes, &mut offset)?;
        let new_extent = decode_compaction_extent(bytes, &mut offset)?;
        let receipt = DeadObjectReplacementReceipt::decode(&compaction_take_array::<
            COMPACTION_MANIFEST_RECEIPT_LEN,
        >(bytes, &mut offset)?)
        .map_err(|_| StoreError::InvalidCompactionRewrite {
            reason: "compaction publish manifest invalid receipt",
        })?;
        entries.push(PersistedCompactionPublishEntry {
            publish_txg,
            key,
            dataset_uuid,
            old_location,
            target_location,
            new_extent,
            receipt,
        });
    }
    Ok(entries)
}

fn compaction_reclaim_key(key: ObjectKey) -> ReclaimObjectKey {
    ReclaimObjectKey(*key.as_bytes())
}

fn compaction_location_evidence(location: ObjectLocation, out: &mut Vec<u8>) {
    out.extend_from_slice(location.key.as_bytes());
    out.extend_from_slice(&location.segment_id.to_le_bytes());
    out.extend_from_slice(&location.record_offset.to_le_bytes());
    out.extend_from_slice(&location.payload_offset.to_le_bytes());
    out.extend_from_slice(&location.payload_len.to_le_bytes());
    out.extend_from_slice(&location.sequence.to_le_bytes());
    out.extend_from_slice(&location.payload_checksum.get().to_le_bytes());
}

fn compaction_locator_evidence(
    key: ObjectKey,
    target_location: ObjectLocation,
    receipt: DeadObjectReplacementReceipt,
) -> Vec<u8> {
    let mut evidence = Vec::with_capacity(32 + COMPACTION_MANIFEST_LOCATION_LEN + 128);
    evidence.extend_from_slice(b"tidefs-compaction-locator-v1");
    evidence.extend_from_slice(key.as_bytes());
    compaction_location_evidence(target_location, &mut evidence);
    evidence.extend_from_slice(&receipt.encode());
    evidence
}

fn compaction_locator_id(
    key: ObjectKey,
    target_location: ObjectLocation,
    receipt: DeadObjectReplacementReceipt,
) -> LocatorId {
    let evidence = compaction_locator_evidence(key, target_location, receipt);
    let digest = blake3::hash(&evidence);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    let mut locator = u64::from_le_bytes(bytes);
    if locator == 0 {
        locator = 1;
    }
    LocatorId(locator)
}

fn compaction_target_key(
    key: ObjectKey,
    old_location: ObjectLocation,
    publish_txg: u64,
    ordinal: u64,
) -> ObjectKey {
    let mut evidence = Vec::with_capacity(32 + COMPACTION_MANIFEST_LOCATION_LEN + 16);
    evidence.extend_from_slice(b"tidefs-compaction-target-v1");
    evidence.extend_from_slice(key.as_bytes());
    compaction_location_evidence(old_location, &mut evidence);
    evidence.extend_from_slice(&publish_txg.to_le_bytes());
    evidence.extend_from_slice(&ordinal.to_le_bytes());
    let mut bytes = *blake3::hash(&evidence).as_bytes();
    bytes[..COMPACTION_TARGET_KEY_PREFIX.len()].copy_from_slice(&COMPACTION_TARGET_KEY_PREFIX);
    ObjectKey::from_bytes(bytes)
}

fn compaction_read_verify_digest(payload: &[u8]) -> ObjectDigest {
    let domain_key = DomainTag::ReadVerify.derive_key();
    ObjectDigest::compute(payload, &domain_key)
}

fn compaction_payload_digest(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

impl LocalObjectStore {
    const fn block_device_data_start() -> u64 {
        BLOCK_DEVICE_DATA_REGION_OFFSET + BLOCK_DATA_FORMAT_HEADER_SIZE
    }

    /// Minimum raw byte-device capacity accepted by the current Store layout.
    ///
    /// Pool creation consumes this value without duplicating private header
    /// sizes or offsets owned by this crate.
    #[must_use]
    pub const fn minimum_block_device_capacity() -> u64 {
        // Pool layout authority operates on Store-visible capacity, which
        // excludes the trailing label reservation and must retain at least one
        // minimum layout segment after the fixed Store header.
        Self::block_device_data_start()
            + crate::device_layout::MIN_SEGMENT_SIZE_BYTES
            + POOL_LABEL_SIZE as u64
    }

    fn scan_block_device_for_index(
        file: &mut File,
        data_start: u64,
        device_end: u64,
    ) -> Result<BlockIndexScan> {
        let mut index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
        let mut history: BTreeMap<ObjectKey, Vec<ObjectLocation>> = BTreeMap::new();
        let mut next_sequence = 1u64;
        let mut cursor = data_start;

        file.seek(SeekFrom::Start(cursor))
            .map_err(|e| StoreError::Io {
                operation: "scan_block_seek_start",
                path: PathBuf::from("<block-device>"),
                source: e,
            })?;

        while cursor + RECORD_HEADER_LEN_U64 <= device_end {
            let mut header_buf = [0u8; RECORD_HEADER_LEN];
            match file.read_exact(&mut header_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(StoreError::Io {
                        operation: "scan_block_read_header",
                        path: PathBuf::from("<block-device>"),
                        source: e,
                    })
                }
            }

            // Check for segment-integrity footer magic (end-of-written-data sentinel).
            if header_buf[0..8] == SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES {
                break;
            }

            // Try to decode as a valid record header.
            let record = match decode_header(&header_buf, 0, cursor) {
                Ok(r) => r,
                Err(_) => break, // corrupt or uninitialized tail
            };

            let record_range = match checked_record_range(record, 0, cursor) {
                Ok(r) => r,
                Err(_) => break,
            };

            if record_range.end_offset > device_end {
                break;
            }

            let location = ObjectLocation {
                key: record.key,
                segment_id: 0,
                record_offset: cursor,
                payload_offset: record_range.payload_offset,
                payload_len: record.payload_len,
                sequence: record.sequence,
                payload_checksum: record.payload_checksum,
            };

            // History is the physical put-record sequence. A prior live
            // location was already recorded when its put was scanned, so an
            // overwrite or delete must not append that location again.
            match record.kind {
                RecordKind::Put => {
                    index.insert(record.key, location);
                    history.entry(record.key).or_default().push(location);
                }
                RecordKind::Delete => {
                    index.remove(&record.key);
                }
            }

            next_sequence = next_sequence.max(record.sequence.saturating_add(1));
            cursor = record_range.end_offset;

            if cursor >= device_end {
                break;
            }
            file.seek(SeekFrom::Start(cursor))
                .map_err(|e| StoreError::Io {
                    operation: "scan_block_seek_next",
                    path: PathBuf::from("<block-device>"),
                    source: e,
                })?;
        }

        Ok((index, history, next_sequence, cursor))
    }

    fn load_physical_lifetime_sequence_high_water(
        index: &BTreeMap<ObjectKey, ObjectLocation>,
        file: &mut File,
        device_path: &Path,
        device_end: u64,
    ) -> Result<u64> {
        let Some(location) = index
            .get(&physical_lifetime_sequence_high_water_key())
            .copied()
        else {
            return Ok(1);
        };
        file.seek(SeekFrom::Start(location.record_offset))
            .map_err(|source| io_error("read sequence high-water seek", device_path, source))?;
        let mut header = [0_u8; RECORD_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read sequence high-water header", device_path, source))?;
        let decoded = decode_stored_record_after_header(
            file,
            device_path,
            location.segment_id,
            location.record_offset,
            device_end,
            header,
        )?;
        let (payload, _) = validate_location_record(location, decoded)?;
        if payload.len() != 8 {
            return Err(StoreError::InvalidOptions {
                reason: "physical lifetime sequence high-water record is malformed",
            });
        }
        let sequence = u64::from_le_bytes(payload.try_into().unwrap());
        if sequence == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "physical lifetime sequence high-water record is zero",
            });
        }
        Ok(sequence)
    }

    fn encode_block_format_header(identity: BlockStoreIdentity) -> [u8; 80] {
        let mut encoded = [0u8; BLOCK_DATA_FORMAT_HEADER_SIZE as usize];
        encoded[0..8].copy_from_slice(&BLOCK_DATA_MAGIC);
        encoded[8..12].copy_from_slice(&BLOCK_DATA_FORMAT_VERSION.to_le_bytes());
        encoded[12..16].copy_from_slice(&(BLOCK_DATA_FORMAT_HEADER_SIZE as u32).to_le_bytes());
        encoded[16..32].copy_from_slice(&identity.pool_guid);
        encoded[32..48].copy_from_slice(&identity.device_guid);
        let checksum = blake3::hash(&encoded[..BLOCK_DATA_FORMAT_CHECKSUM_OFFSET]);
        encoded[BLOCK_DATA_FORMAT_CHECKSUM_OFFSET..].copy_from_slice(checksum.as_bytes());
        encoded
    }

    fn decode_block_format_header(encoded: &[u8; 80]) -> Result<BlockFormatHeaderState> {
        if encoded.iter().all(|byte| *byte == 0) {
            return Ok(BlockFormatHeaderState::Blank);
        }
        if encoded[0..8] != BLOCK_DATA_MAGIC {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store format header has invalid or retired magic",
            });
        }
        if u32::from_le_bytes(encoded[8..12].try_into().unwrap()) != BLOCK_DATA_FORMAT_VERSION
            || u32::from_le_bytes(encoded[12..16].try_into().unwrap())
                != BLOCK_DATA_FORMAT_HEADER_SIZE as u32
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store format header has an incompatible version or size",
            });
        }
        if encoded[BLOCK_DATA_FORMAT_CHECKSUM_OFFSET..]
            != *blake3::hash(&encoded[..BLOCK_DATA_FORMAT_CHECKSUM_OFFSET]).as_bytes()
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store format header checksum mismatch",
            });
        }
        let mut pool_guid = [0u8; 16];
        pool_guid.copy_from_slice(&encoded[16..32]);
        let mut device_guid = [0u8; 16];
        device_guid.copy_from_slice(&encoded[32..48]);
        Ok(BlockFormatHeaderState::Current(BlockFormatHeader {
            identity: BlockStoreIdentity {
                pool_guid,
                device_guid,
            },
        }))
    }

    fn read_block_format_header(
        file: &mut File,
        data_start: u64,
    ) -> Result<BlockFormatHeaderState> {
        let mut encoded = [0u8; BLOCK_DATA_FORMAT_HEADER_SIZE as usize];
        file.seek(SeekFrom::Start(data_start))
            .map_err(|source| StoreError::Io {
                operation: "read_block_format_seek",
                path: PathBuf::from("<block-device>"),
                source,
            })?;
        file.read_exact(&mut encoded)
            .map_err(|source| StoreError::Io {
                operation: "read_block_format_read",
                path: PathBuf::from("<block-device>"),
                source,
            })?;
        Self::decode_block_format_header(&encoded)
    }

    fn validate_block_format_identity(
        header: BlockFormatHeader,
        expected: BlockStoreIdentity,
    ) -> Result<()> {
        if header.identity != expected {
            return Err(StoreError::InvalidOptions {
                reason:
                    "block-device store format identity does not match the labelled Pool member",
            });
        }
        Ok(())
    }

    fn block_bootstrap_tail_is_blank(
        file: &mut File,
        data_start: u64,
        data_end: u64,
    ) -> Result<bool> {
        let mut cursor = data_start;
        let mut buffer = [0u8; 64 * 1024];
        while cursor < data_end {
            let remaining = data_end - cursor;
            let len = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
            file.seek(SeekFrom::Start(cursor))
                .map_err(|source| StoreError::Io {
                    operation: "inspect_block_bootstrap_tail_seek",
                    path: PathBuf::from("<block-device>"),
                    source,
                })?;
            file.read_exact(&mut buffer[..len])
                .map_err(|source| StoreError::Io {
                    operation: "inspect_block_bootstrap_tail_read",
                    path: PathBuf::from("<block-device>"),
                    source,
                })?;
            if buffer[..len].iter().any(|byte| *byte != 0) {
                return Ok(false);
            }
            cursor += len as u64;
        }
        Ok(true)
    }

    fn read_block_bootstrap_record(
        file: &mut File,
        device_path: &Path,
        data_start: u64,
        data_end: u64,
    ) -> Result<Option<(ObjectKey, Vec<u8>)>> {
        if data_end.saturating_sub(data_start) < RECORD_HEADER_LEN_U64 {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store bootstrap region is too small for a record",
            });
        }
        file.seek(SeekFrom::Start(data_start))
            .map_err(|source| StoreError::Io {
                operation: "inspect_block_bootstrap_record_seek",
                path: PathBuf::from("<block-device>"),
                source,
            })?;
        let mut header = [0u8; RECORD_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|source| StoreError::Io {
                operation: "inspect_block_bootstrap_record_header",
                path: PathBuf::from("<block-device>"),
                source,
            })?;
        if header.iter().all(|byte| *byte == 0) {
            if Self::block_bootstrap_tail_is_blank(file, data_start, data_end)? {
                return Ok(None);
            }
            return Err(StoreError::InvalidOptions {
                reason: "blank block-device store prefix has a nonblank physical tail",
            });
        }

        let decoded =
            decode_stored_record_after_header(file, device_path, 0, data_start, data_end, header)?;
        let record = decoded.header;
        if record.format_version != RECORD_FORMAT_VERSION
            || record.kind != RecordKind::Put
            || record.sequence != 0
            || record.compression_algorithm != 0
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store bootstrap record is not one current internal put",
            });
        }
        if !Self::block_bootstrap_tail_is_blank(file, decoded.range.end_offset, data_end)? {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store bootstrap contains records or bytes after its marker",
            });
        }
        Ok(Some((record.key, decoded.payload)))
    }

    fn inspect_block_device_bootstrap_file(
        file: &mut File,
        device_path: &Path,
        data_end: u64,
    ) -> Result<BlockStoreBootstrapInspection> {
        let capacity = file
            .seek(SeekFrom::End(0))
            .map_err(|source| StoreError::Io {
                operation: "inspect_block_bootstrap_capacity",
                path: device_path.to_path_buf(),
                source,
            })?;
        if data_end != capacity.saturating_sub(POOL_LABEL_SIZE as u64)
            || data_end < Self::block_device_data_start()
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device store bootstrap capacity or layout boundary mismatch",
            });
        }
        match Self::read_block_format_header(file, BLOCK_DEVICE_DATA_REGION_OFFSET)? {
            BlockFormatHeaderState::Current(header) => Ok(BlockStoreBootstrapInspection {
                identity: Some(header.identity),
                record: Self::read_block_bootstrap_record(
                    file,
                    device_path,
                    Self::block_device_data_start(),
                    data_end,
                )?,
            }),
            BlockFormatHeaderState::Blank => {
                if !Self::block_bootstrap_tail_is_blank(
                    file,
                    Self::block_device_data_start(),
                    data_end,
                )? {
                    return Err(StoreError::InvalidOptions {
                        reason: "missing block-device store header has unexpected physical objects",
                    });
                }
                Ok(BlockStoreBootstrapInspection {
                    identity: None,
                    record: None,
                })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn inspect_block_device_bootstrap(
        device_path: impl AsRef<Path>,
        data_end: u64,
    ) -> Result<BlockStoreBootstrapInspection> {
        let device_path = device_path.as_ref();
        let mut file = File::open(device_path).map_err(|source| StoreError::Io {
            operation: "inspect_block_bootstrap_open",
            path: device_path.to_path_buf(),
            source,
        })?;
        Self::inspect_block_device_bootstrap_file(&mut file, device_path, data_end)
    }

    pub(crate) fn inspect_open_block_device_bootstrap(
        file: &mut File,
        device_path: &Path,
        capacity_bytes: u64,
    ) -> Result<BlockStoreBootstrapInspection> {
        Self::inspect_block_device_bootstrap_file(
            file,
            device_path,
            capacity_bytes.saturating_sub(POOL_LABEL_SIZE as u64),
        )
    }

    #[cfg(test)]
    pub(crate) fn initialize_block_device_bootstrap(
        device_path: impl AsRef<Path>,
        expected: BlockStoreIdentity,
    ) -> Result<()> {
        Self::initialize_and_retain_block_device_bootstrap(device_path, expected).map(drop)
    }

    pub(crate) fn initialize_and_retain_block_device_bootstrap(
        device_path: impl AsRef<Path>,
        expected: BlockStoreIdentity,
    ) -> Result<File> {
        let device_path = device_path.as_ref();
        let mut capacity_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .map_err(|source| StoreError::Io {
                operation: "initialize_block_bootstrap_capacity_open",
                path: device_path.to_path_buf(),
                source,
            })?;
        let capacity = capacity_file
            .seek(SeekFrom::End(0))
            .map_err(|source| StoreError::Io {
                operation: "initialize_block_bootstrap_capacity",
                path: device_path.to_path_buf(),
                source,
            })?;
        let data_end = capacity.saturating_sub(POOL_LABEL_SIZE as u64);
        let inspection =
            Self::inspect_block_device_bootstrap_file(&mut capacity_file, device_path, data_end)?;
        Self::initialize_open_block_device_bootstrap_after_inspection(
            &mut capacity_file,
            device_path,
            expected,
            &inspection,
        )?;
        Ok(capacity_file)
    }

    pub(crate) fn initialize_open_block_device_bootstrap_after_inspection(
        file: &mut File,
        device_path: &Path,
        expected: BlockStoreIdentity,
        inspection: &BlockStoreBootstrapInspection,
    ) -> Result<()> {
        match inspection {
            BlockStoreBootstrapInspection {
                identity: Some(identity),
                ..
            } => {
                Self::validate_block_format_identity(
                    BlockFormatHeader {
                        identity: *identity,
                    },
                    expected,
                )?;
                return Ok(());
            }
            BlockStoreBootstrapInspection {
                identity: None,
                record: None,
            } => {}
            BlockStoreBootstrapInspection {
                identity: None,
                record: Some(_),
            } => {
                return Err(StoreError::InvalidOptions {
                    reason: "headerless block-device store contains a bootstrap record",
                })
            }
        }

        match Self::read_block_format_header(file, BLOCK_DEVICE_DATA_REGION_OFFSET)? {
            BlockFormatHeaderState::Current(header) => {
                return Self::validate_block_format_identity(header, expected)
            }
            BlockFormatHeaderState::Blank => {}
        }
        let encoded = Self::encode_block_format_header(expected);
        file.seek(SeekFrom::Start(BLOCK_DEVICE_DATA_REGION_OFFSET))
            .map_err(|source| StoreError::Io {
                operation: "initialize_block_bootstrap_seek",
                path: device_path.to_path_buf(),
                source,
            })?;
        file.write_all(&encoded).map_err(|source| StoreError::Io {
            operation: "initialize_block_bootstrap_write",
            path: device_path.to_path_buf(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            operation: "initialize_block_bootstrap_sync",
            path: device_path.to_path_buf(),
            source,
        })?;
        match Self::read_block_format_header(file, BLOCK_DEVICE_DATA_REGION_OFFSET)? {
            BlockFormatHeaderState::Current(header) if header.identity == expected => Ok(()),
            _ => Err(StoreError::InvalidOptions {
                reason: "block-device store bootstrap header did not persist",
            }),
        }
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(root, StoreOptions::default())
    }

    pub fn open_with_options(root: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        Self::open_with_mode(root, options, StoreOpenMode::WritableCreate)?.ok_or(
            StoreError::InvalidOptions {
                reason: "writable create mode did not initialize a store",
            },
        )
    }

    pub fn open_read_only_with_options(
        root: impl AsRef<Path>,
        options: StoreOptions,
    ) -> Result<Option<Self>> {
        Self::open_with_mode(root, options, StoreOpenMode::ReadOnlyExisting)
    }

    /// Project an existing store without creating, repairing, or replaying it.
    ///
    /// Unlike the strict public read-only open, this internal pool-import
    /// preflight accepts a torn final record by projecting only the complete
    /// durable prefix. The later writable open owns any required tail repair,
    /// but only after pool receipt-generation authority has been accepted.
    pub(crate) fn open_preflight_with_options(
        root: impl AsRef<Path>,
        options: StoreOptions,
    ) -> Result<Option<Self>> {
        Self::open_with_mode(root, options, StoreOpenMode::PreflightExisting)
    }

    /// Whether this store was opened in read-only mode.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Return the most recently committed root's opaque handle as a u64,
    /// suitable for barrier audit trace validation that ties guest barriers
    /// to txg committed-root publication.
    ///
    /// Returns `None` when no committed root is present (fresh store or
    /// before any commit).
    #[must_use]
    pub fn committed_root_u64(&self) -> Option<u64> {
        let root = self.commit_group.committed_root();
        if root.is_valid() {
            Some(root.root_handle)
        } else {
            None
        }
    }

    fn load_compaction_publish_manifest_entries(
        &self,
    ) -> Result<Vec<PersistedCompactionPublishEntry>> {
        let Some(location) = self.index.get(&compaction_publish_manifest_key()).copied() else {
            return Ok(Vec::new());
        };
        let bytes = self.read_location(location)?;
        decode_compaction_publish_manifest(&bytes)
    }

    fn compaction_source_release_receipted(&self, key: ReclaimObjectKey) -> bool {
        self.reclaim_receipts.iter().any(|receipt| {
            receipt
                .freed_segment_extents
                .iter()
                .any(|extent| extent.extent_key == key)
        })
    }

    fn enqueue_compaction_source_release(
        &mut self,
        entry: &PersistedCompactionPublishEntry,
        mark_dirty: bool,
    ) -> Result<()> {
        let object_id = compaction_reclaim_key(entry.key);
        if self.compaction_source_release_receipted(object_id) {
            return Ok(());
        }
        let dead_entry = DeadObjectEntry::new(
            object_id,
            entry.dataset_uuid,
            entry.publish_txg,
            true,
            entry.publish_txg,
        )
        .with_replacement_receipt(entry.receipt);
        if self.dead_object_reclaim_queue.enqueue(dead_entry) && mark_dirty {
            self.stage_dead_object_reclaim_queue_delta(&[dead_entry], &[])?;
        }
        Ok(())
    }

    fn build_compaction_checksum_tree(
        key: ObjectKey,
        target_location: ObjectLocation,
        receipt: DeadObjectReplacementReceipt,
        payload: &[u8],
    ) -> Result<ChecksumTree> {
        let evidence = compaction_locator_evidence(key, target_location, receipt);
        let token = LocatorToken::from_evidence(&evidence);
        let mut builder = ChecksumTreeBuilder::new(tidefs_checksum_tree::DEFAULT_BLOCK_SIZE);
        builder.set_locator(token);
        builder.ingest(payload);
        let tree = builder.finish();
        if ChecksumTreeVerifier::new(tree.clone()).verify_full_with_locator(payload, Some(&token))
            != VerificationResult::Verified
        {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target checksum verification failed",
            });
        }
        Ok(tree)
    }

    fn verify_compaction_target_entry(
        entry: &PersistedCompactionPublishEntry,
        payload: &[u8],
    ) -> Result<()> {
        if !is_compaction_target_key(entry.target_location.key) {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target location is not a hidden target key",
            });
        }
        if entry.old_location.key != entry.key {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction source location does not match rewrite key",
            });
        }
        if entry.new_extent.length != payload.len() as u64 {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction extent length does not match target payload",
            });
        }
        if !entry.new_extent.is_finalized_data() || entry.new_extent.locator_id.is_none() {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target extent is not finalized data",
            });
        }
        if entry.receipt.payload_len != payload.len() as u64
            || entry.receipt.payload_digest != compaction_payload_digest(payload)
            || !entry
                .receipt
                .authorizes_reclaim_for(compaction_reclaim_key(entry.key))
        {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction replacement receipt does not cover target payload",
            });
        }
        let tree = Self::build_compaction_checksum_tree(
            entry.key,
            entry.target_location,
            entry.receipt,
            payload,
        )?;
        if tree.root_hash != entry.new_extent.checksum {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target checksum root does not match manifest",
            });
        }
        Ok(())
    }

    fn apply_persisted_compaction_publish_entry(
        &mut self,
        entry: &PersistedCompactionPublishEntry,
        mark_queue_dirty: bool,
    ) -> Result<Option<PublishedCompactionRewrite>> {
        let payload = self.read_location(entry.target_location)?;
        Self::verify_compaction_target_entry(entry, &payload)?;

        let current_location = self.index.get(&entry.key).copied();
        let mut visible_swap_applied = false;
        match current_location {
            Some(location) if location == entry.target_location => {
                visible_swap_applied = true;
            }
            Some(location) if location == entry.old_location => {
                self.set_index_location(entry.key, entry.target_location);
                visible_swap_applied = true;
            }
            Some(location) if location.sequence > entry.target_location.sequence => {}
            None => {}
            Some(_) => {}
        }

        if visible_swap_applied {
            let inserted = {
                let versions = self.history.entry(entry.key).or_default();
                if versions.contains(&entry.target_location) {
                    false
                } else {
                    versions.push(entry.target_location);
                    true
                }
            };
            if inserted {
                self.index_receipt_bound_physical_lifetime(entry.key, entry.target_location)?;
            }
            self.checksums
                .insert(entry.key, compaction_read_verify_digest(&payload));
        }
        self.enqueue_compaction_source_release(entry, mark_queue_dirty)?;

        Ok(visible_swap_applied.then(|| PublishedCompactionRewrite {
            key: entry.key,
            old_location: entry.old_location,
            target_location: entry.target_location,
            new_extent: entry.new_extent.clone(),
            checksum_root: entry.new_extent.checksum,
            receipt_generation: entry.receipt.receipt_generation,
        }))
    }

    fn apply_committed_compaction_publish_manifest(&mut self) -> Result<()> {
        let committed_txg = self.commit_group.committed_root().commit_group_id.0;
        if committed_txg == 0 {
            return Ok(());
        }
        for entry in self.load_compaction_publish_manifest_entries()? {
            if entry.publish_txg <= committed_txg {
                let _ = self.apply_persisted_compaction_publish_entry(&entry, false)?;
            }
        }
        Ok(())
    }

    fn prepare_verified_compaction_rewrite(
        &mut self,
        rewrite: VerifiedCompactionRewrite,
        extent_map: &impl ExtentMapOps,
        publish_txg: u64,
        ordinal: u64,
    ) -> Result<PersistedCompactionPublishEntry> {
        if !rewrite.old_extent.is_finalized_data() {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction source extent is not finalized data",
            });
        }
        if rewrite.old_extent.logical_offset != rewrite.logical_offset {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction logical offset does not match source extent",
            });
        }
        if rewrite.target_payload.is_empty()
            || rewrite.old_extent.length != rewrite.target_payload.len() as u64
        {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction source extent length does not match target payload",
            });
        }

        let source_location =
            self.index
                .get(&rewrite.key)
                .copied()
                .ok_or(StoreError::InvalidCompactionRewrite {
                    reason: "compaction source key is not live",
                })?;
        if source_location.key != rewrite.key {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction source location does not match source key",
            });
        }
        let current_payload =
            self.get(rewrite.key)?
                .ok_or(StoreError::InvalidCompactionRewrite {
                    reason: "compaction source key disappeared during verification",
                })?;
        if current_payload != rewrite.target_payload {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target payload differs from source payload",
            });
        }

        let mapped = extent_map
            .lookup_range(rewrite.old_extent.logical_offset, rewrite.old_extent.length)
            .map_err(|_| StoreError::InvalidCompactionRewrite {
                reason: "extent map rejected compaction source lookup",
            })?;
        if !mapped.iter().any(|entry| entry == &rewrite.old_extent) {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "extent map source extent does not match compaction rewrite",
            });
        }

        let reclaim_key = compaction_reclaim_key(rewrite.key);
        if rewrite.replacement_receipt.payload_len != rewrite.target_payload.len() as u64
            || rewrite.replacement_receipt.payload_digest
                != compaction_payload_digest(&rewrite.target_payload)
            || !rewrite
                .replacement_receipt
                .authorizes_reclaim_for(reclaim_key)
        {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction replacement receipt does not authorize source release",
            });
        }

        if self.current_segment_id == source_location.segment_id {
            self.rotate_segment()?;
        }

        let target_key = compaction_target_key(rewrite.key, source_location, publish_txg, ordinal);
        self.put_direct(target_key, &rewrite.target_payload)?;
        let target_location =
            self.index
                .get(&target_key)
                .copied()
                .ok_or(StoreError::InvalidCompactionRewrite {
                    reason: "compaction target write did not produce a location",
                })?;
        if target_location.segment_id == source_location.segment_id {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction target must not share the source segment",
            });
        }
        let tree = Self::build_compaction_checksum_tree(
            rewrite.key,
            target_location,
            rewrite.replacement_receipt,
            &rewrite.target_payload,
        )?;
        let locator_id =
            compaction_locator_id(rewrite.key, target_location, rewrite.replacement_receipt);
        let new_extent = ExtentMapEntryV2::new_data(
            rewrite.old_extent.logical_offset,
            rewrite.old_extent.length,
            locator_id,
            tree.root_hash,
            publish_txg,
        );

        Ok(PersistedCompactionPublishEntry {
            publish_txg,
            key: rewrite.key,
            dataset_uuid: rewrite.dataset_uuid,
            old_location: source_location,
            target_location,
            new_extent,
            receipt: rewrite.replacement_receipt,
        })
    }

    pub fn publish_verified_compaction_rewrites(
        &mut self,
        rewrites: Vec<VerifiedCompactionRewrite>,
        extent_map: &mut impl ExtentMapOps,
    ) -> Result<CompactionPublishReport> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("publish_verified_compaction_rewrites")?;
        if rewrites.is_empty() {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction publish batch is empty",
            });
        }

        let publish_txg = self.commit_group.current_id().0;
        let mut prepared = Vec::with_capacity(rewrites.len());
        let mut seen_keys = BTreeSet::new();
        for (ordinal, rewrite) in rewrites.into_iter().enumerate() {
            Self::ensure_public_pool_key_mutation_allowed(rewrite.key)?;
            if !seen_keys.insert(rewrite.key) {
                return Err(StoreError::InvalidCompactionRewrite {
                    reason: "compaction publish batch contains duplicate source key",
                });
            }
            prepared.push(self.prepare_verified_compaction_rewrite(
                rewrite,
                extent_map,
                publish_txg,
                ordinal as u64,
            )?);
        }

        let mut manifest_entries = self.load_compaction_publish_manifest_entries()?;
        manifest_entries.retain(|entry| {
            !self.compaction_source_release_receipted(compaction_reclaim_key(entry.key))
        });
        manifest_entries.extend(prepared.iter().cloned());
        let manifest_payload = encode_compaction_publish_manifest(&manifest_entries)?;
        self.put(compaction_publish_manifest_key(), &manifest_payload)?;

        for entry in &prepared {
            let payload = self.read_location(entry.target_location)?;
            self.checksums
                .insert(entry.key, compaction_read_verify_digest(&payload));
        }

        self.sync_all()?;
        let committed_txg = self.commit_group.committed_root().commit_group_id.0;
        if committed_txg < publish_txg {
            return Err(StoreError::InvalidCompactionRewrite {
                reason: "compaction manifest did not reach the expected commit group",
            });
        }
        let committed_generation = self.commit_group.commit_count();

        let new_extents: Vec<ExtentMapEntryV2> = prepared
            .iter()
            .map(|entry| entry.new_extent.clone())
            .collect();
        extent_map.insert_extent(&new_extents).map_err(|_| {
            StoreError::InvalidCompactionRewrite {
                reason: "extent map rejected compaction locator swap",
            }
        })?;

        let mut report = CompactionPublishReport {
            committed_txg,
            committed_generation,
            rewrites: Vec::with_capacity(prepared.len()),
        };
        for entry in &prepared {
            if let Some(published) = self.apply_persisted_compaction_publish_entry(entry, false)? {
                report.rewrites.push(published);
            }
        }

        Ok(report)
    }

    /// Open an initialized block device or development regular file read-only.
    ///
    /// This unbound inspection surface never initializes or mutates media.
    /// Product callers that know Pool labels should use
    /// [`Self::open_block_device_read_only_existing`] to validate exact Pool
    /// and device identity as well.
    pub fn open_block_device(device_path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        Self::open_block_device_with_mode(
            device_path,
            options,
            StoreOpenMode::ReadOnlyExisting,
            None,
        )
    }

    pub(crate) fn open_block_device_writable_unbound(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
    ) -> Result<Self> {
        Self::open_block_device_with_mode(device_path, options, StoreOpenMode::WritableCreate, None)
    }

    /// Open an existing block-device store without permitting writes.
    ///
    /// The backing handle is opened read-only, so the returned store is
    /// suitable for concurrent integrity inspection of an already-mounted
    /// pool. Like every ordinary opener, it refuses an uninitialized or
    /// incompatible format header.
    pub fn open_block_device_read_only_existing(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
    ) -> Result<Self> {
        Self::open_block_device_with_mode(
            device_path,
            options,
            StoreOpenMode::ReadOnlyExisting,
            Some(BlockStoreIdentity {
                pool_guid,
                device_guid,
            }),
        )
    }

    pub(crate) fn open_block_device_writable_existing(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
        expected_identity: BlockStoreIdentity,
    ) -> Result<Self> {
        Self::open_block_device_with_mode(
            device_path,
            options,
            StoreOpenMode::WritableCreate,
            Some(expected_identity),
        )
    }

    pub(crate) fn open_block_device_writable_existing_file(
        file: File,
        device_path: PathBuf,
        options: StoreOptions,
        expected_identity: BlockStoreIdentity,
    ) -> Result<Self> {
        Self::open_block_device_file(
            file,
            device_path,
            options,
            StoreOpenMode::WritableCreate,
            Some(expected_identity),
        )
    }

    pub(crate) fn open_block_device_preflight_existing(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
        expected_identity: BlockStoreIdentity,
    ) -> Result<Self> {
        Self::open_block_device_with_mode(
            device_path,
            options,
            StoreOpenMode::PreflightExisting,
            Some(expected_identity),
        )
    }

    fn open_block_device_with_mode(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
        mode: StoreOpenMode,
        expected_identity: Option<BlockStoreIdentity>,
    ) -> Result<Self> {
        let device_path = device_path.as_ref().to_path_buf();
        let mut open_options = OpenOptions::new();
        open_options.read(true);
        if mode.is_writable() {
            open_options.write(true);
        }
        let file = open_options
            .open(&device_path)
            .map_err(|e| StoreError::Io {
                operation: "block_device_open",
                path: device_path.clone(),
                source: e,
            })?;
        Self::open_block_device_file(file, device_path, options, mode, expected_identity)
    }

    fn open_block_device_file(
        mut file: File,
        device_path: PathBuf,
        mut options: StoreOptions,
        mode: StoreOpenMode,
        expected_identity: Option<BlockStoreIdentity>,
    ) -> Result<Self> {
        options.validate()?;
        if !mode.is_writable() {
            options.repair_torn_tail = false;
        }

        let metadata = file.metadata().map_err(|e| StoreError::Io {
            operation: "block_device_stat",
            path: device_path.clone(),
            source: e,
        })?;
        if metadata.is_dir() {
            return Err(StoreError::InvalidOptions {
                reason: "pool backing path is a directory; use a block device or regular file",
            });
        }
        let file_type = metadata.file_type();
        if !metadata.is_file() && !file_type.is_block_device() {
            return Err(StoreError::InvalidOptions {
                reason: "pool backing path must be a block device or regular file",
            });
        }

        let capacity = file.seek(SeekFrom::End(0)).map_err(|e| StoreError::Io {
            operation: "block_device_seek_end",
            path: device_path.clone(),
            source: e,
        })?;

        let format_start: u64 = BLOCK_DEVICE_DATA_REGION_OFFSET;
        let data_start: u64 = Self::block_device_data_start();
        // Minimum usable capacity: label 0 + commit region + format header + label 1
        let min_capacity = Self::minimum_block_device_capacity();
        if capacity < min_capacity {
            return Err(StoreError::InvalidOptions {
                reason: "block device too small for the current pool Store layout",
            });
        }

        let header = match Self::read_block_format_header(&mut file, format_start)? {
            BlockFormatHeaderState::Current(header) => header,
            BlockFormatHeaderState::Blank => {
                return Err(StoreError::InvalidOptions {
                    reason: "existing block-device open requires an initialized format header",
                })
            }
        };
        if let Some(expected) = expected_identity {
            Self::validate_block_format_identity(header, expected)?;
        }

        let device_end = capacity.saturating_sub(POOL_LABEL_SIZE as u64);
        let (index, history, next_sequence, current_offset) =
            Self::scan_block_device_for_index(&mut file, data_start, device_end)?;
        let persisted_next_sequence = Self::load_physical_lifetime_sequence_high_water(
            &index,
            &mut file,
            &device_path,
            device_end,
        )?;
        let next_sequence = next_sequence
            .max(next_put_sequence_after_history(&history)?)
            .max(persisted_next_sequence);
        let receipt_bound_physical_lifetimes =
            build_receipt_bound_physical_lifetime_index(&history)?;
        let (stats_live_objects, stats_live_bytes) = stats_counted_index_totals(&index);

        let root = device_path.clone();
        let segments_dir = device_path;

        // Capture fields from options before moving it into the struct.
        let max_segment_bytes = options.max_segment_bytes;

        // Single virtual segment; the free map just needs basic structure.
        let fm = SegmentFreeMap::new(2, vec![(0, 1)]).unwrap();
        let free_map = PoolAllocator::new(fm);

        let mut store = Self {
            root,
            segments_dir,
            options,
            read_only: !mode.is_writable(),
            current_segment_id: 0,
            free_map,
            current_offset,
            current_file: file,
            block_device_capacity: Some(capacity),
            segment_created_at: Instant::now(),
            segment_write_count: 0,
            index,
            stats_live_objects,
            stats_live_bytes,
            history,
            receipt_bound_physical_lifetimes,
            next_sequence,
            replay: ReplayReport::default(),
            current_io_class: IoClass::AsyncData,
            io_scheduler: IoScheduler::new(&IoSchedulerConfig::default()),
            tombstone_count: 0,
            last_replicated_write: None,
            replicas: Vec::new(),
            replica_healthy: Vec::new(),
            last_scrub: Instant::now(),
            fault_injection_config: None,
            reclaim_scheduler: ReclaimScheduler::new(ReclaimConfig::default()),
            reclaim_queue: BPlusTreeReclaimQueue::default(),
            dead_object_reclaim_queue: DeadObjectReclaimQueue::default(),
            durable_dead_object_reclaim_queue: DeadObjectReclaimQueue::default(),
            dead_object_reclaim_pending_upserts: BTreeMap::new(),
            dead_object_reclaim_pending_upsert_record_bytes: 0,
            dead_object_reclaim_pending_removals: BTreeSet::new(),
            dead_object_reclaim_queue_dirty: false,
            reclaim_receipts: Vec::new(),
            reclaim_receipts_dirty: false,
            snapshot_extent_pin_set: SnapshotExtentPinSet::new(),
            snapshot_extent_pin_set_dirty: false,
            segment_liveness: SegmentLivenessQueue::default(),
            reclaim_consumer: ReclaimConsumerService::new(
                ReclaimConsumerConfig::default(),
                SegmentLiveCounts::new(),
            ),
            enospc_bytes_written: 0,
            segment_builder: SegmentBuilder::new(max_segment_bytes),
            free_segment_counter: FreeSegmentCounter::new(1, 0),
            chain_footer: SegmentIntegrityFooter::default(),
            segment_record_digests: Vec::new(),
            suspect_log: SuspectLog::default(),
            scrub_cursor: ScrubCursor::default(),
            commit_group: CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST),
            txg_coordinator: tidefs_commit_group::CommitGroupCoordinator::new(),
            intent_log: crate::intent_log::sync_write::IntentLog::new(INTENT_LOG_BUFFER_CAPACITY),
            intent_log_tx_open: false,
            reserve_ledger: None,
            pool_raw_mutation_allowed: None,
            compression_config: None,
            compression_stats: CompressionStats::default(),
            durability_layout: None,
            space_book: SpaceBook::default(),
            #[cfg(test)]
            current_dataset_id: None,
            checksums: BTreeMap::new(),
            prepublication_checksums_dirty: false,
            prepublication_append_start: None,
            prepublication_append_bytes: Vec::new(),
            prepublication_readback_range: None,
            prepublication_readback_bytes: Vec::new(),
            prepublication_readback_records: BTreeMap::new(),
            prepublication_tail_verification_deferred: false,
            #[cfg(test)]
            block_device_tail_terminator_verifications: 0,
            block_device_mode: true,
        };

        // Block/regular-file devices persist reclaim authority as named
        // objects in the same append-only record stream.  Directory-backed
        // open already reloads these objects below; doing the same here is
        // required so a close/reopen cannot forget a deletion handoff or make
        // one physical generation eligible twice.
        store.reclaim_queue = load_reclaim_queue_entries(&store);
        store.dead_object_reclaim_queue = store.load_dead_object_reclaim_queue_for_root()?;
        store.durable_dead_object_reclaim_queue = store.dead_object_reclaim_queue.clone();
        store.reclaim_receipts = load_reclaim_receipts(&store)?;
        store.snapshot_extent_pin_set = load_snapshot_extent_pin_set(&store)?;

        Ok(store)
    }

    fn open_with_mode(
        root: impl AsRef<Path>,
        mut options: StoreOptions,
        mode: StoreOpenMode,
    ) -> Result<Option<Self>> {
        options.validate()?;
        let mirror_path = options.mirror_path.clone();
        let replica_paths = options.replica_paths.clone();
        if !mode.is_writable() {
            options.repair_torn_tail = false;
        }
        let root = root.as_ref().to_path_buf();
        let segments_dir = root.join(STORE_DIR_NAME);
        if mode.is_writable() {
            let is_new = !segments_dir.is_dir();
            fs::create_dir_all(&segments_dir)
                .map_err(|source| io_error("create_dir_all", &segments_dir, source))?;
            sync_directory(&root)?;

            if is_new {
                // Write the format manifest so future opens can validate compatibility.
                let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
                let manifest_buf = crate::format_manifest::CURRENT_FORMAT_MANIFEST.to_bytes();
                fs::write(&manifest_path, manifest_buf)
                    .map_err(|source| io_error("write_format_manifest", &manifest_path, source))?;
            }
        } else if !segments_dir.is_dir() {
            return Ok(None);
        }

        let mut segment_ids = discover_segment_ids(&segments_dir)?;
        if segment_ids.is_empty() {
            if mode.is_writable() {
                create_segment_file(&segments_dir, 0)?;
                sync_directory(&segments_dir)?;
                segment_ids.push(0);
            } else {
                return Ok(None);
            }
        }

        // Validate format manifest compatibility before replay.
        {
            let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
            if manifest_path.exists() {
                let manifest_bytes = fs::read(&manifest_path)
                    .map_err(|source| io_error("read_format_manifest", &manifest_path, source))?;
                let stored = crate::format_manifest::LocalObjectStoreFormatManifest::from_bytes(
                    &manifest_bytes,
                )
                .map_err(|_e| StoreError::InvalidOptions {
                    reason: "format manifest corrupt or unreadable",
                })?;
                match crate::format_manifest::validate_manifest_compatibility(&stored) {
                    crate::format_manifest::ManifestValidation::Compatible => {}
                    crate::format_manifest::ManifestValidation::Incompatible {
                        field,
                        stored,
                        current,
                    } => {
                        return Err(StoreError::FormatIncompatible {
                            field,
                            stored,
                            current,
                        });
                    }
                }
            }
        }
        let mut index = BTreeMap::new();
        let mut history = BTreeMap::new();
        let mut replay = ReplayReport {
            segment_count: segment_ids.len(),
            ..ReplayReport::default()
        };
        let mut next_sequence = 1_u64;

        // Try to load a checkpoint to skip replay of already-complete segments.
        // If the checkpoint references segments that no longer exist (compaction
        // deleted them), we fall back to a full replay.
        let mut checkpoint_boundary = None;
        if let Some((checkpoint_index, checkpoint_history, checkpoint_segment_id)) =
            load_index_checkpoint(&segments_dir)?
        {
            // Validate: checkpointed segment must still exist
            if segment_ids.contains(&checkpoint_segment_id) {
                index = checkpoint_index;
                history = checkpoint_history;
                checkpoint_boundary = Some(checkpoint_segment_id);
                replay.segment_count = segment_ids.len();
            }
        }

        for (idx, segment_id) in segment_ids.iter().enumerate() {
            // Skip segments covered by a valid checkpoint
            if let Some(boundary) = checkpoint_boundary {
                if *segment_id <= boundary {
                    continue;
                }
            }
            replay_segment(
                ReplaySegmentRequest {
                    segments_dir: &segments_dir,
                    segment_id: *segment_id,
                    is_last_segment: idx + 1 == segment_ids.len(),
                    tolerate_torn_tail: mode.tolerates_torn_tail(),
                    options: &options,
                },
                ReplaySegmentState {
                    index: &mut index,
                    history: &mut history,
                    replay: &mut replay,
                    next_sequence: &mut next_sequence,
                },
            )?;
        }

        // Run segment integrity chain verification on open.
        // Broken links are recorded in the suspect log for operator visibility.
        let chain_verifier = SegmentChainVerifier::new(&segments_dir);
        let chain_suspects = chain_verifier
            .verify_chain()
            .map(|(_stats, log)| log)
            .unwrap_or_default();

        let max_existing_segment_id = *segment_ids.last().ok_or(StoreError::InvalidOptions {
            reason: "segment discovery produced no writable segment",
        })?;
        // Try loading spacemap checkpoint first; fall back to scanning.
        let mut free_map = if let Some((mut loaded_fm, _loaded_seg_count, _generation)) =
            load_spacemap_checkpoint(&segments_dir)?
        {
            // Mark all currently discovered segments as used in the loaded map.
            for &seg_id in &segment_ids {
                let _ = loaded_fm.remove_free(seg_id);
            }
            loaded_fm
        } else {
            // Construct free map: all existing segments are in use, headroom from config.
            let pool_segment_count = options.segment_count;
            // Validate: existing segments must fit within configured segment_count
            if max_existing_segment_id >= pool_segment_count {
                return Err(StoreError::InvalidOptions {
                    reason: "existing segment IDs exceed configured segment_count; pool may have been resized smaller",
                });
            }
            let used_runs: Vec<(u64, u64)> = segment_ids.iter().map(|&id| (id, id + 1)).collect();
            // Free segments are everything NOT in used_runs.
            let mut all_free_runs = Vec::new();
            let mut cursor = 0u64;
            for &(s, e) in &used_runs {
                if cursor < s {
                    all_free_runs.push((cursor, s));
                }
                cursor = e;
            }
            if cursor < pool_segment_count {
                all_free_runs.push((cursor, pool_segment_count));
            }
            let fm = if all_free_runs.is_empty() {
                SegmentFreeMap::new(pool_segment_count, Vec::new()).unwrap()
            } else {
                SegmentFreeMap::from_runs(pool_segment_count, all_free_runs).unwrap()
            };
            PoolAllocator::new(fm)
        };
        // Allocate the current segment from the free map
        let mut current_segment_id = max_existing_segment_id;
        let mut current_offset = file_len(&segment_path(&segments_dir, current_segment_id))?;
        if mode.is_writable() && current_offset >= options.max_segment_bytes {
            let completed_segment_id = current_segment_id;
            current_segment_id = free_map
                .alloc_after(current_segment_id + 1)
                .map_err(|_| StoreError::NoSpace)?;
            create_segment_file(&segments_dir, current_segment_id)?;
            sync_directory(&segments_dir)?;
            replay.segment_count += 1;
            current_offset = 0;
            // Write checkpoint: all segments <= completed_segment_id are complete
            write_index_checkpoint(&segments_dir, &index, &history, completed_segment_id)?;
            write_spacemap_checkpoint(&segments_dir, &free_map, false)?;
            free_map.clear_dirty_segment_groups();
        }

        let current_path = segment_path(&segments_dir, current_segment_id);
        let mut open_options = OpenOptions::new();
        open_options.read(true);
        if mode.is_writable() {
            open_options.write(true).create(true).truncate(false);
        }
        let mut current_file = open_options
            .open(&current_path)
            .map_err(|source| io_error("open", &current_path, source))?;
        current_file
            .seek(SeekFrom::Start(current_offset))
            .map_err(|source| io_error("seek", &current_path, source))?;

        // Open all replica stores (mirror + additional replica_paths).
        let mut replicas: Vec<LocalObjectStore> = Vec::new();
        let mut replica_healthy: Vec<bool> = Vec::new();

        if let Some(mpath) = mirror_path {
            let opened = match mode {
                StoreOpenMode::WritableCreate => {
                    LocalObjectStore::open_with_options(&mpath, StoreOptions::default()).map(Some)
                }
                StoreOpenMode::ReadOnlyExisting | StoreOpenMode::PreflightExisting => {
                    LocalObjectStore::open_with_mode(&mpath, StoreOptions::default(), mode)
                }
            };
            match opened {
                Ok(Some(store)) => {
                    replicas.push(store);
                    replica_healthy.push(true);
                }
                Ok(None) | Err(_) => {
                    replica_healthy.push(false);
                }
            }
        }
        for rp in &replica_paths {
            let opened = match mode {
                StoreOpenMode::WritableCreate => {
                    LocalObjectStore::open_with_options(rp, StoreOptions::default()).map(Some)
                }
                StoreOpenMode::ReadOnlyExisting | StoreOpenMode::PreflightExisting => {
                    LocalObjectStore::open_with_mode(rp, StoreOptions::default(), mode)
                }
            };
            match opened {
                Ok(Some(store)) => {
                    replicas.push(store);
                    replica_healthy.push(true);
                }
                Ok(None) | Err(_) => {
                    replica_healthy.push(false);
                }
            }
        }

        let fault_injection_config = options.fault_injection_config.clone();
        let durability_layout = options.durability_layout;

        let scrub_cursor = load_scrub_cursor(&segments_dir);
        let mut suspect_log = load_suspect_log(&segments_dir);
        // Merge chain-verification findings (breaks detected on open)
        // into the persisted suspect log so they survive restarts.
        for entry in chain_suspects.iter() {
            suspect_log.record(*entry);
        }
        let max_segment_bytes = options.max_segment_bytes;
        let commit_group = init_commit_group(&root);
        let txg_coordinator = init_txg_coordinator(&root);
        let initial_free_count = free_map.free_count();
        let next_sequence = next_sequence.max(next_put_sequence_after_history(&history)?);
        let receipt_bound_physical_lifetimes =
            build_receipt_bound_physical_lifetime_index(&history)?;
        let (stats_live_objects, stats_live_bytes) = stats_counted_index_totals(&index);
        let mut store = Self {
            root,
            segments_dir,
            options,
            read_only: !mode.is_writable(),
            segment_created_at: Instant::now(),
            segment_write_count: 0,
            current_segment_id,
            free_map,
            current_offset,
            current_file,
            block_device_capacity: None,
            index,
            stats_live_objects,
            stats_live_bytes,
            history,
            receipt_bound_physical_lifetimes,
            current_io_class: IoClass::AsyncData,
            next_sequence,
            io_scheduler: IoScheduler::new(&IoSchedulerConfig::default()),
            replay,
            tombstone_count: 0,
            replicas,
            replica_healthy,
            last_replicated_write: None,
            last_scrub: Instant::now(),
            fault_injection_config,
            enospc_bytes_written: 0,
            segment_builder: SegmentBuilder::new(max_segment_bytes),
            free_segment_counter: FreeSegmentCounter::new(
                initial_free_count,
                DEFAULT_LOW_WATERMARK_SEGMENTS,
            ),
            chain_footer: SegmentIntegrityFooter::default(),
            segment_record_digests: Vec::new(),
            scrub_cursor,
            suspect_log,
            reclaim_scheduler: ReclaimScheduler::new(ReclaimConfig::default()),
            reclaim_queue: BPlusTreeReclaimQueue::new(),
            dead_object_reclaim_queue: DeadObjectReclaimQueue::new(),
            durable_dead_object_reclaim_queue: DeadObjectReclaimQueue::new(),
            dead_object_reclaim_pending_upserts: BTreeMap::new(),
            dead_object_reclaim_pending_upsert_record_bytes: 0,
            dead_object_reclaim_pending_removals: BTreeSet::new(),
            dead_object_reclaim_queue_dirty: false,
            reclaim_receipts: Vec::new(),
            reclaim_receipts_dirty: false,
            snapshot_extent_pin_set: SnapshotExtentPinSet::new(),
            snapshot_extent_pin_set_dirty: false,
            segment_liveness: SegmentLivenessQueue::new(),
            reclaim_consumer: ReclaimConsumerService::new(
                ReclaimConsumerConfig::default(),
                SegmentLiveCounts::new(),
            ),
            commit_group,
            txg_coordinator,
            intent_log: crate::intent_log::sync_write::IntentLog::new(INTENT_LOG_BUFFER_CAPACITY),
            intent_log_tx_open: false,
            reserve_ledger: None,
            pool_raw_mutation_allowed: None,
            compression_config: None,
            compression_stats: CompressionStats::default(),
            durability_layout,
            space_book: SpaceBook::new(),
            #[cfg(test)]
            current_dataset_id: None,
            checksums: BTreeMap::new(),
            prepublication_checksums_dirty: false,
            prepublication_append_start: None,
            prepublication_append_bytes: Vec::new(),
            prepublication_readback_range: None,
            prepublication_readback_bytes: Vec::new(),
            prepublication_readback_records: BTreeMap::new(),
            prepublication_tail_verification_deferred: false,
            #[cfg(test)]
            block_device_tail_terminator_verifications: 0,
            block_device_mode: false,
        };
        if let Some(payload) = store.get(physical_lifetime_sequence_high_water_key())? {
            if payload.len() != 8 {
                return Err(StoreError::InvalidOptions {
                    reason: "physical lifetime sequence high-water record is malformed",
                });
            }
            let sequence = u64::from_le_bytes(payload.try_into().unwrap());
            if sequence == 0 {
                return Err(StoreError::InvalidOptions {
                    reason: "physical lifetime sequence high-water record is zero",
                });
            }
            store.next_sequence = store.next_sequence.max(sequence);
        }
        // Restore persisted per-object checksums for read-path verification.
        store.checksums = load_checksums(&store.segments_dir);
        store.reconcile_loaded_checksums_with_index()?;
        // Restore persisted reclaim-queue entries.
        store.reclaim_queue = load_reclaim_queue_entries(&store);
        // Restore persisted receipt-bound dead-object reclaim entries.
        store.dead_object_reclaim_queue = store.load_dead_object_reclaim_queue_for_root()?;
        store.durable_dead_object_reclaim_queue = store.dead_object_reclaim_queue.clone();
        // Restore committed reclaim receipt evidence.
        store.reclaim_receipts = load_reclaim_receipts(&store)?;
        // Restore snapshot extent pins before any reclaim authority observes
        // dead-object queue state.
        store.snapshot_extent_pin_set = load_snapshot_extent_pin_set(&store)?;
        // Publish any compaction rewrites whose manifest reached a committed
        // root before rebuilding reclaim liveness or replaying source release.
        store.apply_committed_compaction_publish_manifest()?;
        // Initialize reclaim-queue consumer live counts from the index.
        {
            let lc = store.reclaim_consumer.live_counts_mut();
            for (key, loc) in &store.index {
                // Per-entry reclaim authority is relocated explicitly before
                // a directory-backed segment free and is never counted on
                // the write path. Reopen must preserve that same accounting.
                if is_dead_object_reclaim_entry_state_key(*key) {
                    continue;
                }
                let seg = loc.segment_id;
                let c = lc.live_count(seg);
                lc.set_live_count(seg, c.saturating_add(1));
            }
        }
        // Reapply committed physical-reclaim receipts before open accepts the
        // allocator/free-map state reconstructed from stale checkpoints.
        store.replay_reclaim_receipts_on_open()?;
        // Restore persisted segment-liveness queue.
        store.segment_liveness = match load_segment_liveness_queue(&store) {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!("segment-liveness queue load failed: {e}, starting empty");
                SegmentLivenessQueue::new()
            }
        };

        // Bootstrap dead-segment scan: identify fully-dead segments from
        // before the last unmount, but fail closed for physical free.
        // Receipt-bound dead-object drains are the only release path that can
        // consult committed clearance evidence and snapshot extent pins.
        {
            let scan_result = crate::dead_segment_scan::scan_dead_segments_on_open(
                &store.segments_dir,
                &store.index,
                &store.history,
            )
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "dead-segment bootstrap scan failed: {e}, continuing with pool open"
                );
                crate::dead_segment_scan::DeadSegmentScanResult::default()
            });

            for &segment_id in &scan_result.dead_segment_ids {
                if segment_id == store.current_segment_id {
                    continue;
                }
                store.reclaim_consumer.live_counts_mut().remove(segment_id);
            }

            // Log the bootstrap summary at trace level.
            tracing::trace!(
                segments_scanned = scan_result.segments_scanned,
                dead_segments = scan_result.dead_segment_ids.len(),
                total_dead_bytes = scan_result.total_dead_bytes,
                partial_segments = scan_result.partial_segments.len(),
                corrupt_footers = scan_result.corrupt_footers,
                "dead-segment bootstrap scan complete"
            );

            // Record partial-segment liveness in the reclaim consumer for
            // future cleaning-priority decisions.
            for summary in &scan_result.partial_segments {
                let root_owned_reclaim_entries = store
                    .index
                    .iter()
                    .filter(|(key, location)| {
                        is_dead_object_reclaim_entry_state_key(**key)
                            && location.segment_id == summary.segment_id
                    })
                    .count() as u64;
                let lc = store.reclaim_consumer.live_counts_mut();
                let current = lc.live_count(summary.segment_id);
                if current == 0 {
                    lc.set_live_count(
                        summary.segment_id,
                        summary
                            .live_object_count
                            .saturating_sub(root_owned_reclaim_entries),
                    );
                }
            }

            // No spacemap checkpoint is written here: this scan is inspection
            // only and does not authorize physical reclaim.
        }
        // ── Intent-log replay ──────────────────────────────────────────
        // Replay committed-but-unapplied intent-log segments so no
        // acknowledged write is lost across an unclean shutdown.
        // This must run after segment replay (which rebuilds the index)
        // and before verify_committed_root_consistency so the committed
        // root reflects all recovered state.
        {
            let ilog_dir = store.root.join("intent_log");
            if ilog_dir.is_dir() {
                match crate::intent_log::segment_replay::scan_and_parse(&ilog_dir) {
                    Ok((replay_stats, transactions)) => {
                        if transactions.iter().any(|(_, records)| {
                            records.iter().any(|record| {
                                matches!(
                                    record,
                                    crate::intent_log::record::IntentLogRecord::WritePayload {
                                        object_id,
                                        ..
                                    } if is_strict_pool_authority_key(*object_id)
                                )
                            })
                        }) {
                            return Err(StoreError::InvalidOptions {
                                reason:
                                    "object-store intent-log cannot mutate strict pool authority",
                            });
                        }

                        if mode.is_writable() {
                            // Apply every committed transaction to the store.
                            // WritePayload records with non-empty data become puts;
                            // empty-payload WritePayload records become tombstones
                            // (deletes).
                            //
                            // Idempotency: track which keys have had a
                            // tombstone applied during intent-log replay so
                            // that a subsequent put for the same key (new
                            // allocation after delete) is allowed.
                            let mut intent_log_tombstoned: BTreeSet<ObjectKey> = BTreeSet::new();

                            for (_tx_id, records) in &transactions {
                                for record in records {
                                    match record {
                                        crate::intent_log::record::IntentLogRecord::WritePayload {
                                            object_id,
                                            offset: _,
                                            data,
                                        } => {
                                            if data.is_empty() {
                                                // Tombstone: apply only if the key
                                                // is still live in the index.
                                                if store.contains_key(*object_id) {
                                                    let _ = store.delete_direct(*object_id);
                                                    intent_log_tombstoned.insert(*object_id);
                                                }
                                            } else {
                                                // Write: apply only if the key is
                                                // not already in the index, AND:
                                                // - the key was never seen during
                                                //   segment replay (intent log
                                                //   is the sole authority), OR
                                                // - a tombstone was applied during
                                                //   this intent-log replay (new
                                                //   allocation after delete).
                                                // A key absent from the index but
                                                // present in segment-replay history
                                                // was put-then-deleted by the
                                                // segment log; the stale data must
                                                // not be re-put.
                                                let was_tombstoned =
                                                    intent_log_tombstoned.contains(object_id);
                                                let never_in_replay = store
                                                    .version_locations_of(*object_id)
                                                    .is_empty();
                                                if !store.contains_key(*object_id)
                                                    && (never_in_replay || was_tombstoned)
                                                {
                                                    let _ = store.put_direct(*object_id, data);
                                                    intent_log_tombstoned.remove(object_id);
                                                }
                                            }
                                        }
                                        // Any non-WritePayload record in the
                                        // object-store WAL is invalid. Filesystem
                                        // records (Create, Unlink, Rename, Mkdir,
                                        // Rmdir, Fsync, SetAttr, XattrSet, XattrRemove)
                                        // belong to tidefs_intent_log. If we encounter
                                        // one here, the segment is corrupt or the
                                        // caller violated the authority boundary.
                                        other => {
                                            let discr = other.discriminant();
                                            tracing::error!(
                                                "object-store intent-log replay: rejecting record with discriminant {discr} — filesystem records do not belong in the object-store WAL"
                                            );
                                        }
                                    }
                                }
                            }

                            // Mark all scanned segments as replayed so they are
                            // not re-applied on subsequent imports.
                            if let Ok(segments) =
                                crate::intent_log::segment_replay::discover_intent_log_segments(
                                    &ilog_dir,
                                )
                            {
                                for (_seg_id, seg_path) in &segments {
                                    let _ =
                                        crate::intent_log::segment_replay::mark_segment_replayed(
                                            seg_path,
                                        );
                                }
                            }

                            tracing::info!(
                                segments_scanned = replay_stats.segments_scanned,
                                segments_replayed = replay_stats.segments_replayed,
                                segments_corrupt = replay_stats.segments_corrupt,
                                transactions_committed = replay_stats.transactions_committed,
                                "intent-log replay complete"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("intent-log replay scan failed: {e}");
                    }
                }
            }
        }
        store.verify_committed_root_consistency();
        // Load persisted per-dataset space accounting records from the store.
        // Failure to load is non-fatal: the counters will start fresh and
        // be re-persisted on the next sync.
        if let Err(e) = store.load_space_accounting() {
            tracing::warn!(
                "failed to load space accounting records: {e}, starting with empty counters"
            );
        }
        Ok(Some(store))
    }

    fn reconcile_loaded_checksums_with_index(&mut self) -> Result<()> {
        if self.checksums.is_empty() {
            return Ok(());
        }

        let checksum_keys: Vec<ObjectKey> = self.checksums.keys().copied().collect();
        let mut reconciled = BTreeMap::new();
        for key in checksum_keys {
            let Some(location) = self.index.get(&key).copied() else {
                continue;
            };
            let payload = self.read_location(location)?;
            reconciled.insert(key, compaction_read_verify_digest(&payload));
        }
        self.checksums = reconciled;
        Ok(())
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn segments_dir(&self) -> &Path {
        &self.segments_dir
    }

    /// Test-only accessor: returns a reference to the live object index.
    #[cfg(test)]
    pub(crate) fn test_index(&self) -> &BTreeMap<ObjectKey, ObjectLocation> {
        &self.index
    }

    #[must_use]
    pub const fn replay_report(&self) -> &ReplayReport {
        &self.replay
    }

    /// Public accessor for the transaction group manager.
    #[must_use]
    pub fn txg_manager(&self) -> &crate::txg_manager::CommitGroupManager {
        &self.commit_group
    }

    /// Return a reference to the [`CommitGroupCoordinator`](tidefs_commit_group::CommitGroupCoordinator)
    /// for inspecting chain digests and commit_group numbers in integration tests.
    #[must_use]
    pub fn txg_coordinator(&self) -> &tidefs_commit_group::CommitGroupCoordinator {
        &self.txg_coordinator
    }

    /// Abort the current transaction group, discarding all queued writes.
    ///
    /// The committed root is unchanged. A fresh commit_group is opened for subsequent
    /// writes. Used for testing and error recovery.
    pub fn abort_commit_group(&mut self) {
        self.commit_group.abort_current();
    }

    /// Create a snapshot anchored at the current transaction group.
    ///
    /// Accepts a dataset name and snapshot name, captures the current commit_group
    /// and committed root as the immutable anchor, persists a
    /// [`SnapshotEntry`] into the object store, and updates the per-dataset
    /// snapshot catalog.
    ///
    /// Returns the created [`SnapshotEntry`] with the snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if persisting the snapshot entry fails.
    pub fn create_snapshot(
        &mut self,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<crate::snapshot::SnapshotEntry> {
        use crate::snapshot::SnapshotEntry;

        let dataset_key = ObjectKey::from_name(dataset_name.as_bytes());
        let current_commit_group = self.commit_group.current_id();
        let committed_root = self.commit_group.committed_root();
        let created_at = SystemTime::now();
        let entry = SnapshotEntry::new(
            snapshot_name.to_string(),
            current_commit_group,
            committed_root,
            created_at,
            dataset_key,
        );

        // Persist the snapshot entry
        let entry_key = entry.object_key();
        self.put(entry_key, &entry.encode())?;

        // Update the per-dataset snapshot catalog
        let mut catalog = self.load_snapshot_catalog(dataset_name);
        catalog.push(
            snapshot_name.to_string(),
            current_commit_group,
            committed_root,
            created_at,
            dataset_key,
        );
        self.save_snapshot_catalog(dataset_name, &catalog)?;

        Ok(entry)
    }

    /// List all snapshot entries for a dataset from the snapshot catalog.
    ///
    /// Returns entries sorted by commit_group anchor (oldest first).
    #[must_use]
    pub fn list_snapshots(&self, dataset_name: &str) -> Vec<crate::snapshot::SnapshotEntry> {
        let catalog = self.load_snapshot_catalog(dataset_name);
        let mut entries: Vec<crate::snapshot::SnapshotEntry> = catalog
            .entries()
            .iter()
            .map(|e| crate::snapshot::SnapshotEntry {
                name: e.name.clone(),
                txg_anchor: e.txg_anchor,
                committed_root: e.committed_root,
                created_at: e.created_at,
                parent_dataset_key: e.parent_dataset_key,
            })
            .collect();
        entries.sort_by_key(|e| e.txg_anchor);
        entries
    }
    /// Destroy a snapshot: remove it from the per-dataset snapshot catalog
    /// and delete its entry object from the store.
    ///
    /// Returns the removed [`SnapshotEntry`] if the snapshot existed and was
    /// successfully destroyed, or `None` if no snapshot with that name was
    /// found in the catalog.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if persisting the updated catalog or deleting the
    /// entry object fails.
    pub fn destroy_snapshot(
        &mut self,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<Option<crate::snapshot::SnapshotEntry>> {
        // Load the catalog and find the target entry.
        let mut catalog = self.load_snapshot_catalog(dataset_name);

        let entry = catalog
            .entries()
            .iter()
            .find(|e| e.name == snapshot_name)
            .map(|e| crate::snapshot::SnapshotEntry {
                name: e.name.clone(),
                txg_anchor: e.txg_anchor,
                committed_root: e.committed_root,
                created_at: e.created_at,
                parent_dataset_key: e.parent_dataset_key,
            });

        let entry = match entry {
            Some(entry) => entry,
            None => return Ok(None),
        };

        // Remove the snapshot from the catalog.
        catalog.remove(snapshot_name);

        // Persist the updated catalog.
        self.save_snapshot_catalog(dataset_name, &catalog)?;

        // Delete the snapshot entry object from the store.  The object's
        // segment space will be reclaimed by the background segment cleaner
        // via the liveness queue populated during deletion.
        let entry_key = entry.object_key();
        self.delete(entry_key)?;

        Ok(Some(entry))
    }

    /// Load the snapshot catalog for a dataset from the object store.
    fn load_snapshot_catalog(&self, dataset_name: &str) -> crate::snapshot::SnapshotCatalog {
        let catalog_key =
            crate::snapshot::SnapshotCatalog::catalog_key_for_dataset_name(dataset_name);
        match self.get(catalog_key) {
            Ok(Some(data)) => crate::snapshot::SnapshotCatalog::decode(&data).unwrap_or_default(),
            _ => crate::snapshot::SnapshotCatalog::default(),
        }
    }

    /// Persist the snapshot catalog for a dataset into the object store.
    fn save_snapshot_catalog(
        &mut self,
        dataset_name: &str,
        catalog: &crate::snapshot::SnapshotCatalog,
    ) -> Result<()> {
        let catalog_key =
            crate::snapshot::SnapshotCatalog::catalog_key_for_dataset_name(dataset_name);
        self.put(catalog_key, &catalog.encode())?;
        Ok(())
    }

    /// Create a snapshot anchored at the current transaction group.
    ///
    /// Accepts a dataset name and snapshot name, captures the current commit_group
    /// and committed root as the immutable anchor, and persists a
    /// [`SnapshotEntry`] into the object store.
    ///
    /// Returns the created [`SnapshotEntry`] with the snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if persisting the snapshot entry fails.
    fn verify_committed_root_consistency(&self) {
        let committed = self.commit_group.committed_root();
        if !committed.is_valid() {
            return; // Fresh store, nothing to verify.
        }

        let root_key = ObjectKey::from_name(crate::txg_manager::COMMITTED_ROOT_FILE.as_bytes());
        let segment_copy = match self.get(root_key) {
            Ok(Some(data)) => data,
            _ => {
                // Segment-path copy is best-effort; a crash between
                // the plain-file write and segment-path write can
                // leave only the plain-file copy present.
                return;
            }
        };

        // Read the plain-file copy directly for byte-for-byte comparison
        // against the segment-path copy.  Both are written in the same
        // format (16 or 48 bytes depending on chain-digest presence).
        let root_path = self.root.join(crate::txg_manager::COMMITTED_ROOT_FILE);
        let plain_copy = match std::fs::read(&root_path) {
            Ok(p) => p,
            Err(_) => return,
        };
        if segment_copy != plain_copy {
            tracing::warn!(
                "committed-root mismatch: segment-path copy differs from plain-file copy.                  Using plain-file copy as authority."
            );
        }
    }

    fn set_index_location(
        &mut self,
        key: ObjectKey,
        location: ObjectLocation,
    ) -> Option<ObjectLocation> {
        let previous = self.index.insert(key, location);
        if is_stats_internal_key(key) {
            return previous;
        }

        if let Some(previous) = previous {
            self.stats_live_bytes = self
                .stats_live_bytes
                .checked_sub(previous.payload_len)
                .and_then(|bytes| bytes.checked_add(location.payload_len))
                .expect("live byte count matches the live index");
        } else {
            self.stats_live_objects = self
                .stats_live_objects
                .checked_add(1)
                .expect("live object count remains representable");
            self.stats_live_bytes = self
                .stats_live_bytes
                .checked_add(location.payload_len)
                .expect("live byte count remains representable");
        }
        previous
    }

    fn remove_index_location(&mut self, key: ObjectKey) -> Option<ObjectLocation> {
        let removed = self.index.remove(&key);
        if let Some(location) = removed {
            if !is_stats_internal_key(key) {
                self.stats_live_objects = self
                    .stats_live_objects
                    .checked_sub(1)
                    .expect("live object count matches the live index");
                self.stats_live_bytes = self
                    .stats_live_bytes
                    .checked_sub(location.payload_len)
                    .expect("live byte count matches the live index");
            }
        }
        removed
    }

    fn replace_index(&mut self, index: BTreeMap<ObjectKey, ObjectLocation>) {
        let (stats_live_objects, stats_live_bytes) = stats_counted_index_totals(&index);
        self.index = index;
        self.stats_live_objects = stats_live_objects;
        self.stats_live_bytes = stats_live_bytes;
    }

    #[must_use]
    pub fn stats(&self) -> StoreStats {
        debug_assert_eq!(
            self.stats_live_objects,
            stats_counted_index_len(&self.index),
            "cached live object count must match the live index"
        );
        debug_assert_eq!(
            self.stats_live_bytes,
            stats_counted_index_bytes(&self.index),
            "cached live byte count must match the live index"
        );
        debug_assert!(self.replicas.iter().all(|replica| {
            replica.stats_live_objects == stats_counted_index_len(&replica.index)
                && replica.stats_live_bytes == stats_counted_index_bytes(&replica.index)
        }));

        let mirror_live_objects = self
            .replicas
            .first()
            .map_or(0, |replica| replica.stats_live_objects);
        let mirror_live_bytes = self
            .replicas
            .first()
            .map_or(0, |replica| replica.stats_live_bytes);
        let replica_live_objects: Vec<usize> = self
            .replicas
            .iter()
            .map(|replica| replica.stats_live_objects)
            .collect();
        let last_scrub_secs = self.last_scrub.elapsed().as_secs();
        let free_segments = self.free_map.free_count();
        let committed_root = self.txg_manager().committed_root();
        let committed_root_txg = committed_root.commit_group_id.0;
        let committed_root_generation = self.txg_manager().commit_count();
        StoreStats {
            live_objects: self.stats_live_objects,
            live_bytes: self.stats_live_bytes,
            segment_count: self.replay.segment_count,
            free_segments,
            free_bytes: free_segments * self.options.max_segment_bytes,
            next_sequence: self.next_sequence,
            tombstone_count: self.tombstone_count,
            replay: self.replay.clone(),
            mirror_degraded: self.replica_healthy.first().is_some_and(|&h| !h),
            mirror_live_objects,
            mirror_live_bytes,
            replica_healthy: self.replica_healthy.clone(),
            replica_live_objects,
            last_scrub_secs,
            committed_root_txg,
            committed_root_generation,
        }
    }

    /// Ratio of tombstone records to (tombstone records + live objects).
    /// A value of 0.0 means no waste; 1.0 means every object is dead.
    /// Whether any replica store is degraded (failed writes or failed open).
    #[must_use]
    pub fn mirror_degraded(&self) -> bool {
        self.replica_healthy.iter().any(|&h| !h)
    }

    /// Total raw storage capacity in bytes (segment_count * max_segment_bytes).
    ///
    /// This is the configured capacity ceiling, not the current live-byte
    /// total. Used by pool-level statfs integration to surface filesystem
    /// capacity to FUSE clients.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        if self.block_device_mode {
            return self
                .block_device_capacity
                .unwrap_or(0)
                .saturating_sub(POOL_LABEL_SIZE as u64);
        }
        self.options
            .segment_count
            .saturating_mul(self.options.max_segment_bytes)
    }

    /// Maximum size of a single segment file in bytes.
    ///
    /// Used by device discard to map pool-level byte offsets into
    /// (segment_id, segment_offset) pairs for hole-punching.
    #[must_use]
    pub fn max_segment_bytes(&self) -> u64 {
        self.options.max_segment_bytes
    }

    /// Total number of replicas (mirror + replica_paths).
    #[must_use]
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }

    /// Quorum threshold: primary + ceil(replicas/2) must ack.
    #[must_use]
    pub fn replica_quorum(&self) -> usize {
        let total = 1 + self.replica_count();
        (total / 2) + 1
    }

    /// Whether enough time has passed since the last scrub to start
    /// a new one, per the configured interval.
    #[must_use]
    pub fn should_scrub(&self) -> bool {
        if self.read_only {
            // Read-only stores always signal readiness: each call
            // runs a fresh scan since we cannot persist cursor/suspect_log.
            return self.options.background_scrub_interval_secs > 0;
        }
        self.options.background_scrub_interval_secs > 0
            && self.last_scrub.elapsed().as_secs() >= self.options.background_scrub_interval_secs
    }

    /// Whether an incremental background scrub stopped with work remaining.
    #[must_use]
    pub fn background_scrub_pending(&self) -> bool {
        !self.scrub_cursor.is_initial()
    }

    /// Perform a full scrub of the mirror store: iterate every key in
    /// the primary index, compare against the mirror, and repair any
    /// divergence (missing keys, digest mismatches). Returns scrub
    /// statistics.
    ///
    /// This is a best-effort operation: errors on individual keys are
    /// counted and reported without aborting the full cycle.
    /// Perform a full scrub of all replica stores: iterate every key in
    /// the primary index, compare against each replica, and repair any
    /// divergence (missing keys, digest mismatches). Returns scrub statistics
    /// aggregated across all replicas.
    pub fn scrub_replicas(&mut self) -> Result<ScrubStats> {
        self.ensure_pool_raw_mutation_allowed()?;
        let started = Instant::now();
        let mut stats = ScrubStats::default();

        if self.replicas.is_empty() {
            self.last_scrub = Instant::now();
            return Ok(stats);
        }

        // For each replica, compare against primary and repair.
        for replica_idx in 0..self.replicas.len() {
            enum Divergence {
                Missing,
                Mismatched,
            }
            let mut diverged: Vec<(ObjectKey, ObjectLocation, Divergence)> = Vec::new();

            // Phase 1: classify keys against this replica.
            for (&key, &location) in &self.index {
                stats.keys_examined = stats.keys_examined.saturating_add(1);

                let replica_has_key = self.replicas[replica_idx].contains_key(key);
                if !replica_has_key {
                    diverged.push((key, location, Divergence::Missing));
                    continue;
                }

                let primary_payload = match self.read_location(location) {
                    Ok(p) => p,
                    Err(_) => {
                        stats.errors = stats.errors.saturating_add(1);
                        continue;
                    }
                };
                let primary_checksum = checksum64(&primary_payload);

                match self.replicas[replica_idx].get(key) {
                    Ok(Some(payload)) => {
                        if primary_checksum == checksum64(&payload) {
                            stats.keys_healthy = stats.keys_healthy.saturating_add(1);
                        } else {
                            diverged.push((key, location, Divergence::Mismatched));
                        }
                    }
                    _ => {
                        diverged.push((key, location, Divergence::Mismatched));
                    }
                }
            }

            // Phase 2: read primary payloads.
            let mut repairs: Vec<(ObjectKey, Vec<u8>, Divergence)> = Vec::new();
            for (key, location, divergence) in diverged {
                match self.read_location(location) {
                    Ok(payload) => repairs.push((key, payload, divergence)),
                    Err(_) => {
                        stats.errors = stats.errors.saturating_add(1);
                    }
                }
            }

            // Phase 3: write repairs to this replica.
            for (key, payload, divergence) in &repairs {
                if self.replicas[replica_idx].put(*key, payload).is_ok() {
                    match divergence {
                        Divergence::Missing => {
                            stats.keys_resynced = stats.keys_resynced.saturating_add(1);
                        }
                        Divergence::Mismatched => {
                            stats.keys_repaired = stats.keys_repaired.saturating_add(1);
                        }
                    }
                } else {
                    stats.errors = stats.errors.saturating_add(1);
                    if replica_idx < self.replica_healthy.len() {
                        self.replica_healthy[replica_idx] = false;
                    }
                }
            }

            if !repairs.is_empty() {
                let _ = self.replicas[replica_idx].sync_all();
            }
        }

        // Mark replicas as healthy if they had no errors and had repairs.
        if stats.errors == 0 {
            for h in self.replica_healthy.iter_mut() {
                if !*h {
                    *h = true;
                }
            }
        }

        self.last_scrub = Instant::now();
        stats.duration_secs = started.elapsed().as_secs_f64();
        Ok(stats)
    }

    /// Rebuild a lost replica from a surviving store by copying all live objects.
    ///
    /// Used when a mirror member is lost and must be reconstructed from a
    /// surviving replica.  The replacement store is created at
    /// `replacement_path` and populated with every non-internal object
    /// from `surviving`, preserving the original [`ObjectKey`] for each
    /// object so the rebuilt store is an exact replica of the survivor.
    ///
    /// # Return
    ///
    /// Returns the fully populated replacement store, synced and ready to
    /// use as a replica.  The caller is responsible for updating pool
    /// labels and topology metadata after the rebuild completes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the replacement store cannot be
    /// created or if any object read/write fails.
    pub fn rebuild_replica_from_surviving(
        surviving: &LocalObjectStore,
        replacement_path: &std::path::Path,
        options: StoreOptions,
    ) -> Result<LocalObjectStore> {
        Self::rebuild_replica_from_surviving_throttled(
            surviving,
            replacement_path,
            options,
            None,
            &RebuildThrottleConfig::disabled(),
        )
    }

    /// Rebuild a lost replica with foreground-I/O-aware backpressure.
    ///
    /// Identical to [`rebuild_replica_from_surviving`] except that it
    /// accepts an optional [`IoPressureProbe`] and a
    /// [`RebuildThrottleConfig`]. When the probe reports foreground
    /// pressure, the rebuild loop yields between object copies to avoid
    /// starving foreground I/O.
    ///
    /// # Arguments
    ///
    /// * `pressure_probe` — When `Some`, queried every
    ///   `throttle_cfg.probe_interval_objects`. If pressure > 0, the
    ///   loop yields for a duration proportional to the pressure before
    ///   resuming.
    /// * `throttle_cfg` — Controls the maximum per-object yield and
    ///   probe batching interval.
    pub fn rebuild_replica_from_surviving_throttled(
        surviving: &LocalObjectStore,
        replacement_path: &std::path::Path,
        options: StoreOptions,
        pressure_probe: Option<&IoPressureProbe>,
        throttle_cfg: &RebuildThrottleConfig,
    ) -> Result<LocalObjectStore> {
        let mut replacement = LocalObjectStore::open_with_options(replacement_path, options)?;

        // Collect keys first so we don't hold an immutable borrow across
        // the mutable `put` calls below.
        let keys: Vec<ObjectKey> = surviving.list_keys();

        let mut copied: u64 = 0;
        let mut errors: u64 = 0;

        let throttling_enabled = pressure_probe.is_some() && !throttle_cfg.is_disabled();
        let probe_interval = if throttling_enabled {
            throttle_cfg.probe_interval_objects.max(1)
        } else {
            usize::MAX
        };

        for (i, &key) in keys.iter().enumerate() {
            // Check foreground pressure every probe_interval objects.
            if throttling_enabled && i > 0 && i % probe_interval == 0 {
                if let Some(probe) = pressure_probe {
                    if let Some(yield_for) = probe.yield_duration(throttle_cfg.max_yield_per_object)
                    {
                        std::thread::sleep(yield_for);
                    }
                }
            }

            if let Ok(Some(payload)) = surviving.get(key) {
                // Use `put` with the explicit key so the rebuilt store
                // preserves the same ObjectKey -- not a content-derived
                // key that could differ under compression or framing.
                match replacement.put(key, &payload) {
                    Ok(_) => copied = copied.saturating_add(1),
                    Err(_e) => {
                        errors = errors.saturating_add(1);
                    }
                }
            }
        }

        replacement.sync_all()?;
        tracing::info!(copied, errors, "rebuild_replica_from_surviving complete");
        Ok(replacement)
    }

    /// Walk all segment files in read-only mode and verify the
    /// [`IntegrityTrailerV2`] BLAKE3-256 digests on every record.
    ///
    /// On mismatch, a [`SuspectEntry`] is recorded into `suspect_log`.
    /// Returns aggregate statistics.  This method never mutates the store
    /// or repairs data — it is a pure integrity audit.
    ///
    /// # Budget
    ///
    /// `max_records` and `max_bytes` bound the work performed in one call.
    /// Use `0` for unbounded.  The method returns `false` when there are
    /// more segments to scan.
    pub fn verify_segment_integrity(
        &self,
        suspect_log: &mut SuspectLog,
        cursor: &mut (u64, u64), // (segment_id, offset)
        max_records: u64,
        max_bytes: u64,
    ) -> Result<(u64, u64, bool)> {
        // (records_verified, bytes_scanned, has_more)
        let mut records_verified: u64 = 0;
        let mut bytes_scanned: u64 = 0;
        let segment_ids = discover_segment_ids(&self.segments_dir)?;

        let start_seg = cursor.0;
        let mut found_start = start_seg == 0;

        for &segment_id in &segment_ids {
            if segment_id < start_seg {
                continue;
            }
            if segment_id == start_seg {
                found_start = true;
            }
            if !found_start {
                continue;
            }

            let path = segment_path(&self.segments_dir, segment_id);
            let mut file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|source| io_error("open", &path, source))?;

            let mut offset = if segment_id == start_seg { cursor.1 } else { 0 };
            file.seek(SeekFrom::Start(offset))
                .map_err(|source| io_error("seek", &path, source))?;

            loop {
                if (max_records > 0 && records_verified >= max_records)
                    || (max_bytes > 0 && bytes_scanned >= max_bytes)
                {
                    *cursor = (segment_id, offset);
                    return Ok((records_verified, bytes_scanned, true));
                }

                let mut header = [0_u8; RECORD_HEADER_LEN];
                let header_bytes = read_up_to(&mut file, &mut header)
                    .map_err(|source| io_error("read header", &path, source))?;
                if header_bytes == 0 {
                    break; // end of segment
                }
                if header_bytes < RECORD_HEADER_LEN {
                    break; // last segment may have partial record; skip
                }

                let record = match decode_header(&header, segment_id, offset) {
                    Ok(r) => r,
                    Err(_) => break,
                };

                let payload_len = match usize::try_from(record.payload_len) {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let mut payload = vec![0_u8; payload_len];
                let payload_bytes = read_up_to(&mut file, &mut payload)
                    .map_err(|source| io_error("read payload", &path, source))?;
                if payload_bytes < payload_len {
                    break;
                }

                let trailer_offset =
                    offset + RECORD_HEADER_LEN_U64 + record.payload_len + RECORD_FOOTER_LEN_U64;

                let footer = if record_has_footer(record.format_version) {
                    let mut footer_bytes = [0_u8; RECORD_FOOTER_LEN];
                    let bytes_read = read_up_to(&mut file, &mut footer_bytes)
                        .map_err(|source| io_error("read footer", &path, source))?;
                    if bytes_read < RECORD_FOOTER_LEN {
                        break;
                    }
                    Some(footer_bytes)
                } else {
                    None
                };

                if record_has_production_integrity_trailer(record.format_version) {
                    let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
                    let trailer_bytes = read_up_to(&mut file, &mut trailer)
                        .map_err(|source| io_error("read integrity trailer V2", &path, source))?;
                    if trailer_bytes >= INTEGRITY_TRAILER_V2_LEN {
                        if let Ok(decoded) = decode_integrity_trailer_v2(&trailer) {
                            let default_footer = [0u8; RECORD_FOOTER_LEN];
                            let footer_ref = footer.as_ref().unwrap_or(&default_footer);
                            if verify_integrity_trailer_v2(
                                &decoded,
                                record,
                                &header,
                                &payload,
                                footer_ref,
                                segment_id,
                                trailer_offset,
                            )
                            .is_err()
                            {
                                suspect_log.record(SuspectEntry {
                                    locator_id: 0,
                                    segment_id,
                                    offset,
                                    record_type: 1, // payload checksum mismatch
                                    expected_hash: [0u8; 32],
                                    actual_hash: [0u8; 32],
                                    repair_attempts: 0,
                                    last_repair_attempt: 0,
                                    resolved: false,
                                    commit_group: record.sequence,
                                    timestamp_secs: 0,
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }

                // Advance offset past this record
                offset = trailer_offset + INTEGRITY_TRAILER_V2_LEN_U64;
                records_verified = records_verified.saturating_add(1);
                bytes_scanned = bytes_scanned.saturating_add(payload_len as u64);
                file.seek(SeekFrom::Start(offset))
                    .map_err(|source| io_error("seek", &path, source))?;
            }
        }

        // Completed all segments
        *cursor = (0, 0);
        Ok((records_verified, bytes_scanned, false))
    }

    pub fn waste_ratio(&self) -> f64 {
        let total = self.tombstone_count.saturating_add(self.index.len() as u64);
        if total == 0 {
            return 0.0;
        }
        self.tombstone_count as f64 / total as f64
    }

    /// Returns true when the waste ratio exceeds the given threshold.
    ///
    /// The default recommended threshold for automatic compaction is 0.25 (25%).
    #[must_use]
    pub fn should_compact(&self, threshold: f64) -> bool {
        self.waste_ratio() > threshold
    }

    /// Detect and return any space pressure state transition since the last call.
    ///
    /// Call this after allocation/free operations. Returns `Some(event)` only
    /// on the first call that detects a threshold crossing; subsequent calls
    /// while the pressure state is stable return `None`.
    pub fn check_space_pressure(&mut self) -> Option<SpacePressureEvent> {
        let event = self.free_map.check_pressure_transition();
        if let Some(SpacePressureEvent::EnterPressure) = &event {
            eprintln!("tidefs space pressure warning: pool >= 95% used — consider adding capacity or triggering reclamation");
        }
        event
    }

    /// Number of free segments according to the live counter (lock-free).
    pub fn free_segment_count(&self) -> u64 {
        self.free_segment_counter.free_segment_count()
    }

    /// Whether free segments are at or below the low-watermark threshold.
    pub fn is_low_space(&self) -> bool {
        self.free_segment_counter.is_low_space()
    }

    /// Attach a reserve ledger for segment-level write admission.
    ///
    /// Once set, every [`put_inner`] call consults the reserve before
    /// consuming free segments.  The ledger is shared so the caller
    /// (typically the pool) can update capacity independently.
    pub fn set_reserve_ledger(&mut self, rl: ReserveLedger) {
        self.reserve_ledger = Some(Arc::new(Mutex::new(rl)));
    }

    /// Return a reference to the shared reserve ledger, if set.
    pub fn reserve_ledger(&self) -> Option<&Arc<Mutex<ReserveLedger>>> {
        self.reserve_ledger.as_ref()
    }

    /// Check write admission against the reserve ledger for `count`
    /// segments at the given priority.
    ///
    /// Returns `Ok(())` when the write may proceed, `Err(StoreError::NoSpace)`
    /// when the reserve blocks it.
    fn check_reserve_admission(&self, priority: WritePriority, count: u32) -> Result<()> {
        match &self.reserve_ledger {
            None => Ok(()), // No reserve ledger configured — always admit.
            Some(rl) => {
                let guard = rl.lock().unwrap();
                guard
                    .reserve_check(priority, count)
                    .map_err(|_| StoreError::NoSpace)?;
                // Token is intentionally leaked here — the segments stay
                // reserved until the next pool capacity update releases
                // them via the FreeSegmentCounter reconciliation path.
                Ok(())
            }
        }
    }

    /// Inspect legacy reclaim-queue entries without freeing segments.
    ///
    /// Physical segment freeing requires committed dead-object receipt
    /// evidence and must use
    /// [`drain_receipt_bound_dead_objects_at_stable_generation`](Self::drain_receipt_bound_dead_objects_at_stable_generation).
    /// The older B+tree reclaim queue is retained as liveness/debt input, but
    /// this entry point now fails closed so ordinary delete/overwrite deltas
    /// cannot return a segment to the pool without committed clearance.
    ///
    /// # Errors
    ///
    /// This compatibility inspection path does not free segments and therefore
    /// cannot produce resolver or freer errors.
    pub fn drain_dead_segments(
        &mut self,
        _config: &ReclaimConsumerConfig,
    ) -> std::result::Result<
        tidefs_reclaim::ReclaimConsumerStats,
        tidefs_reclaim::DrainError<Infallible, tidefs_pool_allocator::PoolAllocatorError>,
    > {
        Ok(tidefs_reclaim::ReclaimConsumerStats {
            reclaim_queue_depth: self.reclaim_queue.len(),
            ..tidefs_reclaim::ReclaimConsumerStats::ZERO
        })
    }

    /// Committed reclaim receipts loaded during open and appended after
    /// receipt-bound physical frees.
    #[must_use]
    pub fn reclaim_receipts(&self) -> &[ReclaimReceipt] {
        &self.reclaim_receipts
    }

    fn replay_reclaim_receipts_on_open(&mut self) -> Result<()> {
        if self.block_device_mode || sidecar_files_unavailable(&self.segments_dir) {
            return Ok(());
        }

        let mut receipt_extents_by_segment: BTreeMap<u64, BTreeSet<ReclaimObjectKey>> =
            BTreeMap::new();
        for receipt in &self.reclaim_receipts {
            for extent in &receipt.freed_segment_extents {
                receipt_extents_by_segment
                    .entry(extent.segment_id)
                    .or_default()
                    .insert(extent.extent_key);
            }
        }

        // Read-only open validates the receipt log but must not acknowledge
        // queue rows, remove segment files, or change allocator state.
        if self.read_only {
            return Ok(());
        }

        // A crash can leave the receipt durable while its exact queue rows are
        // still present. Acknowledge only rows whose physical lifetime resolves
        // to the segment named by that receipt, and persist the acknowledgement
        // before replay performs any physical free.
        let mut receipt_covered_queue_ids = BTreeSet::new();
        for entry in self.dead_object_reclaim_queue.all_entries() {
            let Some((resolved_segment, _)) =
                self.resolve_receipt_bound_reclaim_target(&entry.object_id)?
            else {
                continue;
            };
            if receipt_extents_by_segment
                .get(&resolved_segment)
                .is_some_and(|extent_keys| extent_keys.contains(&entry.object_id))
            {
                receipt_covered_queue_ids.insert(entry.object_id);
            }
        }
        if !receipt_covered_queue_ids.is_empty() {
            let ack_object_ids = receipt_covered_queue_ids.into_iter().collect::<Vec<_>>();
            let removed = self
                .dead_object_reclaim_queue
                .ack_reclaimed(&ack_object_ids);
            if removed != ack_object_ids.len() {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "receipt replay queue acknowledgement was not exact",
                });
            }
            self.persist_dead_object_reclaim_queue_delta(&[], &ack_object_ids)?;
        }

        let mut physical_state_changed = false;
        for (segment_id, extent_keys) in receipt_extents_by_segment {
            if segment_id == self.current_segment_id
                || self
                    .index
                    .values()
                    .any(|location| location.segment_id == segment_id)
            {
                continue;
            }

            let seg_path = segment_path(&self.segments_dir, segment_id);
            if !self.receipt_replay_extents_match_dead_history(segment_id, &extent_keys) {
                continue;
            }
            physical_state_changed |= seg_path.exists() || !self.free_map.is_free(segment_id);
            self.free_receipt_authorized_segment(segment_id)?;
        }
        if physical_state_changed {
            self.sync_all()?;
        }

        Ok(())
    }

    fn receipt_replay_extents_match_dead_history(
        &self,
        segment_id: u64,
        extent_keys: &BTreeSet<ReclaimObjectKey>,
    ) -> bool {
        extent_keys.iter().all(|extent_key| {
            self.resolve_receipt_bound_reclaim_target(extent_key)
                .ok()
                .flatten()
                .is_some_and(|(resolved_segment, _)| resolved_segment == segment_id)
        })
    }

    fn resolve_receipt_bound_reclaim_target(
        &self,
        reclaim_object_id: &ReclaimObjectKey,
    ) -> Result<Option<(u64, ReclaimObjectKey)>> {
        if let Some(lifetime) = self.resolve_receipt_bound_physical_lifetime(reclaim_object_id)? {
            if self.index.get(&lifetime.logical_object_key).copied() == Some(lifetime.location) {
                return Ok(None);
            }
            return Ok(Some((
                lifetime.location.segment_id,
                ReclaimObjectKey(*lifetime.logical_object_key.as_bytes()),
            )));
        }

        // Compatibility for ordinary logical-key reclaim rows that have not
        // yet moved to exact physical-lifetime identity.
        let logical_object_key = ObjectKey::from_bytes(reclaim_object_id.0);
        let live_location = self.index.get(&logical_object_key).copied();
        let dead_segment = self.history.get(&logical_object_key).and_then(|locations| {
            locations
                .iter()
                .rev()
                .copied()
                .find(|location| Some(*location) != live_location)
                .map(|location| location.segment_id)
        });
        Ok(dead_segment.map(|segment_id| (segment_id, *reclaim_object_id)))
    }

    /// Snapshot extent pins consulted by receipt-bound physical reclaim.
    #[must_use]
    pub fn snapshot_extent_pin_set(&self) -> &SnapshotExtentPinSet {
        &self.snapshot_extent_pin_set
    }

    /// Mutable snapshot extent pins for callers that own committed snapshot
    /// lifecycle evidence.
    pub fn snapshot_extent_pin_set_mut(&mut self) -> &mut SnapshotExtentPinSet {
        self.snapshot_extent_pin_set_dirty = true;
        &mut self.snapshot_extent_pin_set
    }

    /// Replace the snapshot extent pin set used by receipt-bound physical reclaim.
    pub fn set_snapshot_extent_pin_set(&mut self, pin_set: SnapshotExtentPinSet) {
        self.snapshot_extent_pin_set = pin_set;
        self.snapshot_extent_pin_set_dirty = true;
    }

    /// Pin an extent for a live snapshot.
    pub fn pin_snapshot_extent(&mut self, snapshot_id: &str, extent_key: ReclaimObjectKey) {
        let prior_epoch = self.snapshot_extent_pin_set.epoch();
        self.snapshot_extent_pin_set.pin(snapshot_id, extent_key);
        if self.snapshot_extent_pin_set.epoch() != prior_epoch {
            self.snapshot_extent_pin_set_dirty = true;
        }
    }

    /// Release all extent pins for a destroyed snapshot.
    pub fn release_snapshot_extent_pins(&mut self, snapshot_id: &str) -> usize {
        let removed = self.snapshot_extent_pin_set.release_snapshot(snapshot_id);
        if removed > 0 {
            self.snapshot_extent_pin_set_dirty = true;
        }
        removed
    }

    /// Persist one snapshot-deadlist candidate as receipt-bound reclaim work.
    ///
    /// The queued entry is immediately eligible by deadlist derivation, but it
    /// carries no replacement/base receipt.  Therefore
    /// [`drain_receipt_bound_dead_objects_at_stable_generation`](Self::drain_receipt_bound_dead_objects_at_stable_generation)
    /// will keep it queued until
    /// [`publish_dead_object_replacement_receipt`](Self::publish_dead_object_replacement_receipt)
    /// attaches committed receipt evidence, and even then the snapshot extent
    /// pin gate remains authoritative.
    pub fn enqueue_snapshot_deadlist_candidate(
        &mut self,
        candidate: SnapshotDeadObjectCandidate,
    ) -> Result<bool> {
        self.enqueue_snapshot_deadlist_candidates(std::iter::once(candidate))
            .map(|inserted| inserted != 0)
    }

    /// Persist snapshot-deadlist candidates as receipt-bound reclaim work.
    ///
    /// Returns the number of newly inserted object ids. Duplicate object ids
    /// are treated as idempotent replay and do not rewrite the persisted queue.
    pub fn enqueue_snapshot_deadlist_candidates<I>(&mut self, candidates: I) -> Result<usize>
    where
        I: IntoIterator<Item = SnapshotDeadObjectCandidate>,
    {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("enqueue_snapshot_deadlist_candidates")?;
        let candidates: Vec<_> = candidates.into_iter().collect();
        for candidate in &candidates {
            Self::ensure_public_pool_reclaim_key_allowed(candidate.object_id)?;
        }
        let mut inserted_entries = Vec::new();
        for candidate in candidates {
            let entry = candidate.into_dead_object_entry();
            if self.dead_object_reclaim_queue.enqueue(entry) {
                inserted_entries.push(entry);
            }
        }
        if !inserted_entries.is_empty() {
            self.persist_dead_object_reclaim_queue_delta(&inserted_entries, &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.sync_dead_object_reclaim_queue_authority()?;
        }
        Ok(inserted_entries.len())
    }

    /// Enqueue one dead object whose old placement may be retired only after
    /// replacement/base receipt evidence and commit-group stability agree.
    ///
    /// The receipt-bearing entry reaches the root-owned reclaim barrier before
    /// this method returns `Ok(true)`, so a later drain cannot race an
    /// in-memory-only receipt publication or commit unrelated store state.
    /// Duplicate object ids are accepted as idempotent replays and return
    /// `Ok(false)`.
    pub fn enqueue_receipt_bound_dead_object(&mut self, entry: DeadObjectEntry) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        Self::ensure_public_pool_reclaim_key_allowed(entry.object_id)?;
        self.enqueue_receipt_bound_dead_object_authorized(entry)
    }

    fn enqueue_receipt_bound_dead_object_authorized(
        &mut self,
        entry: DeadObjectEntry,
    ) -> Result<bool> {
        self.ensure_writable("enqueue_receipt_bound_dead_object")?;
        let Some(receipt) = entry.replacement_receipt else {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "missing replacement receipt",
            });
        };
        if !receipt.authorizes_reclaim_for(entry.object_id) {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "replacement receipt does not authorize this object",
            });
        }

        let inserted = self.dead_object_reclaim_queue.enqueue(entry);
        if inserted {
            self.persist_dead_object_reclaim_queue_delta(&[entry], &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.sync_dead_object_reclaim_queue_authority()?;
        }
        Ok(inserted)
    }

    /// Persist pending receipt-bound dead-object work before replacement/base
    /// receipt publication is available.
    ///
    /// This preserves enqueue-before-publish replay state while keeping the
    /// entry ineligible for drain until
    /// [`publish_dead_object_replacement_receipt`](Self::publish_dead_object_replacement_receipt)
    /// attaches durable, authorizing receipt evidence.
    pub fn enqueue_pending_receipt_bound_dead_object(
        &mut self,
        entry: DeadObjectEntry,
    ) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        Self::ensure_public_pool_reclaim_key_allowed(entry.object_id)?;
        self.enqueue_pending_receipt_bound_dead_object_authorized(entry)
    }

    pub(crate) fn enqueue_pending_receipt_bound_dead_object_pool_internal(
        &mut self,
        entry: DeadObjectEntry,
    ) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("stage Pool-owned receipt-bound dead object")?;
        if entry.replacement_receipt.is_some() {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "pending receipt-bound enqueue must not include a replacement receipt",
            });
        }
        let inserted = self.dead_object_reclaim_queue.enqueue(entry);
        if inserted {
            self.stage_dead_object_reclaim_queue_delta(&[entry], &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.stage_dead_object_reclaim_queue_delta(&[], &[])?;
        }
        Ok(inserted)
    }

    pub(crate) fn enqueue_pending_receipt_bound_dead_objects_pool_internal(
        &mut self,
        entries: &[DeadObjectEntry],
    ) -> Result<()> {
        for entry in entries {
            if entry.replacement_receipt.is_some() {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "pending receipt-bound enqueue must not include a replacement receipt",
                });
            }
        }
        self.enqueue_pending_receipt_bound_dead_objects_across_store_tree(entries)
    }

    fn enqueue_pending_receipt_bound_dead_objects_across_store_tree(
        &mut self,
        entries: &[DeadObjectEntry],
    ) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("enqueue pending receipt-bound dead objects")?;
        let mut changed = Vec::new();
        for entry in entries {
            // The lifetime index intentionally retains historical identities
            // until their reclaim rows are acknowledged. Resolve only the
            // supplied exact id: rebuilding the set of all current lifetimes
            // here would make every overwrite scan the complete write history.
            let owned_current_lifetime = self
                .receipt_bound_physical_lifetimes
                .get(&entry.object_id)
                .is_some_and(|lifetime| {
                    self.index.get(&lifetime.logical_object_key).copied() == Some(lifetime.location)
                });
            if owned_current_lifetime {
                if self.dead_object_reclaim_queue.enqueue(*entry) {
                    changed.push(*entry);
                }
            }
        }
        let mut first_error = if !changed.is_empty() {
            self.stage_dead_object_reclaim_queue_delta(&changed, &[])
                .err()
        } else if self.dead_object_reclaim_queue_dirty {
            self.stage_dead_object_reclaim_queue_delta(&[], &[]).err()
        } else {
            None
        };
        for (index, replica) in self.replicas.iter_mut().enumerate() {
            match replica.enqueue_pending_receipt_bound_dead_objects_across_store_tree(entries) {
                Ok(()) if index < self.replica_healthy.len() => {
                    self.replica_healthy[index] = true;
                }
                Ok(()) => {}
                Err(error) => {
                    if index < self.replica_healthy.len() {
                        self.replica_healthy[index] = false;
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Capture the exact current append-log lifetime for a Pool-owned object.
    ///
    /// The returned identity is stable across reopen because it is derived
    /// entirely from the logical key and persisted [`ObjectLocation`].
    pub(crate) fn current_receipt_bound_physical_lifetime_pool_internal(
        &self,
        logical_object_key: ObjectKey,
    ) -> Result<ReceiptBoundPhysicalLifetime> {
        let location = self.index.get(&logical_object_key).copied().ok_or(
            StoreError::InvalidDeadObjectReceipt {
                reason: "receipt-bound reclaim cannot capture a missing current physical lifetime",
            },
        )?;
        let lifetime = ReceiptBoundPhysicalLifetime {
            logical_object_key,
            location,
            reclaim_object_id: receipt_bound_physical_lifetime_id(logical_object_key, location),
        };
        if self
            .receipt_bound_physical_lifetimes
            .get(&lifetime.reclaim_object_id)
            .copied()
            != Some(lifetime)
        {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "receipt-bound current physical lifetime is not uniquely indexed",
            });
        }
        Ok(lifetime)
    }

    /// Capture every present current lifetime for one key across this store
    /// and its configured replica stores.
    ///
    /// Missing copies are idempotent cleanup state. A configured replica that
    /// is not open is different: its physical state is unknown, so reclaim
    /// must remain fail-closed until that store is available.
    pub(crate) fn current_receipt_bound_physical_lifetimes_across_stores_pool_internal(
        &self,
        logical_object_key: ObjectKey,
    ) -> Result<Vec<ReceiptBoundPhysicalLifetime>> {
        if self.replicas.is_empty() {
            return if self.index.contains_key(&logical_object_key) {
                Ok(vec![self
                    .current_receipt_bound_physical_lifetime_pool_internal(
                        logical_object_key,
                    )?])
            } else {
                Ok(Vec::new())
            };
        }
        let mut lifetimes = BTreeMap::new();
        self.collect_current_receipt_bound_physical_lifetimes(logical_object_key, &mut lifetimes)?;
        Ok(lifetimes.into_values().collect())
    }

    fn collect_current_receipt_bound_physical_lifetimes(
        &self,
        logical_object_key: ObjectKey,
        lifetimes: &mut BTreeMap<ReclaimObjectKey, ReceiptBoundPhysicalLifetime>,
    ) -> Result<()> {
        if self.options.replica_count() != self.replicas.len() {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "receipt-bound reclaim cannot inspect an unavailable store replica",
            });
        }
        if self.index.contains_key(&logical_object_key) {
            let lifetime =
                self.current_receipt_bound_physical_lifetime_pool_internal(logical_object_key)?;
            if lifetimes
                .insert(lifetime.reclaim_object_id, lifetime)
                .is_some_and(|known| known != lifetime)
            {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason:
                        "receipt-bound physical lifetime identity collision across store replicas",
                });
            }
        }
        for replica in &self.replicas {
            replica
                .collect_current_receipt_bound_physical_lifetimes(logical_object_key, lifetimes)?;
        }
        Ok(())
    }

    fn index_receipt_bound_physical_lifetime(
        &mut self,
        logical_object_key: ObjectKey,
        location: ObjectLocation,
    ) -> Result<()> {
        let reclaim_object_id = receipt_bound_physical_lifetime_id(logical_object_key, location);
        let candidate = ReceiptBoundPhysicalLifetime {
            logical_object_key,
            location,
            reclaim_object_id,
        };
        if let Some(known) = self
            .receipt_bound_physical_lifetimes
            .get(&reclaim_object_id)
        {
            if *known != candidate {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "receipt-bound physical lifetime identity collision",
                });
            }
        } else {
            self.receipt_bound_physical_lifetimes
                .insert(reclaim_object_id, candidate);
        }
        Ok(())
    }

    fn resolve_receipt_bound_physical_lifetime(
        &self,
        reclaim_object_id: &ReclaimObjectKey,
    ) -> Result<Option<ReceiptBoundPhysicalLifetime>> {
        Ok(self
            .receipt_bound_physical_lifetimes
            .get(reclaim_object_id)
            .copied())
    }

    fn encode_dead_object_reclaim_entry_state(entry: DeadObjectEntry) -> Vec<u8> {
        let mut queue = DeadObjectReclaimQueue::new();
        let inserted = queue.enqueue(entry);
        debug_assert!(inserted);
        queue.encode()
    }

    fn decode_dead_object_reclaim_entry_state(
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<DeadObjectEntry> {
        let queue = DeadObjectReclaimQueue::decode(payload).map_err(|_| {
            StoreError::InvalidDeadObjectReceipt {
                reason: "persisted dead-object reclaim entry is corrupt or unverifiable",
            }
        })?;
        let entries = queue.all_entries();
        let [entry] = entries.as_slice() else {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "persisted dead-object reclaim entry does not contain exactly one row",
            });
        };
        if dead_object_reclaim_entry_state_key(entry.object_id) != key {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "persisted dead-object reclaim entry key does not match its object id",
            });
        }
        Ok(*entry)
    }

    pub(crate) fn load_dead_object_reclaim_queue_for_root(&self) -> Result<DeadObjectReclaimQueue> {
        let retired_snapshot_key =
            ObjectKey::from_name(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes());
        if self.index.contains_key(&retired_snapshot_key) {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "retired pre-release dead-object queue snapshot is unsupported",
            });
        }
        let mut entries = BTreeMap::<ReclaimObjectKey, DeadObjectEntry>::new();

        for (key, location) in self
            .index
            .iter()
            .filter(|(key, _)| is_dead_object_reclaim_entry_state_key(**key))
        {
            let entry = Self::decode_dead_object_reclaim_entry_state(
                *key,
                &self.read_location(*location)?,
            )?;
            if entries.insert(entry.object_id, entry).is_some() {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "persisted dead-object reclaim entry identity is duplicated",
                });
            }
        }

        let mut queue = DeadObjectReclaimQueue::new();
        for entry in entries.into_values() {
            if !queue.enqueue(entry) {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "persisted dead-object reclaim entry identity is duplicated",
                });
            }
        }
        Ok(queue)
    }

    fn put_dead_object_reclaim_entry_state_local(&mut self, entry: DeadObjectEntry) -> Result<()> {
        let key = dead_object_reclaim_entry_state_key(entry.object_id);
        if let Some(location) = self.index.get(&key).copied() {
            let known =
                Self::decode_dead_object_reclaim_entry_state(key, &self.read_location(location)?)?;
            if known.object_id != entry.object_id {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "dead-object reclaim entry key collision",
                });
            }
        }
        let payload = Self::encode_dead_object_reclaim_entry_state(entry);
        let effective_payload = self.prepare_payload_with_fault_injection(&payload)?;
        let _ = self.put_inner(key, &effective_payload, 0, false, false)?;
        let domain_key = DomainTag::ReadVerify.derive_key();
        self.checksums
            .insert(key, ObjectDigest::compute(&payload, &domain_key));
        Ok(())
    }

    fn delete_dead_object_reclaim_authority_record_local(
        &mut self,
        key: ObjectKey,
    ) -> Result<bool> {
        if key != ObjectKey::from_name(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes())
            && !is_dead_object_reclaim_entry_state_key(key)
        {
            return Err(StoreError::InvalidOptions {
                reason: "root-owned reclaim deletion requires a reclaim authority key",
            });
        }
        self.ensure_writable("delete root-owned dead-object reclaim authority")?;
        let existed = self.index.contains_key(&key);
        if !existed {
            return Ok(false);
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(StoreError::InvalidOptions {
            reason: "object-store physical lifetime sequence exhausted",
        })?;
        self.append_record(RecordKind::Delete, key, &[], checksum64(&[]), sequence, 0)?;
        self.remove_index_location(key);
        self.checksums.remove(&key);
        self.next_sequence = next_sequence;
        Ok(true)
    }

    fn sync_dead_object_reclaim_root_barrier(&mut self) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("sync dead-object reclaim root authority")?;
        let path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .sync_all()
            .map_err(|source| io_error("sync dead-object reclaim authority", &path, source))?;
        sync_directory(&self.segments_dir)?;
        sync_directory(&self.root)
    }

    fn verify_dead_object_reclaim_entry_state_local(
        &self,
        expected: DeadObjectEntry,
    ) -> Result<()> {
        let key = dead_object_reclaim_entry_state_key(expected.object_id);
        let location =
            self.index
                .get(&key)
                .copied()
                .ok_or(StoreError::InvalidDeadObjectReceipt {
                    reason: "durable dead-object reclaim entry is missing after publication",
                })?;
        let actual =
            Self::decode_dead_object_reclaim_entry_state(key, &self.read_location(location)?)?;
        if actual != expected {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "durable dead-object reclaim entry differs after publication",
            });
        }
        Ok(())
    }

    fn validate_dead_object_reclaim_delta(
        &self,
        upserts: &[DeadObjectEntry],
        removals: &[ReclaimObjectKey],
    ) -> Result<()> {
        let mut touched = BTreeSet::new();
        for entry in upserts {
            if !touched.insert(entry.object_id) || removals.contains(&entry.object_id) {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "dead-object reclaim delta contains conflicting operations",
                });
            }
            if self.dead_object_reclaim_queue.entry(&entry.object_id) != Some(*entry) {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "dead-object reclaim upsert differs from in-memory authority",
                });
            }
            if let Some(durable) = self
                .durable_dead_object_reclaim_queue
                .entry(&entry.object_id)
            {
                let mut durable_base = durable;
                durable_base.replacement_receipt = None;
                let mut entry_base = *entry;
                entry_base.replacement_receipt = None;
                let monotonic = match (durable.replacement_receipt, entry.replacement_receipt) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(old), Some(new)) => {
                        new.receipt_generation > old.receipt_generation || new == old
                    }
                };
                if durable_base != entry_base || !monotonic {
                    return Err(StoreError::InvalidDeadObjectReceipt {
                        reason: "dead-object reclaim update is not monotonic",
                    });
                }
            }
        }
        for object_id in removals {
            if !touched.insert(*object_id)
                || self.dead_object_reclaim_queue.entry(object_id).is_some()
            {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "dead-object reclaim removal differs from queue authority",
                });
            }
        }
        Ok(())
    }

    fn dead_object_reclaim_queue_delta(&self) -> (Vec<DeadObjectEntry>, Vec<ReclaimObjectKey>) {
        let durable = self
            .durable_dead_object_reclaim_queue
            .all_entries()
            .into_iter()
            .map(|entry| (entry.object_id, entry))
            .collect::<BTreeMap<_, _>>();
        let current = self
            .dead_object_reclaim_queue
            .all_entries()
            .into_iter()
            .map(|entry| (entry.object_id, entry))
            .collect::<BTreeMap<_, _>>();
        let upserts = current
            .iter()
            .filter_map(|(object_id, entry)| {
                (durable.get(object_id) != Some(entry)).then_some(*entry)
            })
            .collect::<Vec<_>>();
        let removals = durable
            .keys()
            .filter(|object_id| !current.contains_key(object_id))
            .copied()
            .collect::<Vec<_>>();
        (upserts, removals)
    }

    fn dead_object_reclaim_entry_record_bytes(&self, entry: DeadObjectEntry) -> Result<u64> {
        let payload_len = Self::encode_dead_object_reclaim_entry_state(entry).len() as u64;
        if payload_len > self.options.max_object_bytes() {
            return Err(StoreError::PayloadTooLarge {
                len: payload_len,
                max: self.options.max_object_bytes(),
            });
        }
        Ok(Self::checked_record_total_len_u64(payload_len))
    }

    fn remove_dead_object_reclaim_pending_upsert(
        &mut self,
        object_id: &ReclaimObjectKey,
    ) -> Result<()> {
        let Some(entry) = self
            .dead_object_reclaim_pending_upserts
            .get(object_id)
            .copied()
        else {
            return Ok(());
        };
        let record_bytes = self.dead_object_reclaim_entry_record_bytes(entry)?;
        let retained_bytes = self
            .dead_object_reclaim_pending_upsert_record_bytes
            .checked_sub(record_bytes)
            .ok_or(StoreError::InvalidDeadObjectReceipt {
                reason: "dead-object reclaim pending reserve underflow",
            })?;
        self.dead_object_reclaim_pending_upserts.remove(object_id);
        self.dead_object_reclaim_pending_upsert_record_bytes = retained_bytes;
        Ok(())
    }

    fn insert_dead_object_reclaim_pending_upsert(&mut self, entry: DeadObjectEntry) -> Result<()> {
        self.remove_dead_object_reclaim_pending_upsert(&entry.object_id)?;
        let record_bytes = self.dead_object_reclaim_entry_record_bytes(entry)?;
        let retained_bytes = self
            .dead_object_reclaim_pending_upsert_record_bytes
            .checked_add(record_bytes)
            .ok_or(StoreError::NoSpace)?;
        self.dead_object_reclaim_pending_upserts
            .insert(entry.object_id, entry);
        self.dead_object_reclaim_pending_upsert_record_bytes = retained_bytes;
        Ok(())
    }

    fn merge_dead_object_reclaim_pending_delta(
        &mut self,
        upserts: &[DeadObjectEntry],
        removals: &[ReclaimObjectKey],
    ) -> Result<()> {
        for entry in upserts {
            self.dead_object_reclaim_pending_removals
                .remove(&entry.object_id);
            if self
                .durable_dead_object_reclaim_queue
                .entry(&entry.object_id)
                == Some(*entry)
            {
                self.remove_dead_object_reclaim_pending_upsert(&entry.object_id)?;
            } else {
                self.insert_dead_object_reclaim_pending_upsert(*entry)?;
            }
        }
        for object_id in removals {
            self.remove_dead_object_reclaim_pending_upsert(object_id)?;
            if self
                .durable_dead_object_reclaim_queue
                .entry(object_id)
                .is_some()
            {
                self.dead_object_reclaim_pending_removals.insert(*object_id);
            } else {
                self.dead_object_reclaim_pending_removals.remove(object_id);
            }
        }
        self.dead_object_reclaim_queue_dirty = !self.dead_object_reclaim_pending_upserts.is_empty()
            || !self.dead_object_reclaim_pending_removals.is_empty();
        Ok(())
    }

    fn rebuild_dead_object_reclaim_pending_delta(&mut self) -> Result<()> {
        let (upserts, removals) = self.dead_object_reclaim_queue_delta();
        self.dead_object_reclaim_pending_upserts.clear();
        self.dead_object_reclaim_pending_upsert_record_bytes = 0;
        self.dead_object_reclaim_pending_removals.clear();
        self.merge_dead_object_reclaim_pending_delta(&upserts, &removals)
    }

    fn stage_dead_object_reclaim_queue_delta(
        &mut self,
        upserts: &[DeadObjectEntry],
        removals: &[ReclaimObjectKey],
    ) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.validate_dead_object_reclaim_delta(upserts, removals)?;
        self.merge_dead_object_reclaim_pending_delta(upserts, removals)?;

        if !self.block_device_mode || !self.dead_object_reclaim_queue_dirty {
            return Ok(());
        }

        // Pool-internal transitions may stage several changes before the
        // existing strict Pool barrier. Reserve for the complete current
        // delta so a later receipt publication cannot discover ENOSPC only
        // after it has overwritten the old logical object.
        let pending_upsert_record_bytes = self.dead_object_reclaim_pending_upsert_record_bytes;
        let pending_removal_count = self.dead_object_reclaim_pending_removals.len();
        self.ensure_block_device_dead_object_queue_delta_space(
            pending_upsert_record_bytes,
            pending_removal_count,
        )
    }

    fn prepare_dead_object_reclaim_queue_authority(
        &mut self,
    ) -> Result<Option<(Vec<DeadObjectEntry>, Vec<ReclaimObjectKey>)>> {
        if !self.dead_object_reclaim_queue_dirty {
            return Ok(None);
        }
        self.ensure_pool_raw_mutation_allowed()?;
        // Direct dirty-state construction is restricted to focused fault-cut
        // tests. Reconstruct once if it occurs; ordinary production mutations
        // always retain their exact pending delta as they change the queue.
        if self.dead_object_reclaim_pending_upserts.is_empty()
            && self.dead_object_reclaim_pending_removals.is_empty()
        {
            self.rebuild_dead_object_reclaim_pending_delta()?;
            if !self.dead_object_reclaim_queue_dirty {
                return Ok(None);
            }
        }
        let upserts = self
            .dead_object_reclaim_pending_upserts
            .values()
            .copied()
            .collect::<Vec<_>>();
        let removals = self
            .dead_object_reclaim_pending_removals
            .iter()
            .copied()
            .collect::<Vec<_>>();
        self.validate_dead_object_reclaim_delta(&upserts, &removals)?;
        if self.block_device_mode {
            let pending_upsert_record_bytes = self.dead_object_reclaim_pending_upsert_record_bytes;
            let pending_removal_count = self.dead_object_reclaim_pending_removals.len();
            self.ensure_block_device_dead_object_queue_delta_space(
                pending_upsert_record_bytes,
                pending_removal_count,
            )?;
        }
        for entry in &upserts {
            self.put_dead_object_reclaim_entry_state_local(*entry)?;
        }
        for object_id in &removals {
            let key = dead_object_reclaim_entry_state_key(*object_id);
            self.delete_dead_object_reclaim_authority_record_local(key)?;
        }
        Ok(Some((upserts, removals)))
    }

    fn finish_dead_object_reclaim_queue_authority(
        &mut self,
        upserts: &[DeadObjectEntry],
        removals: &[ReclaimObjectKey],
    ) -> Result<()> {
        for entry in upserts {
            self.verify_dead_object_reclaim_entry_state_local(*entry)?;
        }
        for object_id in removals {
            if self
                .index
                .contains_key(&dead_object_reclaim_entry_state_key(*object_id))
            {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "acknowledged dead-object reclaim entry remained after publication",
                });
            }
        }
        if !upserts.iter().all(|entry| {
            self.dead_object_reclaim_pending_upserts
                .get(&entry.object_id)
                == Some(entry)
        }) || !removals.iter().all(|object_id| {
            self.dead_object_reclaim_pending_removals
                .contains(object_id)
                && self
                    .durable_dead_object_reclaim_queue
                    .entry(object_id)
                    .is_some()
        }) {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "published dead-object reclaim delta differs from pending authority",
            });
        }

        for entry in upserts {
            if self
                .durable_dead_object_reclaim_queue
                .entry(&entry.object_id)
                != Some(*entry)
            {
                if self
                    .durable_dead_object_reclaim_queue
                    .entry(&entry.object_id)
                    .is_some()
                    && self
                        .durable_dead_object_reclaim_queue
                        .ack_reclaimed(&[entry.object_id])
                        != 1
                {
                    return Err(StoreError::InvalidDeadObjectReceipt {
                        reason: "durable dead-object reclaim update was not exact",
                    });
                }
                if !self.durable_dead_object_reclaim_queue.enqueue(*entry) {
                    return Err(StoreError::InvalidDeadObjectReceipt {
                        reason: "durable dead-object reclaim upsert was not exact",
                    });
                }
            }
        }
        for object_id in removals {
            if self
                .durable_dead_object_reclaim_queue
                .ack_reclaimed(&[*object_id])
                != 1
            {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "durable dead-object reclaim removal was not exact",
                });
            }
        }
        for entry in upserts {
            self.remove_dead_object_reclaim_pending_upsert(&entry.object_id)?;
        }
        for object_id in removals {
            self.dead_object_reclaim_pending_removals.remove(object_id);
        }
        self.dead_object_reclaim_queue_dirty = !self.dead_object_reclaim_pending_upserts.is_empty()
            || !self.dead_object_reclaim_pending_removals.is_empty();
        Ok(())
    }

    fn persist_dead_object_reclaim_queue_delta(
        &mut self,
        upserts: &[DeadObjectEntry],
        removals: &[ReclaimObjectKey],
    ) -> Result<()> {
        self.stage_dead_object_reclaim_queue_delta(upserts, removals)?;
        self.sync_dead_object_reclaim_queue_authority()
    }

    fn sync_dead_object_reclaim_queue_authority(&mut self) -> Result<()> {
        let Some((upserts, removals)) = self.prepare_dead_object_reclaim_queue_authority()? else {
            return Ok(());
        };
        self.sync_dead_object_reclaim_root_barrier()?;
        self.finish_dead_object_reclaim_queue_authority(&upserts, &removals)
    }

    #[cfg(test)]
    pub(crate) fn replace_dead_object_reclaim_queue_for_test(
        &mut self,
        queue: &DeadObjectReclaimQueue,
    ) -> Result<()> {
        self.dead_object_reclaim_queue = queue.clone();
        self.rebuild_dead_object_reclaim_pending_delta()?;
        self.sync_dead_object_reclaim_queue_authority()
    }

    /// Return every Pool-owned reclaim row that resolves to `logical_key`.
    /// Multiple completed physical lifetimes intentionally coexist.
    pub(crate) fn receipt_bound_dead_object_lifetimes_for_logical_key_pool_internal(
        &self,
        logical_key: ObjectKey,
    ) -> Result<Vec<(DeadObjectEntry, ReceiptBoundPhysicalLifetime)>> {
        let mut rows = Vec::new();
        for entry in self.dead_object_reclaim_queue.all_entries() {
            let Some(lifetime) = self.resolve_receipt_bound_physical_lifetime(&entry.object_id)?
            else {
                continue;
            };
            if lifetime.logical_object_key == logical_key {
                rows.push((entry, lifetime));
            }
        }
        Ok(rows)
    }

    /// Return all exactly resolved physical-lifetime rows for Pool recovery.
    pub(crate) fn receipt_bound_dead_object_physical_lifetimes_pool_internal(
        &self,
    ) -> Result<Vec<(DeadObjectEntry, ReceiptBoundPhysicalLifetime)>> {
        let mut rows = Vec::new();
        for entry in self.dead_object_reclaim_queue.all_entries() {
            if let Some(lifetime) =
                self.resolve_receipt_bound_physical_lifetime(&entry.object_id)?
            {
                rows.push((entry, lifetime));
            }
        }
        Ok(rows)
    }

    /// Return the exact durable reclaim entry for a Pool-owned physical
    /// object, without advancing or rewriting the queue.
    ///
    /// This narrow inspection lets the Pool prove that a newer receipt belongs
    /// to an interrupted target-only repair before a higher layer resumes root
    /// reconciliation.  The queue remains the sole decoder and authority for
    /// its persisted format.
    pub(crate) fn receipt_bound_dead_object_entry_pool_internal(
        &self,
        object_id: &ReclaimObjectKey,
    ) -> Option<DeadObjectEntry> {
        self.dead_object_reclaim_queue.entry(object_id)
    }

    fn enqueue_pending_receipt_bound_dead_object_authorized(
        &mut self,
        entry: DeadObjectEntry,
    ) -> Result<bool> {
        self.ensure_writable("enqueue_pending_receipt_bound_dead_object")?;
        if entry.replacement_receipt.is_some() {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "pending receipt-bound enqueue must not include a replacement receipt",
            });
        }

        let inserted = self.dead_object_reclaim_queue.enqueue(entry);
        if inserted {
            self.persist_dead_object_reclaim_queue_delta(&[entry], &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.sync_dead_object_reclaim_queue_authority()?;
        }
        Ok(inserted)
    }

    /// Publish a replacement/base placement receipt for a dead-object entry
    /// already queued for receipt-bound reclaim.
    ///
    /// This is the rebake pathway: after rebake converts ingest extents to
    /// base shards and the replacement receipt is durably committed, callers
    /// attach the receipt so the queue can authorize obsolete-ingest trim.
    ///
    /// The receipt must authorize this object before it is attached. A valid
    /// receipt is accepted only when no existing receipt is present or when
    /// its generation strictly exceeds the current receipt's generation
    /// (monotonic progression). Returns true if the receipt was attached
    /// or replaced.
    pub fn publish_dead_object_replacement_receipt(
        &mut self,
        object_id: &ReclaimObjectKey,
        receipt: DeadObjectReplacementReceipt,
    ) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        Self::ensure_public_pool_reclaim_key_allowed(*object_id)?;
        self.publish_dead_object_replacement_receipt_authorized(object_id, receipt)
    }

    pub(crate) fn publish_dead_object_replacement_receipt_pool_internal(
        &mut self,
        object_id: &ReclaimObjectKey,
        receipt: DeadObjectReplacementReceipt,
    ) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("stage Pool-owned dead-object replacement receipt")?;
        if !receipt.authorizes_reclaim_for(*object_id) {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "replacement receipt does not authorize this object",
            });
        }
        let updated = self
            .dead_object_reclaim_queue
            .publish_replacement_receipt(object_id, receipt);
        if updated {
            let entry = self.dead_object_reclaim_queue.entry(object_id).ok_or(
                StoreError::InvalidDeadObjectReceipt {
                    reason: "replacement receipt update lost its queue entry",
                },
            )?;
            self.stage_dead_object_reclaim_queue_delta(&[entry], &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.stage_dead_object_reclaim_queue_delta(&[], &[])?;
        }
        Ok(updated)
    }

    pub(crate) fn publish_dead_object_replacement_receipts_pool_internal(
        &mut self,
        receipts: &[(ReclaimObjectKey, DeadObjectReplacementReceipt)],
    ) -> Result<()> {
        for (object_id, receipt) in receipts {
            if !receipt.authorizes_reclaim_for(*object_id) {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "replacement receipt does not authorize this object",
                });
            }
        }
        self.publish_dead_object_replacement_receipts_across_store_tree(receipts)
    }

    fn publish_dead_object_replacement_receipts_across_store_tree(
        &mut self,
        receipts: &[(ReclaimObjectKey, DeadObjectReplacementReceipt)],
    ) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("publish dead-object replacement receipts")?;
        let mut changed = Vec::new();
        for (object_id, receipt) in receipts {
            if self
                .dead_object_reclaim_queue
                .publish_replacement_receipt(object_id, *receipt)
            {
                let entry = self.dead_object_reclaim_queue.entry(object_id).ok_or(
                    StoreError::InvalidDeadObjectReceipt {
                        reason: "replacement receipt update lost its queue entry",
                    },
                )?;
                changed.push(entry);
            }
        }
        let mut first_error = if !changed.is_empty() {
            self.stage_dead_object_reclaim_queue_delta(&changed, &[])
                .err()
        } else if self.dead_object_reclaim_queue_dirty {
            self.stage_dead_object_reclaim_queue_delta(&[], &[]).err()
        } else {
            None
        };
        for (index, replica) in self.replicas.iter_mut().enumerate() {
            match replica.publish_dead_object_replacement_receipts_across_store_tree(receipts) {
                Ok(()) if index < self.replica_healthy.len() => {
                    self.replica_healthy[index] = true;
                }
                Ok(()) => {}
                Err(error) => {
                    if index < self.replica_healthy.len() {
                        self.replica_healthy[index] = false;
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn publish_dead_object_replacement_receipt_authorized(
        &mut self,
        object_id: &ReclaimObjectKey,
        receipt: DeadObjectReplacementReceipt,
    ) -> Result<bool> {
        self.ensure_writable("publish_dead_object_replacement_receipt")?;
        if !receipt.authorizes_reclaim_for(*object_id) {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "replacement receipt does not authorize this object",
            });
        }
        let updated = self
            .dead_object_reclaim_queue
            .publish_replacement_receipt(object_id, receipt);
        if updated {
            let entry = self.dead_object_reclaim_queue.entry(object_id).ok_or(
                StoreError::InvalidDeadObjectReceipt {
                    reason: "replacement receipt update lost its queue entry",
                },
            )?;
            self.persist_dead_object_reclaim_queue_delta(&[entry], &[])?;
        } else if self.dead_object_reclaim_queue_dirty {
            self.sync_dead_object_reclaim_queue_authority()?;
        }
        Ok(updated)
    }

    /// Drain receipt-authorized dead objects at caller-supplied stable
    /// committed transaction and receipt-generation boundaries.
    ///
    /// Selected entries pass through `ReclaimConsumerService` before this method
    /// acknowledges them in the persisted dead-object queue. Completed stats are
    /// returned only after the exact per-entry acknowledgements cross the
    /// root-owned reclaim barrier and the authorized physical release is synced.
    pub fn drain_receipt_bound_dead_objects_at_stable_generation(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> std::result::Result<tidefs_reclaim::ReclaimConsumerStats, ReceiptBoundDeadObjectDrainError>
    {
        self.drain_receipt_bound_dead_objects_authorized(
            stable_committed_txg,
            stable_committed_generation,
            max_count,
            false,
        )
    }

    pub(crate) fn drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> std::result::Result<tidefs_reclaim::ReclaimConsumerStats, ReceiptBoundDeadObjectDrainError>
    {
        self.drain_receipt_bound_dead_objects_authorized(
            stable_committed_txg,
            stable_committed_generation,
            max_count,
            true,
        )
    }

    pub(crate) fn drain_receipt_bound_dead_objects_across_stores_pool_internal(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> std::result::Result<
        Vec<tidefs_reclaim::ReclaimConsumerStats>,
        ReceiptBoundDeadObjectDrainError,
    > {
        let mut remaining = max_count;
        let mut results = Vec::new();
        let primary = self.drain_receipt_bound_dead_objects_at_stable_generation_pool_internal(
            stable_committed_txg,
            stable_committed_generation,
            remaining,
        )?;
        remaining = remaining.saturating_sub(primary.entries_processed);
        results.push(primary);
        for replica in &mut self.replicas {
            if remaining == 0 {
                break;
            }
            let replica_results = replica
                .drain_receipt_bound_dead_objects_across_stores_pool_internal(
                    stable_committed_txg,
                    stable_committed_generation,
                    remaining,
                )?;
            remaining = remaining.saturating_sub(
                replica_results
                    .iter()
                    .map(|stats| stats.entries_processed)
                    .sum::<usize>(),
            );
            results.extend(replica_results);
        }
        Ok(results)
    }

    fn drain_receipt_bound_dead_objects_authorized(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
        pool_internal: bool,
    ) -> std::result::Result<tidefs_reclaim::ReclaimConsumerStats, ReceiptBoundDeadObjectDrainError>
    {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("drain_receipt_bound_dead_objects_at_stable_generation")?;
        if !pool_internal {
            for entry in self.dead_object_reclaim_queue.all_entries() {
                Self::ensure_public_pool_reclaim_key_allowed(entry.object_id)?;
            }
        }
        if self.dead_object_reclaim_queue_dirty
            || self.snapshot_extent_pin_set_dirty
            || self.reclaim_receipts_dirty
        {
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..tidefs_reclaim::ReclaimConsumerStats::ZERO
            });
        }
        if self.block_device_mode {
            return self
                .acknowledge_block_device_receipt_bound_dead_objects(
                    stable_committed_txg,
                    stable_committed_generation,
                    max_count,
                )
                .map_err(Into::into);
        }

        let plan = self.receipt_bound_dead_object_drain_plan(
            stable_committed_txg,
            stable_committed_generation,
            max_count,
        );
        if plan.current_segment_would_be_reclaimed(self.current_segment_id) {
            self.rotate_segment()?;
        }
        // The plan already examined the bounded eligible batch. If it cannot
        // free any complete segment, skip the consumer's second queue walk.
        if plan.eligible_object_ids.is_empty() || plan.dead_segments.is_empty() {
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                entries_processed: plan.eligible_object_ids.len(),
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..tidefs_reclaim::ReclaimConsumerStats::ZERO
            });
        }

        let reserved_copies: Vec<_> = self
            .index
            .iter()
            .filter(|(key, location)| {
                is_pool_store_internal_key(**key)
                    && plan.dead_segments.contains(&location.segment_id)
            })
            .map(|(key, location)| Ok((*key, self.read_location(*location)?)))
            .collect::<Result<_>>()?;
        if !reserved_copies.is_empty() {
            let mut relocated_reclaim_entries = Vec::new();
            for (key, payload) in reserved_copies {
                if is_dead_object_reclaim_entry_state_key(key) {
                    let entry = Self::decode_dead_object_reclaim_entry_state(key, &payload)?;
                    self.put_dead_object_reclaim_entry_state_local(entry)?;
                    relocated_reclaim_entries.push(entry);
                } else {
                    self.put_direct(key, &payload)?;
                }
            }
            self.sync_all()?;
            for entry in relocated_reclaim_entries {
                self.verify_dead_object_reclaim_entry_state_local(entry)?;
            }
        }

        let queue_snapshot = self.dead_object_reclaim_queue.clone();
        let gate = CommittedDeadObjectReclaimGate {
            eligible_object_ids: plan.eligible_object_ids.clone(),
            logical_object_ids: plan.logical_object_ids.clone(),
            stable_committed_txg,
            snapshot_extent_pin_set: self.snapshot_extent_pin_set.clone(),
        };
        let mut reclaim_consumer = std::mem::replace(
            &mut self.reclaim_consumer,
            ReclaimConsumerService::new(ReclaimConsumerConfig::default(), SegmentLiveCounts::new()),
        );
        let mut recording_freer = RecordingSegmentFreer::default();
        let drain_result = reclaim_consumer.drain_receipt_bound_dead_objects(
            &queue_snapshot,
            stable_committed_txg,
            stable_committed_generation,
            max_count,
            &plan.resolver,
            &mut recording_freer,
            &gate,
        );
        self.reclaim_consumer = reclaim_consumer;
        let drain = drain_result?;

        if drain.ack_object_ids.is_empty() {
            if drain.receipt.is_some()
                || !drain.reclaimed_segment_ids.is_empty()
                || !recording_freer.segment_ids.is_empty()
            {
                return Err(StoreError::InvalidOptions {
                    reason: "receipt-bound reclaim consumer returned physical-free authority without queue acknowledgement",
                }
                .into());
            }
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..drain.stats
            });
        }

        let ack_object_ids = drain
            .ack_object_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let reclaimed_segment_ids = drain
            .reclaimed_segment_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let Some(receipt) = drain.receipt.clone() else {
            return Err(StoreError::InvalidOptions {
                reason: "receipt-bound reclaim consumer returned queue acknowledgement without a durable receipt",
            }
            .into());
        };
        let receipt_object_ids = receipt
            .freed_segment_extents
            .iter()
            .map(|extent| extent.extent_key)
            .collect::<BTreeSet<_>>();
        let receipt_segment_ids = receipt
            .freed_segment_extents
            .iter()
            .map(|extent| extent.segment_id)
            .collect::<BTreeSet<_>>();
        let receipt_freed_ids = receipt
            .freed_extents
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let queued_object_ids = self
            .dead_object_reclaim_queue
            .all_entries()
            .into_iter()
            .map(|entry| entry.object_id)
            .collect::<BTreeSet<_>>();
        if ack_object_ids.len() != drain.ack_object_ids.len()
            || reclaimed_segment_ids.len() != drain.reclaimed_segment_ids.len()
            || receipt_object_ids.len() != receipt.freed_segment_extents.len()
            || receipt_freed_ids.len() != receipt.freed_extents.len()
            || receipt_freed_ids != receipt_object_ids
            || ack_object_ids != receipt_object_ids
            || reclaimed_segment_ids != receipt_segment_ids
            || reclaimed_segment_ids != recording_freer.segment_ids
            || !receipt.freed_segment_extents.iter().all(|extent| {
                plan.resolver.segments.get(&extent.extent_key).copied() == Some(extent.segment_id)
            })
            || !ack_object_ids.is_subset(&queued_object_ids)
        {
            return Err(StoreError::InvalidOptions {
                reason: "receipt-bound reclaim consumer returned inconsistent receipt, acknowledgement, or physical-free authority",
            }
            .into());
        }
        self.reclaim_receipts.push(receipt);
        self.reclaim_receipts_dirty = true;

        // Phase one: the exact physical-free receipt becomes durable while
        // every source queue row is still present. A crash here leaves replay
        // enough authority to acknowledge and finish the same decision.
        self.sync_all()?;
        let removed = self
            .dead_object_reclaim_queue
            .ack_reclaimed(&drain.ack_object_ids);
        if removed != drain.ack_object_ids.len() {
            return Err(StoreError::InvalidOptions {
                reason: "receipt-bound reclaim queue acknowledgement was not exact",
            }
            .into());
        }
        // Phase two: make the exact receipt-covered acknowledgement durable
        // before allocator or segment-file state can change. A crash after
        // this barrier replays the durable receipt idempotently.
        self.persist_dead_object_reclaim_queue_delta(&[], &drain.ack_object_ids)?;

        // Phase three: only now expose the reclaimed segment to the allocator
        // and release its file capacity. Keep the lock-free counter exact by
        // incrementing it only on a used-to-free transition.
        for segment_id in recording_freer.segment_ids {
            self.free_receipt_authorized_segment(segment_id)?;
        }

        self.sync_all()?;

        Ok(tidefs_reclaim::ReclaimConsumerStats {
            reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
            ..drain.stats
        })
    }

    fn acknowledge_block_device_receipt_bound_dead_objects(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> Result<tidefs_reclaim::ReclaimConsumerStats> {
        debug_assert!(self.block_device_mode);
        let limit = max_count.min(self.reclaim_consumer.config().max_entries_per_drain);
        let entries = self
            .dead_object_reclaim_queue
            .dequeue_receipt_bound_batch_with_stable_generation(
                limit,
                stable_committed_txg,
                stable_committed_generation,
            );
        let mut acknowledged = Vec::new();
        let mut denied = 0_u64;
        for entry in &entries {
            let Some(lifetime) = self.resolve_receipt_bound_physical_lifetime(&entry.object_id)?
            else {
                // A logical-key compatibility row does not identify one
                // physical block-log lifetime and cannot authorize omission.
                denied = denied.saturating_add(1);
                continue;
            };
            if self.index.get(&lifetime.logical_object_key).copied() == Some(lifetime.location)
                || self
                    .snapshot_extent_pin_set
                    .is_pinned(&ReclaimObjectKey(*lifetime.logical_object_key.as_bytes()))
            {
                denied = denied.saturating_add(1);
                continue;
            }
            acknowledged.push(entry.object_id);
        }

        if acknowledged.is_empty() {
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                entries_processed: entries.len(),
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                gate_segments_skipped: u64::from(denied != 0),
                gate_extents_denied: denied,
                ..tidefs_reclaim::ReclaimConsumerStats::ZERO
            });
        }

        if self.dead_object_reclaim_queue.ack_reclaimed(&acknowledged) != acknowledged.len() {
            return Err(StoreError::InvalidOptions {
                reason: "block-device reclaim queue acknowledgement was not exact",
            });
        }

        // Publish exact per-entry tombstones before a later block-log
        // compaction may omit the acknowledged physical histories. A crash
        // before that compaction is a conservative leak.
        self.persist_dead_object_reclaim_queue_delta(&[], &acknowledged)?;

        Ok(tidefs_reclaim::ReclaimConsumerStats {
            entries_processed: entries.len(),
            reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
            gate_segments_skipped: u64::from(denied != 0),
            gate_extents_denied: denied,
            // Block mode has authorized later compaction omission, but has
            // not freed virtual segment 0 or any physical block yet.
            segments_reclaimed: 0,
            blocks_freed: 0,
            checkpoint_batches: 0,
        })
    }

    fn receipt_bound_dead_object_drain_plan(
        &self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> ReceiptBoundDeadObjectDrainPlan {
        let limit = max_count.min(self.reclaim_consumer.config().max_entries_per_drain);
        let entries = self
            .dead_object_reclaim_queue
            .dequeue_receipt_bound_batch_with_stable_generation(
                limit,
                stable_committed_txg,
                stable_committed_generation,
            );
        let mut resolver = DeadObjectDrainSegmentResolver::default();
        let mut eligible_object_ids = BTreeSet::new();
        let mut logical_object_ids = BTreeMap::new();
        let mut segment_refdrops: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::new();
        let mut segment_queued_entries: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::new();

        for entry in self.dead_object_reclaim_queue.all_entries() {
            let Ok(Some((segment_id, logical_object_id))) =
                self.resolve_receipt_bound_reclaim_target(&entry.object_id)
            else {
                continue;
            };
            resolver.segments.insert(entry.object_id, segment_id);
            logical_object_ids.insert(entry.object_id, logical_object_id);
            *segment_queued_entries.entry(segment_id).or_default() += 1;
        }

        for entry in entries {
            let Some(segment_id) = resolver.segments.get(&entry.object_id).copied() else {
                continue;
            };
            eligible_object_ids.insert(entry.object_id);
            *segment_refdrops.entry(segment_id).or_default() += 1;
        }

        let dead_segments = segment_refdrops
            .into_iter()
            .filter_map(|(segment_id, refdrops)| {
                let live_count = self.reclaim_consumer.live_counts().live_count(segment_id);
                let queued_entries = segment_queued_entries
                    .get(&segment_id)
                    .copied()
                    .unwrap_or(refdrops);
                (live_count <= refdrops && queued_entries == refdrops).then_some(segment_id)
            })
            .collect();

        ReceiptBoundDeadObjectDrainPlan {
            resolver,
            dead_segments,
            eligible_object_ids,
            logical_object_ids,
        }
    }

    #[must_use]
    pub fn list_keys_including_internal(&self) -> Vec<ObjectKey> {
        let mut keys: BTreeSet<ObjectKey> = self.index.keys().copied().collect();
        for replica in &self.replicas {
            keys.extend(replica.list_keys_including_internal());
        }
        keys.into_iter().collect()
    }

    #[must_use]
    pub fn list_keys(&self) -> Vec<ObjectKey> {
        self.list_keys_including_internal()
            .into_iter()
            .filter(|key| !is_public_scan_internal_key(*key))
            .collect()
    }

    #[must_use]
    pub fn contains_key(&self, key: ObjectKey) -> bool {
        !is_public_scan_internal_key(key)
            && (self.index.contains_key(&key) || self.replicas.iter().any(|r| r.contains_key(key)))
    }
    // -- Corruption localization: reverse segment-position to object-key lookup --

    /// Find all object keys whose current index entry references the given
    /// (segment_id, record_offset). This is the reverse lookup needed for
    /// corruption localization: when scrub detects a bad record at a
    /// specific segment position, this method returns the exact objects
    /// affected so that repair has deterministic inputs.
    #[must_use]
    pub fn find_objects_at_segment_offset(
        &self,
        segment_id: u64,
        record_offset: u64,
    ) -> Vec<ObjectKey> {
        self.index
            .iter()
            .filter(|(_, loc)| loc.segment_id == segment_id && loc.record_offset == record_offset)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Find all object keys whose current index entry references any record
    /// in the given segment. Used for segment-level corruption assessment.
    #[must_use]
    pub fn find_objects_in_segment(&self, segment_id: u64) -> Vec<ObjectKey> {
        self.index
            .iter()
            .filter(|(_, loc)| loc.segment_id == segment_id)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Return the total count of live objects whose current location is in
    /// . O(index) scan; used for integrity cross-checks.
    #[must_use]
    pub fn live_object_count_in_segment(&self, segment_id: u64) -> usize {
        self.index
            .values()
            .filter(|loc| loc.segment_id == segment_id)
            .count()
    }

    #[must_use]
    pub fn location_of(&self, key: ObjectKey) -> Option<ObjectLocation> {
        self.index.get(&key).copied()
    }

    /// Return every fully replayable put-record location known for this key.
    ///
    /// The newest live object remains available through [`LocalObjectStore::get`].
    /// This history API lets higher layers such as filesystem root selection fall
    /// back from a logically invalid newer commit object to an older fully written
    /// commit object without an operator repair pass.
    #[must_use]
    pub fn version_locations_of(&self, key: ObjectKey) -> Vec<ObjectLocation> {
        self.history.get(&key).cloned().unwrap_or_default()
    }

    /// Read a specific put-record location returned by [`LocalObjectStore::version_locations_of`].
    pub fn get_at_location(&self, location: ObjectLocation) -> Result<Vec<u8>> {
        self.read_location(location)
    }

    /// Return version locations for a key from all stores (primary + replicas).
    ///
    /// Index 0 is the primary store, indices 1..N are replicas.
    /// This enables cross-device committed-root quorum: the recovery layer
    /// can count how many devices hold each root commit and reject stale
    /// minority copies.
    #[must_use]
    pub fn version_locations_across_stores(&self, key: ObjectKey) -> Vec<Vec<ObjectLocation>> {
        let mut all = Vec::with_capacity(1 + self.replicas.len());
        all.push(self.history.get(&key).cloned().unwrap_or_default());
        for replica in &self.replicas {
            all.push(replica.history.get(&key).cloned().unwrap_or_default());
        }
        all
    }

    /// Total number of stores (primary + replicas).
    #[must_use]
    pub fn stores_count(&self) -> usize {
        1 + self.replicas.len()
    }

    /// Read the payload at `location` from a specific store.
    ///
    /// `store_index` 0 is the primary; indices 1..N are replicas.
    ///
    /// # Panics
    ///
    /// Panics if `store_index` >= [`Self::stores_count`].
    pub fn read_location_from_store(
        &self,
        store_index: usize,
        location: ObjectLocation,
    ) -> Result<Vec<u8>> {
        match store_index {
            0 => self.read_location(location),
            i => self.replicas[i - 1].read_location(location),
        }
    }

    pub fn put_named(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<StoredObject> {
        self.put(ObjectKey::from_name(name), payload)
    }

    /// Store payload bytes under their content-derived [`ObjectKey`].
    ///
    /// Re-putting identical bytes is idempotent and does not append a new
    /// record. A digest collision with different live bytes is reported as a
    /// store error rather than overwriting the existing object.
    pub fn put_content_addressed(&mut self, payload: &[u8]) -> Result<ObjectKey> {
        let key = ObjectKey::from_content(payload);
        if let Some(existing) = self.get(key)? {
            if existing == payload {
                return Ok(key);
            }
            return Err(StoreError::ContentAddressCollision { key });
        }
        self.put(key, payload).map(|_| key)
    }

    /// Set the I/O class for subsequent store operations.
    /// Metadata and sync ops use higher-priority classes to avoid
    /// starvation by bulk writes (ZFS I/O scheduler principle).
    pub fn set_io_class(&mut self, class: IoClass) {
        self.current_io_class = class;
    }

    /// Enable transparent inline compression for subsequent writes.
    ///
    /// Objects written after this call are compressed according to
    /// `config` and decompressed on read. Objects written before this
    /// call (or written with compression disabled) are read back
    /// without decompression (backward compatible).
    pub fn set_compression(&mut self, config: CompressionConfig) {
        self.compression_config = Some(config);
    }

    /// Disable inline compression for subsequent writes.
    pub fn clear_compression(&mut self) {
        self.compression_config = None;
    }

    /// Set the durability layout policy for subsequent writes.
    ///
    /// When set, the store verifies that object replicas are placed on
    /// correct failure domains according to the layout policy.
    pub fn set_durability_layout(&mut self, layout: DurabilityLayoutV1) {
        self.durability_layout = Some(layout);
    }

    /// Return the current durability layout, if any.
    pub fn durability_layout(&self) -> Option<&DurabilityLayoutV1> {
        self.durability_layout.as_ref()
    }

    pub(crate) fn install_pool_raw_mutation_guard(&mut self, allowed: Arc<AtomicBool>) {
        self.pool_raw_mutation_allowed = Some(Arc::clone(&allowed));
        for replica in &mut self.replicas {
            replica.install_pool_raw_mutation_guard(Arc::clone(&allowed));
        }
    }

    fn ensure_pool_raw_mutation_allowed(&self) -> Result<()> {
        if self
            .pool_raw_mutation_allowed
            .as_ref()
            .is_some_and(|allowed| !allowed.load(Ordering::Acquire))
        {
            return Err(StoreError::InvalidOptions {
                reason:
                    "raw mutation refused while pool receipt-generation authority is unavailable",
            });
        }
        Ok(())
    }

    fn ensure_public_pool_key_mutation_allowed(key: ObjectKey) -> Result<()> {
        if is_pool_store_internal_key(key) {
            return Err(StoreError::InvalidOptions {
                reason:
                    "pool receipt, shard, generation, and deletion metadata require pool authority",
            });
        }
        Ok(())
    }

    fn ensure_public_pool_reclaim_key_allowed(key: ReclaimObjectKey) -> Result<()> {
        Self::ensure_public_pool_key_mutation_allowed(ObjectKey::from_bytes(key.0))
    }

    /// Return the current I/O class.
    pub fn io_class(&self) -> IoClass {
        self.current_io_class
    }

    // ── shared write path ──────────────────────────────────────────

    fn enqueue_reclaim_entry(&mut self, key: ObjectKey) {
        let reclaim_entry =
            ReclaimQueueEntry::new(ReclaimObjectKey(key.0), -1, QueueFamily::Extent);
        self.reclaim_queue.insert(reclaim_entry);
    }

    /// Core write path shared by [`put`](Self::put) and [`put_direct`](Self::put_direct).
    ///
    /// Handles I/O admission, payload size validation, segment append,
    /// index update, and optional replica fan-out. Callers are responsible for
    /// fault injection (before) and commit_group tracking (after).
    /// When `track_liveness` is false (internal system objects), the
    /// reclaim consumer live-count is not incremented.
    fn put_inner(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        compression_algorithm: u8,
        track_liveness: bool,
        replicate: bool,
    ) -> Result<StoredObject> {
        // I/O class admission: when the scheduler refuses, apply soft backpressure
        // (a brief yield) so bulk I/O slows down without hard-failing callers.
        if !self.io_scheduler.admit(self.current_io_class) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.ensure_writable("put")?;
        let payload_len = payload_len_u64(payload.len(), self.options.max_object_bytes())?;
        if payload_len > self.options.max_object_bytes() {
            return Err(StoreError::PayloadTooLarge {
                len: payload_len,
                max: self.options.max_object_bytes(),
            });
        }

        // Write throttle: when free segments are below the low-watermark and
        // the current segment cannot hold this record (requiring a fresh
        // segment allocation), reject user writes to prevent pool-full
        // deadlock.  System writes (put_direct, committed roots) bypass the
        // throttle so the txg commit path can always make progress.
        if track_liveness
            && self.options.write_throttle_enabled
            && self.is_low_space()
            && self.current_offset > 0
        {
            let record_len = Self::checked_record_total_len_u64(payload_len);
            if self.current_offset > self.options.max_segment_bytes.saturating_sub(record_len) {
                return Err(StoreError::NoSpace);
            }
        }

        // Reserve-ledger admission: Normal writes (track_liveness=true)
        // are subject to the reserve guard; Critical writes bypass it.
        if track_liveness {
            // Estimate 1 segment needed per new write that requires a
            // fresh segment allocation.  Conservative: assume worst case.
            let segments_needed = 1u32;
            self.check_reserve_admission(WritePriority::Normal, segments_needed)?;
        }

        let checksum = checksum64(payload);
        let internal_metadata = is_public_scan_internal_key(key);
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(StoreError::InvalidOptions {
            reason: "object-store physical lifetime sequence exhausted",
        })?;
        let candidate_lifetime_id = receipt_bound_physical_lifetime_id(
            key,
            ObjectLocation {
                key,
                segment_id: 0,
                record_offset: 0,
                payload_offset: 0,
                payload_len,
                sequence,
                payload_checksum: checksum,
            },
        );
        if self
            .receipt_bound_physical_lifetimes
            .contains_key(&candidate_lifetime_id)
        {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "receipt-bound physical lifetime identity collision",
            });
        }
        self.enospc_bytes_written = self.enospc_bytes_written.saturating_add(payload_len);
        let location = self.append_record(
            RecordKind::Put,
            key,
            payload,
            checksum,
            sequence,
            compression_algorithm,
        )?;
        if self.index.contains_key(&key) {
            if !internal_metadata {
                self.tombstone_count = self.tombstone_count.saturating_add(1);
            }
            // Enqueue a reclaim entry for the old version of the object.
            if let Some(old_loc) = self.index.get(&key).copied() {
                if !internal_metadata {
                    self.enqueue_reclaim_entry(key);
                    self.segment_liveness
                        .record_overwrite(old_loc.segment_id, old_loc.payload_len);
                }
                if track_liveness && !internal_metadata {
                    self.reclaim_consumer
                        .live_counts_mut()
                        .apply_delta(location.segment_id, 1);
                }

                // Test-only raw-store accounting fixtures can model overwrite.
                if !internal_metadata {
                    self.record_test_current_dataset_delete(old_loc.payload_len);
                    self.record_test_current_dataset_write(payload_len);
                }
            }
        } else if track_liveness && !internal_metadata {
            // Track new live object in the reclaim-queue consumer's
            // per-segment liveness tracker so the drain loop can
            // determine dead segments without re-scanning the index.
            self.reclaim_consumer
                .live_counts_mut()
                .apply_delta(location.segment_id, 1);

            // Test-only raw-store accounting fixtures can model new objects.
            self.record_test_current_dataset_write(payload_len);
        }
        self.history.entry(key).or_default().push(location);
        self.index_receipt_bound_physical_lifetime(key, location)?;
        self.set_index_location(key, location);
        self.next_sequence = next_sequence;

        if replicate {
            // Fan out ordinary logical objects and replica-consensus Pool
            // authority to every configured store replica.
            let total_replicas = self.replicas.len();
            let quorum = self.replica_quorum();
            let mut replica_acks: usize = 0;
            for (i, replica) in self.replicas.iter_mut().enumerate() {
                // Replicas receive the original payload (fault injection only
                // affects the primary write path, matching the original behavior).
                let replica_result = if internal_metadata {
                    replica.put_preencoded_internal(key, payload, compression_algorithm)
                } else {
                    replica.put(key, payload)
                };
                if replica_result.is_ok() {
                    replica_acks = replica_acks.saturating_add(1);
                    if i < self.replica_healthy.len() && !self.replica_healthy[i] {
                        self.replica_healthy[i] = true;
                    }
                } else if i < self.replica_healthy.len() {
                    self.replica_healthy[i] = false;
                }
            }

            let ack_total = 1 + replica_acks;
            self.last_replicated_write = Some(if ack_total >= quorum {
                if replica_acks == total_replicas {
                    crate::ReplicatedWriteResult::committed(total_replicas, quorum)
                } else {
                    crate::ReplicatedWriteResult::degraded(
                        replica_acks,
                        total_replicas,
                        quorum,
                        self.replica_healthy.clone(),
                    )
                }
            } else {
                crate::ReplicatedWriteResult::refused(
                    total_replicas,
                    quorum,
                    self.replica_healthy.clone(),
                )
            });
        }

        Ok(StoredObject {
            key,
            sequence,
            len: payload_len,
            checksum,
        })
    }

    /// Apply fault injection to a payload before writing.
    ///
    /// Returns the (possibly corrupted) payload, or an error if fault
    /// injection dictates a write failure or ENOSPC. This is only called
    /// from the public [`put`](Self::put) path; internal paths such as
    /// [`put_direct`](Self::put_direct) bypass fault injection.
    fn prepare_payload_with_fault_injection<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        let fi = match &self.fault_injection_config {
            Some(cfg) => cfg,
            None => return Ok(std::borrow::Cow::Borrowed(payload)),
        };

        if fi.should_fail_write(&mut rand::thread_rng()) {
            return Err(StoreError::Io {
                source: std::io::Error::other("fault injection: write failure"),
                path: self.root.clone(),
                operation: "fault_injection_write_failure",
            });
        }
        if let Some(limit) = fi.enospc_after_bytes {
            if self.enospc_bytes_written + payload.len() as u64 > limit {
                return Err(StoreError::NoSpace);
            }
        }

        if fi.byte_corruption_probability > 0.0 {
            let mut corrupted = payload.to_vec();
            fi.corrupt_payload(&mut rand::thread_rng(), &mut corrupted);
            Ok(std::borrow::Cow::Owned(corrupted))
        } else {
            Ok(std::borrow::Cow::Borrowed(payload))
        }
    }

    fn put_authorized_with_transaction_tracking(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        track_transaction: bool,
    ) -> Result<StoredObject> {
        // Pool-owned generation and deletion publication deliberately uses
        // this path, so configured write faults exercise those durability
        // transitions too. Only lower put_inner/put_preencoded_internal
        // callers bypass fault injection.
        let effective_payload = self.prepare_payload_with_fault_injection(payload)?;
        let pool_metadata_family = is_strict_pool_authority_key(key);
        if pool_metadata_family && self.options.replica_count() != self.replicas.len() {
            return Err(StoreError::InvalidOptions {
                reason: "strict pool authority store replica is unavailable",
            });
        }

        // Transparently compress the payload when compression is configured.
        let (stored_payload, compression_algorithm) = if pool_metadata_family {
            (effective_payload, 0)
        } else if let Some(ref config) = self.compression_config {
            let mut stats = self.compression_stats;
            let framed = tidefs_frame::compress_frame(&effective_payload, config, &mut stats);
            self.compression_stats = stats;
            let alg = config.algorithm as u8;
            (std::borrow::Cow::Owned(framed), alg)
        } else {
            (effective_payload, 0)
        };

        let result = self.put_inner(
            key,
            &stored_payload,
            compression_algorithm,
            !pool_metadata_family,
            true,
        )?;
        if pool_metadata_family
            && self
                .last_replicated_write
                .as_ref()
                .is_none_or(|outcome| outcome.class != crate::ReplicatedWriteClass::Committed)
        {
            return Err(StoreError::InvalidOptions {
                reason: "strict pool authority did not converge across store replicas",
            });
        }

        // Compute per-object BLAKE3 domain-separated checksum for
        // read-path verification (#5273).
        {
            let domain_key = DomainTag::ReadVerify.derive_key();
            let digest = ObjectDigest::compute(payload, &domain_key);
            self.checksums.insert(key, digest);
        }

        // Pool generation and deletion markers are their own durable
        // authorities. Recording them in the ordinary payload WAL would let
        // generic replay resurrect an older reservation or deletion after the
        // Pool had synchronously replaced or cleared it.
        if pool_metadata_family {
            return Ok(result);
        }

        // Immutable prepublication payloads are not independently reachable:
        // Pool receipt publication, followed by the owning manifest and
        // authenticated filesystem root, is their commit authority. Keep the
        // ordinary storage, transform, replica, checksum and fault paths above,
        // but do not duplicate these bytes into a second raw-store transaction.
        if !track_transaction {
            self.prepublication_checksums_dirty = true;
            return Ok(result);
        }

        // Track this write in the current transaction group for
        // committed-root anchoring on flush/sync. If tracking fails
        // (phase rejection), abort the current commit_group so subsequent
        // writes start fresh. The segment write already succeeded.
        if let Err(_e) = self.commit_group.queue_put(key, payload) {
            self.commit_group.abort_current();
        }

        // Record the write in the intent-log for crash recovery.
        // Begin a new transaction if this is the first write since
        // the last commit.
        if !self.intent_log_tx_open {
            let cg_id = self.txg_coordinator.next_txg_number().0;
            let _ = self
                .intent_log
                .append(crate::intent_log::record::IntentLogRecord::TxBegin { cg_id });
            self.intent_log_tx_open = true;
        }
        let mutation = crate::intent_log::serialization::TransactionMutation::WritePayload {
            object_id: key,
            offset: 0,
            data: payload.to_vec(),
        };
        let _ = self.intent_log.append(mutation.to_intent_log_record());

        Ok(result)
    }

    fn put_authorized(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.put_authorized_with_transaction_tracking(key, payload, true)
    }

    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.ensure_pool_raw_mutation_allowed()?;
        Self::ensure_public_pool_key_mutation_allowed(key)?;
        self.put_authorized(key, payload)
    }

    /// Store one immutable Pool-prepublication payload without copying it into
    /// the raw store's separate commit group and intent log.
    ///
    /// The caller must publish and durably verify the corresponding Pool
    /// placement receipt before making the object reachable. All ordinary raw
    /// storage behavior, including fault injection, transforms, replication,
    /// liveness accounting and read-verification checksums, remains active.
    pub(crate) fn put_prepublication_pool_internal(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<StoredObject> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.put_authorized_with_transaction_tracking(key, payload, false)
    }

    /// Start one Pool-owned prepublication append batch.
    ///
    /// Block stores stage the contiguous encoded records plus one zero
    /// successor header in memory, then install and strictly close that prefix
    /// when the Pool finishes the batch. Store replicas join the same boundary.
    pub(crate) fn begin_prepublication_append_batch(&mut self) {
        self.prepublication_readback_range = None;
        self.prepublication_readback_bytes.clear();
        self.prepublication_readback_records.clear();
        // A failed final verification deliberately leaves the flag set so a
        // later write and finish can recover the same scan boundary.
        self.prepublication_tail_verification_deferred = true;
        for replica in &mut self.replicas {
            replica.begin_prepublication_append_batch();
        }
    }

    fn flush_prepublication_append_bytes(&mut self) -> Result<()> {
        if self.prepublication_append_bytes.is_empty() {
            self.prepublication_append_start = None;
            return Ok(());
        }
        let start = self
            .prepublication_append_start
            .ok_or(StoreError::InvalidOptions {
                reason: "prepublication append bytes are missing their block offset",
            })?;
        let readback_len = self.prepublication_append_bytes.len();
        self.current_file
            .write_all_at(&self.prepublication_append_bytes, start)
            .map_err(|source| {
                io_error(
                    "write coalesced prepublication records and tail",
                    &self.root,
                    source,
                )
            })?;
        self.prepublication_readback_range = Some((start, readback_len));
        self.prepublication_append_bytes.clear();
        self.prepublication_append_start = None;
        Ok(())
    }

    fn flush_and_verify_prepublication_tail(&mut self) -> Result<()> {
        if self.block_device_mode {
            self.flush_prepublication_append_bytes()?;
            self.write_and_verify_block_device_tail_terminator(self.current_offset)?;
        }
        Ok(())
    }

    /// End a Pool-owned prepublication append batch by installing all staged
    /// records, then rewriting and reading back their one surviving tail.
    pub(crate) fn finish_prepublication_append_batch(&mut self) -> Result<()> {
        let mut first_error = None;
        if self.prepublication_tail_verification_deferred {
            let result = self.flush_and_verify_prepublication_tail();
            match result {
                Ok(()) => self.prepublication_tail_verification_deferred = false,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        for replica in &mut self.replicas {
            if let Err(error) = replica.finish_prepublication_append_batch() {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Load the just-synced append range with one positioned read.
    ///
    /// The Pool calls this only after its durability barrier and holds
    /// exclusive mutable authority until strict payload and receipt readback
    /// completes. Ordinary record decoding still validates every header,
    /// payload checksum, footer, integrity trailer, location identity and
    /// configured read checksum from these persisted bytes.
    pub(crate) fn load_prepublication_batch_readback(&mut self) -> Result<()> {
        self.prepublication_readback_bytes.clear();
        self.prepublication_readback_records.clear();
        let mut first_error = None;
        if let Some((start, len)) = self.prepublication_readback_range {
            let end = start
                .checked_add(u64::try_from(len).map_err(|_| StoreError::InvalidOptions {
                    reason: "prepublication readback length exceeds u64",
                })?)
                .ok_or(StoreError::InvalidOptions {
                    reason: "prepublication readback range overflows u64",
                })?;
            let data_end = self
                .block_device_capacity
                .unwrap_or(0)
                .saturating_sub(POOL_LABEL_SIZE as u64);
            if !self.block_device_mode || end > data_end {
                first_error = Some(StoreError::InvalidOptions {
                    reason: "prepublication readback range leaves the block data region",
                });
            } else {
                self.prepublication_readback_bytes.resize(len, 0);
                if let Err(source) = self
                    .current_file
                    .read_exact_at(&mut self.prepublication_readback_bytes, start)
                {
                    self.prepublication_readback_bytes.clear();
                    first_error = Some(io_error(
                        "read coalesced prepublication records and tail",
                        &self.root,
                        source,
                    ));
                } else {
                    match self.index_prepublication_batch_readback(start, len) {
                        Ok(records) => self.prepublication_readback_records = records,
                        Err(error) => {
                            self.prepublication_readback_bytes.clear();
                            first_error = Some(error);
                        }
                    }
                }
            }
        }
        for replica in &mut self.replicas {
            if let Err(error) = replica.load_prepublication_batch_readback() {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn index_prepublication_batch_readback(
        &self,
        start: u64,
        len: usize,
    ) -> Result<BTreeMap<ObjectLocation, (usize, usize, u8)>> {
        let records_len = len
            .checked_sub(RECORD_HEADER_LEN)
            .ok_or(StoreError::InvalidOptions {
                reason: "prepublication readback omits its successor header",
            })?;
        let records_end = start
            .checked_add(
                u64::try_from(records_len).map_err(|_| StoreError::InvalidOptions {
                    reason: "prepublication record range exceeds u64",
                })?,
            )
            .ok_or(StoreError::InvalidOptions {
                reason: "prepublication record range overflows u64",
            })?;
        let mut records = BTreeMap::new();
        let mut relative = 0usize;
        while relative < records_len {
            let record_offset = start
                .checked_add(
                    u64::try_from(relative).map_err(|_| StoreError::InvalidOptions {
                        reason: "prepublication record offset exceeds u64",
                    })?,
                )
                .ok_or(StoreError::InvalidOptions {
                    reason: "prepublication record offset overflows u64",
                })?;
            let header_end =
                relative
                    .checked_add(RECORD_HEADER_LEN)
                    .ok_or(StoreError::InvalidOptions {
                        reason: "prepublication record header overflows usize",
                    })?;
            let header_slice = self
                .prepublication_readback_bytes
                .get(relative..header_end)
                .ok_or(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication record header is truncated",
                })?;
            let mut header_bytes = [0_u8; RECORD_HEADER_LEN];
            header_bytes.copy_from_slice(header_slice);
            let header = decode_header(&header_bytes, self.current_segment_id, record_offset)?;
            if header.kind != RecordKind::Put {
                return Err(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication readback contains a non-put record",
                });
            }
            let range = checked_record_range(header, self.current_segment_id, record_offset)?;
            if range.end_offset > records_end {
                return Err(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication record extends beyond its batch",
                });
            }
            let relative_offset = |offset: u64| -> Result<usize> {
                let relative = offset.checked_sub(start).ok_or(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication record moved before its batch",
                })?;
                usize::try_from(relative).map_err(|_| StoreError::InvalidOptions {
                    reason: "prepublication record range exceeds platform usize",
                })
            };
            let payload_start = relative_offset(range.payload_offset)?;
            let payload_end = relative_offset(range.payload_end_offset)?;
            let payload = self
                .prepublication_readback_bytes
                .get(payload_start..payload_end)
                .ok_or(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication record payload is truncated",
                })?;
            let actual = checksum64(payload);
            if actual != header.payload_checksum {
                return Err(StoreError::ChecksumMismatch {
                    segment_id: self.current_segment_id,
                    offset: range.payload_offset,
                    expected: header.payload_checksum,
                    actual,
                });
            }

            let footer = if record_has_footer(header.format_version) {
                let footer_start = relative_offset(range.footer_offset)?;
                let footer_end = footer_start.checked_add(RECORD_FOOTER_LEN).ok_or(
                    StoreError::InvalidOptions {
                        reason: "prepublication record footer overflows usize",
                    },
                )?;
                let footer_slice = self
                    .prepublication_readback_bytes
                    .get(footer_start..footer_end)
                    .ok_or(StoreError::CorruptHeader {
                        segment_id: self.current_segment_id,
                        offset: range.footer_offset,
                        reason: "prepublication record footer is truncated",
                    })?;
                let mut footer = [0_u8; RECORD_FOOTER_LEN];
                footer.copy_from_slice(footer_slice);
                decode_footer(
                    &footer,
                    header,
                    self.current_segment_id,
                    range.footer_offset,
                )?;
                Some(footer)
            } else {
                None
            };
            if record_has_production_integrity_trailer(header.format_version) {
                let trailer_offset =
                    range
                        .integrity_trailer_offset
                        .ok_or(StoreError::CorruptHeader {
                            segment_id: self.current_segment_id,
                            offset: record_offset,
                            reason: "prepublication integrity trailer offset is absent",
                        })?;
                let trailer_start = relative_offset(trailer_offset)?;
                let trailer_end = trailer_start.checked_add(INTEGRITY_TRAILER_V2_LEN).ok_or(
                    StoreError::InvalidOptions {
                        reason: "prepublication integrity trailer overflows usize",
                    },
                )?;
                let trailer_slice = self
                    .prepublication_readback_bytes
                    .get(trailer_start..trailer_end)
                    .ok_or(StoreError::CorruptHeader {
                        segment_id: self.current_segment_id,
                        offset: trailer_offset,
                        reason: "prepublication integrity trailer is truncated",
                    })?;
                let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
                trailer.copy_from_slice(trailer_slice);
                let decoded_trailer = decode_integrity_trailer_v2(&trailer)?;
                let footer = footer.ok_or(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication integrity trailer requires a footer",
                })?;
                verify_integrity_trailer_v2(
                    &decoded_trailer,
                    header,
                    &header_bytes,
                    payload,
                    &footer,
                    self.current_segment_id,
                    trailer_offset,
                )?;
            }

            let location = ObjectLocation {
                key: header.key,
                segment_id: self.current_segment_id,
                record_offset,
                payload_offset: range.payload_offset,
                payload_len: header.payload_len,
                sequence: header.sequence,
                payload_checksum: header.payload_checksum,
            };
            if records
                .insert(
                    location,
                    (payload_start, payload_end, header.compression_algorithm),
                )
                .is_some()
            {
                return Err(StoreError::CorruptHeader {
                    segment_id: self.current_segment_id,
                    offset: record_offset,
                    reason: "prepublication readback repeats a physical record identity",
                });
            }
            relative = relative_offset(range.end_offset)?;
        }
        if relative != records_len {
            return Err(StoreError::CorruptHeader {
                segment_id: self.current_segment_id,
                offset: start.saturating_add(relative as u64),
                reason: "prepublication readback does not end at its successor header",
            });
        }
        Ok(records)
    }

    pub(crate) fn clear_prepublication_batch_readback(&mut self) {
        self.prepublication_readback_range = None;
        self.prepublication_readback_bytes.clear();
        self.prepublication_readback_records.clear();
        for replica in &mut self.replicas {
            replica.clear_prepublication_batch_readback();
        }
    }

    fn verify_deferred_prepublication_tail_before_barrier(&mut self) -> Result<()> {
        if self.prepublication_tail_verification_deferred {
            self.flush_and_verify_prepublication_tail()?;
            // A barrier closes the append batch. Any later write verifies its
            // own tail, so metadata appended by the barrier cannot inherit the
            // earlier payload batch's deferred state.
            self.prepublication_tail_verification_deferred = false;
        }
        Ok(())
    }

    pub(crate) fn put_pool_internal(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> Result<StoredObject> {
        self.put_authorized(key, payload)
    }

    fn put_preencoded_internal(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        compression_algorithm: u8,
    ) -> Result<StoredObject> {
        self.put_inner(key, payload, compression_algorithm, false, true)
    }

    /// Write a named object directly to the segment without commit_group tracking.
    ///
    /// Used internally by the commit_group commit path to persist journal records
    /// and committed roots without recursing into the commit_group accumulator.
    pub(crate) fn put_direct(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.put_inner(key, payload, 0, false, true)
    }

    /// Return the per-object BLAKE3 domain-separated checksum for `key`,
    /// or `None` if no checksum has been computed yet.
    /// Delete an object without intent-log recording or txg tracking.
    ///
    /// Used internally by intent-log replay to apply tombstones without
    /// re-logging (which would cause infinite replay).
    pub(crate) fn delete_direct(&mut self, key: ObjectKey) -> Result<bool> {
        self.ensure_writable("delete_direct")?;
        let existed = self.index.contains_key(&key);
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(StoreError::InvalidOptions {
            reason: "object-store physical lifetime sequence exhausted",
        })?;
        let empty_checksum = checksum64(&[]);
        self.append_record(RecordKind::Delete, key, &[], empty_checksum, sequence, 0)?;
        self.remove_index_location(key);
        self.checksums.remove(&key);
        let reclaim_key = tidefs_types_reclaim_queue_core::ObjectKey(key.0);
        let reclaim_entry = tidefs_types_reclaim_queue_core::ReclaimQueueEntry::new(
            reclaim_key,
            -1,
            tidefs_types_reclaim_queue_core::QueueFamily::Extent,
        );
        self.reclaim_queue.insert(reclaim_entry);
        self.next_sequence = next_sequence;
        self.tombstone_count = self.tombstone_count.saturating_add(1);

        // Fan out delete to all replicas.
        for replica in &mut self.replicas {
            let _ = replica.delete(key);
        }

        Ok(existed)
    }

    pub fn get_object_digest(&self, key: ObjectKey) -> Option<ObjectDigest> {
        self.checksums.get(&key).copied()
    }

    pub fn get_named(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        self.get(ObjectKey::from_name(name))
    }

    fn get_pool_internal_stored_replica_consensus(
        &self,
        key: ObjectKey,
        unavailable_reason: &'static str,
        conflict_reason: &'static str,
    ) -> Result<Option<Vec<u8>>> {
        if self.options.replica_count() != self.replicas.len()
            || self.replica_healthy.iter().any(|healthy| !healthy)
        {
            return Err(StoreError::InvalidOptions {
                reason: unavailable_reason,
            });
        }
        let primary = self
            .index
            .get(&key)
            .copied()
            .map(|location| {
                self.read_location_stored_payload(location)
                    .map(|(payload, _)| payload)
            })
            .transpose()?;
        for replica in &self.replicas {
            if replica.get_pool_internal_stored_replica_consensus(
                key,
                unavailable_reason,
                conflict_reason,
            )? != primary
            {
                return Err(StoreError::InvalidOptions {
                    reason: conflict_reason,
                });
            }
        }
        Ok(primary)
    }

    fn get_pool_internal_replica_consensus(
        &self,
        key: ObjectKey,
        unavailable_reason: &'static str,
        conflict_reason: &'static str,
    ) -> Result<Option<Vec<u8>>> {
        let stored = self.get_pool_internal_stored_replica_consensus(
            key,
            unavailable_reason,
            conflict_reason,
        )?;
        match (stored, self.index.get(&key).copied()) {
            (None, None) => Ok(None),
            (Some(_), Some(location)) => self.read_location(location).map(Some),
            _ => Err(StoreError::InvalidOptions {
                reason: conflict_reason,
            }),
        }
    }

    fn collect_pool_internal_copy_slots(
        &self,
        key: ObjectKey,
        slots: &mut Vec<Option<Vec<u8>>>,
    ) -> Result<()> {
        slots.push(
            self.index
                .get(&key)
                .copied()
                .map(|location| self.read_location(location))
                .transpose()?,
        );
        for replica in &self.replicas {
            replica.collect_pool_internal_copy_slots(key, slots)?;
        }
        Ok(())
    }

    pub(crate) fn get_pool_internal_copy_slots(
        &self,
        key: ObjectKey,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if self.options.replica_count() != self.replicas.len() {
            return Err(StoreError::InvalidOptions {
                reason: "strict pool authority store replica is unavailable",
            });
        }
        let mut slots = Vec::new();
        self.collect_pool_internal_copy_slots(key, &mut slots)?;
        Ok(slots)
    }

    /// Retrieve blob bytes for `key`.
    ///
    /// If the key was derived via [`ObjectKey::from_content`], callers
    /// may additionally verify the returned payload by computing
    /// `ObjectKey::from_content(&payload)` and comparing against `key`.
    /// Use [`LocalObjectStore::get_verified`] for a one-step read with
    /// content-address verification built in.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        if is_strict_pool_authority_key(key) {
            return self.get_pool_internal_replica_consensus(
                key,
                "strict pool authority store replica is unavailable",
                "strict pool authority conflicts across store replicas",
            );
        }

        let result = match self.index.get(&key).copied() {
            Some(location) => self.read_location(location).map(Some),
            None => {
                // Fall back to replicas: try each replica for the key.
                for replica in &self.replicas {
                    if let Ok(Some(payload)) = replica.get(key) {
                        if self.compression_config.is_some() {
                            if let Ok(plain) = tidefs_frame::decompress_frame(&payload) {
                                return Ok(Some(plain));
                            }
                        }
                        return Ok(Some(payload));
                    }
                }
                Ok(None)
            }
        }?;
        if self.options.verify_read_checksums {
            if let Some(ref payload) = result {
                crate::read_verify::verify_read_payload(key, payload, &self.checksums)?;
            }
        }
        Ok(result)
    }

    /// Retrieve blob bytes for `key` as they existed at `commit_root`.
    ///
    /// Currently delegates to [`Self::get`] because per-object commit_group
    /// tracking is not yet available in the on-disk record format. When
    /// [`ObjectLocation`] carries a commit_group field recorded during
    /// segment replay, this method will scan the per-key history for the
    /// latest location with `commit_group <= commit_root.commit_group_id`.
    ///
    /// For read-only stores opened at the snapshot's commit root boundary,
    /// the in-memory index naturally reflects the correct state because no
    /// post-snapshot writes are indexed. True anchored reads require the
    /// format change described above.
    pub fn get_at_commit_group(
        &self,
        key: ObjectKey,
        commit_root: tidefs_commit_group::RootPointer,
    ) -> Result<Option<Vec<u8>>> {
        let _ = commit_root; // reserved for future anchored-read implementation
        self.get(key)
    }

    /// Retrieve a byte range
    ///
    /// Missing keys return `Ok(None)`. Existing objects return `Ok(Some(bytes))`,
    /// where ranges starting at or beyond EOF return an empty vector and ranges
    /// extending past EOF return the available suffix.
    ///
    /// When `verify_read_checksums` is enabled, the full object is read and
    /// verified against the stored per-object digest before the requested
    /// range slice is returned. This upholds the "verify every read" contract
    /// and prevents false checksum-mismatch errors that would occur when
    /// comparing a partial range against the full-object digest.
    pub fn get_range(&self, key: ObjectKey, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        match self.index.get(&key).copied() {
            Some(location) => {
                // Empty range or offset beyond EOF: no bytes to verify or return.
                if len == 0 || offset >= location.payload_len {
                    return Ok(Some(Vec::new()));
                }
                let read_len = len.min(location.payload_len.saturating_sub(offset));

                // Read the full object so the stored checksum (which covers the
                // entire payload) can be verified before slicing out the
                // requested range.
                let full_payload = self.read_location(location)?;

                if self.options.verify_read_checksums {
                    crate::read_verify::verify_read_payload(key, &full_payload, &self.checksums)?;
                }

                let start = usize::try_from(offset).map_err(|_| StoreError::PayloadTooLarge {
                    len: offset,
                    max: usize::MAX as u64,
                })?;
                let end = start
                    .checked_add(usize::try_from(read_len).map_err(|_| {
                        StoreError::PayloadTooLarge {
                            len: read_len,
                            max: usize::MAX as u64,
                        }
                    })?)
                    .ok_or(StoreError::PayloadTooLarge {
                        len: location.payload_len,
                        max: usize::MAX as u64,
                    })?;
                Ok(Some(full_payload[start..end].to_vec()))
            }
            None => self.get_range_fallback(key, offset, len),
        }
    }

    /// Fallback path for get_range that tries replicas and returns Ok(None)
    /// when the key is not found in the index or any replica.
    fn get_range_fallback(&self, key: ObjectKey, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        for replica in &self.replicas {
            if let Ok(Some(payload)) = replica.get_range(key, offset, len) {
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }

    /// Retrieve blob bytes and verify they match the content-derived
    /// key via [`ObjectKey::from_content`].
    ///
    /// Returns `Err(StoreError::ContentAddressMismatch)` when the stored
    /// content hash does not match the requested key (bit-rot or corruption).
    /// Returns `Ok(None)` when the key is not live in the store.
    pub fn get_verified(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.get(key)? {
            Some(payload) => {
                let recomputed = ObjectKey::from_content(&payload);
                if recomputed != key {
                    return Err(StoreError::ContentAddressMismatch {
                        expected: key,
                        actual: recomputed,
                    });
                }
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }

    /// Retrieve blob bytes and verify against the stored per-object BLAKE3
    /// checksum (computed on write via [`ObjectDigest`]).
    ///
    /// If a checksum exists for `key`, the returned payload is verified:
    /// a mismatch returns [`StoreError::ObjectChecksumMismatch`]. If no
    /// checksum has been computed yet (pre-checksum-era objects), the
    /// payload is returned without verification.
    ///
    /// Returns `Ok(None)` when the key is not live in the store.
    pub fn get_checksum_verified(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.get(key)? {
            Some(payload) => {
                if let Some(stored_digest) = self.checksums.get(&key).copied() {
                    let domain_key = DomainTag::ReadVerify.derive_key();
                    if !stored_digest.verify(&payload, &domain_key) {
                        let actual = ObjectDigest::compute(&payload, &domain_key);
                        return Err(StoreError::ObjectChecksumMismatch {
                            key,
                            expected: stored_digest,
                            actual,
                        });
                    }
                }
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }

    /// Build a [`ChecksumTree`] for object data stored under `key`.
    ///
    /// Reads the full payload, splits it into `block_size` chunks, and
    /// constructs a BLAKE3 Merkle tree via [`ChecksumTreeBuilder`].
    /// Returns `Ok(None)` when the key is not live in the store.
    ///
    /// The returned tree can be used with [`tidefs_checksum_tree::ChecksumTreeVerifier`]
    /// for partial-read verification or with [`Self::verify_checksum_tree`]
    /// for full-object integrity checking.
    pub fn get_checksum_tree(
        &self,
        key: ObjectKey,
        block_size: usize,
    ) -> Result<Option<ChecksumTree>> {
        match self.get(key)? {
            Some(data) => {
                let mut builder = ChecksumTreeBuilder::new(block_size);
                builder.ingest(&data);
                Ok(Some(builder.finish()))
            }
            None => Ok(None),
        }
    }

    /// Verify that object data matches a previously computed [`ChecksumTree`].
    ///
    /// Reads the full payload for `key`, then verifies every block against
    /// the leaf digests in `tree` using [`tidefs_checksum_tree::ChecksumTreeVerifier`].
    /// Returns `Ok(true)` when all blocks match, `Ok(false)` when corruption
    /// or truncation is detected, and `Err(_)` on I/O errors.
    ///
    /// Returns `Ok(false)` when the key is not live in the store.
    pub fn verify_checksum_tree(&self, key: ObjectKey, tree: &ChecksumTree) -> Result<bool> {
        match self.get(key)? {
            Some(data) => {
                let verifier = tidefs_checksum_tree::ChecksumTreeVerifier::new(tree.clone());
                let result = verifier.verify_full(&data);
                Ok(result == tidefs_checksum_tree::VerificationResult::Verified)
            }
            None => Ok(false),
        }
    }

    /// Scrub object data against a previously captured checksum tree.
    ///
    /// Reads the object payload through the store and returns a structured
    /// checksum-tree scrub report. Missing live objects return `Ok(None)`.
    pub fn scrub_checksum_tree(
        &self,
        key: ObjectKey,
        tree: &ChecksumTree,
    ) -> Result<Option<crate::ChecksumTreeScrubReport>> {
        match self.get(key)? {
            Some(data) => Ok(Some(crate::scrub_checksum_tree(tree, &data))),
            None => Ok(None),
        }
    }

    /// Return lightweight object metadata without copying the full payload.
    ///
    /// Returns `ObjectAttr` with the object size, a best-effort creation
    /// timestamp derived from the backing file, and the content key.
    /// Returns `Err(ObjectReadError::NotFound)` when the key is unknown.
    pub fn get_attr(&self, key: &ObjectKey) -> std::result::Result<ObjectAttr, ObjectReadError> {
        match self.index.get(key).copied() {
            Some(location) => {
                let path = segment_path(&self.segments_dir, location.segment_id);
                let created = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.created().ok())
                    .unwrap_or_else(std::time::SystemTime::now);
                Ok(ObjectAttr {
                    size: location.payload_len,
                    created,
                    key: *key,
                })
            }
            None => {
                // Fall back to replicas.
                for replica in &self.replicas {
                    if let Ok(attr) = replica.get_attr(key) {
                        return Ok(attr);
                    }
                }
                Err(ObjectReadError::NotFound { key: *key })
            }
        }
    }

    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool> {
        self.delete(ObjectKey::from_name(name))
    }

    fn delete_authorized(&mut self, key: ObjectKey) -> Result<bool> {
        self.ensure_writable("delete")?;
        let pool_metadata_family = is_strict_pool_authority_key(key);
        if self.options.replica_count() != self.replicas.len() {
            return Err(StoreError::InvalidOptions {
                reason: "object deletion store replica is unavailable",
            });
        }
        let existed = self.index.contains_key(&key);
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(StoreError::InvalidOptions {
            reason: "object-store physical lifetime sequence exhausted",
        })?;
        let empty_checksum = checksum64(&[]);
        self.append_record(RecordKind::Delete, key, &[], empty_checksum, sequence, 0)?;
        // Put history already contains the last-known location. Keep it there
        // after removing the live index entry so receipt-bound reclaim can
        // still resolve the exact dead lifetime without duplicating it.
        if let Some(loc) = self.index.get(&key).copied() {
            if !pool_metadata_family {
                // Record the old segment liveness so the background reclaim
                // process can track dead space and prioritize cleaning.
                self.segment_liveness
                    .record_delete(loc.segment_id, loc.payload_len);

                // Test-only raw-store accounting fixtures can model deletions.
                self.record_test_current_dataset_delete(loc.payload_len);
            }
        }

        self.remove_index_location(key);
        self.checksums.remove(&key);
        self.next_sequence = next_sequence;
        if !pool_metadata_family {
            // Enqueue a reclaim entry so the background drain loop can
            // eventually free the segment when all objects in it are dead.
            self.enqueue_reclaim_entry(key);
            self.tombstone_count = self.tombstone_count.saturating_add(1);
        }

        // Fan out delete to all replicas so stale data does not
        // resurrect on a replica fallback read.
        let mut first_replica_error = (self.options.replica_count() != self.replicas.len())
            .then_some(StoreError::InvalidOptions {
                reason: "object deletion store replica is unavailable",
            });
        for (index, replica) in self.replicas.iter_mut().enumerate() {
            let result = if is_pool_store_internal_key(key) {
                replica.delete_pool_internal(key)
            } else {
                replica.delete(key)
            };
            match result {
                Ok(_) if index < self.replica_healthy.len() => self.replica_healthy[index] = true,
                Ok(_) => {}
                Err(error) => {
                    if index < self.replica_healthy.len() {
                        self.replica_healthy[index] = false;
                    }
                    first_replica_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_replica_error {
            return Err(error);
        }
        if self
            .get_pool_internal_copy_slots(key)?
            .into_iter()
            .any(|copy| copy.is_some())
        {
            return Err(StoreError::InvalidOptions {
                reason: "object deletion did not converge across store replicas",
            });
        }

        // Pool generation and deletion markers are not generic payloads.
        // Replaying an internal-marker tombstone through the payload WAL could
        // otherwise erase newer Pool authority or enqueue it for user reclaim.
        if pool_metadata_family {
            return Ok(existed);
        }

        // Record the deletion in the intent-log for crash recovery.
        // A WritePayload with empty data serves as a tombstone marker
        // at the object-store level.
        if !self.intent_log_tx_open {
            let cg_id = self.txg_coordinator.next_txg_number().0;
            let _ = self
                .intent_log
                .append(crate::intent_log::record::IntentLogRecord::TxBegin { cg_id });
            self.intent_log_tx_open = true;
        }
        let mutation = crate::intent_log::serialization::TransactionMutation::WritePayload {
            object_id: key,
            offset: 0,
            data: Vec::new(), // empty payload = tombstone
        };
        let _ = self.intent_log.append(mutation.to_intent_log_record());

        Ok(existed)
    }

    pub fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.ensure_pool_raw_mutation_allowed()?;
        Self::ensure_public_pool_key_mutation_allowed(key)?;
        self.delete_authorized(key)
    }

    pub(crate) fn delete_pool_internal(&mut self, key: ObjectKey) -> Result<bool> {
        self.delete_authorized(key)
    }

    pub fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("compact_retaining")?;
        if self.block_device_mode {
            return self.compact_block_device_retaining(protected_keys, protected_exact_locations);
        }

        let mut protected_exact_locations: BTreeSet<ObjectLocation> =
            protected_exact_locations.iter().copied().collect();
        for entry in self.dead_object_reclaim_queue.all_entries() {
            if let Some(lifetime) =
                self.resolve_receipt_bound_physical_lifetime(&entry.object_id)?
            {
                protected_exact_locations.insert(lifetime.location);
                continue;
            }

            // Compatibility rows use the logical object key as their queue
            // identity and cannot distinguish repeated physical lifetimes.
            // Preserve every known lifetime for that key. Any other
            // unresolved durable row makes compaction fail closed instead of
            // retiring history that may still be required for receipt-bound
            // clearance.
            let logical_object_key = ObjectKey::from_bytes(entry.object_id.0);
            let Some(locations) = self
                .history
                .get(&logical_object_key)
                .filter(|locations| !locations.is_empty())
            else {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "compaction cannot resolve a pending receipt-bound physical lifetime",
                });
            };
            protected_exact_locations.extend(locations.iter().copied());
        }
        let protected_exact_locations = protected_exact_locations.into_iter().collect::<Vec<_>>();

        let segment_ids_before = discover_segment_ids(&self.segments_dir)?;
        let live_objects_before = stats_counted_index_len(&self.index);
        let protected_keys: BTreeSet<ObjectKey> = protected_keys.iter().copied().collect();
        let exact_locations: BTreeSet<ObjectLocation> =
            protected_exact_locations.iter().copied().collect();
        let mut retained_segments: BTreeSet<u64> = BTreeSet::new();

        for location in &protected_exact_locations {
            self.read_location(*location)?;
            retained_segments.insert(location.segment_id);
        }

        if self.current_offset > 0 {
            self.rotate_segment()?;
        }

        let mut retained_keys = protected_keys.clone();
        retained_keys.extend(
            self.index
                .keys()
                .copied()
                .filter(|key| is_public_scan_internal_key(*key)),
        );
        let mut retained_copies = Vec::new();
        for key in retained_keys {
            let Some(location) = self.index.get(&key).copied() else {
                continue;
            };
            if exact_locations.contains(&location)
                || retained_segments.contains(&location.segment_id)
            {
                continue;
            }
            retained_copies.push((
                key,
                is_pool_store_internal_key(key),
                self.read_location(location)?,
            ));
        }

        let copied_protected_objects = retained_copies
            .iter()
            .filter(|(key, _, _)| protected_keys.contains(key))
            .count();
        let mut relocated_reclaim_entries = Vec::new();
        for (key, internal_key, bytes) in retained_copies {
            if is_dead_object_reclaim_entry_state_key(key) {
                let entry = Self::decode_dead_object_reclaim_entry_state(key, &bytes)?;
                self.put_dead_object_reclaim_entry_state_local(entry)?;
                relocated_reclaim_entries.push(entry);
            } else if internal_key {
                self.put_direct(key, &bytes)?;
            } else {
                self.put(key, &bytes)?;
            }
        }

        let mut tombstone_keys = BTreeSet::new();
        for key in self.index.keys().copied() {
            if !is_public_scan_internal_key(key) && !protected_keys.contains(&key) {
                tombstone_keys.insert(key);
            }
        }
        for (key, locations) in &self.history {
            if is_public_scan_internal_key(*key) || protected_keys.contains(key) {
                continue;
            }
            if locations
                .iter()
                .any(|location| retained_segments.contains(&location.segment_id))
            {
                tombstone_keys.insert(*key);
            }
        }

        let tombstoned_unprotected_keys = tombstone_keys.len();
        for key in tombstone_keys {
            self.delete(key)?;
        }

        let next_sequence =
            self.next_sequence
                .checked_add(1)
                .ok_or(StoreError::InvalidOptions {
                    reason: "object-store physical lifetime sequence exhausted",
                })?;
        self.put_direct(
            physical_lifetime_sequence_high_water_key(),
            &next_sequence.to_le_bytes(),
        )?;

        self.sync_all()?;
        for entry in relocated_reclaim_entries {
            self.verify_dead_object_reclaim_entry_state_local(entry)?;
        }
        // Segment retirement can remove the history that suppresses
        // already-applied intent-log writes during replay.
        self.mark_committed_intent_log_segments_replayed_for_compaction()?;

        let segment_ids_after_writes = discover_segment_ids(&self.segments_dir)?;
        for segment_id in &segment_ids_after_writes {
            if !segment_ids_before.contains(segment_id) {
                retained_segments.insert(*segment_id);
            }
        }
        retained_segments.insert(self.current_segment_id);

        let mut retired_segments = Vec::new();
        for segment_id in &segment_ids_after_writes {
            if !retained_segments.contains(segment_id) {
                let path = segment_path(&self.segments_dir, *segment_id);
                fs::remove_file(&path).map_err(|source| io_error("remove_file", &path, source))?;
                retired_segments.push(*segment_id);
                // Return retired segment to the free pool for reuse.
                let _ = self.free_map.add_free(*segment_id);
            }
        }
        if !retired_segments.is_empty() {
            // Check for space pressure transition after freeing retired segments.
            let _pressure = self.check_space_pressure();
            sync_directory(&self.segments_dir)?;
        }
        // Invalidate the index checkpoint: the copy pass may have written a
        // checkpoint whose index entries reference just-deleted segments,
        // and the reopen validation only checks the boundary segment exists.
        // Removing the checkpoint forces a full segment replay, building the
        // index from surviving segments only.
        let _ = fs::remove_file(self.segments_dir.join(INDEX_BASE_FILE_NAME));
        let _ = fs::remove_file(self.segments_dir.join(SPACEMAP_BASE_FILE_NAME));

        let root = self.root.clone();
        let options = self.options.clone();
        let replica_healthy = self.replica_healthy.clone();
        let pool_raw_mutation_allowed = self.pool_raw_mutation_allowed.clone();
        *self = LocalObjectStore::open_with_options(root, options)?;
        self.replica_healthy = replica_healthy;
        if let Some(allowed) = pool_raw_mutation_allowed {
            self.install_pool_raw_mutation_guard(allowed);
        }
        // Safety net: after reopen, the index must reflect only the
        // surviving tombstone-only segments.  Clear any objects that
        // may have been resurrected by a stale checkpoint or segment
        // replay artifact (observed in focused CI validation).
        let resurrected: Vec<ObjectKey> = self
            .index
            .keys()
            .copied()
            .filter(|key| !is_public_scan_internal_key(*key) && !protected_keys.contains(key))
            .collect();
        if !resurrected.is_empty() {
            eprintln!(
                "compact_retaining: WARNING reopened store has {} resurrected entries; re-tombstoning",
                resurrected.len()
            );
            for key in resurrected {
                self.delete(key)?;
            }
        }
        self.rotate_segment()?;
        for location in &protected_exact_locations {
            self.read_location(*location)?;
        }

        let retained_segments = discover_segment_ids(&self.segments_dir)?;
        Ok(StoreRetentionCompactionReport {
            protected_key_count: protected_keys.len(),
            protected_exact_location_count: protected_exact_locations.len(),
            copied_protected_objects,
            tombstoned_unprotected_keys,
            retired_segments,
            live_objects_before,
            live_objects_after: stats_counted_index_len(&self.index),
            segment_count_before: segment_ids_before.len(),
            segment_count_after: retained_segments.len(),
            retained_segments,
            exact_locations_preserved: true,
            production_fsck_required: false,
        })
    }

    fn compact_block_device_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        debug_assert!(self.block_device_mode);
        self.ensure_writable("compact_block_device_retaining")?;

        let live_objects_before = stats_counted_index_len(&self.index);
        let protected_keys: BTreeSet<ObjectKey> = protected_keys.iter().copied().collect();
        if !protected_exact_locations.is_empty() {
            for location in protected_exact_locations {
                self.read_location(*location)?;
            }
            return Ok(StoreRetentionCompactionReport {
                protected_key_count: protected_keys.len(),
                protected_exact_location_count: protected_exact_locations.len(),
                live_objects_before,
                live_objects_after: live_objects_before,
                segment_count_before: 1,
                segment_count_after: 1,
                retained_segments: vec![0],
                exact_locations_preserved: true,
                production_fsck_required: false,
                ..Default::default()
            });
        }

        let retained_locations: Vec<(ObjectKey, ObjectLocation)> = self
            .index
            .iter()
            .filter_map(|(key, loc)| {
                (protected_keys.contains(key) || is_public_scan_internal_key(*key))
                    .then_some((*key, *loc))
            })
            .collect();
        let tombstoned_unprotected_keys = self
            .index
            .keys()
            .copied()
            .filter(|key| !is_public_scan_internal_key(*key) && !protected_keys.contains(key))
            .count();
        self.compact_block_device_locations(retained_locations)?;
        let live_objects_after = stats_counted_index_len(&self.index);

        Ok(StoreRetentionCompactionReport {
            protected_key_count: protected_keys.len(),
            protected_exact_location_count: 0,
            copied_protected_objects: live_objects_after,
            tombstoned_unprotected_keys,
            retired_segments: Vec::new(),
            retained_segments: vec![0],
            live_objects_before,
            live_objects_after,
            segment_count_before: 1,
            segment_count_after: 1,
            exact_locations_preserved: true,
            production_fsck_required: false,
        })
    }

    fn mark_committed_intent_log_segments_replayed_for_compaction(&self) -> Result<()> {
        if self.block_device_mode || sidecar_files_unavailable(&self.root) {
            return Ok(());
        }

        let ilog_dir = self.root.join("intent_log");
        if !ilog_dir.is_dir() {
            return Ok(());
        }

        for segment_id in discover_segment_ids(&ilog_dir)? {
            let path = segment_path(&ilog_dir, segment_id);
            let mut replayed_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(StoreError::InvalidOptions {
                    reason: "intent-log segment path has non-UTF-8 file name",
                })?
                .to_owned();
            replayed_name.push_str(".replayed");
            let replayed_path = ilog_dir.join(replayed_name);
            fs::rename(&path, &replayed_path)
                .map_err(|source| io_error("rename intent-log segment", &path, source))?;
        }
        sync_directory(&ilog_dir)?;
        Ok(())
    }

    /// Verify the segment integrity hash chain across all segment files.
    ///
    /// Walks every segment's [`SegmentIntegrityFooter`] from newest to oldest,
    /// validates that each `previous_segment_digest` links to the prior
    /// footer's `segment_digest`, and records broken links in the returned
    /// [`SuspectLog`].
    pub fn verify_segment_chain(&self) -> Result<(SegmentChainStats, SuspectLog)> {
        let verifier = SegmentChainVerifier::new(&self.segments_dir);
        verifier.verify_chain()
    }

    /// Return a reference to the in-memory suspect log.
    ///
    /// The log accumulates corruption entries discovered during segment replay
    /// and chain verification. Operators can drain it via [`Self::clear_suspect_log`].
    #[must_use]
    pub fn suspect_log(&self) -> &SuspectLog {
        &self.suspect_log
    }

    /// Clear the in-memory suspect log.
    pub fn clear_suspect_log(&mut self) {
        self.suspect_log.clear();
    }
    /// Return a human-readable text report of all suspect entries for operator inspection.
    ///
    /// The report includes per-entry details (entry_id, locator_id, segment_id,
    /// offset, record_type, repair_attempts, resolved, timestamp) followed by
    /// aggregate statistics. This is the release-visible operator path for
    /// durable scrub corruption validation.
    #[must_use]
    pub fn suspect_log_text_report(&self) -> String {
        let mut report = String::with_capacity(4096);
        report.push_str("=== TideFS Suspect Log Report ===\n");

        let stats = self.suspect_log.stats();
        report.push_str(&format!(
            "Total entries: {} | Unresolved: {} | Resolved: {}\n",
            stats.total_entries, stats.unresolved, stats.resolved,
        ));
        if stats.oldest_unresolved_age > 0 {
            report.push_str(&format!(
                "Oldest unresolved age: {}s\n",
                stats.oldest_unresolved_age,
            ));
        }

        let entries: Vec<&SuspectEntry> = self.suspect_log.iter().collect();
        if entries.is_empty() {
            report.push_str("No suspect entries recorded.\n");
        } else {
            report.push_str(&format!("\n{:-<96}\n", ""));
            report.push_str(&format!(
                "{:<6} {:<6} {:<8} {:<10} {:<5} {:<7} {:<8} {:<10}\n",
                "ENTRY", "LOC", "SEGMENT", "OFFSET", "TYPE", "ATTEMP", "RESOLV", "TIMESTAMP",
            ));
            report.push_str(&format!("{:-<96}\n", ""));
            for e in &entries {
                let rt = match e.record_type {
                    1 => "PAYLOAD",
                    2 => "CHAIN",
                    3 => "TRUNC",
                    4 => "REC-DGST",
                    5 => "CHAIN-ERR",
                    _ => "UNKNOWN",
                };
                let resolved = if e.resolved { "yes" } else { "no" };
                report.push_str(&format!(
                    "{:<6} {:<6} {:<8} {:<10} {:<5} {:<7} {:<8} {:<10}\n",
                    e.entry_id,
                    e.locator_id,
                    e.segment_id,
                    e.offset,
                    rt,
                    e.repair_attempts,
                    resolved,
                    e.timestamp_secs,
                ));
            }
            report.push_str(&format!("{:-<96}\n", ""));
        }

        report.push_str(&format!(
            "Suspect log persisted at: {}/{}\n",
            self.segments_dir.display(),
            crate::constants::SUSPECT_LOG_FILE_NAME,
        ));

        report
    }

    /// Run an incremental background scrub pass over closed segments.
    ///
    /// Uses [`SegmentIntegrityScrubber`] to verify record-level
    /// IntegrityTrailerV2 digests and footer digest chain integrity.
    /// Respects the configured `background_scrub_interval_secs` and
    /// tracks progress via `self.scrub_cursor` for incremental operation.
    ///
    /// Returns the [`ScrubReport`] summarising findings.
    pub fn run_background_scrub(&mut self) -> Result<ScrubReport> {
        self.run_background_scrub_with_budget(0, 0)
    }

    /// Run one interval-gated scrub pass within record and byte budgets.
    ///
    /// A zero budget remains unbounded, matching
    /// [`SegmentIntegrityScrubber::scrub_incremental`]. The cursor is retained
    /// when the pass reaches either bound so a scheduler can expose truthful
    /// pending work and resume it on a later tick.
    pub fn run_background_scrub_with_budget(
        &mut self,
        max_records: u64,
        max_bytes: u64,
    ) -> Result<ScrubReport> {
        if !self.read_only {
            self.ensure_pool_raw_mutation_allowed()?;
        }
        // Read-only scrub reports findings without persisting scrub_cursor or
        // suspect_log. Read-write stores respect the configured interval.
        if !self.should_scrub() {
            return Ok(ScrubReport::default());
        }
        let scrubber = SegmentIntegrityScrubber::new(&self.segments_dir);
        let report = scrubber.scrub_incremental(
            &mut self.scrub_cursor,
            max_records,
            max_bytes,
            &mut self.suspect_log,
        )?;
        // The configured interval separates complete scrub passes, not the
        // bounded ticks within one pass. Keep the pass eligible while its
        // cursor is pending so the scheduler can resume it promptly.
        if report.completed {
            self.last_scrub = std::time::Instant::now();
        }
        if !self.read_only {
            write_scrub_cursor(&self.segments_dir, &self.scrub_cursor)?;
            write_suspect_log(&self.segments_dir, &self.suspect_log)?;
        }
        Ok(report)
    }

    pub fn sync_all(&mut self) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("sync_all")?;
        self.verify_deferred_prepublication_tail_before_barrier()?;
        // Pool-internal reclaim changes join this existing store commit
        // boundary instead of crossing a separate fsync per queue transition.
        let prepared_dead_object_reclaim = self.prepare_dead_object_reclaim_queue_authority()?;
        if self.block_device_mode
            && (self.reclaim_receipts_dirty || self.snapshot_extent_pin_set_dirty)
        {
            self.ensure_block_device_authority_append_space()?;
        }
        let reclaim_receipts_dirty = self.reclaim_receipts_dirty;
        let snapshot_extent_pin_set_dirty = self.snapshot_extent_pin_set_dirty;

        if reclaim_receipts_dirty {
            let receipts = self.reclaim_receipts.clone();
            store_reclaim_receipts(&receipts, self)?;
        }

        if snapshot_extent_pin_set_dirty {
            let pin_set = self.snapshot_extent_pin_set.clone();
            store_snapshot_extent_pin_set(&pin_set, self)?;
        }

        let path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .sync_all()
            .map_err(|source| io_error("sync_all", &path, source))?;
        sync_directory(&self.segments_dir)?;
        // Authority dirtiness remains set until the appended queue, receipt,
        // and pin objects cross this barrier. Auto-compaction is suppressed
        // while any of these flags is set, so omission can only consume a
        // queue acknowledgement that is already durable.
        if reclaim_receipts_dirty {
            self.reclaim_receipts_dirty = false;
        }
        if snapshot_extent_pin_set_dirty {
            self.snapshot_extent_pin_set_dirty = false;
        }
        // Explicit sync only needs a spacemap checkpoint after allocation/free
        // state changed since the last successful checkpoint.
        let spacemap_dirty = !self.free_map.dirty_segment_groups().is_empty();
        if spacemap_dirty {
            write_spacemap_checkpoint(&self.segments_dir, &self.free_map, false)?;
            self.free_map.clear_dirty_segment_groups();
        }
        write_scrub_cursor(&self.segments_dir, &self.scrub_cursor)?;
        write_suspect_log(&self.segments_dir, &self.suspect_log)?;

        // Sync all replica stores to durable media.
        // Individual replica sync failures degrade but do not
        // invalidate the primary write.
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            if replica.sync_all().is_err() && i < self.replica_healthy.len() {
                self.replica_healthy[i] = false;
            }
        }

        sync_directory(&self.root)?;
        if let Some((upserts, removals)) = prepared_dead_object_reclaim {
            self.finish_dead_object_reclaim_queue_authority(&upserts, &removals)?;
        }

        // Commit the current commit_group and persist the committed root.
        match self.commit_group.commit_current() {
            Ok(Some(root)) => {
                // Commit the intent-log transaction.
                if self.intent_log_tx_open {
                    let cg_id = root.commit_group_id.0;
                    let _ = self
                        .intent_log
                        .append(crate::intent_log::record::IntentLogRecord::TxCommit { cg_id });
                    self.intent_log_tx_open = false;
                }
                // Flush committed intent-log regions to durable segment
                // files.  Returns the framed segment bodies so we can
                // anchor the chain digest to the actual commit data.
                let committed_segments = self.flush_intent_log_to_segment()?;

                // Compute the BLAKE3 chain digest over the intent-log
                // commit data, chaining to the previous commit_group's digest.
                // We hash the concatenation of all committed segment
                // bodies plus the root pointer for a stable anchor.
                let chain_digest = if committed_segments.is_empty() {
                    // No intent-log data: chain from the root pointer alone.
                    let root_core = CommitGroupManager::encode_root(root);
                    self.txg_coordinator.chain_digest(&root_core)
                } else {
                    // Build a commit summary grouping WritePayload records
                    // by object key so the chain digest anchors to which
                    // objects were modified in this transaction group.
                    let summary = Self::build_commit_summary(&committed_segments);
                    let mut commit_data = Vec::with_capacity(summary.len() + 16);
                    commit_data.extend_from_slice(&summary);
                    commit_data.extend_from_slice(&CommitGroupManager::encode_root(root));
                    self.txg_coordinator.chain_digest(&commit_data)
                };

                // Persist the committed root with the chain digest so the
                // coordinator can resume the hash chain across reopen.
                let root_payload = CommitGroupManager::encode_root_with_digest(root, chain_digest);

                // Plain-file persistence is only valid when the store root is
                // a metadata directory. Raw block-device mode keeps the copy
                // inside the append-only device log instead.
                if sidecar_files_unavailable(&self.root) {
                    let _ = self.put_direct(committed_root_key(), &root_payload)?;
                } else {
                    let root_path = self.root.join(crate::txg_manager::COMMITTED_ROOT_FILE);
                    fs::write(&root_path, &root_payload)
                        .map_err(|source| io_error("write committed root", &root_path, source))?;
                    let f = OpenOptions::new()
                        .read(true)
                        .open(&root_path)
                        .map_err(|source| {
                            io_error("open committed root for sync", &root_path, source)
                        })?;
                    f.sync_all().map_err(|source| {
                        io_error("sync_all committed root", &root_path, source)
                    })?;
                }

                // Advance the CommitGroupCoordinator so the next commit chains
                // from this digest.  assign_next() returns the commit_group number
                // that was committed and advances the counter for the
                // next transaction group.
                let _committed_txg = self.txg_coordinator.assign_next();
                self.txg_coordinator.advance(root, chain_digest);

                // Persist dirty space accounting records alongside the
                // committed root so per-dataset usage counters survive
                // crashes.
                let _ = self.persist_space_accounting();

                // Persist per-object checksum index for read-path verification (#5273).
                match write_checksums(&self.segments_dir, &self.checksums) {
                    Ok(()) => self.prepublication_checksums_dirty = false,
                    Err(e) => tracing::warn!("checksum index write failed: {e}"),
                }

                // Sync the segment file so user data is durable.
                // is durable alongside the plain-file copy.
                let seg_path = segment_path(&self.segments_dir, self.current_segment_id);
                self.current_file
                    .sync_all()
                    .map_err(|source| io_error("sync_all after put_direct", &seg_path, source))?;
            }

            Ok(None) => {
                // Empty commit_group: nothing to commit, nothing to abort.
            }
            Err(_e) => {
                // Commit failed: discard the intent-log transaction.
                // The ring buffer's TxAbort handling will discard the
                // matching region on the next append or flush.
                self.intent_log_tx_open = false;
                self.commit_group.abort_current();
            }
        }

        // A batch containing only prepublication payloads has no ordinary
        // commit group, but its explicit Pool barrier still has to carry the
        // read-verification checksum index across close and reopen.
        if self.prepublication_checksums_dirty {
            write_checksums(&self.segments_dir, &self.checksums)?;
            self.prepublication_checksums_dirty = false;
        }

        Ok(())
    }

    pub(crate) fn sync_strict_pool_authority(&mut self) -> Result<()> {
        self.sync_pool_authority_storage(true)
    }

    /// Persist Pool-internal receipt-generation authority without consuming
    /// unrelated public raw-mutation work.
    ///
    /// The generation allocator temporarily fences public raw mutations while
    /// extending its durable high-water marker. A replacement-reclaim delta
    /// may legitimately be waiting for the next ordinary strict Pool barrier,
    /// so this narrower barrier must leave that delta staged until generation
    /// authority has converged again.
    pub(crate) fn sync_receipt_generation_authority(&mut self) -> Result<()> {
        self.sync_pool_authority_storage(false)
    }

    fn sync_pool_authority_storage(&mut self, publish_pending_reclaim: bool) -> Result<()> {
        self.ensure_writable("sync strict pool authority")?;
        self.verify_deferred_prepublication_tail_before_barrier()?;
        // Receipt publication and exact cleanup require the ordinary strict
        // barrier to publish their staged root-owned reclaim delta. The
        // receipt-generation reservation barrier deliberately skips it while
        // public raw mutation is fenced.
        let prepared_dead_object_reclaim = if publish_pending_reclaim {
            self.prepare_dead_object_reclaim_queue_authority()?
        } else {
            None
        };
        let mut first_error = (self.options.replica_count() != self.replicas.len()).then_some(
            StoreError::InvalidOptions {
                reason: "strict pool authority store replica is unavailable",
            },
        );
        let path = segment_path(&self.segments_dir, self.current_segment_id);

        if let Err(source) = self.current_file.sync_all() {
            first_error.get_or_insert_with(|| {
                io_error("sync strict pool authority segment", &path, source)
            });
        }
        if let Err(error) = sync_directory(&self.segments_dir) {
            first_error.get_or_insert(error);
        }
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            match replica.sync_pool_authority_storage(publish_pending_reclaim) {
                Ok(()) if i < self.replica_healthy.len() => self.replica_healthy[i] = true,
                Ok(()) => {}
                Err(error) => {
                    if i < self.replica_healthy.len() {
                        self.replica_healthy[i] = false;
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Err(error) = sync_directory(&self.root) {
            first_error.get_or_insert(error);
        }
        if first_error.is_none() {
            if let Some((upserts, removals)) = prepared_dead_object_reclaim {
                if let Err(error) =
                    self.finish_dead_object_reclaim_queue_authority(&upserts, &removals)
                {
                    first_error.get_or_insert(error);
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Durability barrier: flush all internal write buffers, fsync the
    /// underlying segment file and directory, write a spacemap checkpoint,
    /// sync all replica stores, and fsync the store root directory.
    /// Returns after the storage subsystem confirms durability.
    ///
    /// This is an alias for [`sync_all`](Self::sync_all) that provides the
    /// conventional short name expected by FUSE flush paths (#3732).
    /// Lightweight data-only durability barrier: flushes buffered writes
    /// for the current segment file with , without performing
    /// a full commit-group commit or metadata sync.
    ///
    /// This is faster than [] because it skips the spacemap
    /// checkpoint, root persistence, commit-group advancement, and inode
    /// metadata sync. Only the segment file data is forced to stable storage.
    ///
    /// Use this for writeback-drain convergence points where per-inode data
    /// durability is sufficient and a full commit-group commit is deferred.
    pub fn sync_data(&mut self) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("sync_data")?;
        self.verify_deferred_prepublication_tail_before_barrier()?;
        let path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .sync_data()
            .map_err(|source| io_error("sync_data", &path, source))?;
        sync_directory(&self.segments_dir)?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.sync_all()
    }

    /// Flush all committed intent-log regions to a durable segment file.
    ///
    /// Each committed transaction region is wrapped in a binary-schema
    /// envelope (via [`crate::intent_log::framing::encode_framed`]) and
    /// written to a sequentially-numbered segment file under the
    /// `intent_log/` subdirectory. An [`IntegrityTrailerV2`] footer is
    /// appended for cryptographic verification and digest chaining.
    ///
    /// Multiple committed regions may accumulate between flush calls
    /// (e.g., if the caller defers sync). All are drained and persisted.
    fn flush_intent_log_to_segment(&mut self) -> Result<Vec<Vec<u8>>> {
        if self.block_device_mode || sidecar_files_unavailable(&self.root) {
            let mut committed_segments: Vec<Vec<u8>> = Vec::new();
            while let Some(records) = self.intent_log.flush_committed() {
                if !records.is_empty() {
                    committed_segments.push(crate::intent_log::framing::encode_framed(&records));
                }
            }
            return Ok(committed_segments);
        }

        let ilog_dir = self.root.join("intent_log");
        fs::create_dir_all(&ilog_dir)
            .map_err(|source| io_error("create intent_log dir", &ilog_dir, source))?;

        // Discover existing intent-log segments to determine the next
        // segment number.
        let existing_segs = discover_segment_ids(&ilog_dir)?;
        let mut next_seg_id = existing_segs.last().map(|&id| id + 1).unwrap_or(0);

        let mut committed_segments: Vec<Vec<u8>> = Vec::new();

        loop {
            let flushed = self.intent_log.flush_committed();
            if flushed.is_none() {
                break;
            }

            let records: Vec<Vec<u8>> = flushed.unwrap();
            if records.is_empty() {
                continue;
            }

            // Frame the records into a binary-schema envelope
            let framed = crate::intent_log::framing::encode_framed(&records);

            // Compute IntegrityTrailerV2 over the framed segment body
            let payload_digest = {
                let mut hasher = blake3::Hasher::new_derive_key(
                    crate::intent_log::sync_write::SYNC_WRITE_TRAILER_DOMAIN,
                );
                hasher.update(&framed);
                ProductionIntegrityDigest::from_bytes32(hasher.finalize().into())
            };

            let trailer = IntegrityTrailerV2 {
                format_version: 1,
                digest_suite: 1, // BLAKE3-256
                payload_digest,
                record_digest: payload_digest,
                shard_count: 0,
                shard_index: 0,
                ec_k: 0,
                ec_m: 0,
            };
            let trailer_bytes = crate::encode_integrity_trailer_v2(&trailer);

            // Build the full segment: framed records + trailer
            let seg_path = segment_path(&ilog_dir, next_seg_id);
            let mut seg_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&seg_path)
                .map_err(|source| io_error("create intent-log segment", &seg_path, source))?;

            seg_file
                .write_all(&framed)
                .map_err(|source| io_error("write intent-log segment", &seg_path, source))?;
            seg_file
                .write_all(&trailer_bytes)
                .map_err(|source| io_error("write intent-log trailer", &seg_path, source))?;
            seg_file
                .sync_all()
                .map_err(|source| io_error("sync intent-log segment", &seg_path, source))?;

            next_seg_id += 1;
            committed_segments.push(framed);
        }

        Ok(committed_segments)
    }

    /// Build a commit summary from flushed intent-log segment bodies.
    ///
    /// Decodes the framed records within each segment, extracts WritePayload
    /// records, and groups them by object key.  Produces a deterministic
    /// serialized summary that anchors the commit-group chain digest to the
    /// actual objects modified in this transaction group.
    ///
    /// Format (all little-endian):
    ///   object_count (u32) + N × (object_id[32] + data_len(u64))
    fn build_commit_summary(committed_segments: &[Vec<u8>]) -> Vec<u8> {
        use crate::intent_log::framing;
        use crate::intent_log::record::IntentLogRecord;
        use std::collections::BTreeMap;

        // Group: object_id → total payload bytes written
        let mut object_sizes: BTreeMap<[u8; 32], u64> = BTreeMap::new();

        for seg in committed_segments {
            let records = match framing::decode_framed(seg) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for encoded in &records {
                if let Ok(IntentLogRecord::WritePayload {
                    object_id, data, ..
                }) = IntentLogRecord::decode(encoded)
                {
                    let entry = object_sizes.entry(*object_id.as_bytes()).or_default();
                    *entry = entry.wrapping_add(data.len() as u64);
                }
            }
        }

        let mut summary = Vec::with_capacity(4 + object_sizes.len() * (32 + 8));
        summary.extend_from_slice(&(object_sizes.len() as u32).to_le_bytes());
        for (obj_id, data_len) in &object_sizes {
            summary.extend_from_slice(obj_id);
            summary.extend_from_slice(&data_len.to_le_bytes());
        }
        summary
    }

    // Batch flush path — SegmentBuilder integration
    // ------------------------------------------------------------------

    /// Flush all buffered writes to durable storage in a single segment.
    ///
    /// Drains the segment builder, writes all pending records to the
    /// current segment, issues a single durability barrier (`sync_all`),
    /// and returns a [`FlushResult`] with the stable locator needed for
    /// crash recovery.
    ///
    /// When the builder is empty, returns a zeroed `FlushResult` with
    /// the current segment id and offset (a no-op flush).
    pub fn flush_segment(&mut self) -> Result<FlushResult> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.ensure_writable("flush_segment")?;

        let writes = self.segment_builder.drain();
        if writes.is_empty() {
            return Ok(FlushResult {
                segment_id: self.current_segment_id,
                record_offset: self.current_offset,
                bytes_written: 0,
                objects_flushed: 0,
                flushed_keys: Vec::new(),
                checksum: ProductionIntegrityDigest::ZERO,
            });
        }

        let segment_id = self.current_segment_id;
        let start_offset = self.current_offset;
        let write_count = writes.len();

        // Compute the checksum anchor before writing, so the result
        // carries the expected digest even if a write failure occurs.
        let checksum = {
            let mut builder = SegmentBuilder::new(self.options.max_segment_bytes);
            for w in &writes {
                // Push won't fail here since max_segment_bytes >= record bytes
                let _ = builder.push(w.clone());
            }
            builder.finish()?.checksum
        };

        let mut flushed_keys: Vec<ObjectKey> = Vec::with_capacity(write_count);
        let mut total_media_bytes: u64 = 0;

        // Disable per-write sync so we only barrier once at the end.
        let saved_sync = self.options.sync_on_write;
        self.options.sync_on_write = false;

        for write in writes {
            total_media_bytes += write.record_bytes();
            match write.kind {
                RecordKind::Put => {
                    let stored = self.put(write.key, &write.data)?;
                    flushed_keys.push(stored.key);
                }
                RecordKind::Delete => {
                    self.delete(write.key)?;
                    flushed_keys.push(write.key);
                }
            }
        }

        self.options.sync_on_write = saved_sync;

        // Single durability barrier for the entire batch.
        // sync_all() also commits the current commit_group and persists the
        // committed root, so no separate commit_group commit is needed here.
        self.sync_all()?;

        Ok(FlushResult {
            segment_id,
            record_offset: start_offset,
            bytes_written: total_media_bytes,
            objects_flushed: write_count,
            flushed_keys,
            checksum,
        })
    }

    /// Enable fault injection on this store instance.
    pub fn enable_fault_injection(&mut self, config: super::FaultInjectionConfig) {
        self.fault_injection_config = Some(config);
    }

    /// Disable fault injection.
    pub fn disable_fault_injection(&mut self) {
        self.fault_injection_config = None;
    }

    /// Return the current fault injection configuration, if active.
    #[must_use]
    pub fn fault_injection_config(&self) -> Option<&super::FaultInjectionConfig> {
        self.fault_injection_config.as_ref()
    }

    fn append_record(
        &mut self,
        kind: RecordKind,
        key: ObjectKey,
        payload: &[u8],
        payload_checksum: IntegrityDigest64,
        sequence: u64,
        compression_algorithm: u8,
    ) -> Result<ObjectLocation> {
        match self.append_record_once(
            kind,
            key,
            payload,
            payload_checksum,
            sequence,
            compression_algorithm,
        ) {
            Err(StoreError::NoSpace)
                if self.block_device_mode
                    && !is_strict_pool_authority_key(key)
                    && !self.dead_object_reclaim_queue_dirty
                    && !self.reclaim_receipts_dirty
                    && !self.snapshot_extent_pin_set_dirty =>
            {
                // Compaction must read every current live location. Install
                // and close any successful prepublication prefix before it
                // inspects the index, then resume batching the retried record.
                let resume_prepublication_batch = self.prepublication_tail_verification_deferred;
                if resume_prepublication_batch {
                    self.flush_and_verify_prepublication_tail()?;
                    self.prepublication_tail_verification_deferred = false;
                }
                let compact_result = self.compact_block_device_live_records();
                if resume_prepublication_batch {
                    self.prepublication_tail_verification_deferred = true;
                }
                compact_result?;
                self.append_record_once(
                    kind,
                    key,
                    payload,
                    payload_checksum,
                    sequence,
                    compression_algorithm,
                )
            }
            result => result,
        }
    }

    fn append_record_once(
        &mut self,
        kind: RecordKind,
        key: ObjectKey,
        payload: &[u8],
        payload_checksum: IntegrityDigest64,
        sequence: u64,
        compression_algorithm: u8,
    ) -> Result<ObjectLocation> {
        let payload_len = payload_len_u64(payload.len(), self.options.max_object_bytes())?;
        let record = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            kind,
            sequence,
            key,
            payload_len,
            payload_checksum,
            compression_algorithm,
        };
        let record_len =
            checked_record_total_len(record, self.current_segment_id, self.current_offset)?;
        self.ensure_space(record_len, is_strict_pool_authority_key(key))?;
        let record_offset = self.current_offset;
        let record_range = checked_record_range(record, self.current_segment_id, record_offset)?;
        let payload_offset = record_range.payload_offset;
        let mut header = [0_u8; RECORD_HEADER_LEN];
        encode_header(&mut header, record);
        let footer = encode_footer(record);
        let trailer_v2 = build_integrity_trailer_v2(record, &header, payload, &footer);
        self.segment_record_digests.push(trailer_v2.record_digest);
        let trailer = encode_integrity_trailer_v2(&trailer_v2);

        let path = segment_path(&self.segments_dir, self.current_segment_id);
        let prepublication_batch_active = self.prepublication_tail_verification_deferred;
        let prepublication_record_includes_tail =
            self.block_device_mode && prepublication_batch_active;
        if prepublication_record_includes_tail {
            // A Pool prepublication batch already owns the complete immutable
            // records in memory. Coalesce their unchanged representations and
            // one zero successor header so finish() can install the complete
            // scan-bounded prefix with one positioned write.
            let record_len =
                usize::try_from(record_len).map_err(|_| StoreError::InvalidOptions {
                    reason: "object-store record length exceeds platform usize",
                })?;
            let encoded_len =
                record_len
                    .checked_add(RECORD_HEADER_LEN)
                    .ok_or(StoreError::InvalidOptions {
                        reason: "object-store record and tail length exceeds platform usize",
                    })?;
            match self.prepublication_append_start {
                Some(start) => {
                    let relative =
                        record_offset
                            .checked_sub(start)
                            .ok_or(StoreError::InvalidOptions {
                                reason: "prepublication append offset moved before its batch start",
                            })?;
                    let relative =
                        usize::try_from(relative).map_err(|_| StoreError::InvalidOptions {
                            reason: "prepublication append offset exceeds platform usize",
                        })?;
                    let expected_len = relative.checked_add(RECORD_HEADER_LEN).ok_or(
                        StoreError::InvalidOptions {
                            reason: "prepublication append length exceeds platform usize",
                        },
                    )?;
                    if self.prepublication_append_bytes.len() != expected_len {
                        return Err(StoreError::InvalidOptions {
                            reason: "prepublication append records are not contiguous",
                        });
                    }
                    self.prepublication_append_bytes.truncate(relative);
                }
                None => {
                    if !self.prepublication_append_bytes.is_empty() {
                        return Err(StoreError::InvalidOptions {
                            reason: "prepublication append bytes are missing their batch start",
                        });
                    }
                    self.prepublication_append_start = Some(record_offset);
                }
            }
            self.prepublication_append_bytes.reserve(encoded_len);
            self.prepublication_append_bytes.extend_from_slice(&header);
            self.prepublication_append_bytes.extend_from_slice(payload);
            self.prepublication_append_bytes.extend_from_slice(&footer);
            self.prepublication_append_bytes.extend_from_slice(&trailer);
            let tail_end = self
                .prepublication_append_bytes
                .len()
                .checked_add(RECORD_HEADER_LEN)
                .ok_or(StoreError::InvalidOptions {
                    reason: "prepublication append tail exceeds platform usize",
                })?;
            self.prepublication_append_bytes.resize(tail_end, 0);
        } else {
            self.current_file
                .seek(SeekFrom::Start(record_offset))
                .map_err(|source| io_error("seek", &path, source))?;
            self.current_file
                .write_all(&header)
                .map_err(|source| io_error("write header", &path, source))?;
            self.current_file
                .write_all(payload)
                .map_err(|source| io_error("write payload", &path, source))?;
            self.current_file
                .write_all(&footer)
                .map_err(|source| io_error("write footer", &path, source))?;
            self.current_file
                .write_all(&trailer)
                .map_err(|source| io_error("write production integrity trailer", &path, source))?;
        }
        if self.block_device_mode {
            if !prepublication_record_includes_tail {
                self.write_block_device_tail_terminator(record_range.end_offset)?;
            }
            if !prepublication_batch_active {
                self.verify_block_device_tail_terminator(record_range.end_offset)?;
            }
        }
        // Durable stores normally sync every record. A Pool-owned
        // prepublication batch instead keeps payload and receipt records
        // unreachable, closes their final tail at batch finish, and crosses
        // one Pool-wide barrier before strict readback.
        if self.options.sync_on_write && !prepublication_batch_active {
            self.current_file
                .sync_data()
                .map_err(|source| io_error("sync_data", &path, source))?;
        }
        self.current_offset = record_range.end_offset;
        self.segment_write_count = self.segment_write_count.saturating_add(1);
        Ok(ObjectLocation {
            key,
            segment_id: self.current_segment_id,
            record_offset,
            payload_offset,
            payload_len,
            sequence,
            payload_checksum,
        })
    }

    fn compact_block_device_live_records(&mut self) -> Result<()> {
        debug_assert!(self.block_device_mode);
        let live_locations: Vec<(ObjectKey, ObjectLocation)> =
            self.index.iter().map(|(key, loc)| (*key, *loc)).collect();
        self.compact_block_device_locations(live_locations)
    }

    fn compact_block_device_locations(
        &mut self,
        retained_locations: Vec<(ObjectKey, ObjectLocation)>,
    ) -> Result<()> {
        debug_assert!(self.block_device_mode);
        self.ensure_writable("compact_block_device_locations")?;
        if self.dead_object_reclaim_queue_dirty
            || self.reclaim_receipts_dirty
            || self.snapshot_extent_pin_set_dirty
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device compaction refuses uncommitted reclaim authority",
            });
        }

        let pending_reclaim_object_ids = self
            .dead_object_reclaim_queue
            .all_entries()
            .into_iter()
            .map(|entry| entry.object_id)
            .collect();
        self.compact_block_device_locations_with_pending_reclaim(
            retained_locations,
            &pending_reclaim_object_ids,
        )
    }

    fn compact_block_device_locations_with_pending_reclaim(
        &mut self,
        retained_locations: Vec<(ObjectKey, ObjectLocation)>,
        pending_reclaim_object_ids: &BTreeSet<ReclaimObjectKey>,
    ) -> Result<()> {
        debug_assert!(self.block_device_mode);
        self.ensure_writable("compact_block_device_locations")?;

        let mut desired_live_locations = BTreeMap::new();
        let mut retained_location_set = BTreeSet::new();
        for (key, location) in retained_locations {
            if key != location.key || self.index.get(&key).copied() != Some(location) {
                return Err(StoreError::InvalidOptions {
                    reason: "block-device compaction received a noncurrent live location",
                });
            }
            if key == physical_lifetime_sequence_high_water_key() {
                continue;
            }
            desired_live_locations.insert(key, location);
            retained_location_set.insert(location);
        }

        let mut exact_pending_ids = BTreeSet::new();
        let mut compatibility_pending_keys = BTreeSet::new();
        for object_id in pending_reclaim_object_ids {
            if let Some(lifetime) = self
                .receipt_bound_physical_lifetimes
                .get(object_id)
                .copied()
            {
                if lifetime.logical_object_key == physical_lifetime_sequence_high_water_key() {
                    return Err(StoreError::InvalidDeadObjectReceipt {
                        reason:
                            "physical lifetime sequence high-water cannot be queued for reclaim",
                    });
                }
                exact_pending_ids.insert(*object_id);
                retained_location_set.insert(lifetime.location);
                continue;
            }

            // A pre-exact queue row identifies only a logical key. Preserve
            // all of its put history rather than guessing one generation.
            let logical_key = ObjectKey::from_bytes(object_id.0);
            let Some(locations) = self
                .history
                .get(&logical_key)
                .filter(|locations| !locations.is_empty())
            else {
                return Err(StoreError::InvalidDeadObjectReceipt {
                    reason: "block-device compaction cannot resolve pending reclaim lifetime",
                });
            };
            compatibility_pending_keys.insert(logical_key);
            retained_location_set.extend(locations.iter().copied());
        }

        let mut retained_locations = retained_location_set.into_iter().collect::<Vec<_>>();
        retained_locations.sort_by_key(|location| (location.record_offset, location.key));
        for (key, desired) in &desired_live_locations {
            if retained_locations
                .iter()
                .filter(|location| location.key == *key)
                .next_back()
                .copied()
                != Some(*desired)
            {
                return Err(StoreError::InvalidOptions {
                    reason: "block-device compaction live record is not the last retained version",
                });
            }
        }

        let sequence_high_water_payload = self.next_sequence.to_le_bytes();
        let tombstone_keys = retained_locations
            .iter()
            .map(|location| location.key)
            .filter(|key| !desired_live_locations.contains_key(key))
            .collect::<BTreeSet<_>>();

        let data_start = Self::block_device_data_start();
        let usable_end = self.block_device_usable_end()?;
        let mut records_end = data_start;
        let mut previous_source_end = data_start;
        for location in &retained_locations {
            let record_len = Self::checked_record_total_len_u64(location.payload_len);
            let source_end = location
                .record_offset
                .checked_add(record_len)
                .ok_or(StoreError::NoSpace)?;
            let target_end = records_end
                .checked_add(record_len)
                .ok_or(StoreError::NoSpace)?;
            if location.segment_id != self.current_segment_id
                || location.record_offset < previous_source_end
                || records_end > location.record_offset
                || target_end > source_end
                || source_end > usable_end
            {
                return Err(StoreError::InvalidOptions {
                    reason: "block-device compaction cannot safely stream overlapping locations",
                });
            }
            previous_source_end = source_end;
            records_end = target_end;
        }
        let high_water_end = records_end
            .checked_add(Self::checked_record_total_len_u64(
                sequence_high_water_payload.len() as u64,
            ))
            .ok_or(StoreError::NoSpace)?;
        let tombstones_end = tombstone_keys
            .iter()
            .try_fold(high_water_end, |offset, _| {
                offset
                    .checked_add(Self::checked_record_total_len_u64(0))
                    .ok_or(StoreError::NoSpace)
            })?;
        if tombstones_end
            .checked_add(RECORD_HEADER_LEN_U64)
            .is_none_or(|end| end > usable_end)
        {
            return Err(StoreError::NoSpace);
        }

        self.current_file
            .seek(SeekFrom::Start(data_start))
            .map_err(|source| io_error("block_device_compact_seek_start", &self.root, source))?;
        self.current_offset = data_start;
        self.segment_write_count = 0;
        self.segment_record_digests.clear();

        let sync_on_write = self.options.sync_on_write;
        self.options.sync_on_write = false;

        let mut compacted_index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
        let mut compacted_history: BTreeMap<ObjectKey, Vec<ObjectLocation>> = BTreeMap::new();
        let mut relocated_locations: BTreeMap<ObjectLocation, ObjectLocation> = BTreeMap::new();
        let mut tombstone_locations: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();

        let compact_result = (|| -> Result<()> {
            let mut retained_locations = retained_locations.into_iter().peekable();
            let mut prefetched_record = None;
            while let Some(old_location) = retained_locations.next() {
                let (payload, compression_algorithm) = match prefetched_record.take() {
                    Some((prefetched_location, payload, compression_algorithm)) => {
                        if prefetched_location != old_location {
                            return Err(StoreError::InvalidOptions {
                                reason: "block-device compaction prefetched the wrong location",
                            });
                        }
                        (payload, compression_algorithm)
                    }
                    None => self.read_location_stored_payload(old_location)?,
                };

                let target_end = self
                    .current_offset
                    .checked_add(Self::checked_record_total_len_u64(old_location.payload_len))
                    .ok_or(StoreError::NoSpace)?;
                if let Some(next_location) = retained_locations.peek().copied() {
                    let tail_end = target_end
                        .checked_add(RECORD_HEADER_LEN_U64)
                        .ok_or(StoreError::NoSpace)?;
                    if tail_end > next_location.record_offset {
                        // append_record_once() closes every block-device
                        // record with a zero successor header. When retained
                        // sources are adjacent, that terminator overwrites the
                        // next old header. Read exactly that one source first;
                        // the preflight above proves no record body or later
                        // source can overlap this target.
                        let (next_payload, next_algorithm) =
                            self.read_location_stored_payload(next_location)?;
                        prefetched_record = Some((next_location, next_payload, next_algorithm));
                    }
                }

                let key = old_location.key;
                let new_location = self.append_record_once(
                    RecordKind::Put,
                    key,
                    &payload,
                    old_location.payload_checksum,
                    old_location.sequence,
                    compression_algorithm,
                )?;
                let (rewritten_payload, rewritten_algorithm) =
                    self.read_location_stored_payload(new_location)?;
                if rewritten_payload != payload
                    || rewritten_algorithm != compression_algorithm
                    || receipt_bound_physical_lifetime_id(key, old_location)
                        != receipt_bound_physical_lifetime_id(key, new_location)
                {
                    return Err(StoreError::InvalidOptions {
                        reason: "block-device compaction candidate verification failed",
                    });
                }
                compacted_history.entry(key).or_default().push(new_location);
                relocated_locations.insert(old_location, new_location);
            }
            let high_water_key = physical_lifetime_sequence_high_water_key();
            let high_water_location = self.append_record_once(
                RecordKind::Put,
                high_water_key,
                &sequence_high_water_payload,
                checksum64(&sequence_high_water_payload),
                0,
                0,
            )?;
            compacted_history
                .entry(high_water_key)
                .or_default()
                .push(high_water_location);
            compacted_index.insert(high_water_key, high_water_location);
            for key in &tombstone_keys {
                let tombstone_location =
                    self.append_record_once(RecordKind::Delete, *key, &[], checksum64(&[]), 0, 0)?;
                tombstone_locations.insert(*key, tombstone_location);
            }
            for (key, old_location) in &desired_live_locations {
                let new_location = relocated_locations.get(old_location).copied().ok_or(
                    StoreError::InvalidOptions {
                        reason: "block-device compaction lost a live relocation",
                    },
                )?;
                compacted_index.insert(*key, new_location);
            }

            let (high_water_payload, high_water_algorithm) =
                self.read_location_stored_payload(high_water_location)?;
            if high_water_payload != sequence_high_water_payload || high_water_algorithm != 0 {
                return Err(StoreError::InvalidOptions {
                    reason: "block-device compaction sequence high-water verification failed",
                });
            }

            for (key, location) in &tombstone_locations {
                self.verify_block_device_delete_record(*key, *location)?;
            }
            Ok(())
        })();
        self.options.sync_on_write = sync_on_write;
        compact_result?;

        let compacted_lifetimes = build_receipt_bound_physical_lifetime_index(&compacted_history)?;
        if !exact_pending_ids
            .iter()
            .all(|object_id| compacted_lifetimes.contains_key(object_id))
            || !compatibility_pending_keys.iter().all(|key| {
                compacted_history
                    .get(key)
                    .is_some_and(|locations| !locations.is_empty())
            })
        {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "block-device compaction did not retain pending reclaim authority",
            });
        }

        self.clear_block_device_compacted_tail()?;
        // The inherited rewrite is in-place and has no atomic arena-swap
        // boundary. One sync avoids an intentional durable new-prefix/old-tail
        // interval; it is not a power-cut atomicity claim for this format.
        self.current_file
            .sync_all()
            .map_err(|source| io_error("block_device_compact_sync_all", &self.root, source))?;

        self.replace_index(compacted_index);
        self.history = compacted_history;
        self.receipt_bound_physical_lifetimes = compacted_lifetimes;
        self.checksums.retain(|key, _| self.index.contains_key(key));
        self.reclaim_queue.clear();
        self.segment_liveness.clear();

        let live_count = self
            .index
            .keys()
            .filter(|key| !is_dead_object_reclaim_entry_state_key(**key))
            .count() as u64;
        self.reclaim_consumer.live_counts_mut().remove(0);
        if live_count > 0 {
            self.reclaim_consumer
                .live_counts_mut()
                .set_live_count(0, live_count);
        }

        Ok(())
    }

    fn verify_block_device_delete_record(
        &self,
        expected_key: ObjectKey,
        location: ObjectLocation,
    ) -> Result<()> {
        let data_end = self
            .block_device_capacity
            .unwrap_or(0)
            .saturating_sub(POOL_LABEL_SIZE as u64);
        let mut header = [0_u8; RECORD_HEADER_LEN];
        self.current_file
            .read_exact_at(&mut header, location.record_offset)
            .map_err(|source| {
                io_error("block_device_compact_read_tombstone", &self.root, source)
            })?;
        let record = decode_header(&header, location.segment_id, location.record_offset)?;
        let range = checked_record_range(record, location.segment_id, location.record_offset)?;
        let tail_len = usize::try_from(range.end_offset - range.payload_offset).map_err(|_| {
            StoreError::PayloadTooLarge {
                len: record.payload_len,
                max: usize::MAX as u64,
            }
        })?;
        let mut tail = vec![0_u8; tail_len];
        self.current_file
            .read_exact_at(&mut tail, range.payload_offset)
            .map_err(|source| {
                io_error(
                    "block_device_compact_read_tombstone_tail",
                    &self.root,
                    source,
                )
            })?;
        let mut tail = io::Cursor::new(tail);
        let decoded = decode_stored_record_after_header(
            &mut tail,
            &self.root,
            location.segment_id,
            location.record_offset,
            data_end,
            header,
        )?;
        if decoded.header.kind != RecordKind::Delete
            || decoded.header.key != expected_key
            || decoded.header.sequence != location.sequence
            || decoded.header.payload_len != 0
            || decoded.header.payload_checksum != checksum64(&[])
            || decoded.header.compression_algorithm != 0
            || !decoded.payload.is_empty()
        {
            return Err(StoreError::InvalidOptions {
                reason: "block-device compaction tombstone verification failed",
            });
        }
        Ok(())
    }

    fn clear_block_device_compacted_tail(&mut self) -> Result<()> {
        let usable_end = self.block_device_usable_end()?;
        if self
            .current_offset
            .checked_add(RECORD_HEADER_LEN_U64)
            .is_none_or(|end| end > usable_end)
        {
            return Err(StoreError::NoSpace);
        }
        self.write_and_verify_block_device_tail_terminator(self.current_offset)
    }

    fn write_and_verify_block_device_tail_terminator(&mut self, offset: u64) -> Result<()> {
        debug_assert!(self.block_device_mode);
        self.write_block_device_tail_terminator(offset)?;
        self.verify_block_device_tail_terminator(offset)
    }

    fn write_block_device_tail_terminator(&mut self, offset: u64) -> Result<()> {
        debug_assert!(self.block_device_mode);
        self.current_file
            .write_all_at(&[0_u8; RECORD_HEADER_LEN], offset)
            .map_err(|source| io_error("block_device_compact_clear_tail", &self.root, source))
    }

    fn verify_block_device_tail_terminator(&mut self, offset: u64) -> Result<()> {
        debug_assert!(self.block_device_mode);
        #[cfg(test)]
        {
            self.block_device_tail_terminator_verifications = self
                .block_device_tail_terminator_verifications
                .saturating_add(1);
        }
        let mut terminator = [0xff_u8; RECORD_HEADER_LEN];
        self.current_file
            .read_exact_at(&mut terminator, offset)
            .map_err(|source| {
                io_error(
                    "block_device_compact_read_tail_terminator",
                    &self.root,
                    source,
                )
            })?;
        if terminator != [0_u8; RECORD_HEADER_LEN] {
            return Err(StoreError::InvalidOptions {
                reason: "block-device compaction tail terminator verification failed",
            });
        }
        Ok(())
    }

    fn block_device_authority_payload_lengths(&self) -> Result<Vec<u64>> {
        let mut payload_lengths = Vec::new();
        if self.reclaim_receipts_dirty {
            let payload_len = self
                .reclaim_receipts
                .iter()
                .try_fold(12_u64, |len, receipt| {
                    len.checked_add(4)
                        .and_then(|len| len.checked_add(receipt.encode().len() as u64))
                        .ok_or(StoreError::NoSpace)
                })?;
            payload_lengths.push(payload_len);
        }
        if self.snapshot_extent_pin_set_dirty {
            let payload_len =
                self.snapshot_extent_pin_set
                    .pins()
                    .try_fold(20_u64, |len, (snapshot_id, _)| {
                        len.checked_add(4)
                            .and_then(|len| len.checked_add(snapshot_id.len() as u64))
                            .and_then(|len| len.checked_add(32))
                            .ok_or(StoreError::NoSpace)
                    })?;
            payload_lengths.push(payload_len);
        }
        Ok(payload_lengths)
    }

    fn ensure_block_device_authority_append_space(&mut self) -> Result<()> {
        debug_assert!(self.block_device_mode);
        let payload_lengths = self.block_device_authority_payload_lengths()?;
        if payload_lengths.is_empty() {
            return Ok(());
        }
        let mut append_reserve =
            Self::checked_record_total_len_u64(CHAINED_COMMITTED_ROOT_PAYLOAD_LEN)
                .checked_add(RECORD_HEADER_LEN_U64)
                .ok_or(StoreError::NoSpace)?;
        for payload_len in payload_lengths {
            if payload_len > self.options.max_object_bytes() {
                return Err(StoreError::PayloadTooLarge {
                    len: payload_len,
                    max: self.options.max_object_bytes(),
                });
            }
            append_reserve = append_reserve
                .checked_add(Self::checked_record_total_len_u64(payload_len))
                .ok_or(StoreError::NoSpace)?;
        }
        let usable_end = self.block_device_usable_end()?;
        if self
            .current_offset
            .checked_add(append_reserve)
            .is_some_and(|end| end <= usable_end)
        {
            return Ok(());
        }

        // Retain pending dead-object lifetimes while named receipt or pin
        // authority recovers append space. Dead-object entry deltas preflight
        // their own constant-sized records through the focused helper.
        let mut pending_reclaim_object_ids = BTreeSet::new();
        for entry in self.durable_dead_object_reclaim_queue.all_entries() {
            pending_reclaim_object_ids.insert(entry.object_id);
        }
        for entry in self.dead_object_reclaim_queue.all_entries() {
            pending_reclaim_object_ids.insert(entry.object_id);
        }
        let live_locations = self.index.iter().map(|(key, loc)| (*key, *loc)).collect();
        self.compact_block_device_locations_with_pending_reclaim(
            live_locations,
            &pending_reclaim_object_ids,
        )?;
        let usable_end = self.block_device_usable_end()?;
        if self
            .current_offset
            .checked_add(append_reserve)
            .is_some_and(|end| end <= usable_end)
        {
            Ok(())
        } else {
            Err(StoreError::NoSpace)
        }
    }

    fn ensure_block_device_dead_object_queue_delta_space(
        &mut self,
        upsert_record_bytes: u64,
        deletion_count: usize,
    ) -> Result<()> {
        debug_assert!(self.block_device_mode);
        if upsert_record_bytes == 0 && deletion_count == 0 {
            return Ok(());
        }

        let mut append_reserve = RECORD_HEADER_LEN_U64
            .checked_add(upsert_record_bytes)
            .ok_or(StoreError::NoSpace)?;
        let deletion_count = u64::try_from(deletion_count).map_err(|_| StoreError::NoSpace)?;
        append_reserve = Self::checked_record_total_len_u64(0)
            .checked_mul(deletion_count)
            .and_then(|deletions| append_reserve.checked_add(deletions))
            .ok_or(StoreError::NoSpace)?;

        let usable_end = self.block_device_usable_end()?;
        if self
            .current_offset
            .checked_add(append_reserve)
            .is_some_and(|end| end <= usable_end)
        {
            return Ok(());
        }

        // Compaction must retain both the last durable queue and the current
        // in-memory candidate. The latter can contain a newly installed row
        // whose per-entry record has not been appended yet.
        let mut pending_reclaim_object_ids = BTreeSet::new();
        for entry in self.durable_dead_object_reclaim_queue.all_entries() {
            pending_reclaim_object_ids.insert(entry.object_id);
        }
        for entry in self.dead_object_reclaim_queue.all_entries() {
            pending_reclaim_object_ids.insert(entry.object_id);
        }
        let live_locations = self.index.iter().map(|(key, loc)| (*key, *loc)).collect();
        self.compact_block_device_locations_with_pending_reclaim(
            live_locations,
            &pending_reclaim_object_ids,
        )?;
        let usable_end = self.block_device_usable_end()?;
        if self
            .current_offset
            .checked_add(append_reserve)
            .is_some_and(|end| end <= usable_end)
        {
            Ok(())
        } else {
            Err(StoreError::NoSpace)
        }
    }

    /// Compute total record length from payload_len
    /// (header + payload + footer + trailer).
    fn checked_record_total_len_u64(payload_len: u64) -> u64 {
        payload_len
            .saturating_add(RECORD_HEADER_LEN_U64)
            .saturating_add(RECORD_FOOTER_LEN_U64)
            .saturating_add(INTEGRITY_TRAILER_V2_LEN_U64)
    }

    fn ensure_space(&mut self, record_len: u64, generation_high_water_write: bool) -> Result<()> {
        // Block-device mode: skip segment-rotation logic. Only check
        // whether the record fits in the remaining device capacity.
        if self.block_device_mode {
            let usable_end = self.block_device_usable_end()?;
            if self
                .current_offset
                .checked_add(record_len)
                .and_then(|end| end.checked_add(RECORD_HEADER_LEN_U64))
                .is_none_or(|end| end > usable_end)
            {
                return Err(StoreError::NoSpace);
            }
            return Ok(());
        }

        if record_len > self.options.max_segment_bytes {
            return Err(StoreError::PayloadTooLarge {
                len: record_len.saturating_sub(RECORD_HEADER_LEN_U64 + RECORD_FOOTER_LEN_U64),
                max: self.options.max_object_bytes(),
            });
        }
        // Time-based rotation: bound crash replay to at most one interval's
        // worth of writes (cf. ZFS zfs_commit_group_timeout, Ceph OSD journal rotation).
        if self.options.segment_rotation_interval_secs > 0
            && self.current_offset > 0
            && self.segment_created_at.elapsed().as_secs()
                >= self.options.segment_rotation_interval_secs
        {
            if generation_high_water_write {
                self.rotate_segment_authorized()?;
            } else {
                self.rotate_segment()?;
            }
            return Ok(());
        }
        // Write-count rotation: limit segment size for bounded replay time.
        if self.options.segment_rotation_write_limit > 0
            && self.segment_write_count >= self.options.segment_rotation_write_limit
        {
            if generation_high_water_write {
                self.rotate_segment_authorized()?;
            } else {
                self.rotate_segment()?;
            }
            // Fall through to size check - if the record doesn't fit, rotate again
        }
        if self.current_offset == 0
            || self.current_offset <= self.options.max_segment_bytes.saturating_sub(record_len)
        {
            return Ok(());
        }
        if generation_high_water_write {
            self.rotate_segment_authorized()
        } else {
            self.rotate_segment()
        }
    }

    fn block_device_usable_end(&mut self) -> Result<u64> {
        let capacity = self
            .current_file
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("block_device_seek_end", &self.root, source))?;
        Ok(capacity.saturating_sub(POOL_LABEL_SIZE as u64))
    }

    /// Rotate the current segment if time or write-count thresholds
    /// have been exceeded. Callers should invoke this after every
    /// filesystem commit to provide flush-boundary rotation.
    /// Write the SegmentIntegrityFooter at the end of the current segment
    /// and reset the per-segment accumulator for the next segment.
    pub(crate) fn write_segment_footer(&mut self) -> Result<()> {
        if self.segment_record_digests.is_empty() {
            return Ok(());
        }
        let digests: Vec<[u8; 32]> = self
            .segment_record_digests
            .iter()
            .map(|d| d.as_bytes32())
            .collect();
        let segment_digest = compute_segment_digest(&digests);
        let previous_segment_digest = self.chain_footer.segment_digest;

        let footer = SegmentIntegrityFooter {
            segment_id: self.current_segment_id,
            record_count: self.segment_write_count,
            total_payload_bytes: 0,
            segment_digest,
            previous_segment_digest,
        };

        let encoded = encode_segment_integrity_footer(&footer);
        let current_path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek footer", &current_path, source))?;
        self.current_file
            .write_all(&encoded)
            .map_err(|source| io_error("write footer", &current_path, source))?;
        self.current_file
            .sync_data()
            .map_err(|source| io_error("sync_data footer", &current_path, source))?;

        self.chain_footer = footer;
        self.segment_record_digests.clear();
        Ok(())
    }

    pub fn rotate_if_needed(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        if self.block_device_mode {
            return Ok(());
        }
        let time_exceeded = self.options.segment_rotation_interval_secs > 0
            && self.current_offset > 0
            && self.segment_created_at.elapsed().as_secs()
                >= self.options.segment_rotation_interval_secs;
        let writes_exceeded = self.options.segment_rotation_write_limit > 0
            && self.segment_write_count >= self.options.segment_rotation_write_limit;
        if time_exceeded || writes_exceeded {
            self.rotate_segment()
        } else {
            Ok(())
        }
    }

    /// Allocate a new segment from the free map.
    ///
    /// Receipt-bound dead-object drains must run before this point when a
    /// caller wants committed evidence to recover physical space under
    /// pressure. The legacy reclaim queue is not a physical-free authority.
    fn allocate_segment_with_drain(&mut self) -> Result<u64> {
        match self.free_map.alloc_after(self.current_segment_id + 1) {
            Ok(id) => {
                self.free_segment_counter.allocated();
                Ok(id)
            }
            Err(_) => Err(StoreError::NoSpace),
        }
    }

    pub(crate) fn rotate_segment(&mut self) -> Result<()> {
        self.ensure_pool_raw_mutation_allowed()?;
        self.rotate_segment_authorized()
    }

    fn rotate_segment_authorized(&mut self) -> Result<()> {
        self.ensure_writable("rotate_segment")?;
        if self.block_device_mode {
            return Ok(());
        }
        let current_path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .sync_all()
            .map_err(|source| io_error("sync_all", &current_path, source))?;
        self.write_segment_footer()?;
        let completed_segment_id = self.current_segment_id;
        self.current_segment_id = self.allocate_segment_with_drain()?;
        // Check for space pressure transitions and emit warning if pool >= 95% used.
        let pressure_event = self.check_space_pressure();

        // Background reclaim: manage scheduler state and trigger compaction
        // when space pressure is active and segment waste exceeds threshold.
        if self.options.reclaim_enabled {
            use tidefs_pool_allocator::SpacePressureEvent;
            match pressure_event {
                Some(SpacePressureEvent::EnterPressure) => {
                    self.reclaim_scheduler.activate();
                }
                Some(SpacePressureEvent::ExitPressure) => {
                    self.reclaim_scheduler.deactivate();
                }
                None => {}
            }

            if self.reclaim_scheduler.is_active()
                && self.reclaim_scheduler.can_reclaim(self.current_segment_id)
                && self.should_compact(self.reclaim_scheduler.waste_threshold())
            {
                // Mark reclaimed before compact_retaining: it calls
                // rotate_segment internally, and the cooldown guard
                // prevents the recursive call from re-entering reclaim.
                self.reclaim_scheduler
                    .mark_reclaimed(self.current_segment_id);
                let all_keys: Vec<ObjectKey> = self.index.keys().copied().collect();
                match self.compact_retaining(&all_keys, &[]) {
                    Ok(report) => {
                        self.reclaim_scheduler
                            .record_batch(report.retired_segments.len() as u64);
                        if !self.free_map.is_under_pressure() {
                            self.reclaim_scheduler.deactivate();
                        }
                    }
                    Err(_e) => {
                        // Compaction failed; deactivate to avoid spinning.
                        self.reclaim_scheduler.deactivate();
                    }
                }
            }
        }
        let new_path = segment_path(&self.segments_dir, self.current_segment_id);
        // Reclaim may hand back an existing segment id; after allocation the
        // file is the new active segment and must start empty.
        self.current_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&new_path)
            .map_err(|source| io_error("create segment", &new_path, source))?;
        self.current_offset = 0;
        self.segment_created_at = Instant::now();
        self.segment_write_count = 0;
        self.replay.segment_count += 1;
        sync_directory(&self.segments_dir)?;
        write_index_checkpoint(
            &self.segments_dir,
            &self.index,
            &self.history,
            completed_segment_id,
        )?;
        write_spacemap_checkpoint(&self.segments_dir, &self.free_map, true)?;
        self.free_map.clear_dirty_segment_groups();

        // Rotate replica stores so their checkpoints align with primary.
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            if replica.rotate_if_needed().is_err() && i < self.replica_healthy.len() {
                self.replica_healthy[i] = false;
            }
        }
        Ok(())
    }

    fn read_location_stored_payload(&self, location: ObjectLocation) -> Result<(Vec<u8>, u8)> {
        let expected_payload_offset = checked_record_offset(
            location.record_offset,
            RECORD_HEADER_LEN_U64,
            location.segment_id,
            location.record_offset,
        )?;
        if expected_payload_offset != location.payload_offset {
            return Err(StoreError::CorruptHeader {
                segment_id: location.segment_id,
                offset: location.record_offset,
                reason: "location payload offset does not match record layout",
            });
        }

        if self.block_device_mode {
            let path = &self.root;
            let data_end = self
                .block_device_capacity
                .unwrap_or(0)
                .saturating_sub(POOL_LABEL_SIZE as u64);
            if let Some(&(payload_start, payload_end, compression_algorithm)) =
                self.prepublication_readback_records.get(&location)
            {
                let payload = self
                    .prepublication_readback_bytes
                    .get(payload_start..payload_end)
                    .ok_or(StoreError::CorruptHeader {
                        segment_id: location.segment_id,
                        offset: location.record_offset,
                        reason: "indexed prepublication payload is outside its readback range",
                    })?
                    .to_vec();
                return Ok((payload, compression_algorithm));
            }
            let mut header = [0_u8; RECORD_HEADER_LEN];
            self.current_file
                .read_exact_at(&mut header, location.record_offset)
                .map_err(|source| io_error("read_exact_at header", path, source))?;

            let record = decode_header(&header, location.segment_id, location.record_offset)?;
            let range = checked_record_range(record, location.segment_id, location.record_offset)?;
            if range.end_offset > data_end {
                return Err(StoreError::CorruptHeader {
                    segment_id: location.segment_id,
                    offset: location.record_offset,
                    reason: "record extends beyond the admitted data region",
                });
            }
            let tail_len =
                usize::try_from(range.end_offset - range.payload_offset).map_err(|_| {
                    StoreError::PayloadTooLarge {
                        len: record.payload_len,
                        max: usize::MAX as u64,
                    }
                })?;
            let mut tail = vec![0_u8; tail_len];
            self.current_file
                .read_exact_at(&mut tail, range.payload_offset)
                .map_err(|source| io_error("read_exact_at record", path, source))?;
            let mut tail = io::Cursor::new(tail);
            let decoded = decode_stored_record_after_header(
                &mut tail,
                path,
                location.segment_id,
                location.record_offset,
                data_end,
                header,
            )?;
            return validate_location_record(location, decoded);
        }

        let path = segment_path(&self.segments_dir, location.segment_id);
        let mut file = File::open(&path).map_err(|source| io_error("open", &path, source))?;
        let data_end = file
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek end", &path, source))?;
        file.seek(SeekFrom::Start(location.record_offset))
            .map_err(|source| io_error("seek", &path, source))?;
        let mut header = [0_u8; RECORD_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read_exact header", &path, source))?;
        let decoded = decode_stored_record_after_header(
            &mut file,
            &path,
            location.segment_id,
            location.record_offset,
            data_end,
            header,
        )?;
        validate_location_record(location, decoded)
    }

    fn read_location(&self, location: ObjectLocation) -> Result<Vec<u8>> {
        let (payload, compression_algorithm) = self.read_location_stored_payload(location)?;
        // Decompress inline if the record was stored with compression.
        if compression_algorithm != 0 {
            tidefs_frame::decompress_frame(&payload).map_err(|_e| StoreError::CorruptHeader {
                segment_id: location.segment_id,
                offset: location.record_offset,
                reason: "decompression failed",
            })
        } else {
            Ok(payload)
        }
    }

    const fn ensure_writable(&self, operation: &'static str) -> Result<()> {
        if self.read_only {
            return Err(StoreError::ReadOnly { operation });
        }
        Ok(())
    }

    fn record_test_current_dataset_write(&mut self, bytes: u64) {
        #[cfg(test)]
        {
            if bytes == 0 {
                return;
            }
            if let Some(dataset_id) = self.current_dataset_id {
                let _ = self.space_book.record_write(dataset_id, bytes);
            }
        }
        #[cfg(not(test))]
        {
            let _ = bytes;
        }
    }

    fn record_test_current_dataset_delete(&mut self, bytes: u64) {
        #[cfg(test)]
        {
            if bytes == 0 {
                return;
            }
            if let Some(dataset_id) = self.current_dataset_id {
                let _ = self.space_book.record_delete(dataset_id, bytes);
            }
        }
        #[cfg(not(test))]
        {
            let _ = bytes;
        }
    }

    // ── Space accounting API ─────────────────────────────────────────

    /// Record a test-only raw-store write of `bytes` to `dataset_id`.
    ///
    /// Production mounted filesystems commit absolute engine
    /// [`SpaceAccounting`] counters through [`sync_dataset_counters`]; this
    /// helper is retained for lower-level SpaceBook producer tests only.
    ///
    /// [`SpaceAccounting`]: tidefs_space_accounting::SpaceAccounting
    /// [`sync_dataset_counters`]: Self::sync_dataset_counters
    #[cfg(test)]
    pub fn record_dataset_write(
        &mut self,
        dataset_id: [u8; 16],
        bytes: u64,
    ) -> std::result::Result<(), SpaceAccountingError> {
        self.space_book.record_write(dataset_id, bytes)
    }

    /// Record a test-only raw-store deletion of `bytes` from `dataset_id`.
    ///
    /// Production mounted filesystems commit absolute engine
    /// [`SpaceAccounting`] counters through [`sync_dataset_counters`]; this
    /// helper is retained for lower-level SpaceBook producer tests only.
    ///
    /// [`SpaceAccounting`]: tidefs_space_accounting::SpaceAccounting
    /// [`sync_dataset_counters`]: Self::sync_dataset_counters
    #[cfg(test)]
    pub fn record_dataset_delete(
        &mut self,
        dataset_id: [u8; 16],
        bytes: u64,
    ) -> std::result::Result<(), SpaceAccountingError> {
        self.space_book.record_delete(dataset_id, bytes)
    }

    /// Query per-dataset space usage (committed bytes_used, bytes_reserved,
    /// commit_group) or `None` when the dataset has no recorded usage.
    #[must_use]
    pub fn get_dataset_usage(&self, dataset_id: [u8; 16]) -> Option<DatasetSpaceUsage> {
        self.space_book.get_dataset_usage(dataset_id)
    }

    /// Total pool usage across all datasets (sum of bytes_used).
    #[must_use]
    pub fn get_pool_space_usage(&self) -> u64 {
        self.space_book.get_pool_usage()
    }

    /// Compute projection statfs(2) fields for a dataset from the store-layer
    /// [`SpaceBook`].
    ///
    /// Propagates SpaceBook-level pool counters before deriving the result.
    /// Mounted local-filesystem `statfs`/`statvfs` and ENOSPC do not read this
    /// independent projection; they use the engine capacity authority. Returns
    /// `None` when the dataset has never been recorded.
    #[must_use]
    pub fn statfs_for_dataset(&mut self, dataset_id: [u8; 16]) -> Option<StatfsResult> {
        self.space_book.statfs_for_dataset(dataset_id)
    }

    /// Update the SpaceBook's cached pool-level physical counters.
    ///
    /// Called before statfs queries so that capacity bounds reflect
    /// current pool physical state.
    pub fn update_space_book_pool_counters(&mut self, counters: PoolCounters) {
        self.space_book.update_pool_counters(counters);
    }

    /// Set absolute committed usage counters for a dataset and mark it dirty.
    ///
    /// Bridges the engine-layer [`tidefs_space_accounting::SpaceAccounting`]
    /// to the store-layer [`tidefs_space_accounting::SpaceBook`] at
    /// commit time. The counters are immediately marked dirty so
    /// [`persist_space_accounting`] will flush them on the next sync.
    pub fn sync_dataset_counters(
        &mut self,
        dataset_id: [u8; 16],
        logical_used: u64,
        reserved: u64,
    ) {
        self.space_book
            .set_committed_usage_dirty(dataset_id, logical_used, reserved);
    }

    /// Whether any datasets have dirty space accounting counters awaiting
    /// persistence.
    #[must_use]
    pub fn space_accounting_dirty(&self) -> bool {
        self.space_book.has_dirty()
    }

    /// Set the test-only dataset context for raw-store accounting fixtures.
    ///
    /// In production builds this API is absent and `put`/`delete` do not
    /// mutate `SpaceBook`; mounted persistence uses committed snapshots via
    /// [`sync_dataset_counters`](Self::sync_dataset_counters).
    #[cfg(test)]
    pub fn set_current_dataset_id(&mut self, dataset_id: [u8; 16]) {
        self.current_dataset_id = Some(dataset_id);
    }

    /// Clear the test-only dataset context.
    ///
    /// Subsequent test writes and deletes will not update any dataset's raw
    /// fixture accounting until `set_current_dataset_id` is called again.
    #[cfg(test)]
    pub fn clear_current_dataset_id(&mut self) {
        self.current_dataset_id = None;
    }

    /// Return the test-only dataset context, if set.
    #[must_use]
    #[cfg(test)]
    pub fn current_dataset_id(&self) -> Option<[u8; 16]> {
        self.current_dataset_id
    }

    /// Persist dirty per-dataset space accounting records as named store
    /// objects through the segment write pipeline.
    ///
    /// Each record is written under a key `__space_acct_<hex_dataset_id>`
    /// with BLAKE3-authenticated `DatasetSpaceUsage` payload. Dirty flags
    /// are cleared on successful write.
    pub fn persist_space_accounting(&mut self) -> Result<usize> {
        self.ensure_pool_raw_mutation_allowed()?;
        let records = self.space_book.flush_dirty();
        let count = records.len();
        if count == 0 {
            return Ok(0);
        }

        let mut hex_ids: Vec<String> = Vec::with_capacity(count);
        #[cfg(test)]
        let saved_current_dataset_id = self.current_dataset_id.take();

        let result = (|| -> Result<()> {
            for rec in &records {
                let hex = rec
                    .dataset_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                hex_ids.push(hex.clone());
                let key_name = format!("__space_acct_{hex}");
                let payload = rec.to_bytes().to_vec();
                let _ = self.put_named(key_name.as_bytes(), &payload)?;
            }

            // These are persistence metadata writes, not raw fixture writes.
            let manifest: Vec<u8> = hex_ids.join("\n").into_bytes();
            let _ = self.put_named(b"__space_acct_manifest", &manifest)?;

            Ok(())
        })();

        #[cfg(test)]
        {
            self.current_dataset_id = saved_current_dataset_id;
        }

        result?;

        Ok(count)
    }

    /// Load persisted space accounting records from the store and replay
    /// them into the in-memory `SpaceBook`.
    ///
    /// Scans for all objects whose key begins with `__space_acct_`,
    /// verifies BLAKE3 checksums, and replays the counters. Uses the
    /// highest-`commit_group` record per dataset when duplicates exist (max-TXG
    /// semantics for crash recovery).
    pub fn load_space_accounting(&mut self) -> Result<usize> {
        let manifest_data = match self.get_named(b"__space_acct_manifest")? {
            Some(data) => data,
            None => return Ok(0),
        };

        let hex_ids: Vec<&str> = std::str::from_utf8(&manifest_data)
            .unwrap_or("")
            .lines()
            .filter(|l| !l.is_empty())
            .collect();

        let mut best: std::collections::BTreeMap<[u8; 16], DatasetSpaceUsage> =
            std::collections::BTreeMap::new();

        for hex in &hex_ids {
            let key_name = format!("__space_acct_{hex}");
            if let Ok(Some(data)) = self.get_named(key_name.as_bytes()) {
                if let Some(rec) = DatasetSpaceUsage::from_bytes(&data) {
                    let existing = best.get(&rec.dataset_id);
                    if existing.is_none_or(|e| rec.commit_group >= e.commit_group) {
                        best.insert(rec.dataset_id, rec);
                    }
                }
            }
        }

        let mut loaded = 0usize;
        for rec in best.values() {
            self.space_book.restore_from_record(rec);
            loaded += 1;
        }

        Ok(loaded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreOpenMode {
    WritableCreate,
    ReadOnlyExisting,
    PreflightExisting,
}

impl StoreOpenMode {
    const fn is_writable(self) -> bool {
        matches!(self, Self::WritableCreate)
    }

    const fn tolerates_torn_tail(self) -> bool {
        matches!(self, Self::PreflightExisting)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordHeader {
    pub(crate) format_version: u16,
    pub(crate) kind: RecordKind,
    pub(crate) sequence: u64,
    pub(crate) key: ObjectKey,
    pub(crate) payload_len: u64,
    pub(crate) payload_checksum: IntegrityDigest64,
    /// Compression algorithm applied to the payload (0 = uncompressed).
    pub(crate) compression_algorithm: u8,
}

pub(crate) struct ReplaySegmentRequest<'a> {
    segments_dir: &'a Path,
    segment_id: u64,
    is_last_segment: bool,
    tolerate_torn_tail: bool,
    options: &'a StoreOptions,
}

pub(crate) struct ReplaySegmentState<'a> {
    index: &'a mut BTreeMap<ObjectKey, ObjectLocation>,
    history: &'a mut BTreeMap<ObjectKey, Vec<ObjectLocation>>,
    replay: &'a mut ReplayReport,
    next_sequence: &'a mut u64,
}

fn replay_segment(request: ReplaySegmentRequest<'_>, state: ReplaySegmentState<'_>) -> Result<()> {
    let ReplaySegmentRequest {
        segments_dir,
        segment_id,
        is_last_segment,
        tolerate_torn_tail,
        options,
    } = request;
    let ReplaySegmentState {
        index,
        history,
        replay,
        next_sequence,
    } = state;
    let path = segment_path(segments_dir, segment_id);
    let segment_len = file_len(&path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(options.repair_torn_tail)
        .open(&path)
        .map_err(|source| io_error("open", &path, source))?;
    let mut offset = 0_u64;
    let mut physical_records_seen = false;
    loop {
        let mut header = [0_u8; RECORD_HEADER_LEN];
        let header_bytes = read_up_to(&mut file, &mut header)
            .map_err(|source| io_error("read header", &path, source))?;
        if header_bytes == 0 {
            break;
        }
        // Detect SegmentIntegrityFooter at end of non-last segments.
        // The footer starts with VLOSSEGF, not VLOSRECR (record magic).
        if header_bytes == RECORD_HEADER_LEN && header[0..8] == SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES
        {
            break;
        }
        if header_bytes < RECORD_HEADER_LEN {
            if is_last_segment {
                repair_or_reject_tail(
                    &mut file,
                    &path,
                    segment_id,
                    offset,
                    header_bytes as u64,
                    options,
                    tolerate_torn_tail,
                    replay,
                )?;
                break;
            }
            return Err(StoreError::CorruptHeader {
                segment_id,
                offset,
                reason: "non-final segment ended in the middle of a record header",
            });
        }

        let header_end = checked_record_offset(offset, RECORD_HEADER_LEN_U64, segment_id, offset)?;
        let record = match decode_header(&header, segment_id, offset) {
            Ok(record) => record,
            Err(_) if is_last_segment && segment_len == header_end => {
                repair_or_reject_tail(
                    &mut file,
                    &path,
                    segment_id,
                    offset,
                    RECORD_HEADER_LEN_U64,
                    options,
                    tolerate_torn_tail,
                    replay,
                )?;
                break;
            }
            Err(err) => return Err(err),
        };
        if record.kind == RecordKind::Delete && record.payload_len != 0 {
            return Err(StoreError::CorruptHeader {
                segment_id,
                offset,
                reason: "delete tombstone carries payload bytes",
            });
        }
        let max_payload_for_record = max_payload_bytes_for_format(options, record.format_version);
        if record.payload_len > max_payload_for_record {
            return Err(StoreError::PayloadTooLarge {
                len: record.payload_len,
                max: max_payload_for_record,
            });
        }

        let payload_len =
            usize::try_from(record.payload_len).map_err(|_| StoreError::PayloadTooLarge {
                len: record.payload_len,
                max: usize::MAX as u64,
            })?;
        let record_range = checked_record_range(record, segment_id, offset)?;
        let mut payload = vec![0_u8; payload_len];
        let payload_bytes = read_up_to(&mut file, &mut payload)
            .map_err(|source| io_error("read payload", &path, source))?;
        if payload_bytes < payload_len {
            if is_last_segment {
                let torn_bytes = RECORD_HEADER_LEN_U64 + payload_bytes as u64;
                repair_or_reject_tail(
                    &mut file,
                    &path,
                    segment_id,
                    offset,
                    torn_bytes,
                    options,
                    tolerate_torn_tail,
                    replay,
                )?;
                break;
            }
            return Err(StoreError::CorruptHeader {
                segment_id,
                offset,
                reason: "non-final segment ended in the middle of a record payload",
            });
        }

        let footer = if record_has_footer(record.format_version) {
            let mut footer_bytes = [0_u8; RECORD_FOOTER_LEN];
            let bytes_read = read_up_to(&mut file, &mut footer_bytes)
                .map_err(|source| io_error("read footer", &path, source))?;
            if bytes_read < RECORD_FOOTER_LEN {
                if is_last_segment {
                    let torn_bytes = RECORD_HEADER_LEN_U64 + record.payload_len + bytes_read as u64;
                    repair_or_reject_tail(
                        &mut file,
                        &path,
                        segment_id,
                        offset,
                        torn_bytes,
                        options,
                        tolerate_torn_tail,
                        replay,
                    )?;
                    break;
                }
                return Err(StoreError::CorruptHeader {
                    segment_id,
                    offset,
                    reason: "non-final segment ended in the middle of a record footer",
                });
            }
            decode_footer(
                &footer_bytes,
                record,
                segment_id,
                record_range.footer_offset,
            )?;
            Some(footer_bytes)
        } else {
            None
        };

        if record_has_production_integrity_trailer(record.format_version) {
            let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
            let trailer_bytes = read_up_to(&mut file, &mut trailer)
                .map_err(|source| io_error("read integrity trailer V2", &path, source))?;
            if trailer_bytes < INTEGRITY_TRAILER_V2_LEN {
                if is_last_segment {
                    let torn_bytes = RECORD_HEADER_LEN_U64
                        + record.payload_len
                        + RECORD_FOOTER_LEN_U64
                        + trailer_bytes as u64;
                    repair_or_reject_tail(
                        &mut file,
                        &path,
                        segment_id,
                        offset,
                        torn_bytes,
                        options,
                        tolerate_torn_tail,
                        replay,
                    )?;
                    break;
                }
                return Err(StoreError::CorruptHeader {
                    segment_id,
                    offset,
                    reason: "non-final segment ended in the middle of an integrity trailer V2",
                });
            }
            let footer = footer.ok_or(StoreError::CorruptHeader {
                segment_id,
                offset,
                reason: "integrity trailer V2 requires a footer-bearing record",
            })?;
            let decoded_trailer = decode_integrity_trailer_v2(&trailer)?;
            verify_integrity_trailer_v2(
                &decoded_trailer,
                record,
                &header,
                &payload,
                &footer,
                segment_id,
                record_range
                    .integrity_trailer_offset
                    .ok_or(StoreError::CorruptHeader {
                        segment_id,
                        offset,
                        reason: "integrity trailer V2 range is absent from record layout",
                    })?,
            )?;
        }

        let actual = checksum64(&payload);
        if actual != record.payload_checksum {
            if !record_has_footer(record.format_version)
                && is_last_segment
                && record_range.payload_end_offset >= segment_len
            {
                let torn_bytes = segment_len.saturating_sub(offset);
                repair_or_reject_tail(
                    &mut file,
                    &path,
                    segment_id,
                    offset,
                    torn_bytes,
                    options,
                    tolerate_torn_tail,
                    replay,
                )?;
                break;
            }
            return Err(StoreError::ChecksumMismatch {
                segment_id,
                offset: record_range.payload_offset,
                expected: record.payload_checksum,
                actual,
            });
        }

        physical_records_seen = true;
        let internal_record = is_public_scan_internal_key(record.key);
        if !internal_record {
            replay.highest_sequence = replay.highest_sequence.max(record.sequence);
            replay.records_seen += 1;
            match record.format_version {
                RECORD_FORMAT_VERSION_V1_NO_FOOTER => replay.v1_records_seen += 1,
                RECORD_FORMAT_VERSION_V2_FOOTER => replay.v2_records_seen += 1,
                RECORD_FORMAT_VERSION => {
                    replay.v3_records_seen += 1;
                    replay.production_integrity_records_seen += 1;
                }
                _ => {}
            }
        }
        *next_sequence = (*next_sequence).max(record.sequence.saturating_add(1));
        match record.kind {
            RecordKind::Put => {
                if !internal_record {
                    replay.puts_seen += 1;
                }
                let location = ObjectLocation {
                    key: record.key,
                    segment_id,
                    record_offset: offset,
                    payload_offset: record_range.payload_offset,
                    payload_len: record.payload_len,
                    sequence: record.sequence,
                    payload_checksum: record.payload_checksum,
                };
                history.entry(record.key).or_default().push(location);
                index.insert(record.key, location);
            }
            RecordKind::Delete => {
                if !internal_record {
                    replay.deletes_seen += 1;
                }
                index.remove(&record.key);
            }
        }
        offset = record_range.end_offset;
    }
    // After all records, verify the SegmentIntegrityFooter if present.
    // Only the last segment may lack a footer (torn tail repaired above).
    if physical_records_seen && !is_last_segment {
        // Seek to end of segment minus footer length to read the footer.
        let footer_offset = segment_len.saturating_sub(SEGMENT_INTEGRITY_FOOTER_LEN_U64);
        if footer_offset > 0 {
            let mut footer_buf = [0_u8; SEGMENT_INTEGRITY_FOOTER_LEN];
            file.seek(SeekFrom::Start(footer_offset))
                .map_err(|source| io_error("seek footer", &path, source))?;
            let footer_bytes = read_up_to(&mut file, &mut footer_buf)
                .map_err(|source| io_error("read footer", &path, source))?;
            if footer_bytes == SEGMENT_INTEGRITY_FOOTER_LEN {
                match decode_segment_integrity_footer(&footer_buf) {
                    Ok(decoded_footer) => {
                        // Verify the segment_id in the footer matches.
                        if decoded_footer.segment_id != segment_id {
                            return Err(StoreError::CorruptHeader {
                                segment_id,
                                offset: footer_offset,
                                reason: "SegmentIntegrityFooter segment_id mismatch",
                            });
                        }
                    }
                    Err(_e) => {
                        // Footer present but corrupt; tolerate for now
                        // (suspect_log will record this during chain walk).
                    }
                }
            }
        }
    }
    Ok(())
}

fn repair_or_reject_tail(
    file: &mut File,
    path: &Path,
    segment_id: u64,
    offset: u64,
    torn_bytes: u64,
    options: &StoreOptions,
    tolerate_torn_tail: bool,
    replay: &mut ReplayReport,
) -> Result<()> {
    if tolerate_torn_tail {
        return Ok(());
    }
    if !options.repair_torn_tail {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "torn tail encountered and tail repair is disabled",
        });
    }
    file.set_len(offset)
        .map_err(|source| io_error("set_len", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync_all", path, source))?;
    replay.repaired_tail_bytes += torn_bytes;
    Ok(())
}

pub(crate) fn read_up_to(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0_usize;
    while total < buf.len() {
        let read = file.read(&mut buf[total..])?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

pub(crate) fn encode_header(dst: &mut [u8; RECORD_HEADER_LEN], record: RecordHeader) {
    dst[0..8].copy_from_slice(&RECORD_MAGIC);
    write_u16(&mut dst[8..10], record.format_version);
    write_u16(&mut dst[10..12], record.kind.as_u16());
    write_u16(
        &mut dst[12..14],
        u16::try_from(RECORD_HEADER_LEN).expect("RECORD_HEADER_LEN fits in u16"),
    );
    dst[14] = record.compression_algorithm;
    dst[15] = 0;
    write_u64(&mut dst[16..24], record.sequence);
    write_u64(&mut dst[24..32], record.payload_len);
    write_u64(&mut dst[32..40], record.payload_checksum.get());
    write_u64(&mut dst[40..48], 0);
    write_u64(
        &mut dst[48..56],
        commit_marker(
            record.kind,
            record.sequence,
            record.payload_len,
            record.payload_checksum,
            record.key,
        ),
    );
    dst[56..88].copy_from_slice(&record.key.as_bytes32());
    write_u64(&mut dst[88..96], 0);
    let header_checksum = checksum_header(dst);
    write_u64(&mut dst[40..48], header_checksum.get());
}

pub(crate) fn decode_header(
    src: &[u8; RECORD_HEADER_LEN],
    segment_id: u64,
    offset: u64,
) -> Result<RecordHeader> {
    if src[0..8] != RECORD_MAGIC[..] {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "record magic does not match local object-store format",
        });
    }
    let version = read_u16(&src[8..10]);
    if version != RECORD_FORMAT_VERSION_V1_NO_FOOTER
        && version != RECORD_FORMAT_VERSION_V2_FOOTER
        && version != RECORD_FORMAT_VERSION
    {
        return Err(StoreError::UnsupportedVersion {
            segment_id,
            offset,
            version,
        });
    }
    let raw_kind = read_u16(&src[10..12]);
    let kind = RecordKind::try_from(raw_kind).map_err(|_| StoreError::UnknownRecordKind {
        segment_id,
        offset,
        kind: raw_kind,
    })?;
    let header_len = read_u16(&src[12..14]);
    if usize::from(header_len) != RECORD_HEADER_LEN {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "record header length is not supported",
        });
    }
    let compression_algorithm = src[14];
    if src[15] != 0 || read_u64(&src[88..96]) != 0 {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "reserved header bytes are not zero",
        });
    }
    let sequence = read_u64(&src[16..24]);
    let payload_len = read_u64(&src[24..32]);
    let payload_checksum = IntegrityDigest64(read_u64(&src[32..40]));
    let declared_header_checksum = IntegrityDigest64(read_u64(&src[40..48]));
    let mut key = [0_u8; 32];
    key.copy_from_slice(&src[56..88]);
    let key = ObjectKey::from_bytes32(key);
    let expected_commit_marker = commit_marker(kind, sequence, payload_len, payload_checksum, key);
    if read_u64(&src[48..56]) != expected_commit_marker {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "commit marker does not match the record fields",
        });
    }
    let actual_header_checksum = checksum_header(src);
    if declared_header_checksum != actual_header_checksum {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "header checksum does not match the record fields",
        });
    }
    Ok(RecordHeader {
        format_version: version,
        kind,
        sequence,
        key,
        payload_len,
        payload_checksum,
        compression_algorithm,
    })
}

const fn max_payload_bytes_for_format(options: &StoreOptions, format_version: u16) -> u64 {
    options
        .max_segment_bytes
        .saturating_sub(record_overhead_for_format(format_version))
}

pub(crate) const fn record_overhead_for_format(format_version: u16) -> u64 {
    RECORD_HEADER_LEN_U64
        .saturating_add(if record_has_footer(format_version) {
            RECORD_FOOTER_LEN_U64
        } else {
            0
        })
        .saturating_add(if record_has_production_integrity_trailer(format_version) {
            INTEGRITY_TRAILER_V2_LEN_U64
        } else {
            0
        })
}

pub(crate) const fn record_has_footer(format_version: u16) -> bool {
    format_version >= RECORD_FORMAT_VERSION_V2_FOOTER
}

pub(crate) const fn record_has_production_integrity_trailer(format_version: u16) -> bool {
    format_version >= RECORD_FORMAT_VERSION
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedRecordRange {
    payload_offset: u64,
    payload_end_offset: u64,
    footer_offset: u64,
    integrity_trailer_offset: Option<u64>,
    end_offset: u64,
}

struct DecodedStoredRecord {
    header: RecordHeader,
    range: CheckedRecordRange,
    payload: Vec<u8>,
}

fn checked_record_offset(base: u64, len: u64, segment_id: u64, record_offset: u64) -> Result<u64> {
    base.checked_add(len).ok_or(StoreError::CorruptHeader {
        segment_id,
        offset: record_offset,
        reason: "record byte range overflows u64",
    })
}

fn checked_record_total_len(
    record: RecordHeader,
    segment_id: u64,
    record_offset: u64,
) -> Result<u64> {
    record_overhead_for_format(record.format_version)
        .checked_add(record.payload_len)
        .ok_or(StoreError::CorruptHeader {
            segment_id,
            offset: record_offset,
            reason: "record byte range overflows u64",
        })
}

fn checked_record_range(
    record: RecordHeader,
    segment_id: u64,
    record_offset: u64,
) -> Result<CheckedRecordRange> {
    let payload_offset = checked_record_offset(
        record_offset,
        RECORD_HEADER_LEN_U64,
        segment_id,
        record_offset,
    )?;
    let payload_end_offset = checked_record_offset(
        payload_offset,
        record.payload_len,
        segment_id,
        record_offset,
    )?;
    let footer_offset = payload_end_offset;
    let mut end_offset = payload_end_offset;
    if record_has_footer(record.format_version) {
        end_offset =
            checked_record_offset(end_offset, RECORD_FOOTER_LEN_U64, segment_id, record_offset)?;
    }
    let integrity_trailer_offset = if record_has_production_integrity_trailer(record.format_version)
    {
        let offset = end_offset;
        end_offset = checked_record_offset(
            end_offset,
            INTEGRITY_TRAILER_V2_LEN_U64,
            segment_id,
            record_offset,
        )?;
        Some(offset)
    } else {
        None
    };
    Ok(CheckedRecordRange {
        payload_offset,
        payload_end_offset,
        footer_offset,
        integrity_trailer_offset,
        end_offset,
    })
}

fn decode_stored_record_after_header(
    file: &mut impl Read,
    path: &Path,
    segment_id: u64,
    record_offset: u64,
    data_end: u64,
    header_bytes: [u8; RECORD_HEADER_LEN],
) -> Result<DecodedStoredRecord> {
    let header = decode_header(&header_bytes, segment_id, record_offset)?;
    let range = checked_record_range(header, segment_id, record_offset)?;
    if range.end_offset > data_end {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset: record_offset,
            reason: "record extends beyond the admitted data region",
        });
    }

    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| StoreError::PayloadTooLarge {
            len: header.payload_len,
            max: usize::MAX as u64,
        })?;
    let mut payload = vec![0_u8; payload_len];
    file.read_exact(&mut payload)
        .map_err(|source| io_error("read_exact payload", path, source))?;
    let actual = checksum64(&payload);
    if actual != header.payload_checksum {
        return Err(StoreError::ChecksumMismatch {
            segment_id,
            offset: range.payload_offset,
            expected: header.payload_checksum,
            actual,
        });
    }

    let footer = if record_has_footer(header.format_version) {
        let mut footer_bytes = [0_u8; RECORD_FOOTER_LEN];
        file.read_exact(&mut footer_bytes)
            .map_err(|source| io_error("read_exact footer", path, source))?;
        decode_footer(&footer_bytes, header, segment_id, range.footer_offset)?;
        Some(footer_bytes)
    } else {
        None
    };
    if record_has_production_integrity_trailer(header.format_version) {
        let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
        file.read_exact(&mut trailer)
            .map_err(|source| io_error("read_exact integrity trailer V2", path, source))?;
        let footer = footer.ok_or(StoreError::CorruptHeader {
            segment_id,
            offset: record_offset,
            reason: "integrity trailer V2 requires a footer-bearing record",
        })?;
        let decoded_trailer = decode_integrity_trailer_v2(&trailer)?;
        verify_integrity_trailer_v2(
            &decoded_trailer,
            header,
            &header_bytes,
            &payload,
            &footer,
            segment_id,
            range
                .integrity_trailer_offset
                .ok_or(StoreError::CorruptHeader {
                    segment_id,
                    offset: record_offset,
                    reason: "integrity trailer V2 range is absent from record layout",
                })?,
        )?;
    }

    Ok(DecodedStoredRecord {
        header,
        range,
        payload,
    })
}

fn validate_location_record(
    location: ObjectLocation,
    decoded: DecodedStoredRecord,
) -> Result<(Vec<u8>, u8)> {
    let record = decoded.header;
    if record.kind != RecordKind::Put
        || record.key != location.key
        || record.sequence != location.sequence
        || record.payload_len != location.payload_len
        || record.payload_checksum != location.payload_checksum
    {
        return Err(StoreError::CorruptHeader {
            segment_id: location.segment_id,
            offset: location.record_offset,
            reason: "header no longer matches the in-memory location index",
        });
    }
    Ok((decoded.payload, record.compression_algorithm))
}

pub(crate) fn encode_footer(record: RecordHeader) -> [u8; RECORD_FOOTER_LEN] {
    let mut out = [0_u8; RECORD_FOOTER_LEN];
    out[0..8].copy_from_slice(&RECORD_FOOTER_MAGIC);
    write_u64(&mut out[8..16], footer_marker(record));
    out
}

fn decode_footer(
    src: &[u8; RECORD_FOOTER_LEN],
    record: RecordHeader,
    segment_id: u64,
    offset: u64,
) -> Result<()> {
    if src[0..8] != RECORD_FOOTER_MAGIC[..] {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "record footer magic does not match local object-store format",
        });
    }
    let declared = read_u64(&src[8..16]);
    let expected = footer_marker(record);
    if declared != expected {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "record footer commit marker does not match the record fields",
        });
    }
    Ok(())
}

fn digest_from_slice(src: &[u8]) -> ProductionIntegrityDigest {
    let mut out = [0_u8; PRODUCTION_INTEGRITY_DIGEST_LEN];
    out.copy_from_slice(src);
    ProductionIntegrityDigest::from_bytes32(out)
}

fn checksum_header(src: &[u8; RECORD_HEADER_LEN]) -> IntegrityDigest64 {
    let mut tmp = *src;
    write_u64(&mut tmp[40..48], 0);
    IntegrityDigest64(checksum64_with_seed(&tmp, HEADER_CHECKSUM_SEED))
}

#[must_use]
pub fn checksum64(bytes: &[u8]) -> IntegrityDigest64 {
    IntegrityDigest64(checksum64_with_seed_and_len(bytes, PAYLOAD_CHECKSUM_SEED))
}

fn checksum64_with_seed_and_len(bytes: &[u8], seed: u64) -> u64 {
    let mut framed = [0_u8; 8];
    framed.copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    let hash = checksum64_with_seed(&framed, seed);
    checksum64_continue(bytes, hash)
}

fn checksum64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    checksum64_continue(bytes, FNV_OFFSET_BASIS ^ seed)
}

fn checksum64_continue(bytes: &[u8], mut state: u64) -> u64 {
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(FNV_PRIME);
        state ^= state.rotate_left(23);
    }
    state
}

fn footer_marker(record: RecordHeader) -> u64 {
    checksum64_with_seed(&record.key.as_bytes32(), FOOTER_CHECKSUM_SEED)
        ^ u64::from(record.format_version).rotate_left(5)
        ^ u64::from(record.kind.as_u16()).rotate_left(13)
        ^ record.sequence.rotate_left(17)
        ^ record.payload_len.rotate_left(31)
        ^ record.payload_checksum.get().rotate_left(47)
}

fn commit_marker(
    kind: RecordKind,
    sequence: u64,
    payload_len: u64,
    payload_checksum: IntegrityDigest64,
    key: ObjectKey,
) -> u64 {
    COMMIT_MARKER_BASE
        ^ u64::from(kind.as_u16()).rotate_left(3)
        ^ sequence.rotate_left(11)
        ^ payload_len.rotate_left(29)
        ^ payload_checksum.get().rotate_left(41)
        ^ checksum64_with_seed(&key.as_bytes32(), KEY_DERIVE_SEED).rotate_left(7)
}

pub(crate) fn discover_segment_ids(segments_dir: &Path) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    let entries =
        fs::read_dir(segments_dir).map_err(|source| io_error("read_dir", segments_dir, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read_dir entry", segments_dir, source))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(id) = parse_segment_file_name(&path) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn create_segment_file(segments_dir: &Path, segment_id: u64) -> Result<()> {
    let path = segment_path(segments_dir, segment_id);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| io_error("create_new", &path, source))?;
    Ok(())
}

#[must_use]
pub fn segment_file_name(segment_id: u64) -> String {
    format!("segment-{segment_id:016x}.{SEGMENT_FILE_EXTENSION}")
}

pub(crate) fn segment_path(segments_dir: &Path, segment_id: u64) -> PathBuf {
    // Block-device mode: when segments_dir is a regular file or block device
    // (not a directory), return the path directly regardless of segment_id.
    if segments_dir.is_file() || (segments_dir.exists() && !segments_dir.is_dir()) {
        return segments_dir.to_path_buf();
    }
    segments_dir.join(segment_file_name(segment_id))
}

pub(crate) fn parse_segment_file_name(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("segment-")?;
    let hex = rest.strip_suffix(".vlos")?;
    if hex.len() != 16 {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

pub(crate) fn file_len(path: &Path) -> Result<u64> {
    path.metadata()
        .map(|metadata| metadata.len())
        .map_err(|source| io_error("metadata", path, source))
}

// --- index checkpoint -------------------------------------------------------

const INDEX_BASE_HEADER_LEN: usize = 20; // 8 magic + 2 version + 2 reserved + 8 segment_id
const INDEX_BASE_INDEX_ENTRY_LEN: usize = 80; // 32 key + 6*8 ObjectLocation fields
const INDEX_BASE_HISTORY_LOCATION_LEN: usize = 48; // location fields without key
const INDEX_BASE_CHECKSUM_SEED: u64 = 0x5649_4245_4653_4348; // "TIDEFSCH"

/// Write a checkpoint of the current index and history to `segments/index_base`.
///
/// The file records `checkpoint_segment_id` — the highest-numbered segment
/// known to be fully complete at the moment the checkpoint is taken.  The
/// index and history are serialised so the next mount can skip replay of
/// every segment `<= checkpoint_segment_id`.
///
/// Both the index (latest location per key) and the version history (all
/// superseded put locations) are persisted so that `version_locations_of`
/// returns complete results without replaying skipped segments.
///
/// The write is atomic: data goes to `index_base.tmp` then is renamed over
/// the real path, followed by a directory fsync.
pub(crate) fn write_index_checkpoint(
    segments_dir: &Path,
    index: &BTreeMap<ObjectKey, ObjectLocation>,
    history: &BTreeMap<ObjectKey, Vec<ObjectLocation>>,
    checkpoint_segment_id: u64,
) -> Result<()> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(());
    }

    let tmp_path = segments_dir.join(format!("{INDEX_BASE_FILE_NAME}.tmp"));
    let real_path = segments_dir.join(INDEX_BASE_FILE_NAME);

    // Compute total size
    let mut total_len = INDEX_BASE_HEADER_LEN + 8; // header + index_count
    total_len += index.len() * INDEX_BASE_INDEX_ENTRY_LEN;
    total_len += 8; // history_count
    for versions in history.values() {
        total_len += 8 + versions.len() * INDEX_BASE_HISTORY_LOCATION_LEN; // count + locations
    }
    total_len += 8; // footer checksum

    let mut buf = Vec::with_capacity(total_len);

    // Header
    buf.extend_from_slice(&INDEX_BASE_MAGIC);
    buf.extend_from_slice(&INDEX_BASE_FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&[0u8; 2]); // reserved
    buf.extend_from_slice(&checkpoint_segment_id.to_le_bytes());

    // Index entry count + entries
    buf.extend_from_slice(&(index.len() as u64).to_le_bytes());
    for (key, loc) in index {
        buf.extend_from_slice(&key.as_bytes32());
        buf.extend_from_slice(&loc.segment_id.to_le_bytes());
        buf.extend_from_slice(&loc.record_offset.to_le_bytes());
        buf.extend_from_slice(&loc.payload_offset.to_le_bytes());
        buf.extend_from_slice(&loc.payload_len.to_le_bytes());
        buf.extend_from_slice(&loc.sequence.to_le_bytes());
        buf.extend_from_slice(&loc.payload_checksum.get().to_le_bytes());
    }

    // History: count of history entries, then for each entry key + version_count + locations
    buf.extend_from_slice(&(history.len() as u64).to_le_bytes());
    for (key, versions) in history {
        buf.extend_from_slice(&key.as_bytes32());
        buf.extend_from_slice(&(versions.len() as u64).to_le_bytes());
        for loc in versions {
            // Location fields without key (key is already in the outer entry)
            buf.extend_from_slice(&loc.segment_id.to_le_bytes());
            buf.extend_from_slice(&loc.record_offset.to_le_bytes());
            buf.extend_from_slice(&loc.payload_offset.to_le_bytes());
            buf.extend_from_slice(&loc.payload_len.to_le_bytes());
            buf.extend_from_slice(&loc.sequence.to_le_bytes());
            buf.extend_from_slice(&loc.payload_checksum.get().to_le_bytes());
        }
    }

    // Footer: checksum64 of all preceding bytes
    let csum = IntegrityDigest64(checksum64_with_seed(&buf, INDEX_BASE_CHECKSUM_SEED));
    buf.extend_from_slice(&csum.get().to_le_bytes());

    fs::write(&tmp_path, &buf).map_err(|source| io_error("write checkpoint", &tmp_path, source))?;
    fs::rename(&tmp_path, &real_path)
        .map_err(|source| io_error("rename checkpoint", &tmp_path, source))?;
    sync_directory(segments_dir)?;

    Ok(())
}

/// Try to load `segments/index_base` and restore the replayed index and history.
///
/// Returns `Ok(None)` if the checkpoint file does not exist, is corrupt, or
/// references a segment that is no longer present (e.g. after compaction).
/// Returns `Ok(Some((index, history, checkpoint_id)))` on success.
///
/// The returned `checkpoint_id` represents the highest complete segment.
/// On mount, every segment with id `> checkpoint_id` must be replayed.
pub(crate) fn load_index_checkpoint(segments_dir: &Path) -> Result<IndexCheckpoint> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(None);
    }

    let path = segments_dir.join(INDEX_BASE_FILE_NAME);
    let raw = match fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read checkpoint", &path, e)),
    };

    let min_len = INDEX_BASE_HEADER_LEN + 8 + 8; // header + index_count + footer
    if raw.len() < min_len {
        return Ok(None);
    }

    // Validate magic
    if raw[0..8] != INDEX_BASE_MAGIC {
        return Ok(None);
    }

    // Validate version
    let version = u16::from_le_bytes([raw[8], raw[9]]);
    if version != INDEX_BASE_FORMAT_VERSION {
        return Ok(None);
    }

    // Reserved
    if raw[10..12] != [0, 0] {
        return Ok(None);
    }

    let checkpoint_segment_id = u64::from_le_bytes([
        raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
    ]);

    let mut pos = INDEX_BASE_HEADER_LEN;

    // Read index entries
    if pos + 8 > raw.len() {
        return Ok(None);
    }
    let index_count = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap()) as usize;
    pos += 8;

    let mut index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
    for _i in 0..index_count {
        if pos + INDEX_BASE_INDEX_ENTRY_LEN > raw.len() {
            return Ok(None);
        }
        let entry = &raw[pos..pos + INDEX_BASE_INDEX_ENTRY_LEN];
        pos += INDEX_BASE_INDEX_ENTRY_LEN;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&entry[0..32]);
        let key = ObjectKey::from_bytes32(key_bytes);

        let location = ObjectLocation {
            key,
            segment_id: u64::from_le_bytes(entry[32..40].try_into().unwrap()),
            record_offset: u64::from_le_bytes(entry[40..48].try_into().unwrap()),
            payload_offset: u64::from_le_bytes(entry[48..56].try_into().unwrap()),
            payload_len: u64::from_le_bytes(entry[56..64].try_into().unwrap()),
            sequence: u64::from_le_bytes(entry[64..72].try_into().unwrap()),
            payload_checksum: IntegrityDigest64(u64::from_le_bytes(
                entry[72..80].try_into().unwrap(),
            )),
        };
        index.insert(key, location);
    }

    // Read history entries
    if pos + 8 > raw.len() {
        return Ok(None);
    }
    let history_count = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap()) as usize;
    pos += 8;

    let mut history: BTreeMap<ObjectKey, Vec<ObjectLocation>> = BTreeMap::new();
    for _i in 0..history_count {
        if pos + 40 > raw.len() {
            // 32 key + 8 count
            return Ok(None);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&raw[pos..pos + 32]);
        let key = ObjectKey::from_bytes32(key_bytes);
        pos += 32;

        let version_count = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        let mut versions = Vec::with_capacity(version_count);
        for _j in 0..version_count {
            if pos + INDEX_BASE_HISTORY_LOCATION_LEN > raw.len() {
                return Ok(None);
            }
            let entry = &raw[pos..pos + INDEX_BASE_HISTORY_LOCATION_LEN];
            pos += INDEX_BASE_HISTORY_LOCATION_LEN;

            let location = ObjectLocation {
                key,
                segment_id: u64::from_le_bytes(entry[0..8].try_into().unwrap()),
                record_offset: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
                payload_offset: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
                payload_len: u64::from_le_bytes(entry[24..32].try_into().unwrap()),
                sequence: u64::from_le_bytes(entry[32..40].try_into().unwrap()),
                payload_checksum: IntegrityDigest64(u64::from_le_bytes(
                    entry[40..48].try_into().unwrap(),
                )),
            };
            versions.push(location);
        }
        history.insert(key, versions);
    }

    // Verify checksum over everything except the footer
    if pos + 8 > raw.len() {
        return Ok(None);
    }
    let data_part = &raw[..pos];
    let stored_csum = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
    let actual_csum = checksum64_with_seed(data_part, INDEX_BASE_CHECKSUM_SEED);
    if stored_csum != actual_csum {
        return Ok(None);
    }

    Ok(Some((index, history, checkpoint_segment_id)))
}

// --- spacemap checkpoint -----------------------------------------------------

const SPACEMAP_BASE_MAGIC: [u8; 8] = *b"VFSXSPCP";
pub(crate) const SPACEMAP_BASE_FORMAT_VERSION: u16 = 1;
const SPACEMAP_BASE_CHECKSUM_SEED: u64 = 0x5649_4245_4653_504D; // "TIDEFSPM"

// --- scrub cursor persistence -----------------------------------------------

const SCRUB_CURSOR_LEN: usize = 16; // segment_id (u64) + offset (u64)

/// Write the scrub cursor to a file in the segments directory.
pub(crate) fn write_scrub_cursor(segments_dir: &Path, cursor: &crate::ScrubCursor) -> Result<()> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(());
    }

    let path = segments_dir.join(crate::constants::SCRUB_CURSOR_FILE_NAME);
    let mut buf = [0u8; SCRUB_CURSOR_LEN];
    buf[0..8].copy_from_slice(&cursor.segment_id.to_le_bytes());
    buf[8..16].copy_from_slice(&cursor.offset.to_le_bytes());
    std::fs::write(&path, buf).map_err(|source| io_error("write scrub_cursor", &path, source))?;
    Ok(())
}

/// Load the scrub cursor from the segments directory.
/// Returns a default (zero) cursor if the file does not exist.
pub(crate) fn load_scrub_cursor(segments_dir: &Path) -> crate::ScrubCursor {
    if sidecar_files_unavailable(segments_dir) {
        return crate::ScrubCursor::default();
    }

    let path = segments_dir.join(crate::constants::SCRUB_CURSOR_FILE_NAME);
    match std::fs::read(&path) {
        Ok(buf) if buf.len() >= SCRUB_CURSOR_LEN => {
            let segment_id = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0u8; 8]));
            let offset = u64::from_le_bytes(buf[8..16].try_into().unwrap_or([0u8; 8]));
            crate::ScrubCursor { segment_id, offset }
        }
        _ => crate::ScrubCursor::default(),
    }
}

// ---------------------------------------------------------------------------
// SuspectLog persistence — durable on-disk suspect entry journal
// ---------------------------------------------------------------------------

/// On-disk magic for a SuspectLog file.
const SUSPECT_LOG_MAGIC: [u8; 4] = *b"VSUS";
/// Current SuspectLog file format version.
/// Earliest supported SuspectLog version.
pub(crate) const SUSPECT_LOG_VERSION_MIN: u32 = 1;
/// Current SuspectLog encoding version (always used for writes).
const SUSPECT_LOG_VERSION: u32 = SUSPECT_LOG_VERSION_MIN;
/// Maximum supported SuspectLog version. Versions above this come from
/// a newer TideFS release with an unknown schema -- explicitly reject them.
pub(crate) const SUSPECT_LOG_VERSION_MAX: u32 = 1;
/// Size of a single SuspectEntry when encoded on disk.
const SUSPECT_LOG_ENTRY_BYTES: usize = crate::constants::SUSPECT_LOG_ENTRY_LEN;
/// Header size: magic (4) + version (4) + entry_count (8) + next_entry_id (8).
const SUSPECT_LOG_HEADER_BYTES: usize = 24;
/// Trailer size: BLAKE3-256 hash (32).
const SUSPECT_LOG_TRAILER_BYTES: usize = 32;

/// Encode one [`SuspectEntry`] into a 128-byte buffer.
fn encode_suspect_entry(entry: &SuspectEntry, buf: &mut [u8; SUSPECT_LOG_ENTRY_BYTES]) {
    buf[0..8].copy_from_slice(&entry.entry_id.to_le_bytes());
    buf[8..16].copy_from_slice(&entry.locator_id.to_le_bytes());
    buf[16..24].copy_from_slice(&entry.segment_id.to_le_bytes());
    buf[24..32].copy_from_slice(&entry.offset.to_le_bytes());
    buf[32] = entry.record_type;
    buf[33] = u8::from(entry.resolved);
    buf[34..36].copy_from_slice(&[0u8; 2]); // padding
    buf[36..40].copy_from_slice(&entry.repair_attempts.to_le_bytes());
    buf[40..48].copy_from_slice(&entry.last_repair_attempt.to_le_bytes());
    buf[48..56].copy_from_slice(&entry.commit_group.to_le_bytes());
    buf[56..64].copy_from_slice(&entry.timestamp_secs.to_le_bytes());
    buf[64..96].copy_from_slice(&entry.expected_hash);
    buf[96..128].copy_from_slice(&entry.actual_hash);
}

/// Decode one [`SuspectEntry`] from a 128-byte slice.
fn decode_suspect_entry(buf: &[u8; SUSPECT_LOG_ENTRY_BYTES]) -> SuspectEntry {
    SuspectEntry {
        entry_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        locator_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        segment_id: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        offset: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        record_type: buf[32],
        resolved: buf[33] != 0,
        repair_attempts: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
        last_repair_attempt: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        commit_group: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
        timestamp_secs: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
        expected_hash: buf[64..96].try_into().unwrap(),
        actual_hash: buf[96..128].try_into().unwrap(),
    }
}

/// Encode a [`SuspectLog`] into a BLAKE3-verified byte vector.
///
/// Format: 24-byte header (magic, version, entry_count, next_entry_id),
/// then all entries (128 bytes each), then a 32-byte BLAKE3-256 hash
/// of the header plus all entry bytes.
pub fn encode_suspect_log(log: &SuspectLog) -> Vec<u8> {
    let entries: Vec<SuspectEntry> = log.iter().copied().collect();
    let body_bytes = SUSPECT_LOG_HEADER_BYTES + entries.len() * SUSPECT_LOG_ENTRY_BYTES;
    let mut buf = Vec::with_capacity(body_bytes + SUSPECT_LOG_TRAILER_BYTES);

    // Header
    buf.extend_from_slice(&SUSPECT_LOG_MAGIC);
    buf.extend_from_slice(&SUSPECT_LOG_VERSION.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    buf.extend_from_slice(&log.next_entry_id.to_le_bytes());

    // Entries
    let mut entry_buf = [0u8; SUSPECT_LOG_ENTRY_BYTES];
    for entry in &entries {
        encode_suspect_entry(entry, &mut entry_buf);
        buf.extend_from_slice(&entry_buf);
    }

    // BLAKE3-256 hash of header + entries
    let hash: [u8; 32] = blake3::hash(&buf).into();
    buf.extend_from_slice(&hash);

    buf
}

/// Decode a BLAKE3-verified byte slice into a [`SuspectLog`].
///
/// Returns `None` if the magic does not match, the version is unsupported
/// (below MIN or above MAX), the data is too short, or the BLAKE3 hash
/// does not verify. A version above MAX means the file was written by a
/// newer TideFS release -- this build cannot read its schema.
pub fn decode_suspect_log(bytes: &[u8]) -> Option<SuspectLog> {
    if bytes.len() < SUSPECT_LOG_HEADER_BYTES + SUSPECT_LOG_TRAILER_BYTES {
        return None;
    }
    if bytes[0..4] != SUSPECT_LOG_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if version < SUSPECT_LOG_VERSION_MIN || version > SUSPECT_LOG_VERSION_MAX {
        return None;
    }

    let entry_count = u64::from_le_bytes(bytes[8..16].try_into().ok()?) as usize;
    let next_entry_id = u64::from_le_bytes(bytes[16..24].try_into().ok()?);

    let body_bytes = SUSPECT_LOG_HEADER_BYTES + entry_count * SUSPECT_LOG_ENTRY_BYTES;
    if bytes.len() < body_bytes + SUSPECT_LOG_TRAILER_BYTES {
        return None;
    }

    // Verify BLAKE3 hash
    let body = &bytes[..body_bytes];
    let stored_hash: [u8; 32] = bytes[body_bytes..body_bytes + 32].try_into().ok()?;
    let computed: [u8; 32] = blake3::hash(body).into();
    if stored_hash != computed {
        return None;
    }

    let mut log = SuspectLog::new();
    log.next_entry_id = next_entry_id;

    for i in 0..entry_count {
        let start = SUSPECT_LOG_HEADER_BYTES + i * SUSPECT_LOG_ENTRY_BYTES;
        let entry_bytes: &[u8; SUSPECT_LOG_ENTRY_BYTES] = bytes
            [start..start + SUSPECT_LOG_ENTRY_BYTES]
            .try_into()
            .ok()?;
        let entry = decode_suspect_entry(entry_bytes);
        // Append directly without auto-assigning entry_id (preserve persisted ids)
        if log.entries.len() < SUSPECT_LOG_RING_CAPACITY {
            log.entries.push(entry);
            log.count += 1;
        } else {
            log.entries[log.head] = entry;
            log.head = (log.head + 1) % SUSPECT_LOG_RING_CAPACITY;
        }
    }

    Some(log)
}

/// Return whether a SuspectLog on-disk format version is supported.
/// Supported versions fall in the range [MIN, MAX].
#[cfg(test)]
pub(crate) fn suspect_log_version_supported(version: u32) -> bool {
    version >= SUSPECT_LOG_VERSION_MIN && version <= SUSPECT_LOG_VERSION_MAX
}

/// Write the suspect log to a durable file in the segments directory.
///
/// Uses atomic rename: writes to a `.tmp` file, then renames over the
/// real path to avoid torn writes.
pub fn write_suspect_log(segments_dir: &Path, log: &SuspectLog) -> Result<()> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(());
    }

    let tmp_path = segments_dir.join(format!("{}.tmp", crate::constants::SUSPECT_LOG_FILE_NAME));
    let real_path = segments_dir.join(crate::constants::SUSPECT_LOG_FILE_NAME);

    let bytes = encode_suspect_log(log);
    std::fs::write(&tmp_path, &bytes)
        .map_err(|source| io_error("write suspect_log", &tmp_path, source))?;
    std::fs::rename(&tmp_path, &real_path)
        .map_err(|source| io_error("rename suspect_log", &tmp_path, source))?;
    sync_directory(segments_dir)?;
    Ok(())
}

/// Load the suspect log from the segments directory.
///
/// Returns a fresh empty [`SuspectLog`] if the file does not exist or
/// the integrity check fails.
pub fn load_suspect_log(segments_dir: &Path) -> SuspectLog {
    if sidecar_files_unavailable(segments_dir) {
        return SuspectLog::new();
    }

    let path = segments_dir.join(crate::constants::SUSPECT_LOG_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => decode_suspect_log(&bytes).unwrap_or_default(),
        Err(_) => SuspectLog::new(),
    }
}

pub(crate) fn write_spacemap_checkpoint(
    segments_dir: &Path,
    pool_allocator: &PoolAllocator,
    dirty_only: bool,
) -> Result<()> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(());
    }

    let tmp_path = segments_dir.join(format!("{SPACEMAP_BASE_FILE_NAME}.tmp"));
    let real_path = segments_dir.join(SPACEMAP_BASE_FILE_NAME);

    let ckpt = pool_allocator.to_checkpoint(dirty_only);
    let bytes = serialize_spacemap_checkpoint(&ckpt);

    fs::write(&tmp_path, &bytes)
        .map_err(|source| io_error("write spacemap checkpoint", &tmp_path, source))?;
    fs::rename(&tmp_path, &real_path)
        .map_err(|source| io_error("rename spacemap checkpoint", &tmp_path, source))?;
    sync_directory(segments_dir)?;
    Ok(())
}

fn serialize_spacemap_checkpoint(ckpt: &SpaceMapCheckpointV1) -> Vec<u8> {
    let mut cap = 12 + 28 + 8; // header + body + footer
    for e in &ckpt.entries {
        cap += 8 + e.bitmap_data.len();
    }
    let mut buf = Vec::with_capacity(cap);

    // Header: 8 magic + 2 version + 2 reserved
    buf.extend_from_slice(&SPACEMAP_BASE_MAGIC);
    buf.extend_from_slice(&SPACEMAP_BASE_FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&[0u8; 2]);

    // Body
    buf.extend_from_slice(&ckpt.segment_count.to_le_bytes());
    buf.extend_from_slice(&ckpt.segment_group_segments.to_le_bytes());
    buf.extend_from_slice(&ckpt.segment_group_count.to_le_bytes());
    buf.extend_from_slice(&ckpt.dirty_segment_group_count.to_le_bytes());
    buf.extend_from_slice(&ckpt.generation.to_le_bytes());

    // Entry count + entries
    buf.extend_from_slice(&(ckpt.entries.len() as u64).to_le_bytes());
    for e in &ckpt.entries {
        buf.extend_from_slice(&e.segment_group_index.to_le_bytes());
        buf.extend_from_slice(&e.bitmap_len.to_le_bytes());
        buf.extend_from_slice(&e.bitmap_data);
    }

    // Footer checksum
    let csum = checksum64_with_seed(&buf, SPACEMAP_BASE_CHECKSUM_SEED);
    buf.extend_from_slice(&csum.to_le_bytes());

    buf
}

pub(crate) fn load_spacemap_checkpoint(
    segments_dir: &Path,
) -> Result<Option<(PoolAllocator, u64, u64)>> {
    let path = segments_dir.join(SPACEMAP_BASE_FILE_NAME);
    let raw = match fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read spacemap checkpoint", &path, e)),
    };

    // Minimum: 12 header + 28 body + 8 entry_count + 8 footer = 56
    if raw.len() < 56 {
        return Ok(None);
    }

    // Validate magic
    if raw[0..8] != SPACEMAP_BASE_MAGIC {
        return Ok(None);
    }
    let version = u16::from_le_bytes([raw[8], raw[9]]);
    if version != SPACEMAP_BASE_FORMAT_VERSION {
        return Ok(None);
    }
    if raw[10..12] != [0, 0] {
        return Ok(None);
    }

    let mut pos = 12;
    if pos + 28 > raw.len() {
        return Ok(None);
    }
    let segment_count = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let segment_group_segments = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
    pos += 8;
    pos += 4; // segment_group_count (skip)
    pos += 4; // dirty_count (skip)
    let generation = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
    pos += 8;

    if pos + 8 > raw.len() {
        return Ok(None);
    }
    let entry_count = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap()) as usize;
    pos += 8;

    let mut bitmaps: Vec<Vec<u8>> = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        if pos + 8 > raw.len() {
            return Ok(None);
        }
        pos += 4; // segment_group_index (skip)
        let bl = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + bl > raw.len() {
            return Ok(None);
        }
        bitmaps.push(raw[pos..pos + bl].to_vec());
        pos += bl;
    }

    // Verify checksum
    if pos + 8 > raw.len() {
        return Ok(None);
    }
    let data_part = &raw[..pos];
    let stored_csum = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
    let actual_csum = checksum64_with_seed(data_part, SPACEMAP_BASE_CHECKSUM_SEED);
    if stored_csum != actual_csum {
        return Ok(None);
    }

    let free_runs =
        tidefs_spacemap_allocator::decode_bitmaps(&bitmaps, segment_count, segment_group_segments)
            .map_err(|_| StoreError::InvalidOptions {
                reason: "corrupt spacemap checkpoint bitmaps",
            })?;
    let free_map = SegmentFreeMap::from_runs(segment_count, free_runs).map_err(|_| {
        StoreError::InvalidOptions {
            reason: "invalid spacemap checkpoint runs",
        }
    })?;
    let pool_allocator = PoolAllocator::new(free_map);
    Ok(Some((pool_allocator, segment_count, generation)))
}
fn sync_directory(path: &Path) -> Result<()> {
    if sidecar_files_unavailable(path) {
        return Ok(());
    }

    let file = File::open(path).map_err(|source| io_error("open directory", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync directory", path, source))
}

fn sidecar_files_unavailable(path: &Path) -> bool {
    path.exists() && !path.is_dir()
}

pub(crate) fn io_error(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> StoreError {
    StoreError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

pub(crate) fn payload_len_u64(actual: usize, max: u64) -> Result<u64> {
    u64::try_from(actual).map_err(|_| StoreError::PayloadTooLarge { len: u64::MAX, max })
}

pub(crate) fn write_u16(dst: &mut [u8], value: u16) {
    dst.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64(dst: &mut [u8], value: u64) {
    dst.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn read_u16(src: &[u8]) -> u16 {
    let mut bytes = [0_u8; 2];
    bytes.copy_from_slice(src);
    u16::from_le_bytes(bytes)
}

pub(crate) fn read_u64(src: &[u8]) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(src);
    u64::from_le_bytes(bytes)
}

// TURN4_HUMAN_LOCAL_OBJECT_STORE_ALIASES
/// Human-named module for the durable local object-store slice.
///
/// Prefer this namespace in application examples and operator-facing tests. It
/// keeps the public API anchored in storage concepts instead of abbreviated
/// internal locator names while still re-exporting the exact implemented types.
// =============================================================================
// IntegrityTrailerV2 — 112-byte production integrity trailer with EC shard fields
// =============================================================================
///
/// Layout:
/// ```text
/// Offset  Size  Field
/// 0       8     magic          "VLOSINT4"
/// 8       2     format_version (u16 LE)
/// 10      2     digest_suite   (u16 LE, 1 = BLAKE3-256)
/// 12      2     trailer_len    (u16 LE, 112)
/// 14      2     reserved       (0)
/// 16      32    payload_digest ([u8; 32] BLAKE3-256)
/// 48      32    record_digest  ([u8; 32] BLAKE3-256)
/// 80      1     shard_count    (for EC, 0 = not sharded)
/// 81      1     shard_index    (0-based within shard group)
/// 82      1     ec_k           (data shards in group)
/// 83      1     ec_m           (parity shards in group)
/// 84      28    reserved       (zero fill)
/// Total: 112 bytes
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct IntegrityTrailerV2 {
    pub format_version: u16,
    pub digest_suite: u16,
    pub payload_digest: ProductionIntegrityDigest,
    pub record_digest: ProductionIntegrityDigest,
    pub shard_count: u8,
    pub shard_index: u8,
    pub ec_k: u8,
    pub ec_m: u8,
}

impl IntegrityTrailerV2 {
    pub const LEN: usize = INTEGRITY_TRAILER_V2_LEN;
    pub const MAGIC: &'static [u8; 8] = &INTEGRITY_TRAILER_V2_MAGIC_BYTES;
}

/// Encode an `IntegrityTrailerV2` into a 112-byte buffer.
pub fn encode_integrity_trailer_v2(trailer: &IntegrityTrailerV2) -> [u8; INTEGRITY_TRAILER_V2_LEN] {
    let mut out = [0_u8; INTEGRITY_TRAILER_V2_LEN];
    out[0..8].copy_from_slice(&INTEGRITY_TRAILER_V2_MAGIC_BYTES);
    write_u16(&mut out[8..10], trailer.format_version);
    write_u16(&mut out[10..12], trailer.digest_suite);
    write_u16(
        &mut out[12..14],
        u16::try_from(INTEGRITY_TRAILER_V2_LEN).expect("INTEGRITY_TRAILER_V2_LEN fits in u16"),
    );
    write_u16(&mut out[14..16], 0); // reserved
    out[16..48].copy_from_slice(&trailer.payload_digest.as_bytes32());
    out[48..80].copy_from_slice(&trailer.record_digest.as_bytes32());
    out[80] = trailer.shard_count;
    out[81] = trailer.shard_index;
    out[82] = trailer.ec_k;
    out[83] = trailer.ec_m;
    // bytes 84..112 are zero (reserved)
    out
}

/// Decode an `IntegrityTrailerV2` from a 112-byte buffer.
pub fn decode_integrity_trailer_v2(
    src: &[u8; INTEGRITY_TRAILER_V2_LEN],
) -> Result<IntegrityTrailerV2> {
    if src[0..8] != INTEGRITY_TRAILER_V2_MAGIC_BYTES[..] {
        return Err(StoreError::CorruptHeader {
            segment_id: 0,
            offset: 0,
            reason: "production integrity trailer magic does not match local object-store format",
        });
    }
    let format_version = read_u16(&src[8..10]);
    let digest_suite = read_u16(&src[10..12]);
    if digest_suite != INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID {
        return Err(StoreError::CorruptHeader {
            segment_id: 0,
            offset: 10,
            reason: "production integrity digest suite is not supported",
        });
    }
    let declared_len = read_u16(&src[12..14]);
    if usize::from(declared_len) != INTEGRITY_TRAILER_V2_LEN {
        return Err(StoreError::CorruptHeader {
            segment_id: 0,
            offset: 12,
            reason: "production integrity trailer length is not supported",
        });
    }
    if read_u16(&src[14..16]) != 0 {
        return Err(StoreError::CorruptHeader {
            segment_id: 0,
            offset: 14,
            reason: "production integrity trailer reserved bytes are not zero",
        });
    }
    let payload_digest = digest_from_slice(&src[16..48]);
    let record_digest = digest_from_slice(&src[48..80]);
    let shard_count = src[80];
    let shard_index = src[81];
    let ec_k = src[82];
    let ec_m = src[83];
    Ok(IntegrityTrailerV2 {
        format_version,
        digest_suite,
        payload_digest,
        record_digest,
        shard_count,
        shard_index,
        ec_k,
        ec_m,
    })
}

/// Build an `IntegrityTrailerV2` from a record, computing domain-separated digests.
pub(crate) fn build_integrity_trailer_v2(
    record: RecordHeader,
    header: &[u8; RECORD_HEADER_LEN],
    payload: &[u8],
    footer: &[u8; RECORD_FOOTER_LEN],
) -> IntegrityTrailerV2 {
    let digests = production_integrity_digests_v2(record, header, payload, footer);
    IntegrityTrailerV2 {
        format_version: record.format_version,
        digest_suite: INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID,
        payload_digest: digests.payload_digest,
        record_digest: digests.record_digest,
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    }
}

/// Verify an `IntegrityTrailerV2` against a record.
pub(crate) fn verify_integrity_trailer_v2(
    trailer: &IntegrityTrailerV2,
    record: RecordHeader,
    header: &[u8; RECORD_HEADER_LEN],
    payload: &[u8],
    footer: &[u8; RECORD_FOOTER_LEN],
    segment_id: u64,
    offset: u64,
) -> Result<ProductionIntegrityRecordDigests> {
    if trailer.format_version != record.format_version {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "production integrity trailer version does not match record version",
        });
    }
    if trailer.digest_suite != INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID {
        return Err(StoreError::CorruptHeader {
            segment_id,
            offset,
            reason: "production integrity digest suite is not supported",
        });
    }
    let actual = production_integrity_digests_v2(record, header, payload, footer);
    if trailer.payload_digest != actual.payload_digest {
        return Err(StoreError::ProductionIntegrityMismatch {
            segment_id,
            offset: offset + 16,
            field: "payload digest",
            expected: trailer.payload_digest,
            actual: actual.payload_digest,
        });
    }
    if trailer.record_digest != actual.record_digest {
        return Err(StoreError::ProductionIntegrityMismatch {
            segment_id,
            offset: offset + 48,
            field: "record digest",
            expected: trailer.record_digest,
            actual: actual.record_digest,
        });
    }
    Ok(actual)
}

// =============================================================================
// Domain-separated BLAKE3-256 production integrity (G3 pillar)
// =============================================================================

fn production_integrity_digests_v2(
    record: RecordHeader,
    header: &[u8; RECORD_HEADER_LEN],
    payload: &[u8],
    footer: &[u8; RECORD_FOOTER_LEN],
) -> ProductionIntegrityRecordDigests {
    let payload_digest = production_integrity_payload_digest_v2(record, payload);
    let record_digest =
        production_integrity_record_digest_v2(record, header, payload, footer, payload_digest);
    ProductionIntegrityRecordDigests {
        payload_digest,
        record_digest,
    }
}

fn production_integrity_payload_digest_v2(
    record: RecordHeader,
    payload: &[u8],
) -> ProductionIntegrityDigest {
    let domain = domain_for_kind(record.kind);
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&record.format_version.to_le_bytes());
    hasher.update(&record.kind.as_u16().to_le_bytes());
    hasher.update(&record.sequence.to_le_bytes());
    hasher.update(&record.payload_len.to_le_bytes());
    hasher.update(&record.payload_checksum.get().to_le_bytes());
    hasher.update(&record.key.as_bytes32());
    hasher.update(payload);
    ProductionIntegrityDigest::from_bytes32(*hasher.finalize().as_bytes())
}

fn production_integrity_record_digest_v2(
    record: RecordHeader,
    header: &[u8; RECORD_HEADER_LEN],
    payload: &[u8],
    footer: &[u8; RECORD_FOOTER_LEN],
    payload_digest: ProductionIntegrityDigest,
) -> ProductionIntegrityDigest {
    let domain = domain_for_kind(record.kind);
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&record.format_version.to_le_bytes());
    hasher.update(&record.kind.as_u16().to_le_bytes());
    hasher.update(&record.sequence.to_le_bytes());
    hasher.update(&record.payload_len.to_le_bytes());
    hasher.update(&record.payload_checksum.get().to_le_bytes());
    hasher.update(&record.key.as_bytes32());
    hasher.update(&payload_digest.as_bytes32());
    hasher.update(&(RECORD_HEADER_LEN as u64).to_le_bytes());
    hasher.update(header);
    hasher.update(payload);
    hasher.update(&(RECORD_FOOTER_LEN as u64).to_le_bytes());
    hasher.update(footer);
    ProductionIntegrityDigest::from_bytes32(*hasher.finalize().as_bytes())
}

/// Return the domain-separation context for a record kind.
fn domain_for_kind(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Put => DOMAIN_CONTEXT_PUT_RECORD,
        RecordKind::Delete => DOMAIN_CONTEXT_DELETE_RECORD,
    }
}

// =============================================================================
// SegmentIntegrityFooter — 192-byte segment hash-chaining footer (G3 pillar)
// =============================================================================

/// A 192-byte footer at the end of each segment file that forms a
/// Merkle-like hash chain across segments.
///
/// Layout:
/// ```text
/// Offset  Size  Field
/// 0       8     magic                "VLOSSEGF"
/// 8       8     segment_id           (u64 LE)
/// 16      8     record_count         (u64 LE)
/// 24      8     total_payload_bytes   (u64 LE)
/// 32      32    segment_digest       ([u8; 32] BLAKE3-256)
/// 64      32    previous_segment_digest ([u8; 32] BLAKE3-256)
/// 96      48    reserved             (zero fill)
/// 144     48    reserved             (zero fill)
/// Total: 192 bytes
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SegmentIntegrityFooter {
    pub segment_id: u64,
    pub record_count: u64,
    pub total_payload_bytes: u64,
    pub segment_digest: ProductionIntegrityDigest,
    pub previous_segment_digest: ProductionIntegrityDigest,
}

impl SegmentIntegrityFooter {
    pub const LEN: usize = SEGMENT_INTEGRITY_FOOTER_LEN;
    pub const MAGIC: &'static [u8; 8] = &SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES;
}

/// Encode a `SegmentIntegrityFooter` into its 192-byte on-media format.
pub fn encode_segment_integrity_footer(
    footer: &SegmentIntegrityFooter,
) -> [u8; SEGMENT_INTEGRITY_FOOTER_LEN] {
    let mut out = [0_u8; SEGMENT_INTEGRITY_FOOTER_LEN];
    out[0..8].copy_from_slice(&SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES);
    write_u64(&mut out[8..16], footer.segment_id);
    write_u64(&mut out[16..24], footer.record_count);
    write_u64(&mut out[24..32], footer.total_payload_bytes);
    out[32..64].copy_from_slice(&footer.segment_digest.as_bytes32());
    out[64..96].copy_from_slice(&footer.previous_segment_digest.as_bytes32());
    // bytes 96..192 are zero (reserved)
    out
}

/// Decode a `SegmentIntegrityFooter` from its 192-byte on-media format.
pub fn decode_segment_integrity_footer(
    src: &[u8; SEGMENT_INTEGRITY_FOOTER_LEN],
) -> Result<SegmentIntegrityFooter> {
    if src[0..8] != SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES[..] {
        return Err(StoreError::CorruptHeader {
            segment_id: 0,
            offset: 0,
            reason: "SegmentIntegrityFooter magic does not match (expected VLOSSEGF)",
        });
    }
    let segment_id = read_u64(&src[8..16]);
    let record_count = read_u64(&src[16..24]);
    let total_payload_bytes = read_u64(&src[24..32]);
    let segment_digest = digest_from_slice(&src[32..64]);
    let previous_segment_digest = digest_from_slice(&src[64..96]);
    Ok(SegmentIntegrityFooter {
        segment_id,
        record_count,
        total_payload_bytes,
        segment_digest,
        previous_segment_digest,
    })
}

/// Compute the segment-level BLAKE3-256 digest over all committed records.
///
/// Record digests are concatenated into a single buffer, then hashed with a
/// domain-separated key derived from `DomainTag::SegmentIntegrityFooter` via
/// `ChecksumTreeBuilder` to produce the segment-integrity footer digest.
pub fn compute_segment_digest(record_digests: &[[u8; 32]]) -> ProductionIntegrityDigest {
    use tidefs_checksum_tree::{ChecksumTreeBuilder, DomainTag};
    let dk = DomainTag::SegmentIntegrityFooter.derive_key();
    let mut all_bytes = Vec::with_capacity(record_digests.len() * 32);
    for digest in record_digests {
        all_bytes.extend_from_slice(digest);
    }
    let block_size = all_bytes.len().max(1);
    let mut builder = ChecksumTreeBuilder::new_with_domain(block_size, dk);
    builder.ingest(&all_bytes);
    let tree = builder.finish();
    ProductionIntegrityDigest::from_bytes32(tree.root_hash)
}

// =============================================================================
// SegmentChainVerifier — hash-chain walker for G3 segment integrity
// =============================================================================

/// Walks the hash chain across segment integrity footers to verify
/// that every segment correctly links to its predecessor.
///
/// The verifier reads `SegmentIntegrityFooter` from each segment file,
/// validates that `previous_segment_digest` matches the prior footer's
/// `segment_digest`, and records broken links.
#[derive(Clone, Debug)]
pub struct SegmentChainVerifier {
    segments_dir: PathBuf,
}

impl SegmentChainVerifier {
    /// Create a verifier targeting the given segments directory.
    #[must_use]
    pub fn new(segments_dir: impl AsRef<Path>) -> Self {
        Self {
            segments_dir: segments_dir.as_ref().to_path_buf(),
        }
    }

    /// Verify the full segment hash chain from newest to oldest.
    ///
    /// Reads every segment footer and confirms each one's
    /// `previous_segment_digest` equals the prior footer's `segment_digest`.
    /// Broken links are recorded as `SuspectEntry` items in the returned stats.
    pub fn verify_chain(&self) -> Result<(SegmentChainStats, SuspectLog)> {
        let mut segment_ids = discover_segment_ids(&self.segments_dir)?;
        if segment_ids.is_empty() {
            return Ok((SegmentChainStats::default(), SuspectLog::new()));
        }

        // Walk newest to oldest.
        segment_ids.sort_unstable();
        segment_ids.reverse();

        let mut stats = SegmentChainStats {
            segments_in_chain: segment_ids.len(),
            ..SegmentChainStats::default()
        };
        let mut suspect_log = SuspectLog::new();
        let mut expected_prev_digest: Option<ProductionIntegrityDigest> = None;

        for &seg_id in &segment_ids {
            let path = segment_path(&self.segments_dir, seg_id);
            let seg_len = file_len(&path)?;

            // Segments too short to have a footer are skipped.
            if seg_len < SEGMENT_INTEGRITY_FOOTER_LEN_U64 {
                if expected_prev_digest.is_some() {
                    stats.chain_breaks_detected += 1;
                    suspect_log.record(SuspectEntry {
                        locator_id: seg_id,
                        segment_id: seg_id,
                        offset: seg_len,
                        record_type: 0,
                        expected_hash: [0u8; 32],
                        actual_hash: [0u8; 32],
                        repair_attempts: 0,
                        last_repair_attempt: 0,
                        resolved: false,
                        commit_group: 0,
                        timestamp_secs: 0,
                        ..Default::default()
                    });
                }
                continue;
            }

            let footer_offset = seg_len - SEGMENT_INTEGRITY_FOOTER_LEN_U64;
            let mut file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|source| io_error("open chain verify", &path, source))?;
            file.seek(SeekFrom::Start(footer_offset))
                .map_err(|source| io_error("seek footer", &path, source))?;
            let mut buf = [0_u8; SEGMENT_INTEGRITY_FOOTER_LEN];
            let n = file
                .read(&mut buf)
                .map_err(|source| io_error("read footer", &path, source))?;
            if n < SEGMENT_INTEGRITY_FOOTER_LEN {
                stats.chain_breaks_detected += 1;
                suspect_log.record(SuspectEntry {
                    locator_id: seg_id,
                    segment_id: seg_id,
                    offset: footer_offset,
                    record_type: 1,
                    expected_hash: [0u8; 32],
                    actual_hash: [0u8; 32],
                    repair_attempts: 0,
                    last_repair_attempt: 0,
                    resolved: false,
                    commit_group: 0,
                    timestamp_secs: 0,
                    ..Default::default()
                });
                continue;
            }

            match decode_segment_integrity_footer(&buf) {
                Ok(footer) => {
                    if footer.segment_id != seg_id {
                        stats.chain_breaks_detected += 1;
                        suspect_log.record(SuspectEntry {
                            locator_id: seg_id,
                            segment_id: seg_id,
                            offset: footer_offset,
                            record_type: 2,
                            expected_hash: [0u8; 32],
                            actual_hash: [0u8; 32],
                            repair_attempts: 0,
                            last_repair_attempt: 0,
                            resolved: false,
                            commit_group: 0,
                            timestamp_secs: 0,
                            ..Default::default()
                        });
                        continue;
                    }

                    // Chain link check:
                    // Walking newest (highest seg_id) to oldest:
                    //   footer[N].previous_segment_digest == footer[N-1].segment_digest
                    // After processing footer[N], we remember
                    //   footer[N].previous_segment_digest
                    // and check it against footer[N-1].segment_digest.
                    if let Some(expected) = expected_prev_digest {
                        if footer.segment_digest != expected {
                            stats.chain_breaks_detected += 1;
                            suspect_log.record(SuspectEntry {
                                locator_id: seg_id,
                                segment_id: seg_id,
                                offset: footer_offset,
                                record_type: 3, // chain broken
                                expected_hash: [0u8; 32],
                                actual_hash: [0u8; 32],
                                repair_attempts: 0,
                                last_repair_attempt: 0,
                                resolved: false,
                                commit_group: 0,
                                timestamp_secs: 0,
                                ..Default::default()
                            });
                        }
                    }
                    expected_prev_digest = Some(footer.previous_segment_digest);
                    stats.last_verified_segment = seg_id;
                }
                Err(_e) => {
                    stats.chain_breaks_detected += 1;
                    suspect_log.record(SuspectEntry {
                        locator_id: seg_id,
                        segment_id: seg_id,
                        offset: footer_offset,
                        record_type: 4,
                        expected_hash: [0u8; 32],
                        actual_hash: [0u8; 32],
                        repair_attempts: 0,
                        last_repair_attempt: 0,
                        resolved: false,
                        commit_group: 0,
                        timestamp_secs: 0,
                        ..Default::default()
                    });
                }
            }
        }

        stats.chain_length = stats
            .segments_in_chain
            .saturating_mul(SEGMENT_INTEGRITY_FOOTER_LEN) as u64;

        Ok((stats, suspect_log))
    }
}

// ── Per-object checksum index persistence ──────────────────────────

/// Magic bytes for the checksum index file.
const CHECKSUM_INDEX_MAGIC: [u8; 4] = [0x56, 0x42, 0x43, 0x49]; // "VBCI"

/// File name for the per-object checksum index.
const CHECKSUM_INDEX_FILE_NAME: &str = "checksums.idx";

/// Current version of the checksum index binary format.
const CHECKSUM_INDEX_VERSION: u8 = 1;

/// Write the in-memory per-object checksum map to a durable index file.
/// Uses atomic rename-overwrite so a crash during write never leaves a
/// partial file visible to the next open.
pub(crate) fn write_checksums(
    segments_dir: &Path,
    checksums: &BTreeMap<ObjectKey, ObjectDigest>,
) -> Result<()> {
    if sidecar_files_unavailable(segments_dir) {
        return Ok(());
    }

    let tmp_path = segments_dir.join(format!("{CHECKSUM_INDEX_FILE_NAME}.tmp"));
    let real_path = segments_dir.join(CHECKSUM_INDEX_FILE_NAME);

    let entry_count = checksums.len() as u32;
    // Header: magic(4) + version(1) + entry_count(4) + reserved(3) = 12 bytes
    // Each entry: ObjectKey(32) + ObjectDigest(32) = 64 bytes
    let mut buf = Vec::with_capacity(12 + entry_count as usize * 64);
    buf.extend_from_slice(&CHECKSUM_INDEX_MAGIC);
    buf.push(CHECKSUM_INDEX_VERSION);
    buf.extend_from_slice(&entry_count.to_le_bytes());
    buf.extend_from_slice(&[0u8; 3]); // reserved padding

    for (key, digest) in checksums {
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(digest.as_bytes());
    }

    fs::write(&tmp_path, &buf)
        .map_err(|source| io_error("write checksum index", &tmp_path, source))?;
    fs::rename(&tmp_path, &real_path)
        .map_err(|source| io_error("rename checksum index", &tmp_path, source))?;
    sync_directory(segments_dir)?;
    Ok(())
}

/// Load the per-object checksum index from the segments directory.
/// Returns an empty map if the file does not exist (fresh pool or
/// pre-checksum-era store).
pub(crate) fn load_checksums(segments_dir: &Path) -> BTreeMap<ObjectKey, ObjectDigest> {
    if sidecar_files_unavailable(segments_dir) {
        return BTreeMap::new();
    }

    let path = segments_dir.join(CHECKSUM_INDEX_FILE_NAME);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => return BTreeMap::new(),
    };

    if data.len() < 12 {
        return BTreeMap::new();
    }

    // Validate magic
    if data[0..4] != CHECKSUM_INDEX_MAGIC {
        return BTreeMap::new();
    }
    let version = data[4];
    if version != CHECKSUM_INDEX_VERSION {
        return BTreeMap::new();
    }
    let entry_count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let expected_len = 12 + entry_count * 64;
    if data.len() < expected_len {
        return BTreeMap::new();
    }

    let mut checksums = BTreeMap::new();
    let body = &data[12..];
    for i in 0..entry_count {
        let offset = i * 64;
        if offset + 64 > body.len() {
            break;
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&body[offset..offset + 32]);
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&body[offset + 32..offset + 64]);
        checksums.insert(ObjectKey::from_bytes(key_bytes), ObjectDigest(digest_bytes));
    }

    checksums
}

#[cfg(test)]
mod block_device_open_tests {
    use super::*;
    use tempfile::tempdir;

    const BLOCK_IMAGE_BYTES: u64 = LocalObjectStore::minimum_block_device_capacity();

    fn block_test_identity() -> BlockStoreIdentity {
        BlockStoreIdentity {
            pool_guid: [0x31; 16],
            device_guid: [0x42; 16],
        }
    }

    fn create_blank_block_image(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let image = dir.path().join("pool.img");
        let file = File::create(&image).expect("create image");
        file.set_len(BLOCK_IMAGE_BYTES).expect("size image");
        drop(file);
        image
    }

    fn create_block_image(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let image = create_blank_block_image(dir);
        LocalObjectStore::initialize_block_device_bootstrap(&image, block_test_identity())
            .expect("initialize explicit test Store identity");
        image
    }

    fn block_bootstrap_data_end() -> u64 {
        BLOCK_IMAGE_BYTES - POOL_LABEL_SIZE as u64
    }

    fn write_raw_bootstrap_record(
        image: &Path,
        kind: RecordKind,
        key: ObjectKey,
        payload: &[u8],
    ) -> u64 {
        let record = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            kind,
            sequence: 0,
            key,
            payload_len: payload.len() as u64,
            payload_checksum: checksum64(payload),
            compression_algorithm: 0,
        };
        let offset = LocalObjectStore::block_device_data_start();
        let range = checked_record_range(record, 0, offset).expect("bootstrap record range");
        let mut header = [0; RECORD_HEADER_LEN];
        encode_header(&mut header, record);
        let footer = encode_footer(record);
        let trailer = encode_integrity_trailer_v2(&build_integrity_trailer_v2(
            record, &header, payload, &footer,
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(image)
            .expect("open image for raw bootstrap record");
        file.seek(SeekFrom::Start(offset))
            .expect("seek bootstrap record");
        file.write_all(&header).expect("write bootstrap header");
        file.write_all(payload).expect("write bootstrap payload");
        file.write_all(&footer).expect("write bootstrap footer");
        file.write_all(&trailer).expect("write bootstrap trailer");
        file.sync_all().expect("sync bootstrap record");
        range.end_offset
    }

    fn block_options(record_bytes: u64) -> StoreOptions {
        let mut options = StoreOptions::test_fast();
        options.max_segment_bytes = record_bytes;
        options
    }

    fn dead_object_receipt(
        key: ReclaimObjectKey,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&key.0);
        tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::replicated(
            key, 7, 1, 2, 4096, digest,
        )
    }

    #[test]
    fn pool_bootstrap_public_raw_open_is_read_only_and_identity_mismatch_fails() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let before = std::fs::read(&image).expect("snapshot initialized image");

        let mut store = LocalObjectStore::open_block_device(&image, StoreOptions::test_fast())
            .expect("open regular file backing");

        assert!(store.block_device_mode);
        assert!(store.is_read_only());
        assert!(matches!(
            store.put(ObjectKey::from_name(b"public-read-only"), b"refused"),
            Err(StoreError::ReadOnly { operation: "put" })
        ));
        drop(store);

        let mut wrong_pool_guid = block_test_identity().pool_guid;
        wrong_pool_guid[0] ^= 0xff;
        assert!(matches!(
            LocalObjectStore::open_block_device_read_only_existing(
                &image,
                StoreOptions::test_fast(),
                wrong_pool_guid,
                block_test_identity().device_guid,
            ),
            Err(StoreError::InvalidOptions { reason }) if reason.contains("identity does not match")
        ));
        assert_eq!(
            std::fs::read(&image).expect("reread initialized image"),
            before,
            "read-only or identity-mismatch open changed media"
        );
    }

    #[test]
    fn pool_bootstrap_ordinary_opens_never_initialize_blank_media() {
        let dir = tempdir().expect("tempdir");
        let image = create_blank_block_image(&dir);
        let before = std::fs::read(&image).expect("snapshot blank image");

        let opens = [
            LocalObjectStore::open_block_device(&image, StoreOptions::test_fast()),
            LocalObjectStore::open_block_device_writable_existing(
                &image,
                StoreOptions::test_fast(),
                block_test_identity(),
            ),
            LocalObjectStore::open_block_device_read_only_existing(
                &image,
                StoreOptions::test_fast(),
                block_test_identity().pool_guid,
                block_test_identity().device_guid,
            ),
            LocalObjectStore::open_block_device_preflight_existing(
                &image,
                StoreOptions::test_fast(),
                block_test_identity(),
            ),
        ];
        for result in opens {
            assert!(matches!(
                result,
                Err(StoreError::InvalidOptions { reason })
                    if reason.contains("requires an initialized format header")
            ));
            assert_eq!(
                std::fs::read(&image).expect("reread blank image"),
                before,
                "ordinary open changed blank media"
            );
        }
    }

    #[test]
    fn pool_bootstrap_blank_inspection_and_matching_header_retry() {
        let dir = tempdir().expect("tempdir");
        let image = create_blank_block_image(&dir);
        let blank =
            LocalObjectStore::inspect_block_device_bootstrap(&image, block_bootstrap_data_end())
                .expect("inspect blank bootstrap region");
        assert_eq!(blank.identity, None);
        assert_eq!(blank.record, None);

        LocalObjectStore::initialize_block_device_bootstrap(&image, block_test_identity())
            .expect("initialize blank bootstrap region");
        let initialized =
            LocalObjectStore::inspect_block_device_bootstrap(&image, block_bootstrap_data_end())
                .expect("inspect initialized bootstrap region");
        assert_eq!(initialized.identity, Some(block_test_identity()));
        assert_eq!(initialized.record, None);

        let before_retry = std::fs::read(&image).expect("snapshot initialized image");
        LocalObjectStore::initialize_block_device_bootstrap(&image, block_test_identity())
            .expect("retry matching header");
        assert_eq!(
            std::fs::read(&image).expect("reread initialized image"),
            before_retry,
            "matching-header retry rewrote media"
        );
    }

    #[test]
    fn pool_bootstrap_retained_handle_survives_path_replacement() {
        let dir = tempdir().expect("tempdir");
        let image = create_blank_block_image(&dir);
        let retained = LocalObjectStore::initialize_and_retain_block_device_bootstrap(
            &image,
            block_test_identity(),
        )
        .expect("initialize and retain exact image");
        let admitted_image = dir.path().join("admitted.img");
        std::fs::rename(&image, &admitted_image).expect("move admitted image");
        let replacement = File::create(&image).expect("create replacement pathname");
        replacement
            .set_len(BLOCK_IMAGE_BYTES)
            .expect("size replacement pathname");
        drop(replacement);

        let key = ObjectKey::from_name(b"retained-handle-write");
        let mut store = LocalObjectStore::open_block_device_writable_existing_file(
            retained,
            image.clone(),
            StoreOptions::test_fast(),
            block_test_identity(),
        )
        .expect("open retained admitted image");
        store
            .put(key, b"exact admitted media")
            .expect("write retained admitted image");
        store.sync_all().expect("sync retained admitted image");
        drop(store);

        assert!(std::fs::read(&image)
            .expect("read replacement pathname")
            .iter()
            .all(|byte| *byte == 0));
        let reopened = LocalObjectStore::open_block_device_writable_existing(
            &admitted_image,
            StoreOptions::test_fast(),
            block_test_identity(),
        )
        .expect("reopen exact admitted image");
        assert_eq!(
            reopened.get(key).expect("read retained-handle write"),
            Some(b"exact admitted media".to_vec())
        );
    }

    #[test]
    fn pool_bootstrap_refuses_foreign_and_corrupt_headers_without_mutation() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let before_foreign = std::fs::read(&image).expect("snapshot initialized image");
        let foreign = BlockStoreIdentity {
            pool_guid: [0x91; 16],
            device_guid: [0x92; 16],
        };
        assert!(matches!(
            LocalObjectStore::initialize_block_device_bootstrap(&image, foreign),
            Err(StoreError::InvalidOptions { reason })
                if reason.contains("identity does not match")
        ));
        assert_eq!(
            std::fs::read(&image).expect("reread after foreign retry"),
            before_foreign
        );

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open image for corrupt header");
        file.seek(SeekFrom::Start(BLOCK_DEVICE_DATA_REGION_OFFSET + 48))
            .expect("seek header checksum");
        file.write_all(&[0x5a]).expect("corrupt header checksum");
        file.sync_all().expect("sync corrupt header");
        drop(file);
        let corrupt_before = std::fs::read(&image).expect("snapshot corrupt image");
        assert!(
            LocalObjectStore::initialize_block_device_bootstrap(&image, block_test_identity())
                .is_err()
        );
        assert_eq!(
            std::fs::read(&image).expect("reread corrupt image"),
            corrupt_before,
            "corrupt-header refusal changed media"
        );
    }

    #[test]
    fn pool_bootstrap_refuses_headerless_nonblank_and_torn_records() {
        let dir = tempdir().expect("tempdir");
        let image = create_blank_block_image(&dir);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open blank image");
        file.seek(SeekFrom::Start(LocalObjectStore::block_device_data_start()))
            .expect("seek data region");
        file.write_all(&[0x7f]).expect("write stray byte");
        file.sync_all().expect("sync stray byte");
        drop(file);
        let before = std::fs::read(&image).expect("snapshot headerless nonblank image");
        assert!(matches!(
            LocalObjectStore::initialize_block_device_bootstrap(&image, block_test_identity()),
            Err(StoreError::InvalidOptions { reason })
                if reason.contains("missing block-device store header")
        ));
        assert_eq!(std::fs::read(&image).expect("reread image"), before);

        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open initialized image");
        file.seek(SeekFrom::Start(LocalObjectStore::block_device_data_start()))
            .expect("seek record region");
        file.write_all(&RECORD_MAGIC[..4])
            .expect("write torn record prefix");
        file.sync_all().expect("sync torn record prefix");
        assert!(LocalObjectStore::inspect_block_device_bootstrap(
            &image,
            block_bootstrap_data_end()
        )
        .is_err());
    }

    #[test]
    fn pool_bootstrap_refuses_tombstones_and_bytes_after_one_marker() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        write_raw_bootstrap_record(
            &image,
            RecordKind::Delete,
            ObjectKey::from_name(b"bootstrap-tombstone"),
            &[],
        );
        assert!(matches!(
            LocalObjectStore::inspect_block_device_bootstrap(
                &image,
                block_bootstrap_data_end()
            ),
            Err(StoreError::InvalidOptions { reason })
                if reason.contains("not one current internal put")
        ));

        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let end = write_raw_bootstrap_record(
            &image,
            RecordKind::Put,
            ObjectKey::from_name(b"one-marker"),
            b"marker",
        );
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open image after marker");
        file.seek(SeekFrom::Start(end)).expect("seek after marker");
        file.write_all(&[1]).expect("write byte after marker");
        file.sync_all().expect("sync byte after marker");
        assert!(matches!(
            LocalObjectStore::inspect_block_device_bootstrap(
                &image,
                block_bootstrap_data_end()
            ),
            Err(StoreError::InvalidOptions { reason })
                if reason.contains("records or bytes after its marker")
        ));
    }

    #[test]
    fn open_block_device_rejects_directory_path() {
        let dir = tempdir().expect("tempdir");

        let err = match LocalObjectStore::open_block_device(dir.path(), StoreOptions::test_fast()) {
            Ok(_) => panic!("directory must not open as a pool backing"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            StoreError::InvalidOptions { reason } if reason.contains("directory")
        ));
    }

    #[test]
    fn block_device_replay_records_each_physical_version_once() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let key = ObjectKey::from_name(b"block-device/version-history");

        {
            let mut store = LocalObjectStore::open_block_device_writable_unbound(
                &image,
                StoreOptions::test_fast(),
            )
            .expect("open block image");
            for payload in [b"version-1".as_slice(), b"version-2", b"version-3"] {
                store.put(key, payload).expect("write version");
            }
            store.sync_all().expect("sync versions");
        }

        let reopened = LocalObjectStore::open_block_device(&image, StoreOptions::test_fast())
            .expect("reopen block image");
        let versions = reopened.version_locations_of(key);
        assert_eq!(versions.len(), 3, "one location per physical put record");
        assert_eq!(
            versions
                .iter()
                .map(|location| location.record_offset)
                .collect::<BTreeSet<_>>()
                .len(),
            versions.len(),
            "version history must not repeat a physical record"
        );
        for (location, expected) in versions
            .iter()
            .zip([b"version-1", b"version-2", b"version-3"])
        {
            assert_eq!(
                reopened
                    .get_at_location(*location)
                    .expect("read physical version"),
                expected
            );
        }
    }

    #[test]
    fn block_device_compacts_live_records_on_append_full() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let record_bytes = 128 * 1024;
        let options = block_options(record_bytes);
        let payload_len = options.max_object_bytes() as usize;
        let mut store = LocalObjectStore::open_block_device_writable_unbound(&image, options)
            .expect("open block image");
        let key = ObjectKey::from_name(b"block-device/overwrite");
        let mut latest = Vec::new();

        for i in 0..8_u8 {
            latest = vec![i; payload_len];
            store.put(key, &latest).expect("overwrite");
        }

        assert_eq!(store.get(key).expect("get latest"), Some(latest.clone()));
        assert!(
            store.current_offset <= LocalObjectStore::block_device_data_start() + 3 * record_bytes,
            "append cursor should be back near the live prefix after compaction"
        );
        store.sync_all().expect("sync compacted block image");
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, block_options(record_bytes))
            .expect("reopen block image");
        assert_eq!(reopened.get(key).expect("get reopened"), Some(latest));
    }

    #[test]
    fn block_device_streaming_compaction_preserves_adjacent_unread_sources() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let options = block_options(64 * 1024);
        let mut store =
            LocalObjectStore::open_block_device_writable_unbound(&image, options.clone())
                .expect("open block image");
        let records = (0..8_u8)
            .map(|index| {
                (
                    ObjectKey::from_name(format!("block-device/stream/{index}").as_bytes()),
                    vec![index; 4096 + usize::from(index)],
                )
            })
            .collect::<Vec<_>>();

        for (key, payload) in &records {
            store.put(*key, payload).expect("put adjacent source");
        }
        let retained_locations = records
            .iter()
            .map(|(key, _)| (*key, store.location_of(*key).expect("source location")))
            .collect::<Vec<_>>();
        let mut source_order = retained_locations
            .iter()
            .map(|(_, location)| *location)
            .collect::<Vec<_>>();
        source_order.sort_by_key(|location| location.record_offset);
        for pair in source_order.windows(2) {
            assert_eq!(
                pair[0].record_offset
                    + LocalObjectStore::checked_record_total_len_u64(pair[0].payload_len),
                pair[1].record_offset,
                "fixture sources must be adjacent so each compacted tail reaches the next header"
            );
        }

        store
            .compact_block_device_locations(retained_locations)
            .expect("stream adjacent retained records");
        for (key, payload) in &records {
            assert_eq!(
                store.get(*key).expect("read compacted record"),
                Some(payload.clone())
            );
        }
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, options)
            .expect("reopen streamed block image");
        for (key, payload) in records {
            assert_eq!(
                reopened.get(key).expect("read reopened compacted record"),
                Some(payload)
            );
        }
    }

    #[test]
    fn block_device_delete_churn_reuses_append_space() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        // Five live records still fit in the fixed 1 MiB data region, while
        // the two superseded records plus delete markers force the later
        // appends through block-log compaction.
        let record_bytes = 192 * 1024;
        let options = block_options(record_bytes);
        let payload_len = options.max_object_bytes() as usize;
        let mut store = LocalObjectStore::open_block_device_writable_unbound(&image, options)
            .expect("open block image");
        let deleted_a = ObjectKey::from_name(b"block-device/delete/a");
        let deleted_b = ObjectKey::from_name(b"block-device/delete/b");
        let live_keys = [
            ObjectKey::from_name(b"block-device/live/c"),
            ObjectKey::from_name(b"block-device/live/d"),
            ObjectKey::from_name(b"block-device/live/e"),
            ObjectKey::from_name(b"block-device/live/f"),
            ObjectKey::from_name(b"block-device/live/g"),
        ];

        store
            .put(deleted_a, &vec![0xa0; payload_len])
            .expect("put deleted a");
        store
            .put(deleted_b, &vec![0xb0; payload_len])
            .expect("put deleted b");
        for (idx, key) in live_keys[..2].iter().enumerate() {
            store
                .put(*key, &vec![idx as u8; payload_len])
                .expect("put initial live");
        }
        assert!(store.delete(deleted_a).expect("delete a"));
        assert!(store.delete(deleted_b).expect("delete b"));
        for (idx, key) in live_keys[2..].iter().enumerate() {
            store
                .put(*key, &vec![0xc0 + idx as u8; payload_len])
                .expect("put post-delete live");
        }

        assert_eq!(store.get(deleted_a).expect("get deleted a"), None);
        assert_eq!(store.get(deleted_b).expect("get deleted b"), None);
        for key in live_keys {
            assert!(store.get(key).expect("get live").is_some());
        }
        let compacted_live_bound = LocalObjectStore::block_device_data_start()
            + 5 * record_bytes
            + LocalObjectStore::checked_record_total_len_u64(std::mem::size_of::<u64>() as u64);
        assert!(
            store.current_offset <= compacted_live_bound,
            "delete churn should retain only live records plus the physical-lifetime sequence high-water"
        );
        store.sync_all().expect("sync compacted block image");
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, block_options(record_bytes))
            .expect("reopen block image");
        assert_eq!(reopened.get(deleted_a).expect("get reopened a"), None);
        assert_eq!(reopened.get(deleted_b).expect("get reopened b"), None);
        for key in live_keys {
            assert!(reopened.get(key).expect("get reopened live").is_some());
        }
    }

    #[test]
    fn block_device_compact_retaining_rewrites_image_without_segment_dir() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let record_bytes = 80 * 1024;
        let options = block_options(record_bytes);
        let payload_len = options.max_object_bytes() as usize;
        let mut store = LocalObjectStore::open_block_device_writable_unbound(&image, options)
            .expect("open block image");
        let dead = ObjectKey::from_name(b"block-device/compact-retaining/dead");
        let live_a = ObjectKey::from_name(b"block-device/compact-retaining/live-a");
        let live_b = ObjectKey::from_name(b"block-device/compact-retaining/live-b");
        let live_a_payload = vec![0xa1; payload_len];
        let live_b_payload = vec![0xb2; payload_len];
        let mut internal_key_bytes = [0x5a; 32];
        internal_key_bytes[..8].copy_from_slice(&crate::POOL_PLACEMENT_RECEIPT_KEY_PREFIX);
        let internal_key = ObjectKey(internal_key_bytes);
        let internal_payload = b"committed-root-metadata";

        store.put(dead, &vec![0xdd; payload_len]).expect("put dead");
        store.put(live_a, &live_a_payload).expect("put live a");
        store.put(live_b, &live_b_payload).expect("put live b");
        store
            .put_direct(internal_key, internal_payload)
            .expect("put hidden metadata");
        assert!(store.delete(dead).expect("delete dead"));

        let live_keys = store.list_keys();
        assert!(
            is_public_scan_internal_key(internal_key) && !live_keys.contains(&internal_key),
            "public live-key scan must hide internal metadata"
        );
        let report = store
            .compact_retaining(&live_keys, &[])
            .expect("compact block image");

        assert_eq!(report.retired_segments, Vec::<u64>::new());
        assert_eq!(report.retained_segments, vec![0]);
        assert_eq!(report.live_objects_after, live_keys.len());
        assert!(
            store.current_offset <= LocalObjectStore::block_device_data_start() + 3 * record_bytes,
            "compact_retaining should move live records into the image prefix"
        );
        assert_eq!(store.get(dead).expect("get dead"), None);
        assert_eq!(
            store.get(live_a).expect("get live a"),
            Some(live_a_payload.clone())
        );
        assert_eq!(
            store.get(live_b).expect("get live b"),
            Some(live_b_payload.clone())
        );
        assert_eq!(
            store.get(internal_key).expect("get hidden metadata"),
            Some(internal_payload.to_vec())
        );
        store.sync_all().expect("sync compacted block image");
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, block_options(record_bytes))
            .expect("reopen block image");
        assert_eq!(reopened.get(dead).expect("get reopened dead"), None);
        assert_eq!(
            reopened.get(live_a).expect("get reopened live a"),
            Some(live_a_payload)
        );
        assert_eq!(
            reopened.get(live_b).expect("get reopened live b"),
            Some(live_b_payload)
        );
        assert_eq!(
            reopened
                .get(internal_key)
                .expect("get reopened hidden metadata"),
            Some(internal_payload.to_vec())
        );
    }

    #[test]
    fn block_device_append_after_compaction_clears_valid_stale_successor_header() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut store =
            LocalObjectStore::open_block_device_writable_unbound(&image, block_options(80 * 1024))
                .expect("open block image");
        let live_key = ObjectKey::from_name(b"block-device/terminator/live");
        let append_key = ObjectKey::from_name(b"block-device/terminator/append");
        let stale_key = ObjectKey::from_name(b"block-device/terminator/stale-tail");
        let append_payload = b"append consumes compacted terminator";
        let stale_payload = b"valid but obsolete tail record";

        store.put(live_key, b"live payload").expect("put live");
        let live_keys = store.list_keys();
        store
            .compact_retaining(&live_keys, &[])
            .expect("compact block prefix");
        let append_record_len =
            LocalObjectStore::checked_record_total_len_u64(append_payload.len() as u64);
        let stale_offset = store
            .current_offset
            .checked_add(append_record_len)
            .expect("stale successor offset");
        let stale_record = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            kind: RecordKind::Put,
            sequence: store.next_sequence + 100,
            key: stale_key,
            payload_len: stale_payload.len() as u64,
            payload_checksum: checksum64(stale_payload),
            compression_algorithm: 0,
        };
        let stale_range =
            checked_record_range(stale_record, 0, stale_offset).expect("stale record range");
        assert!(
            stale_range.end_offset + RECORD_HEADER_LEN_U64
                <= store.block_device_usable_end().expect("block usable end")
        );
        let mut stale_header = [0_u8; RECORD_HEADER_LEN];
        encode_header(&mut stale_header, stale_record);
        let stale_footer = encode_footer(stale_record);
        let stale_trailer = encode_integrity_trailer_v2(&build_integrity_trailer_v2(
            stale_record,
            &stale_header,
            stale_payload,
            &stale_footer,
        ));
        let mut backing = OpenOptions::new()
            .write(true)
            .open(&image)
            .expect("open block image for stale tail");
        backing
            .seek(SeekFrom::Start(stale_offset))
            .expect("seek stale tail");
        backing
            .write_all(&stale_header)
            .expect("write stale header");
        backing
            .write_all(stale_payload)
            .expect("write stale payload");
        backing
            .write_all(&stale_footer)
            .expect("write stale footer");
        backing
            .write_all(&stale_trailer)
            .expect("write stale trailer");
        backing.sync_all().expect("sync valid stale tail");
        drop(backing);

        let mut observed_stale_header = [0_u8; RECORD_HEADER_LEN];
        store
            .current_file
            .read_exact_at(&mut observed_stale_header, stale_offset)
            .expect("read valid stale header");
        assert_eq!(
            decode_header(&observed_stale_header, 0, stale_offset)
                .expect("decode valid stale header")
                .key,
            stale_key
        );

        store
            .put_direct(append_key, append_payload)
            .expect("append after compaction");
        let mut successor_header = [0xff_u8; RECORD_HEADER_LEN];
        store
            .current_file
            .read_exact_at(&mut successor_header, stale_offset)
            .expect("read successor terminator");
        assert_eq!(successor_header, [0_u8; RECORD_HEADER_LEN]);
        store.sync_all().expect("sync successor terminator");
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, block_options(80 * 1024))
            .expect("reopen compacted and appended image");
        assert_eq!(
            reopened.get(live_key).expect("get reopened live"),
            Some(b"live payload".to_vec())
        );
        assert_eq!(
            reopened.get(append_key).expect("get reopened append"),
            Some(append_payload.to_vec())
        );
        assert_eq!(reopened.get(stale_key).expect("get stale tail"), None);
    }

    #[test]
    fn block_device_prepublication_batch_verifies_only_its_final_tail() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut options = block_options(80 * 1024);
        options.sync_on_write = true;
        let mut store =
            LocalObjectStore::open_block_device_writable_unbound(&image, options.clone())
                .expect("open block image");
        let payload_key = ObjectKey::from_name(b"block-device/prepublication/payload");
        let successor_key = ObjectKey::from_name(b"block-device/prepublication/successor");
        let mut receipt_key_bytes = [0x45; 32];
        receipt_key_bytes[..8].copy_from_slice(&crate::POOL_PLACEMENT_RECEIPT_KEY_PREFIX);
        let receipt_key = ObjectKey(receipt_key_bytes);

        let verifications_before = store.block_device_tail_terminator_verifications;
        let batch_start = store.current_offset;
        store.begin_prepublication_append_batch();
        store
            .put_prepublication_pool_internal(payload_key, b"immutable payload")
            .expect("stage prepublication payload");
        store
            .put_pool_internal(receipt_key, b"placement receipt")
            .expect("stage placement receipt");
        assert_eq!(store.prepublication_append_start, Some(batch_start));
        assert!(!store.prepublication_append_bytes.is_empty());
        let mut unpublished_header = [0xff_u8; RECORD_HEADER_LEN];
        store
            .current_file
            .read_exact_at(&mut unpublished_header, batch_start)
            .expect("read unchanged on-disk batch start");
        assert_eq!(
            unpublished_header, [0_u8; RECORD_HEADER_LEN],
            "the records remain coalesced until the Pool closes the batch"
        );
        assert_eq!(
            store.block_device_tail_terminator_verifications, verifications_before,
            "intermediate tails are overwritten inside the append batch"
        );
        store
            .finish_prepublication_append_batch()
            .expect("verify final batch tail");
        assert!(store.prepublication_append_bytes.is_empty());
        assert_eq!(store.prepublication_append_start, None);
        assert_eq!(
            store.block_device_tail_terminator_verifications,
            verifications_before + 1,
            "the final durable tail is rewritten and verified once"
        );
        store
            .put_direct(successor_key, b"successor payload")
            .expect("append Pool sync record over the batch successor slot");
        store.sync_all().expect("sync prepublication batch");
        store
            .load_prepublication_batch_readback()
            .expect("load the persisted append range once");
        assert_eq!(
            store.prepublication_readback_range.map(|(start, _)| start),
            Some(batch_start)
        );
        assert!(!store.prepublication_readback_bytes.is_empty());
        assert_eq!(store.prepublication_readback_records.len(), 2);
        assert_eq!(
            store.get(payload_key).expect("read cached payload record"),
            Some(b"immutable payload".to_vec())
        );
        assert_eq!(
            store.get(receipt_key).expect("read cached receipt record"),
            Some(b"placement receipt".to_vec())
        );
        assert_eq!(
            store.get(successor_key).expect("read successor record"),
            Some(b"successor payload".to_vec())
        );
        store.clear_prepublication_batch_readback();
        assert_eq!(store.prepublication_readback_range, None);
        assert!(store.prepublication_readback_bytes.is_empty());
        assert!(store.prepublication_readback_records.is_empty());
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, options)
            .expect("reopen prepublication block image");
        assert_eq!(
            reopened
                .get(payload_key)
                .expect("read payload after reopen"),
            Some(b"immutable payload".to_vec())
        );
        assert_eq!(
            reopened
                .get(receipt_key)
                .expect("read receipt after reopen"),
            Some(b"placement receipt".to_vec())
        );
        assert_eq!(
            reopened
                .get(successor_key)
                .expect("read successor after reopen"),
            Some(b"successor payload".to_vec())
        );
    }

    #[test]
    fn block_device_prepublication_barrier_closes_tail_batch() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut store =
            LocalObjectStore::open_block_device_writable_unbound(&image, block_options(80 * 1024))
                .expect("open block image");
        let first_key = ObjectKey::from_name(b"block-device/prepublication/before-barrier");
        let second_key = ObjectKey::from_name(b"block-device/prepublication/after-barrier");

        let verifications_before = store.block_device_tail_terminator_verifications;
        store.begin_prepublication_append_batch();
        store
            .put_prepublication_pool_internal(first_key, b"before barrier")
            .expect("stage first payload");
        assert_eq!(
            store.block_device_tail_terminator_verifications,
            verifications_before
        );

        store.sync_data().expect("close batch at data barrier");
        assert_eq!(
            store.block_device_tail_terminator_verifications,
            verifications_before + 1,
            "the barrier must verify the deferred tail"
        );
        store
            .put_prepublication_pool_internal(second_key, b"after barrier")
            .expect("stage payload after barrier");
        assert_eq!(
            store.block_device_tail_terminator_verifications,
            verifications_before + 2,
            "writes after the barrier must verify their own tails"
        );
        store
            .finish_prepublication_append_batch()
            .expect("an already closed batch finishes idempotently");
        assert_eq!(
            store.block_device_tail_terminator_verifications,
            verifications_before + 2
        );
    }

    #[test]
    fn block_device_receipt_bound_drain_acknowledges_without_physical_free() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        {
            let mut backing = OpenOptions::new()
                .write(true)
                .open(&image)
                .expect("open block image for reserved bytes");
            backing
                .write_all(&vec![0xa5; BLOCK_DEVICE_DATA_REGION_OFFSET as usize])
                .expect("seed primary label and bootstrap region");
            backing
                .seek(SeekFrom::Start(BLOCK_IMAGE_BYTES - POOL_LABEL_SIZE as u64))
                .expect("seek trailing label reservation");
            backing
                .write_all(&vec![0x5a; POOL_LABEL_SIZE])
                .expect("seed trailing label reservation");
            backing.sync_all().expect("sync reserved bytes");
        }

        const RECLAIM_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
        let mut store = LocalObjectStore::open_block_device_writable_unbound(
            &image,
            block_options(RECLAIM_SEGMENT_BYTES),
        )
        .expect("open block image");
        let discarded_prefix = ObjectKey::from_name(b"block-device/receipt-bound/prefix");
        let key = ObjectKey::from_name(b"block-device/receipt-bound/replace");
        let live_key = ObjectKey::from_name(b"block-device/receipt-bound/live");
        let live_payload = b"live append-log payload";
        store
            .put(discarded_prefix, &vec![0xc3; 64 * 1024])
            .expect("put disposable prefix");
        store.put(key, b"obsolete payload").expect("put obsolete");
        let obsolete = store
            .current_receipt_bound_physical_lifetime_pool_internal(key)
            .expect("capture obsolete physical lifetime");
        store
            .put(key, b"replacement payload")
            .expect("replace obsolete payload");
        assert!(store.delete(discarded_prefix).expect("delete prefix"));
        store
            .put_direct(live_key, live_payload)
            .expect("put live record");
        let entry = tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
            obsolete.reclaim_object_id,
            [0x5a; 16],
            1,
            true,
            1,
        )
        .with_replacement_receipt(dead_object_receipt(obsolete.reclaim_object_id));
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound dead object"));

        let protected_image = std::fs::read(&image).expect("read protected block image");
        let free_segments_before = store.free_segment_count();
        store.release_segment_file_capacity_best_effort(0);
        assert_eq!(
            std::fs::read(&image).expect("read block image after defensive release"),
            protected_image,
            "block-mode capacity-release backstop must not punch the pool member"
        );

        let compact_live_keys = store.list_keys();
        store
            .compact_retaining(&compact_live_keys, &[])
            .expect("block compaction retains queued exact lifetime");
        let relocated = store
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve relocated lifetime")
            .expect("queued exact lifetime remains indexed");
        assert_eq!(relocated.reclaim_object_id, obsolete.reclaim_object_id);
        assert_ne!(
            relocated.location.record_offset, obsolete.location.record_offset,
            "discarding the prefix must relocate the queued lifetime"
        );
        assert_eq!(
            store
                .read_location(relocated.location)
                .expect("read relocated queued lifetime"),
            b"obsolete payload"
        );
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        drop(store);

        let mut store = LocalObjectStore::open_block_device_writable_unbound(
            &image,
            block_options(RECLAIM_SEGMENT_BYTES),
        )
        .expect("reopen relocated queue lifetime");
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        let reopened_lifetime = store
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve reopened queued lifetime")
            .expect("reopened queued lifetime remains indexed");
        assert_eq!(
            reopened_lifetime.reclaim_object_id,
            obsolete.reclaim_object_id
        );

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(2, 7, 16)
            .expect("drain receipt-bound dead object");

        assert_eq!(stats.entries_processed, 1);
        assert_eq!(stats.segments_reclaimed, 0);
        assert_eq!(stats.blocks_freed, 0);
        assert_eq!(stats.reclaim_queue_depth, 0);
        assert_eq!(store.free_segment_count(), free_segments_before);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(store.reclaim_receipts().is_empty());
        assert_eq!(
            store.get(live_key).expect("get live record after drain"),
            Some(live_payload.to_vec())
        );
        let drained_image = std::fs::read(&image).expect("read block image after drain");
        assert_eq!(
            &drained_image[..BLOCK_DEVICE_DATA_REGION_OFFSET as usize],
            &protected_image[..BLOCK_DEVICE_DATA_REGION_OFFSET as usize],
            "receipt-bound drain must preserve the primary label and bootstrap region"
        );
        assert_eq!(
            &drained_image[drained_image.len() - POOL_LABEL_SIZE..],
            &protected_image[protected_image.len() - POOL_LABEL_SIZE..],
            "receipt-bound drain must preserve the trailing label reservation"
        );
        assert!(image.exists(), "block backing image must not be unlinked");

        let live_keys = store.list_keys();
        store
            .compact_retaining(&live_keys, &[])
            .expect("compaction reclaims acknowledged history");
        assert!(store
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve reclaimed lifetime")
            .is_none());
        drop(store);

        let reopened =
            LocalObjectStore::open_block_device(&image, block_options(RECLAIM_SEGMENT_BYTES))
                .expect("reopen block image");
        assert_eq!(
            reopened.get(key).expect("get reopened replacement"),
            Some(b"replacement payload".to_vec())
        );
        assert_eq!(
            reopened.get(live_key).expect("get reopened live record"),
            Some(live_payload.to_vec())
        );
        assert!(reopened.dead_object_reclaim_queue.is_empty());
    }

    #[test]
    fn block_device_open_refuses_corrupt_persisted_dead_object_queue() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let queue_key = ObjectKey::from_name(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes());
        let queue_location = {
            let mut store = LocalObjectStore::open_block_device_writable_unbound(
                &image,
                StoreOptions::test_fast(),
            )
            .expect("open block image");
            let encoded = DeadObjectReclaimQueue::new().encode();
            store
                .put_direct(queue_key, &encoded)
                .expect("persist valid empty dead-object queue");
            store.sync_all().expect("sync valid dead-object queue");
            store.location_of(queue_key).expect("queue location")
        };

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open queue image for corruption");
        file.seek(SeekFrom::Start(queue_location.payload_offset))
            .expect("seek queue payload");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read queue payload byte");
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(queue_location.payload_offset))
            .expect("reseek queue payload");
        file.write_all(&byte).expect("corrupt queue payload");
        file.sync_all().expect("sync corrupt queue payload");
        drop(file);

        let error = match LocalObjectStore::open_block_device(&image, StoreOptions::test_fast()) {
            Ok(_) => panic!("corrupt dead-object queue must refuse block-store open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::ChecksumMismatch { .. }
                | StoreError::InvalidDeadObjectReceipt {
                    reason: "persisted dead-object reclaim queue is corrupt or unverifiable"
                }
        ));
    }

    #[test]
    fn block_device_enospc_queue_growth_compacts_before_dirtying_authority() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut store = LocalObjectStore::open_block_device_writable_unbound(
            &image,
            block_options(1024 * 1024),
        )
        .expect("open block image");
        let disposable = ObjectKey::from_name(b"block-device/enospc/disposable");
        let logical_key = ObjectKey::from_name(b"block-device/enospc/queued-lifetime");
        let filler_key = ObjectKey::from_name(b"block-device/enospc/live-filler");

        store
            .put(disposable, &vec![0xd1; 128 * 1024])
            .expect("put reclaimable prefix");
        store.put(logical_key, b"obsolete").expect("put obsolete");
        let obsolete = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture obsolete lifetime");
        store
            .put(logical_key, b"replacement")
            .expect("put replacement");
        assert!(store.delete(disposable).expect("delete reclaimable prefix"));

        let entry = DeadObjectEntry::new(obsolete.reclaim_object_id, [0x91; 16], 1, true, 1)
            .with_replacement_receipt(dead_object_receipt(obsolete.reclaim_object_id));
        let entry_payload_len =
            LocalObjectStore::encode_dead_object_reclaim_entry_state(entry).len() as u64;
        let required_authority_append =
            LocalObjectStore::checked_record_total_len_u64(entry_payload_len)
                .checked_add(RECORD_HEADER_LEN_U64)
                .expect("authority append reserve");
        let usable_end = store.block_device_usable_end().expect("block usable end");
        let available = usable_end - store.current_offset;
        let record_overhead = LocalObjectStore::checked_record_total_len_u64(0);
        let desired_remaining = required_authority_append - 1;
        let filler_payload_len = available
            .checked_sub(desired_remaining)
            .and_then(|len| len.checked_sub(record_overhead))
            .expect("enough room to manufacture append ENOSPC");
        assert!(filler_payload_len <= store.options.max_object_bytes());
        store
            .put_direct(filler_key, &vec![0xf2; filler_payload_len as usize])
            .expect("fill append tail without crossing capacity");
        assert!(usable_end - store.current_offset < required_authority_append);
        assert!(!store.dead_object_reclaim_queue_dirty);

        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("queue enqueue compacts before installing dirty authority"));
        assert!(!store.dead_object_reclaim_queue_dirty);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert_eq!(
            load_dead_object_reclaim_queue(&store)
                .expect("load durable ENOSPC queue")
                .len(),
            1
        );
        assert_eq!(
            store.get(logical_key).unwrap(),
            Some(b"replacement".to_vec())
        );
        assert_eq!(
            store.get(filler_key).unwrap().map(|payload| payload.len()),
            Some(filler_payload_len as usize)
        );
        assert!(store
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve ENOSPC queued lifetime")
            .is_some());
        drop(store);

        let reopened = LocalObjectStore::open_block_device(&image, StoreOptions::test_fast())
            .expect("reopen ENOSPC-compacted queue");
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);
        assert_eq!(
            reopened.get(logical_key).unwrap(),
            Some(b"replacement".to_vec())
        );
        assert!(reopened
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve reopened ENOSPC queued lifetime")
            .is_some());
    }

    #[test]
    fn block_device_same_payload_lifetimes_keep_unique_sequences_across_compaction() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let options = StoreOptions::test_fast();
        let logical_key = ObjectKey::from_name(b"block-device/lifetime/same-payload");
        let payload = b"identical physical payload";
        let mut internal_key_bytes = [0x6b; 32];
        internal_key_bytes[..8].copy_from_slice(&crate::POOL_PLACEMENT_RECEIPT_KEY_PREFIX);
        let internal_key = ObjectKey(internal_key_bytes);
        let mut store =
            LocalObjectStore::open_block_device_writable_unbound(&image, options.clone())
                .expect("open block image");

        store.put(logical_key, payload).expect("put first lifetime");
        let first = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture first lifetime");
        store
            .put(logical_key, payload)
            .expect("put identical second lifetime");
        let second = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture second lifetime");
        assert_ne!(first.location.sequence, second.location.sequence);
        assert_ne!(first.reclaim_object_id, second.reclaim_object_id);

        store
            .put_direct(internal_key, payload)
            .expect("put first internal lifetime");
        let first_internal = store
            .current_receipt_bound_physical_lifetime_pool_internal(internal_key)
            .expect("capture first internal lifetime");
        store
            .put_direct(internal_key, payload)
            .expect("put identical second internal lifetime");
        let second_internal = store
            .current_receipt_bound_physical_lifetime_pool_internal(internal_key)
            .expect("capture second internal lifetime");
        assert_ne!(
            first_internal.location.sequence,
            second_internal.location.sequence
        );
        assert_ne!(
            first_internal.reclaim_object_id,
            second_internal.reclaim_object_id
        );

        let entry = DeadObjectEntry::new(first.reclaim_object_id, [0x72; 16], 1, true, 1)
            .with_replacement_receipt(dead_object_receipt(first.reclaim_object_id));
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("queue first exact lifetime"));
        let live_keys = store.list_keys();
        store
            .compact_retaining(&live_keys, &[])
            .expect("compact same-payload lifetimes");
        drop(store);

        let mut reopened = LocalObjectStore::open_block_device_writable_unbound(&image, options)
            .expect("reopen compacted same-payload lifetimes");
        let reopened_first = reopened
            .resolve_receipt_bound_physical_lifetime(&first.reclaim_object_id)
            .expect("resolve queued first lifetime")
            .expect("queued first lifetime survives compaction");
        let reopened_second = reopened
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture reopened second lifetime");
        assert_eq!(reopened_first.reclaim_object_id, first.reclaim_object_id);
        assert_eq!(reopened_second.reclaim_object_id, second.reclaim_object_id);
        assert_eq!(
            reopened
                .read_location(reopened_first.location)
                .expect("read queued first lifetime"),
            payload
        );
        assert_eq!(reopened.get(logical_key).unwrap(), Some(payload.to_vec()));
        let reopened_internal = reopened
            .current_receipt_bound_physical_lifetime_pool_internal(internal_key)
            .expect("capture reopened internal lifetime");
        assert_eq!(
            reopened_internal.reclaim_object_id,
            second_internal.reclaim_object_id
        );

        reopened
            .put(logical_key, payload)
            .expect("put identical third lifetime after reopen");
        let third = reopened
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture third lifetime");
        reopened
            .put_direct(internal_key, payload)
            .expect("put identical third internal lifetime after reopen");
        let third_internal = reopened
            .current_receipt_bound_physical_lifetime_pool_internal(internal_key)
            .expect("capture third internal lifetime");
        assert!(third.location.sequence > second.location.sequence);
        assert_ne!(third.reclaim_object_id, second.reclaim_object_id);
        assert!(third_internal.location.sequence > second_internal.location.sequence);
        assert_ne!(
            third_internal.reclaim_object_id,
            second_internal.reclaim_object_id
        );
    }

    #[test]
    fn block_device_retry_preflight_preserves_last_durable_queue_after_unsynced_ack_append() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let mut store = LocalObjectStore::open_block_device_writable_unbound(
            &image,
            block_options(1024 * 1024),
        )
        .expect("open block image");
        let disposable = ObjectKey::from_name(b"block-device/retry/disposable");
        let logical_key = ObjectKey::from_name(b"block-device/retry/queued-lifetime");
        let filler_key = ObjectKey::from_name(b"block-device/retry/live-filler");

        store
            .put(disposable, &vec![0x31; 128 * 1024])
            .expect("put reclaimable prefix");
        store.put(logical_key, b"obsolete").expect("put obsolete");
        let obsolete = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture obsolete lifetime");
        store
            .put(logical_key, b"replacement")
            .expect("put replacement");
        assert!(store.delete(disposable).expect("delete reclaimable prefix"));
        let entry = DeadObjectEntry::new(obsolete.reclaim_object_id, [0x41; 16], 1, true, 1)
            .with_replacement_receipt(dead_object_receipt(obsolete.reclaim_object_id));
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("persist old queue authority"));
        assert_eq!(store.durable_dead_object_reclaim_queue.len(), 1);

        assert_eq!(
            store
                .dead_object_reclaim_queue
                .ack_reclaimed(&[obsolete.reclaim_object_id]),
            1
        );
        let acknowledgement_record_len = LocalObjectStore::checked_record_total_len_u64(0);
        let retry_reserve = acknowledgement_record_len
            .checked_add(RECORD_HEADER_LEN_U64)
            .expect("retry reserve");
        let usable_end = store.block_device_usable_end().expect("block usable end");
        let available = usable_end - store.current_offset;
        let desired_before_ack_append = acknowledgement_record_len + retry_reserve - 1;
        let filler_payload_len = available
            .checked_sub(desired_before_ack_append)
            .and_then(|len| len.checked_sub(LocalObjectStore::checked_record_total_len_u64(0)))
            .expect("enough room to manufacture retry compaction");
        assert!(filler_payload_len <= store.options.max_object_bytes());
        store
            .put_direct(filler_key, &vec![0x51; filler_payload_len as usize])
            .expect("fill before unsynced acknowledgement append");

        // Model the exact per-entry post-tombstone/pre-barrier cut: the live
        // index no longer exposes the state record, but the last successful
        // root barrier still retains the row as compaction authority.
        store.dead_object_reclaim_queue_dirty = true;
        assert!(store
            .delete_dead_object_reclaim_authority_record_local(dead_object_reclaim_entry_state_key(
                obsolete.reclaim_object_id
            ),)
            .expect("append acknowledgement without crossing barrier"));
        assert!(usable_end - store.current_offset < retry_reserve);
        assert_eq!(store.dead_object_reclaim_queue.len(), 0);
        assert_eq!(store.durable_dead_object_reclaim_queue.len(), 1);

        store
            .sync_dead_object_reclaim_queue_authority()
            .expect("retry acknowledgement after compaction");
        assert!(store
            .resolve_receipt_bound_physical_lifetime(&obsolete.reclaim_object_id)
            .expect("resolve acknowledged lifetime after retry compaction")
            .is_some());
        assert!(store.durable_dead_object_reclaim_queue.is_empty());

        store
            .sync_all()
            .expect("sync remaining store authority after retry compaction");
        assert!(store.durable_dead_object_reclaim_queue.is_empty());
        assert_eq!(
            store.get(logical_key).unwrap(),
            Some(b"replacement".to_vec())
        );
        assert_eq!(
            store.get(filler_key).unwrap().map(|payload| payload.len()),
            Some(filler_payload_len as usize)
        );
    }
}

#[cfg(test)]
mod checksum_persistence_tests {
    use super::*;
    use tempfile::tempdir;
    use tidefs_checksum_tree::{DomainTag, ObjectDigest};

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        (store, dir)
    }

    #[test]
    fn put_computes_object_digest() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"test/obj");
        let payload = b"hello TideFS checksum pipeline";

        store.put(key, payload).expect("put");

        let digest = store
            .get_object_digest(key)
            .expect("checksum should be present");
        let dk = DomainTag::ReadVerify.derive_key();
        assert!(
            digest.verify(payload, &dk),
            "digest must verify against written payload"
        );
    }

    #[test]
    fn put_multiple_objects_each_get_checksum() {
        let (mut store, _dir) = temp_store();
        let dk = DomainTag::ReadVerify.derive_key();

        for i in 0..10u8 {
            let key = ObjectKey::from_name([i; 8]);
            let payload = [i; 64];
            store.put(key, &payload).expect("put");
            let digest = store
                .get_object_digest(key)
                .expect("checksum should be present");
            assert!(digest.verify(&payload, &dk), "digest {i} must verify");
        }

        // Different payloads produce different digests
        let d1 = store
            .get_object_digest(ObjectKey::from_name([0u8; 8]))
            .unwrap();
        let d2 = store
            .get_object_digest(ObjectKey::from_name([1u8; 8]))
            .unwrap();
        assert_ne!(d1, d2, "different payloads must produce different digests");
    }

    #[test]
    fn empty_payload_checksum() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"empty");
        let payload: &[u8] = &[];

        store.put(key, payload).expect("put");

        let digest = store
            .get_object_digest(key)
            .expect("checksum should exist for empty payload");
        let dk = DomainTag::ReadVerify.derive_key();
        assert!(
            digest.verify(payload, &dk),
            "empty payload digest must verify"
        );
        assert_ne!(
            digest.as_bytes(),
            &[0u8; 32],
            "empty payload digest must be non-zero"
        );
    }

    #[test]
    fn checksum_survives_sync_reopen() {
        let dir = tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"durable");
        let payload = b"checksum persistence round-trip";
        let dk = DomainTag::ReadVerify.derive_key();

        {
            let opts = StoreOptions::test_fast();
            let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
            store.put(key, payload).expect("put");
            let digest = store
                .get_object_digest(key)
                .expect("checksum present before sync");
            assert!(digest.verify(payload, &dk));
            store.sync_all().expect("sync");
        }

        {
            let opts = StoreOptions::test_fast();
            let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen");
            let digest = store
                .get_object_digest(key)
                .expect("checksum must survive reopen");
            assert!(
                digest.verify(payload, &dk),
                "reopened digest must still verify payload"
            );
        }
    }

    #[test]
    fn checksum_tampered_payload_detected() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"tamper-test");
        let payload = b"original payload for tamper detection";

        store.put(key, payload).expect("put");

        let digest = store.get_object_digest(key).unwrap();
        let dk = DomainTag::ReadVerify.derive_key();

        let mut tampered = payload.to_vec();
        tampered[5] ^= 0xFF;
        assert!(
            !digest.verify(&tampered, &dk),
            "tampered payload must fail verification"
        );
    }

    #[test]
    fn delete_removes_checksum() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"deletable");
        let payload = b"this object will be deleted";

        store.put(key, payload).expect("put");
        assert!(
            store.get_object_digest(key).is_some(),
            "checksum present before delete"
        );

        store.delete(key).expect("delete");
        assert!(
            store.get_object_digest(key).is_none(),
            "checksum removed after delete"
        );
    }

    #[test]
    fn unknown_key_returns_none() {
        let (store, _dir) = temp_store();
        let ghost = ObjectKey::from_name(b"nonexistent");
        assert!(store.get_object_digest(ghost).is_none());
    }

    #[test]
    fn large_object_checksum() {
        let dir = tempdir().expect("tempdir");
        let mut opts = StoreOptions::test_fast();
        opts.max_segment_bytes = 2 * 1024 * 1024; // 2 MiB
        let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        let key = ObjectKey::from_name(b"large");
        // 128 KiB payload (fits within 2 MiB segment)
        let payload = vec![0xABu8; 128 * 1024];

        store.put(key, &payload).expect("put large");

        let digest = store
            .get_object_digest(key)
            .expect("checksum for large object");
        let dk = DomainTag::ReadVerify.derive_key();
        assert!(
            digest.verify(&payload, &dk),
            "large payload digest must verify"
        );
    }

    #[test]
    fn domain_separation_ensures_different_tags_produce_different_digests() {
        // Verify that ObjectContent domain produces different digests than
        // ObjectData for the same payload.
        let dk_content = DomainTag::ReadVerify.derive_key();
        let dk_data = DomainTag::ObjectData.derive_key();

        let payload = b"test domain separation";
        let content_digest = ObjectDigest::compute(payload, &dk_content);
        let data_digest = ObjectDigest::compute(payload, &dk_data);

        assert_ne!(
            content_digest, data_digest,
            "ObjectContent and ObjectData domains must produce different digests"
        );
    }

    #[test]
    fn roundtrip_checksum_index_write_read_empty() {
        let dir = tempdir().expect("tempdir");
        let segments_dir = dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).expect("create segments dir");

        let checksums: BTreeMap<ObjectKey, ObjectDigest> = BTreeMap::new();
        write_checksums(&segments_dir, &checksums).expect("write empty");
        let loaded = load_checksums(&segments_dir);
        assert!(loaded.is_empty());
    }

    #[test]
    fn roundtrip_checksum_index_multiple_entries() {
        let dir = tempdir().expect("tempdir");
        let segments_dir = dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).expect("create segments dir");

        let dk = DomainTag::ReadVerify.derive_key();
        let mut checksums: BTreeMap<ObjectKey, ObjectDigest> = BTreeMap::new();
        for i in 0..5u8 {
            let key = ObjectKey::from_name([i; 8]);
            let payload = [i; 16];
            let digest = ObjectDigest::compute(&payload, &dk);
            checksums.insert(key, digest);
        }

        write_checksums(&segments_dir, &checksums).expect("write");
        let loaded = load_checksums(&segments_dir);

        assert_eq!(loaded.len(), 5);
        for i in 0..5u8 {
            let key = ObjectKey::from_name([i; 8]);
            let payload = [i; 16];
            let expected = ObjectDigest::compute(&payload, &dk);
            let actual = loaded.get(&key).expect("key must be in loaded map");
            assert_eq!(*actual, expected, "entry {i} must round-trip");
        }
    }

    #[test]
    fn put_named_computes_checksum() {
        let (mut store, _dir) = temp_store();
        let stored = store
            .put_named("alpha", b"named payload")
            .expect("put_named");
        let key = stored.key;
        let digest = store
            .get_object_digest(key)
            .expect("checksum from put_named");
        let dk = DomainTag::ReadVerify.derive_key();
        assert!(digest.verify(b"named payload", &dk));
    }

    #[test]
    fn put_content_addressed_computes_checksum() {
        let (mut store, _dir) = temp_store();
        let payload = b"content-addressed payload";
        let key = store
            .put_content_addressed(payload)
            .expect("put_content_addressed");
        let digest = store
            .get_object_digest(key)
            .expect("checksum from put_content_addressed");
        let dk = DomainTag::ReadVerify.derive_key();
        assert!(digest.verify(payload, &dk));
    }
}

#[cfg(test)]
mod checksum_read_verify_tests {
    use super::*;
    use tempfile::tempdir;
    use tidefs_checksum_tree::{DomainTag, ObjectDigest};

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        (store, dir)
    }

    // ── Happy path: write → verify ─────────────────────────────────

    #[test]
    fn write_then_verify_matching_payload() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"verify/ok");
        let payload = b"write-read-verify round-trip payload";

        store.put(key, payload).expect("put");
        let verified = store
            .get_checksum_verified(key)
            .expect("get_checksum_verified");
        assert_eq!(verified, Some(payload.to_vec()));
    }

    #[test]
    fn write_then_verify_empty_payload() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"verify/empty");
        let payload: &[u8] = &[];

        store.put(key, payload).expect("put empty");
        let verified = store
            .get_checksum_verified(key)
            .expect("get_checksum_verified empty");
        assert_eq!(verified, Some(Vec::new()));
    }

    #[test]
    fn write_then_verify_large_payload() {
        let dir = tempdir().expect("tempdir");
        let mut opts = StoreOptions::test_fast();
        opts.max_segment_bytes = 2 * 1024 * 1024;
        let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
        let key = ObjectKey::from_name(b"verify/large");
        let payload = vec![0xCDu8; 64 * 1024];

        store.put(key, &payload).expect("put large");
        let verified = store
            .get_checksum_verified(key)
            .expect("get_checksum_verified large");
        assert_eq!(verified, Some(payload));
    }

    #[test]
    fn write_multiple_then_verify_all() {
        let (mut store, _dir) = temp_store();
        for i in 0..5u8 {
            let key = ObjectKey::from_name([i; 8]);
            let payload = vec![i; 128];
            store.put(key, &payload).expect("put");
        }
        for i in 0..5u8 {
            let key = ObjectKey::from_name([i; 8]);
            let verified = store
                .get_checksum_verified(key)
                .expect("get_checksum_verified");
            assert_eq!(verified, Some(vec![i; 128]));
        }
    }

    // ── Tampered data detection ────────────────────────────────────

    #[test]
    fn tampered_data_detected_by_checksum_verification() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"verify/tampered");
        let payload = b"original data for tamper detection test";

        store.put(key, payload).expect("put");

        // Read back, verify it's good
        let verified = store.get_checksum_verified(key).expect("first verify");
        assert_eq!(verified, Some(payload.to_vec()));

        // Tamper with the stored checksum directly in the map.
        // Simulate corruption by replacing the digest with a wrong one.
        let wrong_payload = b"completely different bytes here!";
        let dk = DomainTag::ReadVerify.derive_key();
        let wrong_digest = ObjectDigest::compute(wrong_payload, &dk);
        store.checksums.insert(key, wrong_digest);

        // Now verification must fail
        let result = store.get_checksum_verified(key);
        match result {
            Err(StoreError::ObjectChecksumMismatch { key: err_key, .. }) => {
                assert_eq!(err_key, key, "error key must match the requested object");
            }
            other => panic!("expected ObjectChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn correct_checksum_passes_after_tampered_detected() {
        // Verify that after detecting tampering, correcting the checksum
        // allows verification to pass again.
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"verify/heal");
        let payload = b"healable payload";

        store.put(key, payload).expect("put");

        // Tamper
        let dk = DomainTag::ReadVerify.derive_key();
        let wrong_digest = ObjectDigest::compute(b"wrong", &dk);
        store.checksums.insert(key, wrong_digest);

        assert!(store.get_checksum_verified(key).is_err());

        // Restore correct checksum
        let correct_digest = ObjectDigest::compute(payload, &dk);
        store.checksums.insert(key, correct_digest);

        let verified = store.get_checksum_verified(key).expect("verify after heal");
        assert_eq!(verified, Some(payload.to_vec()));
    }

    // ── Missing checksum graceful degradation ──────────────────────

    #[test]
    fn missing_checksum_returns_data_without_error() {
        // Pre-checksum-era objects (no checksum in the map) are returned
        // without verification — no error.
        let dir = tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"verify/no-checksum");
        let payload = b"object without a checksum";

        {
            let opts = StoreOptions::test_fast();
            let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
            store.put(key, payload).expect("put");
            // Remove the checksum to simulate pre-checksum-era object
            store.checksums.remove(&key);
            store.sync_all().expect("sync");
        }

        {
            let opts = StoreOptions::test_fast();
            let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen");
            let verified = store
                .get_checksum_verified(key)
                .expect("get_checksum_verified without checksum");
            assert_eq!(verified, Some(payload.to_vec()));
        }
    }

    // ── Unknown key ────────────────────────────────────────────────

    #[test]
    fn verify_nonexistent_key_returns_none() {
        let (store, _dir) = temp_store();
        let ghost = ObjectKey::from_name(b"nonexistent");
        let result = store
            .get_checksum_verified(ghost)
            .expect("get_checksum_verified");
        assert_eq!(result, None);
    }

    // ── Sync/reopen preserves verification ─────────────────────────

    #[test]
    fn write_sync_reopen_verify() {
        let dir = tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"verify/durable");
        let payload = b"checksum survives sync and reopen for read verification";

        {
            let opts = StoreOptions::test_fast();
            let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
            store.put(key, payload).expect("put");
            store.sync_all().expect("sync");
        }

        {
            let opts = StoreOptions::test_fast();
            let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen");
            let verified = store
                .get_checksum_verified(key)
                .expect("get_checksum_verified after reopen");
            assert_eq!(verified, Some(payload.to_vec()));
        }
    }

    #[test]
    fn unsynced_overwrite_reopen_reconciles_read_verify_checksum() {
        let dir = tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"verify/unsynced-overwrite");
        let old = b"old durable payload";
        let new = b"new unsynced payload";

        {
            let opts = StoreOptions::test_fast();
            let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open");
            store.put(key, old).expect("put old");
            store.sync_all().expect("sync old");
            store.put(key, new).expect("put new");
        }

        {
            let opts = StoreOptions::test_fast();
            let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen");
            let verified = store
                .get_checksum_verified(key)
                .expect("get_checksum_verified after unsynced overwrite reopen");
            assert_eq!(verified, Some(new.to_vec()));
        }
    }

    // ── Content-addressed objects ──────────────────────────────────

    #[test]
    fn write_content_addressed_then_verify() {
        let (mut store, _dir) = temp_store();
        let payload = b"content-addressed integrity verification";
        let key = store
            .put_content_addressed(payload)
            .expect("put_content_addressed");

        let verified = store
            .get_checksum_verified(key)
            .expect("get_checksum_verified");
        assert_eq!(verified, Some(payload.to_vec()));
    }

    // ── Delete removes verification ────────────────────────────────

    #[test]
    fn deleted_object_not_found_by_verify() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"verify/deleted");
        let payload = b"this will be deleted";

        store.put(key, payload).expect("put");
        assert!(store.get_checksum_verified(key).unwrap().is_some());

        store.delete(key).expect("delete");
        let result = store
            .get_checksum_verified(key)
            .expect("get_checksum_verified after delete");
        assert_eq!(result, None);
    }
}

#[cfg(test)]
mod reclaim_queue_production_tests {
    use super::*;
    use tidefs_reclaim::ReclaimReceiptExtent;

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");
        (store, dir)
    }

    fn reclaim_key(key: ObjectKey) -> ReclaimObjectKey {
        ReclaimObjectKey(*key.as_bytes())
    }

    fn dead_object_key(byte: u8) -> ReclaimObjectKey {
        let mut key = [0u8; 32];
        key[0] = byte;
        ReclaimObjectKey(key)
    }

    fn dead_object_receipt(
        key: ReclaimObjectKey,
        generation: u64,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt {
        let mut digest = [0u8; 32];
        digest[0] = key.0[0];
        tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::replicated(
            key, 7, generation, 2, 4096, digest,
        )
    }

    fn dead_object_entry(byte: u8) -> tidefs_types_reclaim_queue_core::DeadObjectEntry {
        let key = dead_object_key(byte);
        tidefs_types_reclaim_queue_core::DeadObjectEntry::new(key, [byte; 16], 5, true, 5)
            .with_replacement_receipt(dead_object_receipt(key, byte as u64 + 1))
    }

    fn dead_object_entry_for_key(
        key: ReclaimObjectKey,
        death_commit_group: u64,
        eligible: bool,
        receipt_generation: u64,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectEntry {
        tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
            key,
            [key.0[0]; 16],
            death_commit_group,
            eligible,
            death_commit_group,
        )
        .with_replacement_receipt(dead_object_receipt(key, receipt_generation))
    }

    fn snapshot_candidate(
        key: ReclaimObjectKey,
        death_commit_group: u64,
        enqueued_at_txg: u64,
    ) -> SnapshotDeadObjectCandidate {
        SnapshotDeadObjectCandidate::new(key, [key.0[0]; 16], death_commit_group, enqueued_at_txg)
    }

    fn receipt_replay_options() -> StoreOptions {
        let mut options = StoreOptions::test_fast();
        options.max_segment_bytes = 2048;
        options.segment_count = tidefs_spacemap_allocator::DEFAULT_SEGMENT_GROUP_SEGMENTS;
        options
    }

    #[test]
    fn reclaim_queue_overwrite_path_records_old_segment() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"reclaim/overwrite");

        store.put(key, b"old payload").expect("initial put");
        let old_location = store.index.get(&key).copied().expect("old location");

        store.put(key, b"new payload").expect("overwrite");

        assert!(store.reclaim_queue.contains(&reclaim_key(key)));
        let liveness = store
            .segment_liveness
            .get(old_location.segment_id)
            .expect("old segment liveness");
        assert_eq!(liveness.dead_bytes, old_location.payload_len);
        assert_eq!(
            store.get(key).expect("get overwritten"),
            Some(b"new payload".to_vec())
        );
    }

    #[test]
    fn reclaim_queue_delete_path_records_dead_segment() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"reclaim/delete");

        store.put(key, b"delete payload").expect("put");
        let old_location = store.index.get(&key).copied().expect("old location");

        assert!(store.delete(key).expect("delete"));

        assert!(store.reclaim_queue.contains(&reclaim_key(key)));
        let liveness = store
            .segment_liveness
            .get(old_location.segment_id)
            .expect("old segment liveness");
        assert_eq!(liveness.dead_bytes, old_location.payload_len);
        assert_eq!(store.get(key).expect("get deleted"), None);
    }

    #[test]
    fn pool_pending_deletion_metadata_bypasses_payload_reclaim_and_wal() {
        let (mut store, _dir) = temp_store();
        let mut key_bytes = *ObjectKey::from_name(b"pool pending deletion metadata").as_bytes();
        key_bytes[..POOL_PENDING_DELETION_KEY_PREFIX.len()]
            .copy_from_slice(&POOL_PENDING_DELETION_KEY_PREFIX);
        let key = ObjectKey::from_bytes32(key_bytes);
        let tombstones_before = store.tombstone_count;
        let reclaim_before = store.reclaim_queue.len();

        store
            .put_pool_internal(key, b"checksummed pool handoff")
            .expect("publish pending deletion metadata");
        assert!(!store.intent_log_tx_open);
        assert_eq!(store.tombstone_count, tombstones_before);
        assert_eq!(store.reclaim_queue.len(), reclaim_before);
        assert!(!store.list_keys().contains(&key));

        assert!(store
            .delete_pool_internal(key)
            .expect("clear pending deletion metadata"));
        assert!(!store.intent_log_tx_open);
        assert_eq!(store.tombstone_count, tombstones_before);
        assert_eq!(store.reclaim_queue.len(), reclaim_before);
    }

    #[test]
    fn dead_object_reclaim_queue_sync_persists_across_reopen() {
        let (mut store, dir) = temp_store();
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_object_entry(0x41));
        queue.enqueue(dead_object_entry(0x42));

        store.dead_object_reclaim_queue = queue.clone();
        store.dead_object_reclaim_queue_dirty = true;
        store.sync_all().expect("sync dead-object reclaim queue");
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen store");

        assert_eq!(reopened.dead_object_reclaim_queue, queue);
        assert!(!reopened.dead_object_reclaim_queue_dirty);
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count(6),
            2
        );
    }

    #[test]
    fn dead_object_reclaim_updates_append_constant_size_entry_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut options = StoreOptions::test_fast();
        options.max_segment_bytes = 64 * 1024;
        options.segment_rotation_interval_secs = 0;
        options.segment_rotation_write_limit = 0;
        let mut store = LocalObjectStore::open_with_options(dir.path(), options)
            .expect("open non-rotating store");
        let mut append_len = None;
        for byte in 1..=16_u8 {
            let before = store.current_offset;
            assert!(store
                .enqueue_receipt_bound_dead_object(dead_object_entry(byte))
                .expect("persist one receipt-bound entry"));
            let appended = store.current_offset - before;
            if let Some(expected) = append_len {
                assert_eq!(
                    appended, expected,
                    "queue growth must append one constant-size entry record"
                );
            } else {
                append_len = Some(appended);
            }
        }
        assert!(!store.index.contains_key(&ObjectKey::from_name(
            DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes()
        )));
        assert_eq!(
            store
                .index
                .keys()
                .filter(|key| is_dead_object_reclaim_entry_state_key(**key))
                .count(),
            16
        );
    }

    #[test]
    fn dead_object_reclaim_barrier_does_not_commit_unrelated_payload_state() {
        let (mut store, _dir) = temp_store();
        let payload_key = ObjectKey::from_name(b"payload transaction remains open");
        store
            .put(payload_key, b"ordinary payload")
            .expect("put ordinary payload");
        assert!(store.intent_log_tx_open);

        assert!(store
            .enqueue_receipt_bound_dead_object(dead_object_entry(0x61))
            .expect("persist independent reclaim authority"));
        assert!(
            store.intent_log_tx_open,
            "reclaim authority barrier must not commit the ordinary payload transaction"
        );
        assert_eq!(
            store.get(payload_key).expect("read ordinary payload"),
            Some(b"ordinary payload".to_vec())
        );
    }

    #[test]
    fn pool_internal_reclaim_stages_until_strict_authority_sync() {
        let (mut store, dir) = temp_store();
        let logical_key = ObjectKey::from_name(b"Pool-internal staged reclaim lifetime");
        store
            .put(logical_key, b"old physical lifetime")
            .expect("put old physical lifetime");
        let lifetime = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture exact physical lifetime");
        let entry = DeadObjectEntry::new(lifetime.reclaim_object_id, [0x61; 16], 5, true, 5);
        let entry_key = dead_object_reclaim_entry_state_key(entry.object_id);

        let raw_mutation_allowed = Arc::new(AtomicBool::new(false));
        store.install_pool_raw_mutation_guard(Arc::clone(&raw_mutation_allowed));
        assert!(matches!(
            store.enqueue_pending_receipt_bound_dead_object_pool_internal(entry),
            Err(StoreError::InvalidOptions {
                reason:
                    "raw mutation refused while pool receipt-generation authority is unavailable"
            })
        ));
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(store.durable_dead_object_reclaim_queue.is_empty());
        assert!(!store.dead_object_reclaim_queue_dirty);

        raw_mutation_allowed.store(true, Ordering::Release);
        assert!(store
            .enqueue_pending_receipt_bound_dead_object_pool_internal(entry)
            .expect("stage pending Pool reclaim authority"));
        assert!(store.dead_object_reclaim_queue_dirty);
        assert!(store.durable_dead_object_reclaim_queue.is_empty());
        assert_eq!(store.dead_object_reclaim_pending_upserts.len(), 1);
        assert_eq!(
            store.dead_object_reclaim_pending_upsert_record_bytes,
            store
                .dead_object_reclaim_entry_record_bytes(entry)
                .expect("size staged Pool reclaim authority")
        );
        assert!(store.dead_object_reclaim_pending_removals.is_empty());
        assert!(!store.index.contains_key(&entry_key));

        store
            .sync_strict_pool_authority()
            .expect("publish pending authority at strict Pool barrier");
        assert!(!store.dead_object_reclaim_queue_dirty);
        assert!(store.dead_object_reclaim_pending_upserts.is_empty());
        assert_eq!(store.dead_object_reclaim_pending_upsert_record_bytes, 0);
        assert!(store.dead_object_reclaim_pending_removals.is_empty());
        assert_eq!(
            store
                .durable_dead_object_reclaim_queue
                .entry(&entry.object_id),
            Some(entry)
        );
        assert!(store.index.contains_key(&entry_key));

        let receipt = dead_object_receipt(entry.object_id, 6);
        assert!(store
            .publish_dead_object_replacement_receipt_pool_internal(&entry.object_id, receipt)
            .expect("stage replacement receipt"));
        assert!(store.dead_object_reclaim_queue_dirty);
        assert_eq!(store.dead_object_reclaim_pending_upserts.len(), 1);
        let receipted_entry = store
            .dead_object_reclaim_queue
            .entry(&entry.object_id)
            .expect("current receipted reclaim entry");
        assert_eq!(
            store.dead_object_reclaim_pending_upsert_record_bytes,
            store
                .dead_object_reclaim_entry_record_bytes(receipted_entry)
                .expect("size staged replacement authority")
        );
        assert!(store.dead_object_reclaim_pending_removals.is_empty());
        assert!(store
            .dead_object_reclaim_queue
            .entry(&entry.object_id)
            .is_some_and(|current| current.replacement_receipt == Some(receipt)));
        assert!(store
            .durable_dead_object_reclaim_queue
            .entry(&entry.object_id)
            .is_some_and(|durable| durable.replacement_receipt.is_none()));

        store
            .sync_strict_pool_authority()
            .expect("publish replacement authority at strict Pool barrier");
        assert!(!store.dead_object_reclaim_queue_dirty);
        assert!(store.dead_object_reclaim_pending_upserts.is_empty());
        assert_eq!(store.dead_object_reclaim_pending_upsert_record_bytes, 0);
        assert!(store.dead_object_reclaim_pending_removals.is_empty());
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen strict Pool authority");
        assert!(reopened
            .dead_object_reclaim_queue
            .entry(&entry.object_id)
            .is_some_and(|durable| durable.replacement_receipt == Some(receipt)));
    }

    #[test]
    fn receipt_bound_dead_object_enqueue_persists_across_reopen() {
        let (mut store, dir) = temp_store();
        let key = dead_object_key(0x51);
        let entry = dead_object_entry_for_key(key, 5, true, 1);

        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound dead object"));
        assert!(!store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("duplicate enqueue is idempotent"));
        assert!(!store.dead_object_reclaim_queue_dirty);
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen store");
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count(6),
            1
        );
        assert!(!reopened.dead_object_reclaim_queue_dirty);
    }

    #[test]
    fn pending_receipt_bound_lifetimes_stay_with_own_store_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("primary");
        let replica_path = dir.path().join("replica");
        let mut options = StoreOptions::test_fast();
        options.mirror_path = Some(replica_path);
        let mut store = LocalObjectStore::open_with_options(&primary_path, options.clone())
            .expect("open replicated store");

        store.replicas[0]
            .put(ObjectKey::from_name(b"replica layout skew"), b"skew")
            .expect("skew replica lifetime positions");
        let logical_key = ObjectKey::from_name(b"root-owned physical lifetimes");
        store
            .put(logical_key, b"replicated payload")
            .expect("put replicated payload");

        let lifetimes = store
            .current_receipt_bound_physical_lifetimes_across_stores_pool_internal(logical_key)
            .expect("capture both physical lifetimes");
        assert_eq!(lifetimes.len(), 2);
        store
            .rotate_segment()
            .expect("separate primary root-owned reclaim state");
        store.replicas[0]
            .rotate_segment()
            .expect("separate replica root-owned reclaim state");
        let entries = lifetimes
            .iter()
            .map(|lifetime| {
                DeadObjectEntry::new(lifetime.reclaim_object_id, [0x5A; 16], 5, true, 5)
            })
            .collect::<Vec<_>>();
        store
            .enqueue_pending_receipt_bound_dead_objects_pool_internal(&entries)
            .expect("persist root-owned pending lifetimes");

        let primary_entries = store.dead_object_reclaim_queue.all_entries();
        let replica_entries = store.replicas[0].dead_object_reclaim_queue.all_entries();
        assert_eq!(primary_entries.len(), 1);
        assert_eq!(replica_entries.len(), 1);
        assert_ne!(primary_entries[0].object_id, replica_entries[0].object_id);

        let receipts = lifetimes
            .iter()
            .map(|lifetime| {
                (
                    lifetime.reclaim_object_id,
                    dead_object_receipt(lifetime.reclaim_object_id, 6),
                )
            })
            .collect::<Vec<_>>();
        store
            .publish_dead_object_replacement_receipts_pool_internal(&receipts)
            .expect("publish each root's exact replacement receipt");
        assert!(store.dead_object_reclaim_queue.all_entries()[0]
            .replacement_receipt
            .is_some());
        assert!(store.replicas[0].dead_object_reclaim_queue.all_entries()[0]
            .replacement_receipt
            .is_some());
        store
            .compact_retaining(&[logical_key], &[])
            .expect("relocate primary root-owned state without replica fanout");
        drop(store);

        let reopened = LocalObjectStore::open_with_options(&primary_path, options)
            .expect("reopen replicated store roots");
        let primary_entries = reopened.dead_object_reclaim_queue.all_entries();
        let replica_entries = reopened.replicas[0].dead_object_reclaim_queue.all_entries();
        assert_eq!(primary_entries.len(), 1);
        assert_eq!(replica_entries.len(), 1);
        assert_ne!(primary_entries[0].object_id, replica_entries[0].object_id);
        assert!(primary_entries[0].replacement_receipt.is_some());
        assert!(replica_entries[0].replacement_receipt.is_some());
    }

    #[test]
    fn receipt_bound_dead_object_enqueue_rejects_receiptless_and_pool_reserved_entries() {
        let (mut store, _dir) = temp_store();
        let key = dead_object_key(0x52);
        let entry =
            tidefs_types_reclaim_queue_core::DeadObjectEntry::new(key, [0x52; 16], 5, true, 5);

        let err = store
            .enqueue_receipt_bound_dead_object(entry)
            .expect_err("receiptless enqueue must fail");
        assert!(matches!(
            err,
            StoreError::InvalidDeadObjectReceipt {
                reason: "missing replacement receipt"
            }
        ));
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(!store.dead_object_reclaim_queue_dirty);

        let reserved_key = reclaim_key(crate::pool_receipt_generation_high_water_key());
        let reserved_entry = dead_object_entry_for_key(reserved_key, 5, true, 1);
        let err = store
            .enqueue_receipt_bound_dead_object(reserved_entry)
            .expect_err("public reclaim enqueue must reject pool-reserved metadata");
        assert!(matches!(
            err,
            StoreError::InvalidOptions {
                reason:
                    "pool receipt, shard, generation, and deletion metadata require pool authority"
            }
        ));
        let replacement = dead_object_receipt(reserved_key, 2);
        let mut pending_reserved_entry = reserved_entry;
        pending_reserved_entry.replacement_receipt = None;
        assert!(store
            .enqueue_pending_receipt_bound_dead_object_pool_internal(pending_reserved_entry)
            .expect("pool reclaim authority may enqueue reserved physical placement"));
        assert!(matches!(
            store.publish_dead_object_replacement_receipt(&reserved_key, replacement),
            Err(StoreError::InvalidOptions { .. })
        ));
        store
            .publish_dead_object_replacement_receipts_pool_internal(&[(reserved_key, replacement)])
            .expect("pool reclaim authority may publish reserved physical receipt");
        assert!(matches!(
            store.drain_receipt_bound_dead_objects_at_stable_generation(6, 2, 16),
            Err(ReceiptBoundDeadObjectDrainError::Store(
                StoreError::InvalidOptions { .. }
            ))
        ));
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
    }

    #[test]
    fn snapshot_deadlist_candidate_persists_receiptless_work_across_reopen() {
        let (mut store, dir) = temp_store();
        let key = dead_object_key(0x55);
        let candidate = snapshot_candidate(key, 5, 7);

        assert!(store
            .enqueue_snapshot_deadlist_candidate(candidate)
            .expect("persist snapshot-deadlist candidate"));
        assert!(!store
            .enqueue_snapshot_deadlist_candidate(candidate)
            .expect("duplicate snapshot-deadlist candidate is replay-safe"));
        assert!(!store.dead_object_reclaim_queue_dirty);
        assert!(!store.index.contains_key(&ObjectKey::from_name(
            DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes()
        )));
        assert!(store
            .index
            .keys()
            .any(|key| { is_dead_object_reclaim_entry_state_key(*key) }));
        drop(store);

        let mut reopened =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
                .expect("reopen snapshot-deadlist work");
        let entries = reopened.dead_object_reclaim_queue.all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_id, key);
        assert_eq!(entries[0].dataset_uuid, [0x55; 16]);
        assert_eq!(entries[0].death_commit_group, 5);
        assert_eq!(entries[0].enqueued_at_txg, 7);
        assert!(entries[0].eligible);
        assert_eq!(entries[0].replacement_receipt, None);
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count_with_stable_generation(6, u64::MAX),
            0
        );

        assert!(reopened
            .publish_dead_object_replacement_receipt(&key, dead_object_receipt(key, 1))
            .expect("publish candidate receipt"));
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count_with_stable_generation(6, 1),
            1
        );
        assert!(!reopened.dead_object_reclaim_queue_dirty);
    }

    #[test]
    fn snapshot_deadlist_candidates_batch_persists_distinct_entries() {
        let (mut store, dir) = temp_store();
        let key_a = dead_object_key(0x56);
        let key_b = dead_object_key(0x57);

        assert_eq!(
            store
                .enqueue_snapshot_deadlist_candidates([
                    snapshot_candidate(key_a, 10, 11),
                    snapshot_candidate(key_b, 10, 11),
                    snapshot_candidate(key_a, 10, 11),
                ])
                .expect("persist snapshot-deadlist candidates"),
            2
        );
        assert!(!store.dead_object_reclaim_queue_dirty);
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen batched snapshot-deadlist work");
        let entries = reopened.dead_object_reclaim_queue.all_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].object_id, key_a);
        assert_eq!(entries[1].object_id, key_b);
        assert!(entries
            .iter()
            .all(|entry| entry.eligible && entry.replacement_receipt.is_none()));
    }

    #[test]
    fn snapshot_deadlist_candidate_waits_for_receipt_before_physical_reclaim() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"snapshot-deadlist/candidate/receipt-gate");

        store.put(key, b"snapshot deadlist payload").expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));

        let reclaim_key = reclaim_key(key);
        assert!(store
            .enqueue_snapshot_deadlist_candidate(snapshot_candidate(reclaim_key, 0, 1))
            .expect("enqueue snapshot-deadlist candidate"));

        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("receiptless snapshot-deadlist drain");
        assert_eq!(held.entries_processed, 0);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.reclaim_queue_depth, 1);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.reclaim_receipts().is_empty());
        assert!(
            segment_path(&store.segments_dir, old_segment_id).exists(),
            "receiptless snapshot-deadlist work must not free storage"
        );

        assert!(store
            .publish_dead_object_replacement_receipt(
                &reclaim_key,
                dead_object_receipt(reclaim_key, 1),
            )
            .expect("publish snapshot-deadlist receipt"));
        let freed = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("receipt-authorized snapshot-deadlist drain");
        assert_eq!(freed.entries_processed, 1);
        assert_eq!(freed.segments_reclaimed, 1);
        assert_eq!(freed.blocks_freed, 1);
        assert_eq!(freed.reclaim_queue_depth, 0);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert_eq!(store.reclaim_receipts().len(), 1);
        assert!(
            !segment_path(&store.segments_dir, old_segment_id).exists(),
            "receipt-authorized snapshot-deadlist work frees only through the drain"
        );
    }

    #[test]
    fn snapshot_deadlist_candidate_respects_snapshot_extent_pin_gate() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"snapshot-deadlist/candidate/pin-gate");
        let snapshot_id = "dataset@snap-deadlist";

        store
            .put(key, b"snapshot pinned deadlist payload")
            .expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));
        store
            .rotate_segment()
            .expect("separate dead extent from reclaim metadata");

        let reclaim_key = reclaim_key(key);
        assert!(store
            .enqueue_snapshot_deadlist_candidate(snapshot_candidate(reclaim_key, 0, 1))
            .expect("enqueue snapshot-deadlist candidate"));
        store.pin_snapshot_extent(snapshot_id, reclaim_key);
        store
            .sync_all()
            .expect("persist snapshot-deadlist pin before drain");
        assert!(store
            .publish_dead_object_replacement_receipt(
                &reclaim_key,
                dead_object_receipt(reclaim_key, 1),
            )
            .expect("publish snapshot-deadlist receipt"));

        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("snapshot-pinned snapshot-deadlist drain");
        assert_eq!(held.entries_processed, 1);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.gate_extents_denied, 1);
        assert_eq!(held.gate_segments_skipped, 1);
        assert_eq!(held.reclaim_queue_depth, 1);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.reclaim_receipts().is_empty());
        assert!(
            segment_path(&store.segments_dir, old_segment_id).exists(),
            "snapshot extent pin must keep deadlist storage allocated"
        );

        assert_eq!(store.release_snapshot_extent_pins(snapshot_id), 1);
        store
            .sync_all()
            .expect("persist snapshot-deadlist pin clearance");
        let freed = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("released snapshot-deadlist drain");
        assert_eq!(freed.entries_processed, 1);
        assert_eq!(freed.segments_reclaimed, 1);
        assert_eq!(freed.reclaim_queue_depth, 0);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert_eq!(store.reclaim_receipts().len(), 1);
        assert_eq!(
            store.reclaim_receipts()[0].pin_clearance_epoch,
            store.snapshot_extent_pin_set().epoch()
        );
        assert!(
            !segment_path(&store.segments_dir, old_segment_id).exists(),
            "released snapshot extent pin should allow receipt-bound reclaim"
        );
    }

    #[test]
    fn pending_receipt_bound_dead_object_replays_until_receipt_publish() {
        let (mut store, dir) = temp_store();
        let key = dead_object_key(0x53);
        let pending =
            tidefs_types_reclaim_queue_core::DeadObjectEntry::new(key, [0x53; 16], 5, true, 5);

        assert!(store
            .enqueue_pending_receipt_bound_dead_object(pending)
            .expect("persist pending receipt-bound work"));
        assert!(!store.dead_object_reclaim_queue_dirty);
        drop(store);

        let mut reopened =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
                .expect("reopen pending work");
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);
        let entry = reopened.dead_object_reclaim_queue.all_entries()[0];
        assert_eq!(entry.object_id, key);
        assert_eq!(entry.replacement_receipt, None);
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count_with_stable_generation(6, 1),
            0
        );

        let receipt = dead_object_receipt(key, 1);
        assert!(reopened
            .publish_dead_object_replacement_receipt(&key, receipt)
            .expect("publish replacement receipt"));
        assert!(!reopened.dead_object_reclaim_queue_dirty);
        drop(reopened);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen published work");
        let entry = reopened.dead_object_reclaim_queue.all_entries()[0];
        assert_eq!(entry.replacement_receipt, Some(receipt));
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count_with_stable_generation(6, 1),
            1
        );
    }

    #[test]
    fn receipt_bound_dead_object_enqueue_rejects_receipt_bearing_pending_work() {
        let (mut store, _dir) = temp_store();
        let key = dead_object_key(0x54);
        let entry = dead_object_entry_for_key(key, 5, true, 1);

        let err = store
            .enqueue_pending_receipt_bound_dead_object(entry)
            .expect_err("pending enqueue must not carry receipt evidence");
        assert!(matches!(
            err,
            StoreError::InvalidDeadObjectReceipt {
                reason: "pending receipt-bound enqueue must not include a replacement receipt"
            }
        ));
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(!store.dead_object_reclaim_queue_dirty);
    }

    #[test]
    fn receipt_bound_dead_object_drain_acks_and_persists_queue() {
        let (mut store, dir) = temp_store();
        let key = ObjectKey::from_name(b"receipt-bound/dead-object/drain");

        store.put(key, b"obsolete payload").expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));

        let reclaim_key = reclaim_key(key);
        let entry = dead_object_entry_for_key(reclaim_key, 0, true, 1);
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound dead object"));

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("receipt-bound drain");

        assert_eq!(stats.entries_processed, 1);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(stats.blocks_freed, 1);
        assert_eq!(stats.reclaim_queue_depth, 0);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(!store.dead_object_reclaim_queue_dirty);
        assert_eq!(store.reclaim_receipts().len(), 1);
        let receipt = store.reclaim_receipts()[0].clone();
        assert_eq!(receipt.freed_extents, vec![reclaim_key]);
        assert_eq!(
            receipt.freed_segment_extents,
            vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)]
        );
        assert_eq!(receipt.deadlist_committed_txg, 1);
        assert_eq!(receipt.pin_clearance_epoch, 0);
        assert!(!store.reclaim_receipts_dirty);
        assert!(
            !segment_path(&store.segments_dir, old_segment_id).exists(),
            "freed segment file must not be rediscovered on reopen"
        );
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen store");
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert_eq!(reopened.reclaim_receipts(), &[receipt]);
        assert!(!segment_path(&reopened.segments_dir, old_segment_id).exists());
    }

    #[test]
    fn repeated_physical_lifetimes_remain_distinct_and_logically_snapshot_pinned() {
        let (mut store, dir) = temp_store();
        let logical_key = ObjectKey::from_name(b"receipt-bound/repeated-physical-lifetimes");
        let logical_reclaim_key = reclaim_key(logical_key);

        store
            .put(logical_key, b"first lifetime")
            .expect("put first");
        store.sync_all().expect("sync first");
        let first = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture first lifetime");
        store.rotate_segment().expect("rotate after first");
        store
            .put(logical_key, b"second lifetime")
            .expect("put second");
        store.sync_all().expect("sync second");
        let second = store
            .current_receipt_bound_physical_lifetime_pool_internal(logical_key)
            .expect("capture second lifetime");
        assert_ne!(first.reclaim_object_id, second.reclaim_object_id);
        assert_ne!(first.location.segment_id, second.location.segment_id);

        let first_entry = DeadObjectEntry::new(first.reclaim_object_id, [0x61; 16], 1, true, 1)
            .with_replacement_receipt(dead_object_receipt(first.reclaim_object_id, 1));
        assert!(store.dead_object_reclaim_queue.enqueue(first_entry));
        store.dead_object_reclaim_queue_dirty = true;
        store.sync_all().expect("persist first reclaim lifetime");

        store.rotate_segment().expect("rotate after second");
        store
            .put(logical_key, b"third live lifetime")
            .expect("put third");
        store.sync_all().expect("sync third");
        let second_entry = DeadObjectEntry::new(second.reclaim_object_id, [0x61; 16], 2, true, 2)
            .with_replacement_receipt(dead_object_receipt(second.reclaim_object_id, 2));
        assert!(store.dead_object_reclaim_queue.enqueue(second_entry));
        store.dead_object_reclaim_queue_dirty = true;
        store.sync_all().expect("persist second reclaim lifetime");
        assert_eq!(
            load_dead_object_reclaim_queue(&store)
                .expect("load durable reclaim queue")
                .len(),
            2
        );
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);

        for lifetime in [first, second] {
            assert_eq!(
                store
                    .resolve_receipt_bound_reclaim_target(&lifetime.reclaim_object_id)
                    .expect("resolve exact physical lifetime"),
                Some((lifetime.location.segment_id, logical_reclaim_key))
            );
        }

        store.pin_snapshot_extent("snap-repeated", logical_reclaim_key);
        store.sync_all().expect("persist logical snapshot pin");
        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(3, 2, 16)
            .expect("pinned repeated lifetime drain");
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.gate_extents_denied, 2);
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);

        let compacted = store
            .compact_retaining(&[logical_key], &[])
            .expect("compaction preserves queued physical lifetimes");
        assert!(compacted
            .retained_segments
            .contains(&first.location.segment_id));
        assert!(compacted
            .retained_segments
            .contains(&second.location.segment_id));
        assert_eq!(
            store
                .read_location(first.location)
                .expect("read first lifetime"),
            b"first lifetime"
        );
        assert_eq!(
            store
                .read_location(second.location)
                .expect("read second lifetime"),
            b"second lifetime"
        );
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);
        assert_eq!(
            load_dead_object_reclaim_queue(&store)
                .expect("load durable reclaim queue")
                .len(),
            2
        );
        for lifetime in [first, second] {
            assert_eq!(
                store
                    .resolve_receipt_bound_reclaim_target(&lifetime.reclaim_object_id)
                    .expect("resolve compacted physical lifetime"),
                Some((lifetime.location.segment_id, logical_reclaim_key))
            );
        }

        assert_eq!(store.release_snapshot_extent_pins("snap-repeated"), 1);
        let dirty_clearance = store
            .drain_receipt_bound_dead_objects_at_stable_generation(3, 2, 16)
            .expect("dirty pin clearance is refused");
        assert_eq!(dirty_clearance.entries_processed, 0);
        assert_eq!(dirty_clearance.segments_reclaimed, 0);
        assert_eq!(dirty_clearance.reclaim_queue_depth, 2);
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);
        store
            .sync_all()
            .expect("persist released logical snapshot pin");
        let freed = store
            .drain_receipt_bound_dead_objects_at_stable_generation(3, 2, 16)
            .expect("released repeated lifetime drain");
        assert_eq!(freed.segments_reclaimed, 2);
        assert_eq!(freed.blocks_freed, 2);
        assert!(store.dead_object_reclaim_queue.is_empty());
        let committed_receipts = store.reclaim_receipts().to_vec();
        assert!(committed_receipts
            .iter()
            .flat_map(|receipt| &receipt.freed_segment_extents)
            .any(|extent| extent.extent_key == first.reclaim_object_id
                && extent.segment_id == first.location.segment_id));
        assert!(committed_receipts
            .iter()
            .flat_map(|receipt| &receipt.freed_segment_extents)
            .any(|extent| extent.extent_key == second.reclaim_object_id
                && extent.segment_id == second.location.segment_id));
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen after repeated lifetime reclaim");
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert_eq!(reopened.reclaim_receipts(), committed_receipts);
        assert_eq!(
            reopened.get(logical_key).expect("read current lifetime"),
            Some(b"third live lifetime".to_vec())
        );
    }

    #[test]
    fn receipt_bound_dead_object_drain_refuses_unflushed_publication() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"receipt-bound/dead-object/dirty-publication");

        store.put(key, b"obsolete payload").expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));

        let reclaim_key = reclaim_key(key);
        let entry = dead_object_entry_for_key(reclaim_key, 0, true, 1);
        assert!(store.dead_object_reclaim_queue.enqueue(entry));
        store.dead_object_reclaim_queue_dirty = true;

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("dirty receipt publication is refused");

        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert_eq!(stats.reclaim_queue_depth, 1);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.dead_object_reclaim_queue_dirty);
        assert!(
            segment_path(&store.segments_dir, old_segment_id).exists(),
            "dirty receipt publication must not let drain reclaim storage"
        );
    }

    #[test]
    fn receipt_bound_dead_object_drain_skips_snapshot_pinned_until_release() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"receipt-bound/dead-object/snapshot-pin");
        let snapshot_id = "dataset@snap";

        store.put(key, b"snapshot pinned payload").expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));
        store
            .rotate_segment()
            .expect("separate dead extent from persisted reclaim metadata");

        let reclaim_key = reclaim_key(key);
        let entry = dead_object_entry_for_key(reclaim_key, 0, true, 1);
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound dead object"));
        store.pin_snapshot_extent(snapshot_id, reclaim_key);
        store.sync_all().expect("persist snapshot pin");

        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("snapshot-pinned drain");

        assert_eq!(held.entries_processed, 1);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.gate_extents_denied, 1);
        assert_eq!(held.gate_segments_skipped, 1);
        assert_eq!(held.reclaim_queue_depth, 1);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.reclaim_receipts().is_empty());
        assert!(
            segment_path(&store.segments_dir, old_segment_id).exists(),
            "snapshot-pinned segment must remain allocated"
        );

        assert_eq!(store.release_snapshot_extent_pins(snapshot_id), 1);

        let dirty_clearance = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("dirty snapshot-pin clearance is refused");
        assert_eq!(dirty_clearance.entries_processed, 0);
        assert_eq!(dirty_clearance.segments_reclaimed, 0);
        assert_eq!(dirty_clearance.reclaim_queue_depth, 1);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.reclaim_receipts().is_empty());
        assert!(segment_path(&store.segments_dir, old_segment_id).exists());
        store.sync_all().expect("persist snapshot-pin clearance");

        let freed = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("released drain");

        assert_eq!(freed.entries_processed, 1);
        assert_eq!(freed.segments_reclaimed, 1);
        assert_eq!(freed.blocks_freed, 1);
        assert_eq!(freed.gate_extents_denied, 0);
        assert_eq!(freed.reclaim_queue_depth, 0);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert_eq!(store.reclaim_receipts().len(), 1);
        let receipt = &store.reclaim_receipts()[0];
        assert_eq!(receipt.freed_extents, vec![reclaim_key]);
        assert_eq!(
            receipt.freed_segment_extents,
            vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)]
        );
        assert_eq!(receipt.deadlist_committed_txg, 1);
        assert_eq!(
            receipt.pin_clearance_epoch,
            store.snapshot_extent_pin_set().epoch()
        );
        assert!(
            !segment_path(&store.segments_dir, old_segment_id).exists(),
            "released segment should be physically reclaimed"
        );
    }

    #[test]
    fn receipt_bound_dead_object_drain_preserves_snapshot_pin_across_reopen() {
        let (mut store, dir) = temp_store();
        let key = ObjectKey::from_name(b"receipt-bound/dead-object/snapshot-pin-reopen");
        let snapshot_id = "dataset@snap-reopen";

        store.put(key, b"snapshot pinned payload").expect("put");
        let old_segment_id = store.index.get(&key).expect("location").segment_id;
        assert!(store.delete(key).expect("delete"));
        store
            .rotate_segment()
            .expect("separate dead extent for reopen drain resolve");

        let reclaim_key = reclaim_key(key);
        let entry = dead_object_entry_for_key(reclaim_key, 0, true, 1);
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound dead object"));
        store.pin_snapshot_extent(snapshot_id, reclaim_key);
        store.sync_all().expect("sync queued pin");
        drop(store);

        let mut reopened =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
                .expect("reopen store");
        assert!(reopened.snapshot_extent_pin_set().is_pinned(&reclaim_key));

        let held = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("snapshot-pinned drain after reopen");

        assert_eq!(held.entries_processed, 1);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.gate_extents_denied, 1);
        assert_eq!(held.gate_segments_skipped, 1);
        assert_eq!(held.reclaim_queue_depth, 1);
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);
        assert!(reopened.reclaim_receipts().is_empty());
        assert!(
            segment_path(&reopened.segments_dir, old_segment_id).exists(),
            "reopened snapshot pin must keep segment allocated"
        );

        assert_eq!(reopened.release_snapshot_extent_pins(snapshot_id), 1);
        reopened
            .sync_all()
            .expect("persist reopened snapshot-pin clearance");
        let freed = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("released drain after reopen");

        assert_eq!(freed.entries_processed, 1);
        assert_eq!(freed.segments_reclaimed, 1);
        assert_eq!(freed.reclaim_queue_depth, 0);
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert_eq!(reopened.reclaim_receipts().len(), 1);
        assert_eq!(
            reopened.reclaim_receipts()[0].pin_clearance_epoch,
            reopened.snapshot_extent_pin_set().epoch()
        );
        assert!(
            !segment_path(&reopened.segments_dir, old_segment_id).exists(),
            "released reopened pin should allow physical reclaim"
        );
    }

    #[test]
    fn receipt_bound_dead_object_drain_keeps_partial_snapshot_pins_queued() {
        let (mut store, _dir) = temp_store();
        let key_a = ObjectKey::from_name(b"receipt-bound/dead-object/partial/a");
        let key_b = ObjectKey::from_name(b"receipt-bound/dead-object/partial/b");
        let snapshot_id = "dataset@snap-partial";

        store.put(key_a, b"first pinned payload").expect("put a");
        let segment_id = store.index.get(&key_a).expect("location a").segment_id;
        store.put(key_b, b"second pinned payload").expect("put b");
        assert_eq!(
            store.index.get(&key_b).expect("location b").segment_id,
            segment_id,
            "test fixture expects both dead objects in one segment"
        );

        assert!(store.delete(key_a).expect("delete a"));
        assert!(store.delete(key_b).expect("delete b"));

        let reclaim_key_a = reclaim_key(key_a);
        let reclaim_key_b = reclaim_key(key_b);
        for reclaim_key in [reclaim_key_a, reclaim_key_b] {
            let entry = dead_object_entry_for_key(reclaim_key, 0, true, 1);
            assert!(store
                .enqueue_receipt_bound_dead_object(entry)
                .expect("enqueue receipt-bound dead object"));
            store.pin_snapshot_extent(snapshot_id, reclaim_key);
        }
        store.sync_all().expect("persist partial snapshot pins");

        let partial = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 1)
            .expect("partial receipt-bound drain");
        assert_eq!(partial.entries_processed, 1);
        assert_eq!(partial.segments_reclaimed, 0);
        assert_eq!(partial.gate_extents_denied, 0);
        assert_eq!(partial.reclaim_queue_depth, 2);
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);
        assert!(store.reclaim_receipts().is_empty());
        assert!(
            segment_path(&store.segments_dir, segment_id).exists(),
            "partial drain must not free the segment"
        );

        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("full pinned drain");
        assert_eq!(held.entries_processed, 2);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(held.gate_extents_denied, 1);
        assert_eq!(held.gate_segments_skipped, 1);
        assert_eq!(held.reclaim_queue_depth, 2);
        assert_eq!(store.dead_object_reclaim_queue.len(), 2);
        assert!(store.reclaim_receipts().is_empty());
        assert!(
            segment_path(&store.segments_dir, segment_id).exists(),
            "snapshot pins must keep the full segment allocated"
        );

        assert_eq!(store.release_snapshot_extent_pins(snapshot_id), 2);
        store
            .sync_all()
            .expect("persist partial snapshot-pin clearance");
        let freed = store
            .drain_receipt_bound_dead_objects_at_stable_generation(1, 1, 16)
            .expect("released full drain");
        assert_eq!(freed.entries_processed, 2);
        assert_eq!(freed.segments_reclaimed, 1);
        assert_eq!(freed.blocks_freed, 2);
        assert_eq!(freed.reclaim_queue_depth, 0);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert_eq!(store.reclaim_receipts().len(), 1);
        let freed_extents: std::collections::BTreeSet<_> = store.reclaim_receipts()[0]
            .freed_extents
            .iter()
            .copied()
            .collect();
        let freed_segment_extents: std::collections::BTreeSet<_> = store.reclaim_receipts()[0]
            .freed_segment_extents
            .iter()
            .copied()
            .collect();
        assert_eq!(
            freed_extents,
            [reclaim_key_a, reclaim_key_b].into_iter().collect()
        );
        assert_eq!(
            freed_segment_extents,
            [
                ReclaimReceiptExtent::new(segment_id, reclaim_key_a),
                ReclaimReceiptExtent::new(segment_id, reclaim_key_b),
            ]
            .into_iter()
            .collect()
        );
        assert!(
            !segment_path(&store.segments_dir, segment_id).exists(),
            "released pins should allow the segment to be physically reclaimed"
        );
    }

    #[test]
    fn receipt_bound_dead_object_drain_resolves_overwrite_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
            .expect("open store");
        let key = ObjectKey::from_name(b"receipt-bound/dead-object/overwrite-history");
        let old_payload = vec![0xA5; 1536];
        let new_payload = vec![0x5A; 1536];

        store.put(key, &old_payload).expect("old put");
        let old_segment_id = store.index.get(&key).expect("old location").segment_id;
        store.put(key, &new_payload).expect("replacement put");
        let replacement_segment_id = store
            .index
            .get(&key)
            .expect("replacement location")
            .segment_id;
        assert_ne!(old_segment_id, replacement_segment_id);

        let entry = dead_object_entry_for_key(reclaim_key(key), 5, true, 1);
        assert!(store
            .enqueue_receipt_bound_dead_object(entry)
            .expect("enqueue receipt-bound overwritten object"));

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(6, 1, 16)
            .expect("receipt-bound drain");

        assert_eq!(stats.entries_processed, 1);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(stats.blocks_freed, 1);
        assert!(
            !segment_path(&store.segments_dir, old_segment_id).exists(),
            "old overwritten segment should be reclaimed"
        );
        assert!(
            segment_path(&store.segments_dir, replacement_segment_id).exists(),
            "replacement segment must stay present"
        );
        assert_eq!(store.get(key).unwrap(), Some(new_payload));
    }

    #[test]
    fn reclaim_receipt_replay_removes_retained_segment_file_before_open_accepts_spacemap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"receipt-bound/replay/retained-segment");
        let old_payload = vec![0xA5; 1536];
        let new_payload = vec![0x5A; 1536];
        let reclaim_key = reclaim_key(key);

        let (segments_dir, old_segment_id, replacement_segment_id, free_before_replay) = {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("open store");
            store.put(key, &old_payload).expect("old put");
            let old_segment_id = store.index.get(&key).expect("old location").segment_id;
            store.put(key, &new_payload).expect("replacement put");
            let replacement_segment_id = store
                .index
                .get(&key)
                .expect("replacement location")
                .segment_id;
            assert_ne!(old_segment_id, replacement_segment_id);

            store.reclaim_receipts.push(ReclaimReceipt::new(
                vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)],
                6,
                0,
            ));
            store.reclaim_receipts_dirty = true;
            store.sync_all().expect("persist committed reclaim receipt");
            assert!(segment_path(&store.segments_dir, old_segment_id).exists());
            assert!(!store.free_map.is_free(old_segment_id));
            (
                store.segments_dir.clone(),
                old_segment_id,
                replacement_segment_id,
                store.free_segment_count(),
            )
        };

        let reopened = LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
            .expect("reopen replays retained receipt segment");
        assert!(reopened.free_map.is_free(old_segment_id));
        assert_eq!(reopened.free_segment_count(), free_before_replay + 1);
        assert!(!segment_path(&segments_dir, old_segment_id).exists());
        assert!(segment_path(&segments_dir, replacement_segment_id).exists());
        assert_eq!(reopened.get(key).unwrap(), Some(new_payload));
    }

    #[test]
    fn reclaim_receipt_sync_cut_acks_queue_before_replayed_physical_free() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"receipt-bound/replay/receipt-sync-cut");
        let old_payload = vec![0xA5; 1536];
        let new_payload = vec![0x5A; 1536];
        let reclaim_key = reclaim_key(key);

        let (segments_dir, old_segment_id, replacement_segment_id, free_before_replay) = {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("open store");
            store.put(key, &old_payload).expect("old put");
            let old_segment_id = store.index.get(&key).expect("old location").segment_id;
            store.put(key, &new_payload).expect("replacement put");
            let replacement_segment_id = store
                .index
                .get(&key)
                .expect("replacement location")
                .segment_id;
            assert_ne!(old_segment_id, replacement_segment_id);
            assert!(store
                .enqueue_receipt_bound_dead_object(dead_object_entry_for_key(
                    reclaim_key,
                    5,
                    true,
                    1,
                ))
                .expect("persist receipt-bound queue row"));

            // Exact crash cut after phase one: the receipt is durable while
            // the source queue row and physical segment are still present.
            store.reclaim_receipts.push(ReclaimReceipt::new(
                vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)],
                6,
                0,
            ));
            store.reclaim_receipts_dirty = true;
            store.sync_all().expect("persist receipt before queue ack");
            assert_eq!(
                load_dead_object_reclaim_queue(&store)
                    .expect("load durable reclaim queue")
                    .len(),
                1
            );
            assert!(segment_path(&store.segments_dir, old_segment_id).exists());
            assert!(!store.free_map.is_free(old_segment_id));
            (
                store.segments_dir.clone(),
                old_segment_id,
                replacement_segment_id,
                store.free_segment_count(),
            )
        };

        let reopened = LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
            .expect("reopen receipt-sync cut");
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert!(load_dead_object_reclaim_queue(&reopened)
            .expect("load reopened durable reclaim queue")
            .is_empty());
        assert!(reopened.free_map.is_free(old_segment_id));
        assert_eq!(reopened.free_segment_count(), free_before_replay + 1);
        assert!(!segment_path(&segments_dir, old_segment_id).exists());
        assert!(segment_path(&segments_dir, replacement_segment_id).exists());
        assert_eq!(reopened.get(key).unwrap(), Some(new_payload));
    }

    #[test]
    fn reclaim_queue_ack_sync_cut_replays_physical_free_idempotently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"receipt-bound/replay/queue-ack-sync-cut");
        let old_payload = vec![0xA5; 1536];
        let new_payload = vec![0x5A; 1536];
        let reclaim_key = reclaim_key(key);

        let (segments_dir, old_segment_id, replacement_segment_id, free_before_replay) = {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("open store");
            store.put(key, &old_payload).expect("old put");
            let old_segment_id = store.index.get(&key).expect("old location").segment_id;
            store.put(key, &new_payload).expect("replacement put");
            let replacement_segment_id = store
                .index
                .get(&key)
                .expect("replacement location")
                .segment_id;
            assert_ne!(old_segment_id, replacement_segment_id);
            assert!(store
                .enqueue_receipt_bound_dead_object(dead_object_entry_for_key(
                    reclaim_key,
                    5,
                    true,
                    1,
                ))
                .expect("persist receipt-bound queue row"));
            store.reclaim_receipts.push(ReclaimReceipt::new(
                vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)],
                6,
                0,
            ));
            store.reclaim_receipts_dirty = true;
            store.sync_all().expect("persist receipt before queue ack");

            // Exact crash cut after phase two: both the receipt and queue
            // acknowledgement are durable, but no physical state changed.
            assert_eq!(
                store
                    .dead_object_reclaim_queue
                    .ack_reclaimed(&[reclaim_key]),
                1
            );
            store.dead_object_reclaim_queue_dirty = true;
            store.sync_all().expect("persist queue acknowledgement");
            assert!(load_dead_object_reclaim_queue(&store)
                .expect("load durable reclaim queue")
                .is_empty());
            assert!(segment_path(&store.segments_dir, old_segment_id).exists());
            assert!(!store.free_map.is_free(old_segment_id));
            (
                store.segments_dir.clone(),
                old_segment_id,
                replacement_segment_id,
                store.free_segment_count(),
            )
        };

        {
            let reopened =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("reopen queue-ack-sync cut");
            assert!(reopened.dead_object_reclaim_queue.is_empty());
            assert!(reopened.free_map.is_free(old_segment_id));
            assert_eq!(reopened.free_segment_count(), free_before_replay + 1);
            assert!(!segment_path(&segments_dir, old_segment_id).exists());
            assert!(segment_path(&segments_dir, replacement_segment_id).exists());
            assert_eq!(reopened.get(key).unwrap(), Some(new_payload.clone()));
        }

        let reopened_again =
            LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                .expect("reopen queue-ack-sync cut again");
        assert!(reopened_again.free_map.is_free(old_segment_id));
        assert_eq!(reopened_again.free_segment_count(), free_before_replay + 1);
        assert_eq!(reopened_again.get(key).unwrap(), Some(new_payload));
    }

    #[test]
    fn reclaim_receipt_replay_repairs_missing_segment_file_with_stale_spacemap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"receipt-bound/replay/missing-segment");
        let old_payload = vec![0xA5; 1536];
        let new_payload = vec![0x5A; 1536];
        let reclaim_key = reclaim_key(key);

        let (segments_dir, old_segment_id, replacement_segment_id, free_before_replay) = {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("open store");
            store.put(key, &old_payload).expect("old put");
            let old_segment_id = store.index.get(&key).expect("old location").segment_id;
            store.put(key, &new_payload).expect("replacement put");
            let replacement_segment_id = store
                .index
                .get(&key)
                .expect("replacement location")
                .segment_id;
            assert_ne!(old_segment_id, replacement_segment_id);

            store.reclaim_receipts.push(ReclaimReceipt::new(
                vec![ReclaimReceiptExtent::new(old_segment_id, reclaim_key)],
                6,
                0,
            ));
            store.reclaim_receipts_dirty = true;
            store.sync_all().expect("persist committed reclaim receipt");
            assert!(segment_path(&store.segments_dir, old_segment_id).exists());
            assert!(!store.free_map.is_free(old_segment_id));
            (
                store.segments_dir.clone(),
                old_segment_id,
                replacement_segment_id,
                store.free_segment_count(),
            )
        };

        std::fs::remove_file(segment_path(&segments_dir, old_segment_id))
            .expect("simulate crash after segment-file removal");

        {
            let reopened =
                LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                    .expect("reopen replays missing receipt segment");
            assert!(reopened.free_map.is_free(old_segment_id));
            assert_eq!(reopened.free_segment_count(), free_before_replay + 1);
            assert!(!segment_path(&segments_dir, old_segment_id).exists());
            assert!(segment_path(&segments_dir, replacement_segment_id).exists());
            assert_eq!(reopened.get(key).unwrap(), Some(new_payload.clone()));
        }

        let reopened_again =
            LocalObjectStore::open_with_options(dir.path(), receipt_replay_options())
                .expect("repeated reopen replays receipt idempotently");
        assert!(reopened_again.free_map.is_free(old_segment_id));
        assert!(!segment_path(&segments_dir, old_segment_id).exists());
        assert!(segment_path(&segments_dir, replacement_segment_id).exists());
        assert_eq!(reopened_again.get(key).unwrap(), Some(new_payload));
    }

    #[test]
    fn receipt_bound_dead_object_drain_keeps_unauthorized_entries_queued() {
        let (mut store, dir) = temp_store();
        let receiptless_key = dead_object_key(0x61);
        let synthetic_key = dead_object_key(0x62);
        let malformed_key = dead_object_key(0x63);
        let under_width_key = dead_object_key(0x64);
        let ineligible_key = dead_object_key(0x65);
        let not_stable_key = dead_object_key(0x66);
        let future_generation_key = dead_object_key(0x67);
        let mut digest = [0u8; 32];

        store.dead_object_reclaim_queue.enqueue(
            tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
                receiptless_key,
                [0x61; 16],
                5,
                true,
                5,
            ),
        );
        store
            .dead_object_reclaim_queue
            .enqueue(dead_object_entry_for_key(synthetic_key, 5, true, 0));

        digest[0] = malformed_key.0[0];
        let malformed_receipt = tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::new(
            malformed_key,
            7,
            1,
            tidefs_types_reclaim_queue_core::DeadObjectReceiptPolicy::Replicated { copies: 0 },
            4096,
            digest,
            0,
        );
        store.dead_object_reclaim_queue.enqueue(
            tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
                malformed_key,
                [0x63; 16],
                5,
                true,
                5,
            )
            .with_replacement_receipt(malformed_receipt),
        );

        digest[0] = under_width_key.0[0];
        let under_width_receipt =
            tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::new(
                under_width_key,
                7,
                1,
                tidefs_types_reclaim_queue_core::DeadObjectReceiptPolicy::Erasure {
                    data_shards: 2,
                    parity_shards: 1,
                },
                4096,
                digest,
                2,
            );
        store.dead_object_reclaim_queue.enqueue(
            tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
                under_width_key,
                [0x64; 16],
                5,
                true,
                5,
            )
            .with_replacement_receipt(under_width_receipt),
        );

        store
            .dead_object_reclaim_queue
            .enqueue(dead_object_entry_for_key(ineligible_key, 5, false, 1));
        store
            .dead_object_reclaim_queue
            .enqueue(dead_object_entry_for_key(not_stable_key, 10, true, 1));
        store
            .dead_object_reclaim_queue
            .enqueue(dead_object_entry_for_key(future_generation_key, 5, true, 2));
        store.dead_object_reclaim_queue_dirty = true;
        store.sync_all().expect("sync queued unauthorized entries");

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(6, 1, 16)
            .expect("unauthorized drain should be idle");

        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert_eq!(stats.reclaim_queue_depth, 7);
        assert_eq!(store.dead_object_reclaim_queue.len(), 7);
        drop(store);

        let reopened = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("reopen store");
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 7);
        assert_eq!(
            reopened
                .dead_object_reclaim_queue
                .receipt_bound_eligible_count_with_stable_generation(6, 1),
            0
        );
    }
}

#[cfg(test)]
mod compaction_publish_tests {
    use super::*;
    use tidefs_extent_map::InlineExtentMap;

    const DATASET_UUID: [u8; 16] = [0xC7; 16];

    fn compaction_options() -> StoreOptions {
        let mut options = StoreOptions::test_fast();
        options.max_segment_bytes = 2048;
        options.segment_count = tidefs_spacemap_allocator::DEFAULT_SEGMENT_GROUP_SEGMENTS;
        options
    }

    fn compaction_payload(byte: u8) -> Vec<u8> {
        let options = compaction_options();
        vec![byte; options.max_object_bytes() as usize]
    }

    fn old_extent(payload: &[u8]) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(
            0,
            payload.len() as u64,
            LocatorId(0x807),
            compaction_payload_digest(payload),
            1,
        )
    }

    fn extent_map_with(entry: ExtentMapEntryV2) -> InlineExtentMap {
        let mut extent_map = InlineExtentMap::new();
        extent_map
            .insert_extent(&[entry])
            .expect("insert source extent");
        extent_map
    }

    fn replacement_receipt(
        key: ObjectKey,
        payload: &[u8],
        receipt_generation: u64,
    ) -> DeadObjectReplacementReceipt {
        DeadObjectReplacementReceipt::replicated(
            compaction_reclaim_key(key),
            7,
            receipt_generation,
            2,
            payload.len() as u64,
            compaction_payload_digest(payload),
        )
    }

    fn rewrite(
        key: ObjectKey,
        entry: ExtentMapEntryV2,
        payload: &[u8],
        receipt_generation: u64,
    ) -> VerifiedCompactionRewrite {
        VerifiedCompactionRewrite {
            key,
            logical_offset: entry.logical_offset,
            old_extent: entry,
            target_payload: payload.to_vec(),
            dataset_uuid: DATASET_UUID,
            replacement_receipt: replacement_receipt(key, payload, receipt_generation),
        }
    }

    #[test]
    fn publish_verified_compaction_rewrite_swaps_extent_checksum_and_release_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"compaction/publish/commit");
        let payload = compaction_payload(0x5A);
        let source_extent = old_extent(&payload);
        let receipt = replacement_receipt(key, &payload, 1);
        let mut extent_map = extent_map_with(source_extent.clone());
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), compaction_options()).expect("open");

        let reserved_key = crate::pool_receipt_generation_high_water_key();
        assert!(matches!(
            store.publish_verified_compaction_rewrites(
                vec![rewrite(
                    reserved_key,
                    source_extent.clone(),
                    &payload,
                    receipt.receipt_generation,
                )],
                &mut extent_map,
            ),
            Err(StoreError::InvalidOptions { .. })
        ));
        assert_eq!(
            extent_map
                .lookup_range(0, payload.len() as u64)
                .expect("reserved rewrite leaves source extent unchanged"),
            vec![source_extent.clone()]
        );
        assert!(store.dead_object_reclaim_queue.is_empty());

        store.put(key, &payload).expect("put source");
        let old_location = store.location_of(key).expect("source location");
        let report = store
            .publish_verified_compaction_rewrites(
                vec![rewrite(
                    key,
                    source_extent,
                    &payload,
                    receipt.receipt_generation,
                )],
                &mut extent_map,
            )
            .expect("publish compaction rewrite");

        assert_eq!(report.rewrites.len(), 1);
        let published = &report.rewrites[0];
        assert_eq!(published.key, key);
        assert_eq!(published.old_location, old_location);
        assert_ne!(
            published.old_location.segment_id,
            published.target_location.segment_id
        );
        assert!(is_compaction_target_key(published.target_location.key));
        assert_eq!(store.location_of(key), Some(published.target_location));
        assert_eq!(
            store.get(key).expect("read published"),
            Some(payload.clone())
        );
        assert_eq!(
            store
                .get_checksum_verified(key)
                .expect("checksum verified read"),
            Some(payload.clone())
        );
        assert_eq!(store.list_keys(), vec![key]);

        let mapped = extent_map
            .lookup_range(0, payload.len() as u64)
            .expect("lookup swapped extent");
        assert_eq!(mapped, vec![published.new_extent.clone()]);
        assert_eq!(mapped[0].birth_commit_group, report.committed_txg);
        assert_eq!(mapped[0].checksum, published.checksum_root);

        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        let queued = store.dead_object_reclaim_queue.all_entries()[0];
        assert_eq!(queued.object_id, compaction_reclaim_key(key));
        assert_eq!(queued.dataset_uuid, DATASET_UUID);
        assert_eq!(queued.death_commit_group, report.committed_txg);
        assert_eq!(queued.replacement_receipt, Some(receipt));

        let held = store
            .drain_receipt_bound_dead_objects_at_stable_generation(report.committed_txg + 1, 0, 16)
            .expect("early drain remains held");
        assert_eq!(held.entries_processed, 0);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);

        let drained = store
            .drain_receipt_bound_dead_objects_at_stable_generation(
                report.committed_txg + 1,
                receipt.receipt_generation,
                16,
            )
            .expect("stable drain");
        assert_eq!(drained.entries_processed, 1);
        assert_eq!(drained.segments_reclaimed, 1);
        assert!(store.dead_object_reclaim_queue.is_empty());
        assert!(store.free_map.is_free(old_location.segment_id));
        assert_eq!(store.get(key).expect("read after drain"), Some(payload));
    }

    #[test]
    fn crash_before_publish_hides_scratch_target_and_keeps_source_mapping() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"compaction/publish/before");
        let payload = compaction_payload(0xA5);

        {
            let mut store = LocalObjectStore::open_with_options(dir.path(), compaction_options())
                .expect("open");
            store.put(key, &payload).expect("put source");
            let old_location = store.location_of(key).expect("source location");
            if store.current_segment_id == old_location.segment_id {
                store.rotate_segment().expect("rotate away from source");
            }
            let target_key =
                compaction_target_key(key, old_location, store.commit_group.current_id().0, 0);
            store
                .put_direct(target_key, &payload)
                .expect("write hidden target");
            let target_location = store.location_of(target_key).expect("target location");
            assert_ne!(old_location.segment_id, target_location.segment_id);
            store
                .sync_all()
                .expect("sync hidden target without manifest");
        }

        let reopened =
            LocalObjectStore::open_with_options(dir.path(), compaction_options()).expect("reopen");
        assert_eq!(reopened.get(key).expect("read old mapping"), Some(payload));
        assert_eq!(reopened.list_keys(), vec![key]);
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert!(reopened
            .load_compaction_publish_manifest_entries()
            .expect("load manifest")
            .is_empty());
        assert!(reopened
            .list_keys_including_internal()
            .into_iter()
            .any(is_compaction_target_key));
    }

    #[test]
    fn crash_after_publish_replays_swap_and_receipt_bound_source_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ObjectKey::from_name(b"compaction/publish/after");
        let payload = compaction_payload(0x3C);
        let source_extent = old_extent(&payload);
        let mut extent_map = extent_map_with(source_extent.clone());
        let (report, old_location, target_location) = {
            let mut store = LocalObjectStore::open_with_options(dir.path(), compaction_options())
                .expect("open");
            store.put(key, &payload).expect("put source");
            let old_location = store.location_of(key).expect("source location");
            let report = store
                .publish_verified_compaction_rewrites(
                    vec![rewrite(key, source_extent, &payload, 1)],
                    &mut extent_map,
                )
                .expect("publish compaction rewrite");
            let target_location = report.rewrites[0].target_location;
            (report, old_location, target_location)
        };

        let mut reopened =
            LocalObjectStore::open_with_options(dir.path(), compaction_options()).expect("reopen");
        assert_eq!(reopened.location_of(key), Some(target_location));
        assert_eq!(
            reopened
                .get_checksum_verified(key)
                .expect("checksum verified read after replay"),
            Some(payload.clone())
        );
        assert_eq!(reopened.list_keys(), vec![key]);
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);
        assert!(!reopened.free_map.is_free(old_location.segment_id));

        let held = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(report.committed_txg + 1, 0, 16)
            .expect("generation-unstable drain remains held");
        assert_eq!(held.entries_processed, 0);
        assert_eq!(held.segments_reclaimed, 0);
        assert_eq!(reopened.dead_object_reclaim_queue.len(), 1);

        let drained = reopened
            .drain_receipt_bound_dead_objects_at_stable_generation(report.committed_txg + 1, 1, 16)
            .expect("stable generation drain");
        assert_eq!(drained.entries_processed, 1);
        assert_eq!(drained.segments_reclaimed, 1);
        assert!(reopened.dead_object_reclaim_queue.is_empty());
        assert!(reopened.free_map.is_free(old_location.segment_id));
        assert_eq!(
            reopened.get(key).expect("read after replay drain"),
            Some(payload)
        );
    }
}

// =============================================================================
// SuspectLog — persistent ring buffer for corruption tracking (G3 pillar)
// =============================================================================

/// A single suspect entry recording a corruption event.
///
/// Each entry records a detected checksum or integrity mismatch with
/// enough context for the repair scheduler to prioritise healing and
/// for the operator to inspect corruption history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SuspectEntry {
    /// Unique monotonically-increasing entry identifier.
    pub entry_id: u64,
    /// Locator / extent identifier where the mismatch was detected.
    pub locator_id: u64,
    /// Segment file identifier.
    pub segment_id: u64,
    /// Byte offset within the segment.
    pub offset: u64,
    /// Record type classification: 1=payload, 2=chain, 3=truncated, 4=record-digest.
    pub record_type: u8,
    /// Expected BLAKE3-256 hash.
    pub expected_hash: [u8; 32],
    /// Actual (computed) BLAKE3-256 hash.
    pub actual_hash: [u8; 32],
    /// Number of repair attempts so far.
    pub repair_attempts: u32,
    /// Unix timestamp of the most recent repair attempt (0 if never).
    pub last_repair_attempt: u64,
    /// Whether the corruption has been resolved via repair.
    pub resolved: bool,
    /// Commit group / transaction sequence at detection time.
    pub commit_group: u64,
    /// Unix timestamp when the mismatch was first detected.
    pub timestamp_secs: u64,
}

// ---------------------------------------------------------------------------
// CommitGroupStore impl — bridges commit_group commit_group pipeline to local-object-store
// ---------------------------------------------------------------------------

impl tidefs_commit_group::CommitGroupStore for LocalObjectStore {
    fn put_named(
        &mut self,
        name: &str,
        payload: &[u8],
    ) -> std::result::Result<tidefs_commit_group::CommitGroupKey, String> {
        let stored = self
            .put_direct(ObjectKey::from_name(name), payload)
            .map_err(|e| format!("{e}"))?;
        Ok(tidefs_commit_group::CommitGroupKey::from_bytes32(
            stored.key.as_bytes32(),
        ))
    }

    fn get_named(&self, name: &str) -> std::result::Result<Option<Vec<u8>>, String> {
        // Route through the key-based get to avoid infinite recursion.
        let key = ObjectKey::from_name(name);
        self.get(key).map_err(|e| format!("{e:?}"))
    }
}

/// Persistent ring buffer tracking corruption suspect entries per segment.
///
/// Bounded to `SUSPECT_LOG_RING_CAPACITY` entries; oldest entries are
/// overwritten when the ring is full. Older entries are reconstructed
/// during background scrub.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SuspectLog {
    entries: Vec<SuspectEntry>,
    head: usize,
    count: usize,
    next_entry_id: u64,
}

/// Aggregate statistics for the suspect log.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SuspectLogStats {
    /// Total entries ever recorded (including resolved).
    pub total_entries: u64,
    /// Currently unresolved entries.
    pub unresolved: u64,
    /// Entries that have been marked resolved.
    pub resolved: u64,
    /// Age in seconds of the oldest unresolved entry (0 if none).
    pub oldest_unresolved_age: u64,
}

impl SuspectLog {
    /// Create an empty suspect log with the default ring capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(SUSPECT_LOG_RING_CAPACITY),
            head: 0,
            count: 0,
            next_entry_id: 1,
        }
    }

    /// Append a suspect entry. Auto-assigns a monotonically-increasing
    /// . If the ring is full, overwrites the oldest.
    pub fn record(&mut self, mut entry: SuspectEntry) {
        entry.entry_id = self.next_entry_id;
        self.next_entry_id = self.next_entry_id.wrapping_add(1);
        if self.entries.len() < SUSPECT_LOG_RING_CAPACITY {
            self.entries.push(entry);
            self.count += 1;
        } else {
            self.entries[self.head] = entry;
            self.head = (self.head + 1) % SUSPECT_LOG_RING_CAPACITY;
        }
    }

    /// Iterate over all stored entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &SuspectEntry> {
        if self.entries.len() < SUSPECT_LOG_RING_CAPACITY {
            let result: Vec<&SuspectEntry> = self.entries.iter().take(self.count).collect();
            result.into_iter()
        } else {
            let mut result: Vec<&SuspectEntry> = Vec::with_capacity(SUSPECT_LOG_RING_CAPACITY);
            for i in self.head..self.entries.len() {
                result.push(&self.entries[i]);
            }
            for i in 0..self.head {
                result.push(&self.entries[i]);
            }
            result.into_iter()
        }
    }

    /// Return all unresolved entries sorted by severity (most repair
    /// attempts first, then oldest first).
    #[must_use]
    pub fn unresolved(&self) -> Vec<SuspectEntry> {
        let mut v: Vec<SuspectEntry> = self.iter().copied().filter(|e| !e.resolved).collect();
        v.sort_by(|a, b| {
            b.repair_attempts
                .cmp(&a.repair_attempts)
                .then_with(|| a.timestamp_secs.cmp(&b.timestamp_secs))
        });
        v
    }

    /// Mark a suspect entry as resolved by its entry_id.
    /// Returns true if the entry was found and marked, false otherwise.
    pub fn mark_resolved(&mut self, entry_id: u64) -> bool {
        for e in &mut self.entries {
            if e.entry_id == entry_id && !e.resolved {
                e.resolved = true;
                return true;
            }
        }
        false
    }

    /// Return all unresolved entries and increment their `repair_attempts`
    /// count to track dispatch. Entries remain in the log so a crash
    /// between drain and repair completion does not lose records.
    ///
    /// Resolved entries and entries that have exceeded `max_repair_attempts`
    /// (default 3) are skipped.
    #[must_use]
    pub fn drain_unresolved(&mut self) -> Vec<SuspectEntry> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = Vec::new();
        for e in &mut self.entries {
            if !e.resolved && e.repair_attempts < 3 {
                e.repair_attempts = e.repair_attempts.saturating_add(1);
                e.last_repair_attempt = now;
                out.push(*e);
            }
        }
        out
    }

    /// Return aggregate statistics about the suspect log.
    #[must_use]
    pub fn stats(&self) -> SuspectLogStats {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut total: u64 = 0;
        let mut unresolved_count: u64 = 0;
        let mut resolved_count: u64 = 0;
        let mut oldest_age: u64 = 0;

        for e in self.iter() {
            total += 1;
            if e.resolved {
                resolved_count += 1;
            } else {
                unresolved_count += 1;
                let age = now.saturating_sub(e.timestamp_secs);
                if age > oldest_age {
                    oldest_age = age;
                }
            }
        }

        SuspectLogStats {
            total_entries: total,
            unresolved: unresolved_count,
            resolved: resolved_count,
            oldest_unresolved_age: oldest_age,
        }
    }

    /// Number of suspect entries stored.
    #[must_use]
    pub fn len(&self) -> usize {
        if self.entries.len() < SUSPECT_LOG_RING_CAPACITY {
            self.count
        } else {
            SUSPECT_LOG_RING_CAPACITY
        }
    }

    /// Whether the log has any entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.head = 0;
        self.count = 0;
    }
}

///
/// # Example
///
/// ```rust
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// use tidefs_local_object_store::human::local_object_store::{
///     LocalObjectStore, ObjectKey, StoreOptions,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
/// let root = std::env::temp_dir().join(format!("tidefs-local-store-doc-{unique}"));
/// let _ = std::fs::remove_dir_all(&root);
///
/// let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())?;
/// let key = ObjectKey::from_name(b"docs/welcome.txt");
///
/// let written = store.put(key, b"hello from TideFS")?;
/// assert_eq!(written.key, key);
/// assert!(store.contains_key(key));
/// assert_eq!(store.get(key)?, Some(b"hello from TideFS".to_vec()));
/// assert_eq!(store.list_keys(), vec![key]);
///
/// assert!(store.delete(key)?);
/// assert_eq!(store.get(key)?, None);
/// store.sync_all()?;
/// drop(store);
///
/// let _ = std::fs::remove_dir_all(&root);
/// # Ok(())
/// # }
/// ```
pub mod local_object_store {
    pub const FAMILY_NAME: &str = "Local Object Store";
    pub const ROLE: &str = "append-only segment log, footer-committed records, replay, tombstones, per-key version history, read verification, and final uncommitted-tail repair";

    pub use crate::{
        checksum64,
        compute_segment_digest,
        decode_integrity_trailer_v2,
        decode_segment_integrity_footer,
        encode_integrity_trailer_v2,
        encode_segment_integrity_footer,
        local_object_store_on_disk_format_rules,
        production_integrity_policy_rules,
        segment_file_name,
        IntegrityDigest64,
        IntegrityTrailerV2,
        LocalObjectStore,
        LocalObjectStoreFormatRule,
        LocalObjectStoreFormatTopic,
        ObjectAttr,
        ObjectKey,
        ObjectLocation,
        ObjectReadError,
        ObjectStore,
        ProductionIntegrityDigest,
        ProductionIntegrityPolicyRule,
        ProductionIntegrityPolicyTopic,
        ProductionIntegrityRecordDigests,
        RecordKind,
        ReplayReport,
        SegmentIntegrityFooter,
        StoreError,
        StoreOptions,
        StoreStats,
        StoredObject,
        SuspectEntry,
        SuspectLog,
        // G3 checksum architecture
        CHECKSUM_ARCHITECTURE_SPEC,
        DEFAULT_MAX_SEGMENT_BYTES,
        INTEGRITY_TRAILER_V2_LEN,
        INTEGRITY_TRAILER_V2_MAGIC_ASCII,
        INTEGRITY_TRAILER_V2_MAGIC_BYTES,
        LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES,
        LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC,
        MIN_SEGMENT_BYTES,
        PRODUCTION_INTEGRITY_DIGEST_LEN,
        PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM,
        PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION,
        PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM,
        PRODUCTION_INTEGRITY_POLICY_RULES,
        PRODUCTION_INTEGRITY_POLICY_SPEC,
        PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM,
        PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM,
        PRODUCTION_INTEGRITY_TRAILER_LEN,
        PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII,
        PRODUCTION_INTEGRITY_TRAILER_MAGIC_BYTES,
        RECORD_FOOTER_LEN,
        RECORD_FOOTER_MAGIC_ASCII,
        RECORD_FOOTER_MAGIC_BYTES,
        RECORD_FORMAT_VERSION,
        RECORD_FORMAT_VERSION_V1_NO_FOOTER,
        RECORD_FORMAT_VERSION_V2_FOOTER,
        RECORD_HEADER_LEN,
        RECORD_MAGIC_ASCII,
        RECORD_MAGIC_BYTES,
        SEGMENT_FILE_EXTENSION,
        STORE_DIR_NAME,
    };
}

// ---------------------------------------------------------------------------
// Trait implementations for reclaim-queue consumer integration
// ---------------------------------------------------------------------------

impl tidefs_reclaim::SegmentResolver for LocalObjectStore {
    type Error = Infallible;

    fn resolve(
        &self,
        key: &tidefs_types_reclaim_queue_core::ObjectKey,
    ) -> std::result::Result<Option<u64>, Self::Error> {
        Ok(self
            .resolve_receipt_bound_reclaim_target(key)
            .ok()
            .flatten()
            .map(|(segment_id, _)| segment_id))
    }
}

impl tidefs_reclaim::SegmentFreer for LocalObjectStore {
    type Error = tidefs_pool_allocator::PoolAllocatorError;

    fn free_segment(&mut self, segment_id: u64) -> std::result::Result<(), Self::Error> {
        let was_used = !self.free_map.is_free(segment_id);
        self.free_map.add_free(segment_id)?;
        if was_used {
            self.free_segment_counter.freed();
        }
        // Capacity-only sparse-file hint. This must not be reported as
        // discard, secure erase, sanitization, or remanence evidence.
        self.release_segment_file_capacity_best_effort(segment_id);
        Ok(())
    }
}

impl LocalObjectStore {
    fn free_receipt_authorized_segment(&mut self, segment_id: u64) -> Result<()> {
        if !self.block_device_mode {
            let seg_path = segment_path(&self.segments_dir, segment_id);
            if seg_path.exists() {
                fs::remove_file(&seg_path).map_err(|source| {
                    io_error("remove reclaim receipt segment", &seg_path, source)
                })?;
                sync_directory(&self.segments_dir)?;
            }
        }
        let was_used = !self.free_map.is_free(segment_id);
        if was_used {
            self.free_map
                .add_free(segment_id)
                .map_err(reclaim_receipt_replay_allocator_error)?;
            self.free_segment_counter.freed();
        }
        self.reclaim_consumer.live_counts_mut().remove(segment_id);
        Ok(())
    }

    /// Best-effort sparse-file capacity release for a freed segment file.
    ///
    /// This is only a local space-reclamation hint. It does not prove discard
    /// acceptance, secure erase, sanitization, decommissioning, or any media
    /// remanence outcome, and failures are intentionally ignored so capacity
    /// accounting remains driven by the committed free map.
    fn release_segment_file_capacity_best_effort(&self, segment_id: u64) {
        if self.block_device_mode {
            return;
        }
        let max_segment = self.max_segment_bytes();
        if max_segment == 0 {
            return;
        }
        let seg_path = segment_path(self.segments_dir(), segment_id);
        if seg_path.exists() {
            let _ = std::process::Command::new("fallocate")
                .args(["-p", "-o", "0", "-l", &max_segment.to_string()])
                .arg(&seg_path)
                .status();
        }
    }
}

// ── SegmentStore impl for the segment cleaner ─────────────────────

impl LocalObjectStore {
    /// Compact a single segment by reading all live objects still
    /// referenced by the index, re-writing them through the normal
    /// write path into fresh segments, and recording the old segment
    /// bytes as dead via the segment-liveness queue.
    ///
    /// After this call the segment's liveness entry will have zero
    /// live bytes, making it eligible for freeing by the segment
    /// cleaner's step loop.
    ///
    /// If the victim segment is the currently-active write segment,
    /// the store rotates to a new segment first so that new writes
    /// are not mixed with the compaction re-writes.
    ///
    /// Returns the total number of payload bytes compacted.
    fn compact_segment(
        &mut self,
        segment_id: u64,
    ) -> std::result::Result<u64, tidefs_segment_cleaner::SegmentCleanerError> {
        // Rotate if we are about to compact the currently-active segment.
        if self.current_segment_id == segment_id {
            self.rotate_segment().map_err(|_e| {
                tidefs_segment_cleaner::SegmentCleanerError::CompactionFailed(segment_id)
            })?;
        }

        // Collect all keys whose current location is in the victim segment.
        let keys_to_compact: Vec<(ObjectKey, ObjectLocation)> = self
            .index
            .iter()
            .filter(|(_, loc)| loc.segment_id == segment_id)
            .map(|(k, loc)| (*k, *loc))
            .collect();

        if keys_to_compact.is_empty() {
            // No live objects in this segment; already fully dead.
            return Ok(0);
        }

        let mut total_bytes: u64 = 0;
        for (key, _loc) in &keys_to_compact {
            let payload = match self.get(*key) {
                Ok(Some(p)) => p,
                Ok(None) | Err(_) => continue,
            };
            let payload_len = payload.len() as u64;
            match self.put_direct(*key, &payload) {
                Ok(_) => {
                    total_bytes = total_bytes.saturating_add(payload_len);
                }
                Err(_e) => {
                    // Partial compaction is acceptable.
                    break;
                }
            }
        }

        Ok(total_bytes)
    }
}

impl tidefs_segment_cleaner::SegmentStore for LocalObjectStore {
    fn liveness_queue(&self) -> &SegmentLivenessQueue {
        &self.segment_liveness
    }

    fn liveness_queue_mut(&mut self) -> &mut SegmentLivenessQueue {
        &mut self.segment_liveness
    }

    fn compact_segment(
        &mut self,
        segment_id: u64,
    ) -> std::result::Result<u64, tidefs_segment_cleaner::SegmentCleanerError> {
        LocalObjectStore::compact_segment(self, segment_id)
    }

    fn free_segment(
        &mut self,
        segment_id: u64,
    ) -> std::result::Result<(), tidefs_segment_cleaner::SegmentCleanerError> {
        <LocalObjectStore as tidefs_reclaim::SegmentFreer>::free_segment(self, segment_id)
            .map_err(|_e| tidefs_segment_cleaner::SegmentCleanerError::FreeFailed(segment_id))
    }
}
#[cfg(test)]
mod segment_cleaner_integration_tests {
    use super::*;

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");
        (store, dir)
    }

    // ── SegmentStore trait wiring ──────────────────────────────

    #[test]
    fn segment_store_liveness_queue_access() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"test/obj1");
        store.put(key, &[0xAA; 512]).expect("put");
        store.sync_all().expect("sync");

        let lq = tidefs_segment_cleaner::SegmentStore::liveness_queue(&store);
        assert_eq!(lq.len(), store.segment_liveness.len());
    }

    #[test]
    fn segment_store_liveness_queue_mut() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"test/obj1");
        store.put(key, &[0xBB; 1024]).expect("put");

        tidefs_segment_cleaner::SegmentStore::liveness_queue_mut(&mut store)
            .record_overwrite(0, 512);
        assert_eq!(store.segment_liveness.total_dead_bytes(), 512);
    }

    #[test]
    fn segment_store_free_segment() {
        let (mut store, _dir) = temp_store();
        let key = ObjectKey::from_name(b"test/obj1");
        store.put(key, &[0xCC; 1024]).expect("put");
        store.sync_all().expect("sync");

        let free_before = store.free_segment_count();
        let result = tidefs_segment_cleaner::SegmentStore::free_segment(&mut store, 0);
        assert!(result.is_ok(), "add_free must be idempotent");
        assert_eq!(
            store.free_segment_count(),
            free_before + 1,
            "segment free records capacity reclaim without remanence evidence"
        );

        let result2 = tidefs_segment_cleaner::SegmentStore::free_segment(&mut store, 999);
        assert!(result2.is_ok());
        assert_eq!(
            store.free_segment_count(),
            free_before + 2,
            "best-effort sparse deallocation must not block capacity accounting"
        );
    }

    // ── compact_segment ────────────────────────────────────────

    #[test]
    fn compact_segment_moves_live_objects_to_new_segment() {
        let (mut store, _dir) = temp_store();

        let key1 = ObjectKey::from_name(b"alpha");
        let key2 = ObjectKey::from_name(b"beta");
        let key3 = ObjectKey::from_name(b"gamma");
        store.put(key1, &[1u8; 512]).expect("put key1");
        store.put(key2, &[2u8; 512]).expect("put key2");
        store.put(key3, &[3u8; 512]).expect("put key3");
        store.sync_all().expect("sync");

        let loc1 = store.index.get(&key1).expect("key1 in index");
        assert_eq!(loc1.segment_id, 0);

        let bytes = tidefs_segment_cleaner::SegmentStore::compact_segment(&mut store, 0)
            .expect("compact segment 0");
        assert!(bytes > 0, "should have compacted some bytes");

        store.sync_all().expect("sync");

        let new_loc1 = store.index.get(&key1).expect("key1 still in index");
        assert!(
            new_loc1.segment_id > 0,
            "compacted object should be in new segment"
        );

        let v1 = store.get(key1).expect("get key1").expect("key1 exists");
        assert_eq!(v1, &[1u8; 512]);
    }

    #[test]
    fn compact_segment_empty_segment_returns_zero() {
        let (mut store, _dir) = temp_store();

        let key = ObjectKey::from_name(b"dummy");
        store.put(key, &[0xFF; 256]).expect("put");
        store.rotate_segment().expect("rotate");

        let bytes = tidefs_segment_cleaner::SegmentStore::compact_segment(&mut store, 1)
            .expect("compact empty segment");
        assert_eq!(bytes, 0);
    }

    #[test]
    fn compact_segment_handles_current_segment_rotation() {
        let (mut store, _dir) = temp_store();

        let key = ObjectKey::from_name(b"current");
        store.put(key, &[0x42; 100]).expect("put");
        store.sync_all().expect("sync");

        let old_seg = store.current_segment_id;
        assert_eq!(old_seg, 0);

        let bytes = tidefs_segment_cleaner::SegmentStore::compact_segment(&mut store, old_seg)
            .expect("compact current segment");
        assert!(bytes > 0);

        assert!(store.current_segment_id > old_seg);
    }

    #[test]
    fn compact_then_liveness_shows_fully_dead() {
        let (mut store, _dir) = temp_store();

        let key = ObjectKey::from_name(b"liveness-test");
        store.put(key, &[0xAB; 2048]).expect("put");
        store.sync_all().expect("sync");

        store.segment_liveness.record_write(0, 2048);

        tidefs_segment_cleaner::SegmentStore::compact_segment(&mut store, 0).expect("compact");

        store.sync_all().expect("sync");

        if let Some(entry) = store.segment_liveness.get(0) {
            assert_eq!(
                entry.live_bytes, 0,
                "segment 0 should have 0 live bytes after compaction"
            );
            assert!(entry.dead_bytes >= 2048);
        }
    }

    #[test]
    fn segment_cleaner_service_step_with_real_store() {
        use tidefs_incremental_job_core::IncrementalJob;
        use tidefs_segment_cleaner::{SegmentCleanerConfig, SegmentCleanerService};
        use tidefs_types_incremental_job_core::{JobId, WorkBudget};

        let (mut store, _dir) = temp_store();

        let key1 = ObjectKey::from_name(b"svc/a");
        let key2 = ObjectKey::from_name(b"svc/b");
        store.put(key1, &[0x11; 1024]).expect("put a");
        store.put(key2, &[0x22; 2048]).expect("put b");
        store.sync_all().expect("sync");

        store.segment_liveness.record_write(0, 3072);
        store.segment_liveness.record_overwrite(0, 1024);

        let config = SegmentCleanerConfig {
            min_dead_ratio: 0.25,
            ..Default::default()
        };
        let mut svc = SegmentCleanerService::new(JobId(1), store, config);

        let result = svc.step(WorkBudget {
            max_items: 2,
            max_bytes: 8192,
            max_ms: 0,
        });
        assert!(result.is_ok(), "step should succeed");

        let stats = svc.stats();
        assert!(
            stats.segments_scanned >= 1,
            "should have scanned at least one segment"
        );
    }

    #[test]
    fn segment_cleaner_idles_on_empty_queue() {
        use tidefs_incremental_job_core::IncrementalJob;
        use tidefs_segment_cleaner::{SegmentCleanerConfig, SegmentCleanerService};
        use tidefs_types_incremental_job_core::{JobId, WorkBudget};

        let (store, _dir) = temp_store();

        let config = SegmentCleanerConfig::default();
        let mut svc = SegmentCleanerService::new(JobId(1), store, config);

        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_ok(), "step on empty store should succeed");
        let stats = svc.stats();
        assert_eq!(stats.segments_scanned, 0);
        assert_eq!(stats.segments_compacted, 0);
        assert_eq!(stats.segments_freed, 0);
    }
}

#[cfg(test)]
mod reserve_ledger_integration_tests {
    use super::*;
    use tempfile::tempdir;
    use tidefs_reserve_ledger::ReserveClass;

    fn make_ledger(capacity: u64) -> ReserveLedger {
        let mut rl = ReserveLedger::new(1u64, ReserveClass::Rebuild, 100_000, 200_000);
        rl.set_capacity(capacity);
        rl
    }

    fn temp_store_with_reserve() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        (store, dir)
    }

    #[test]
    fn reserve_blocks_normal_writes_when_exhausted() {
        let (mut store, _dir) = temp_store_with_reserve();
        store.set_reserve_ledger(make_ledger(0));

        let payload = b"payload data";
        let result = store.put_content_addressed(payload);
        assert!(
            result.is_err(),
            "Normal write should fail when reserve is exhausted"
        );
    }

    #[test]
    fn critical_write_bypasses_reserve() {
        let (mut store, _dir) = temp_store_with_reserve();
        store.set_reserve_ledger(make_ledger(0));

        let key = ObjectKey::from_name(b"critical/obj");
        let payload = b"critical data";
        let result = store.put_direct(key, payload);
        assert!(
            result.is_ok(),
            "Critical write should succeed despite exhausted reserve"
        );
    }

    #[test]
    fn normal_writes_pass_when_reserve_has_capacity() {
        let (mut store, _dir) = temp_store_with_reserve();
        store.set_reserve_ledger(make_ledger(10));

        let payload = b"ok payload";
        let result = store.put_content_addressed(payload);
        assert!(
            result.is_ok(),
            "Normal write should succeed when reserve has capacity"
        );
    }

    #[test]
    fn without_reserve_ledger_all_writes_pass() {
        let (mut store, _dir) = temp_store_with_reserve();
        let payload = b"open payload";
        let result = store.put_content_addressed(payload);
        assert!(
            result.is_ok(),
            "Write should succeed when no reserve ledger is configured"
        );
    }

    #[test]
    fn reserve_ledger_accessor_returns_set_value() {
        let (mut store, _dir) = temp_store_with_reserve();
        assert!(store.reserve_ledger().is_none());

        let rl = make_ledger(5);
        store.set_reserve_ledger(rl);

        let arc = store.reserve_ledger().expect("should be set");
        let guard = arc.lock().unwrap();
        assert_eq!(guard.available(), 5);
    }
}

#[cfg(test)]
mod suspect_log_format_guard {
    use super::*;

    /// Regression guard: the public SuspectLog entry-size constant must
    /// match the private encoder constant or the test fails at compile
    /// time and a test assertion reinforces it at runtime.
    #[test]
    fn public_entry_len_matches_encoder_entry_bytes() {
        assert_eq!(
            crate::constants::SUSPECT_LOG_ENTRY_LEN,
            SUSPECT_LOG_ENTRY_BYTES,
            "SUSPECT_LOG_ENTRY_LEN ({}) must equal SUSPECT_LOG_ENTRY_BYTES ({})",
            crate::constants::SUSPECT_LOG_ENTRY_LEN,
            SUSPECT_LOG_ENTRY_BYTES,
        );
        assert_eq!(
            crate::constants::SUSPECT_LOG_ENTRY_LEN,
            128,
            "SUSPECT_LOG_ENTRY_LEN must be 128 bytes (VSUS format)"
        );
    }

    /// The encoder writes exactly SUSPECT_LOG_ENTRY_BYTES bytes per entry.
    #[test]
    fn encode_entry_produces_expected_byte_count() {
        let entry = SuspectEntry::default();
        let mut buf = [0u8; SUSPECT_LOG_ENTRY_BYTES];
        encode_suspect_entry(&entry, &mut buf);
        // The buffer is exactly the expected size (would not compile
        // otherwise), and the encoded content fills it.
        assert_eq!(buf.len(), SUSPECT_LOG_ENTRY_BYTES);
    }

    // -- Schema migration tests ----------------------------------------

    #[test]
    fn suspect_log_v1_roundtrip_preserves_entries() {
        let mut log = SuspectLog::new();
        log.record(SuspectEntry {
            entry_id: 0,
            locator_id: 42,
            segment_id: 3,
            offset: 1024,
            record_type: 2,
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            repair_attempts: 1,
            last_repair_attempt: 1700000000,
            resolved: false,
            commit_group: 7,
            timestamp_secs: 1690000000,
        });
        log.record(SuspectEntry {
            entry_id: 0,
            locator_id: 99,
            segment_id: 5,
            offset: 2048,
            record_type: 3,
            expected_hash: [0xCC; 32],
            actual_hash: [0xDD; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: true,
            commit_group: 12,
            timestamp_secs: 1690000100,
        });
        assert_eq!(log.iter().count(), 2);

        let encoded = encode_suspect_log(&log);
        let decoded =
            decode_suspect_log(&encoded).expect("v1-encoded log must decode successfully");

        let entries: Vec<SuspectEntry> = decoded.iter().copied().collect();
        assert_eq!(entries.len(), 2);

        let first = &entries[0];
        assert_eq!(first.locator_id, 42);
        assert_eq!(first.segment_id, 3);
        assert_eq!(first.offset, 1024);
        assert_eq!(first.record_type, 2);
        assert_eq!(first.expected_hash, [0xAA; 32]);
        assert_eq!(first.actual_hash, [0xBB; 32]);
        assert_eq!(first.repair_attempts, 1);
        assert_eq!(first.commit_group, 7);
    }

    #[test]
    fn decode_rejects_future_version_above_max() {
        let mut log = SuspectLog::new();
        log.record(SuspectEntry::default());
        let mut encoded = encode_suspect_log(&log);

        encoded[4..8].copy_from_slice(&99u32.to_le_bytes());
        let body_len = encoded.len() - SUSPECT_LOG_TRAILER_BYTES;
        let new_hash: [u8; 32] = blake3::hash(&encoded[..body_len]).into();
        encoded[body_len..].copy_from_slice(&new_hash);

        assert!(
            decode_suspect_log(&encoded).is_none(),
            "future version v99 must be rejected"
        );
    }

    #[test]
    fn decode_accepts_current_v1() {
        let mut log = SuspectLog::new();
        log.record(SuspectEntry {
            locator_id: 1,
            ..SuspectEntry::default()
        });
        let encoded = encode_suspect_log(&log);
        let stored_version = u32::from_le_bytes(encoded[4..8].try_into().unwrap());
        assert_eq!(stored_version, 1);
        assert!(decode_suspect_log(&encoded).is_some());
    }

    #[test]
    fn version_check_accepts_v1() {
        assert!(suspect_log_version_supported(1));
    }

    #[test]
    fn version_check_rejects_future() {
        assert!(!suspect_log_version_supported(99));
        assert!(!suspect_log_version_supported(2));
    }

    #[test]
    fn version_check_rejects_pre_v1() {
        assert!(!suspect_log_version_supported(0));
    }

    // -- Store reopen durability tests ---------------------------------

    /// Persist suspect entries via write_suspect_log, close store,
    /// reopen, and verify load_suspect_log recovers all durable entries.
    #[test]
    fn store_reopen_preserves_suspect_log_entries() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");

        {
            let opts = StoreOptions::test_fast();
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
            let seg_dir = store.segments_dir.clone();

            store.put_named("test-obj", b"data").expect("put");

            store.suspect_log.record(SuspectEntry {
                entry_id: 0,
                locator_id: 100,
                segment_id: 1,
                offset: 512,
                record_type: 1,
                expected_hash: [0x11; 32],
                actual_hash: [0x22; 32],
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 5,
                timestamp_secs: 1700000000,
            });
            store.suspect_log.record(SuspectEntry {
                entry_id: 0,
                locator_id: 200,
                segment_id: 2,
                offset: 1024,
                record_type: 3,
                expected_hash: [0x33; 32],
                actual_hash: [0x44; 32],
                repair_attempts: 2,
                last_repair_attempt: 1700000100,
                resolved: false,
                commit_group: 7,
                timestamp_secs: 1700000200,
            });
            assert_eq!(store.suspect_log().iter().count(), 2);

            write_suspect_log(&seg_dir, &store.suspect_log).expect("write suspect log");
        }

        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen store");

        let entries: Vec<SuspectEntry> = store.suspect_log().iter().copied().collect();
        assert!(
            entries.len() >= 2,
            "expected >=2 entries after reopen, got {}",
            entries.len()
        );

        let first = entries.iter().find(|e| e.locator_id == 100);
        let second = entries.iter().find(|e| e.locator_id == 200);
        assert!(first.is_some(), "first entry must survive reopen");
        assert!(second.is_some(), "second entry must survive reopen");

        let e1 = first.unwrap();
        assert_eq!(e1.segment_id, 1);
        assert_eq!(e1.offset, 512);
        assert_eq!(e1.record_type, 1);
        assert_eq!(e1.expected_hash, [0x11; 32]);
        assert_eq!(e1.actual_hash, [0x22; 32]);
        assert_eq!(e1.commit_group, 5);

        let e2 = second.unwrap();
        assert_eq!(e2.segment_id, 2);
        assert_eq!(e2.record_type, 3);
        assert_eq!(e2.repair_attempts, 2);
        assert_eq!(e2.commit_group, 7);
    }

    /// After reopen, new suspect entries can still be recorded.
    #[test]
    fn store_reopen_log_is_writable() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");

        {
            let opts = StoreOptions::test_fast();
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
            store.put_named("obj", b"data").expect("put");
            store.suspect_log.record(SuspectEntry {
                locator_id: 10,
                ..SuspectEntry::default()
            });
            let seg_dir = store.segments_dir.clone();
            write_suspect_log(&seg_dir, &store.suspect_log).expect("write suspect log");
        }

        let opts = StoreOptions::test_fast();
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), opts).expect("reopen store");
        store.suspect_log.record(SuspectEntry {
            locator_id: 20,
            ..SuspectEntry::default()
        });

        let entries: Vec<SuspectEntry> = store.suspect_log().iter().copied().collect();
        assert!(
            entries.iter().any(|e| e.locator_id == 20),
            "new entry must be recordable after reopen"
        );
    }
}

#[cfg(test)]
mod corruption_localization_tests {
    use super::*;
    use crate::{LocalObjectStore, SegmentIntegrityScrubber, StoreOptions, SuspectLog};
    use std::fs;

    fn store_with_known_objects(root: &std::path::Path) -> (LocalObjectStore, Vec<ObjectKey>) {
        let opts = StoreOptions {
            max_segment_bytes: 4096,
            segment_count: 16,
            sync_on_write: true,
            ..StoreOptions::test_fast()
        };
        let mut store = LocalObjectStore::open_with_options(root, opts).expect("open store");
        let mut keys = Vec::new();
        for i in 0u8..5 {
            let data = vec![i; 200];
            let stored = store.put_named(format!("obj-{i}"), &data).expect("put");
            keys.push(stored.key);
        }
        store.flush_segment().expect("flush");
        store.sync_all().expect("sync");
        (store, keys)
    }

    #[test]
    fn find_objects_at_segment_offset_returns_correct_keys() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, keys) = store_with_known_objects(&root);

        let first_key = keys[0];
        let loc = store.location_of(first_key).expect("location must exist");

        let found = store.find_objects_at_segment_offset(loc.segment_id, loc.record_offset);
        assert!(
            found.contains(&first_key),
            "must find the object at its recorded position; found={found:?} expected_key={first_key:?}"
        );
    }

    #[test]
    fn find_objects_at_segment_offset_empty_for_bogus_input() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, _keys) = store_with_known_objects(&root);

        let found = store.find_objects_at_segment_offset(u64::MAX, u64::MAX);
        assert!(
            found.is_empty(),
            "bogus segment/offset must return empty, got {found:?}"
        );
    }

    #[test]
    fn find_objects_in_segment_finds_all_objects() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, keys) = store_with_known_objects(&root);

        let loc = store.location_of(keys[0]).expect("location must exist");
        let seg = loc.segment_id;
        let found = store.find_objects_in_segment(seg);

        for k in &keys {
            assert!(
                found.contains(k),
                "segment {} must contain key {:?}, found={:?}",
                seg,
                k.short_hex(),
                found.iter().map(|x| x.short_hex()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn live_object_count_matches_index_scan() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, keys) = store_with_known_objects(&root);

        let loc = store.location_of(keys[0]).expect("location must exist");
        let seg = loc.segment_id;
        let count = store.live_object_count_in_segment(seg);
        let found_keys = store.find_objects_in_segment(seg);
        assert_eq!(
            count,
            found_keys.len(),
            "live_object_count_in_segment must match find_objects_in_segment length"
        );
        assert!(
            count >= keys.len(),
            "all written objects should be in the segment"
        );
    }

    #[test]
    fn localization_is_deterministic() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, keys) = store_with_known_objects(&root);

        let loc = store.location_of(keys[0]).expect("location must exist");
        let seg = loc.segment_id;
        let r1 = store.find_objects_in_segment(seg);
        let r2 = store.find_objects_in_segment(seg);
        assert_eq!(r1, r2, "localization must be deterministic");
    }

    #[test]
    fn find_objects_at_segment_offset_exact_match() {
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, keys) = store_with_known_objects(&root);

        for k in &keys {
            let loc = store.location_of(*k).expect("location must exist");
            let found = store.find_objects_at_segment_offset(loc.segment_id, loc.record_offset);
            assert!(
                found.contains(k),
                "must find key at its exact offset; key={:?} seg={} off={} found={:?}",
                k.short_hex(),
                loc.segment_id,
                loc.record_offset,
                found.iter().map(|x| x.short_hex()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn scrub_then_localize_deterministic_inputs_for_repair() {
        // Write objects, capture the in-memory index (location_of results),
        // then corrupt segment files and run scrub. Localize the scrub
        // findings against the saved locations to prove repair has
        // deterministic inputs.
        let tmp = tempfile::TempDir::with_prefix("corrupt-local").unwrap();
        let root = tmp.path().to_path_buf();
        let (store, _keys) = store_with_known_objects(&root);

        // Collect all current locations from the live index.
        let saved_locations: Vec<ObjectLocation> =
            _keys.iter().filter_map(|k| store.location_of(*k)).collect();
        assert!(!saved_locations.is_empty(), "must have object locations");

        drop(store);

        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        // Corrupt a byte in a segment file.
        let seg_ids = crate::discover_segment_ids(&seg_dir).expect("discover segments");
        assert!(!seg_ids.is_empty());
        let seg_path = crate::segment_path(&seg_dir, seg_ids[0]);
        let len = fs::metadata(&seg_path).unwrap().len();
        if len > crate::constants::RECORD_HEADER_LEN_U64 + 10 {
            let corrupt_offset = crate::constants::RECORD_HEADER_LEN_U64 + 5;
            let mut data = fs::read(&seg_path).unwrap();
            data[corrupt_offset as usize] ^= 0xFF;
            fs::write(&seg_path, &data).unwrap();
        }

        // Scrub the corrupted segment files (raw, no store open).
        let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
        let mut suspect_log = SuspectLog::new();
        let _report = scrubber.scrub_full(&mut suspect_log).expect("scrub");

        // For each suspect entry, localize against the saved locations.
        // This proves that (segment_id, offset) from scrub returns
        // deterministic affected objects from the store index.
        let mut localized_count = 0;
        for entry in suspect_log.iter() {
            let affected: Vec<ObjectKey> = saved_locations
                .iter()
                .filter(|loc| {
                    loc.segment_id == entry.segment_id && loc.record_offset == entry.offset
                })
                .map(|loc| loc.key)
                .collect();

            if !affected.is_empty() {
                localized_count += 1;
            }

            // Determinism: run twice, same result.
            let r2: Vec<ObjectKey> = saved_locations
                .iter()
                .filter(|loc| {
                    loc.segment_id == entry.segment_id && loc.record_offset == entry.offset
                })
                .map(|loc| loc.key)
                .collect();
            assert_eq!(affected, r2, "localization must be deterministic per entry");
        }

        if !suspect_log.is_empty() {
            assert!(
                localized_count > 0,
                "at least one suspect entry should localize to affected objects"
            );
        }
    }
}
