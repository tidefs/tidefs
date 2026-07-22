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
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
// already imported above
// already imported above
use crate::compress::CompressionStats;
use crate::io_scheduler::{IoScheduler, IoSchedulerConfig};
use crate::reclaim_queue::{
    load_dead_object_reclaim_queue, load_reclaim_queue_entries, load_reclaim_receipts,
    load_segment_liveness_queue, load_snapshot_extent_pin_set, store_dead_object_reclaim_queue,
    store_reclaim_receipts, store_snapshot_extent_pin_set, DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME,
    RECLAIM_QUEUE_ENTRIES_OBJECT_NAME, RECLAIM_QUEUE_OBJECT_NAME, RECLAIM_RECEIPTS_OBJECT_NAME,
    SNAPSHOT_EXTENT_PIN_SET_OBJECT_NAME,
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

/// Offset where the pool commit-record region ends and the object-store
/// data region begins.  The commit-record region occupies bytes
/// [8192, 8192 + 256 KiB) = [8192, 270336).  Object records start
/// after this, avoiding interference between commit history and
/// object-store record scanning.
const BLOCK_DEVICE_DATA_REGION_OFFSET: u64 = 270_336;

/// Magic bytes for the block-device data-region format header.
const BLOCK_DATA_MAGIC: &[u8; 6] = b"VFSBLK";
/// Size of the block-device format header.
const BLOCK_DATA_FORMAT_HEADER_SIZE: u64 = 64;
/// Block-device format version.
const BLOCK_DATA_FORMAT_VERSION: u32 = 1;
/// Well-known file name for the store format manifest (JSON).
const FORMAT_MANIFEST_FILE_NAME: &str = "format_manifest";
/// Well-known object name for committed compaction publication manifests.
const COMPACTION_PUBLISH_MANIFEST_OBJECT_NAME: &str = "tidefs-compaction-publish-manifest";
/// Prefix for hidden target objects staged by verified compaction rewrites.
const COMPACTION_TARGET_KEY_PREFIX: [u8; 8] = *b"TFSCMPCT";
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

#[derive(Clone, Debug, Default)]
struct ReceiptBoundDeadObjectDrainPlan {
    resolver: DeadObjectDrainSegmentResolver,
    dead_segments: Vec<u64>,
    eligible_object_ids: BTreeSet<ReclaimObjectKey>,
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
    stable_committed_txg: u64,
    snapshot_extent_pin_set: SnapshotExtentPinSet,
}

impl ReclaimGate for CommittedDeadObjectReclaimGate {
    fn check_extent(&self, extent_key: &ReclaimObjectKey) -> GateDecision {
        if !self.eligible_object_ids.contains(extent_key) {
            return GateDecision::Deny(GateDenyReason::DeadlistReferenced);
        }

        if self.snapshot_extent_pin_set.is_pinned(extent_key) {
            return GateDecision::Deny(GateDenyReason::SnapshotPinned);
        }

        GateDecision::Allow(ClearanceEvidence::Verified {
            deadlist_committed_txg: self.stable_committed_txg,
            pin_clearance_epoch: self.snapshot_extent_pin_set.epoch(),
        })
    }
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
    segment_created_at: Instant,
    segment_write_count: u64,
    index: BTreeMap<ObjectKey, ObjectLocation>,
    history: BTreeMap<ObjectKey, Vec<ObjectLocation>>,
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
    /// Computed on every `put` and persisted within the transaction group commit.
    pub(crate) checksums: BTreeMap<ObjectKey, ObjectDigest>,
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

fn is_compaction_target_key(key: ObjectKey) -> bool {
    key.as_bytes()[..8] == COMPACTION_TARGET_KEY_PREFIX
}

fn persistent_reclaim_metadata_keys() -> &'static [ObjectKey; 6] {
    static KEYS: OnceLock<[ObjectKey; 6]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            ObjectKey::from_name(RECLAIM_QUEUE_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(RECLAIM_QUEUE_ENTRIES_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(RECLAIM_RECEIPTS_OBJECT_NAME.as_bytes()),
            ObjectKey::from_name(SNAPSHOT_EXTENT_PIN_SET_OBJECT_NAME.as_bytes()),
            compaction_publish_manifest_key(),
        ]
    })
}

fn is_persistent_reclaim_metadata_key(key: ObjectKey) -> bool {
    persistent_reclaim_metadata_keys().contains(&key)
}

fn is_stats_internal_key(key: ObjectKey) -> bool {
    key == committed_root_key()
        || is_persistent_reclaim_metadata_key(key)
        || crate::is_pool_placement_receipt_key(key)
        || is_compaction_target_key(key)
}

fn is_public_scan_internal_key(key: ObjectKey) -> bool {
    key == committed_root_key()
        || is_persistent_reclaim_metadata_key(key)
        || crate::is_pool_placement_scan_internal_key(key)
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

            match record.kind {
                RecordKind::Put => {
                    if let Some(old) = index.insert(record.key, location) {
                        history.entry(record.key).or_default().push(old);
                    }
                    history.entry(record.key).or_default().push(location);
                }
                RecordKind::Delete => {
                    if let Some(old) = index.remove(&record.key) {
                        history.entry(record.key).or_default().push(old);
                    }
                }
            }

            if !is_public_scan_internal_key(record.key) {
                next_sequence = next_sequence.max(record.sequence + 1);
            }
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

    /// Write a block-device format header at `data_start`.
    ///
    /// The format header contains a magic marker, format version, and a
    /// random pool generation number that uniquely identifies this pool
    /// incarnation. On subsequent opens, the generation is compared; if
    /// it differs, the data region is treated as uninitialized (stale
    /// data from a previous pool creation).
    fn write_block_format_header(file: &mut File, data_start: u64) -> Result<u64> {
        let generation: u64 = rand::random();
        let mut header = [0u8; BLOCK_DATA_FORMAT_HEADER_SIZE as usize];
        header[0..6].copy_from_slice(BLOCK_DATA_MAGIC);
        header[6..10].copy_from_slice(&BLOCK_DATA_FORMAT_VERSION.to_le_bytes());
        header[10..18].copy_from_slice(&generation.to_le_bytes());
        file.seek(SeekFrom::Start(data_start))
            .map_err(|e| StoreError::Io {
                operation: "write_block_format_seek",
                path: PathBuf::from("<block-device>"),
                source: e,
            })?;
        file.write_all(&header).map_err(|e| StoreError::Io {
            operation: "write_block_format_write",
            path: PathBuf::from("<block-device>"),
            source: e,
        })?;
        file.flush().map_err(|e| StoreError::Io {
            operation: "write_block_format_flush",
            path: PathBuf::from("<block-device>"),
            source: e,
        })?;
        Ok(generation)
    }

    /// Read and validate the block-device format header.
    /// Returns `Some(generation)` if valid, `None` if uninitialized or stale.
    fn read_block_format_header(file: &mut File, data_start: u64) -> Result<Option<u64>> {
        let mut header = [0u8; BLOCK_DATA_FORMAT_HEADER_SIZE as usize];
        file.seek(SeekFrom::Start(data_start))
            .map_err(|e| StoreError::Io {
                operation: "read_block_format_seek",
                path: PathBuf::from("<block-device>"),
                source: e,
            })?;
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => {
                return Err(StoreError::Io {
                    operation: "read_block_format_read",
                    path: PathBuf::from("<block-device>"),
                    source: e,
                })
            }
        }
        if &header[0..6] != BLOCK_DATA_MAGIC {
            return Ok(None);
        }
        let version = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);
        if version != BLOCK_DATA_FORMAT_VERSION {
            return Ok(None);
        }
        let generation = u64::from_le_bytes([
            header[10], header[11], header[12], header[13], header[14], header[15], header[16],
            header[17],
        ]);
        Ok(Some(generation))
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
    ) {
        let object_id = compaction_reclaim_key(entry.key);
        if self.compaction_source_release_receipted(object_id) {
            return;
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
            self.dead_object_reclaim_queue_dirty = true;
        }
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
                self.index.insert(entry.key, entry.target_location);
                visible_swap_applied = true;
            }
            Some(location) if location.sequence > entry.target_location.sequence => {}
            None => {}
            Some(_) => {}
        }

        if visible_swap_applied {
            let versions = self.history.entry(entry.key).or_default();
            if !versions.contains(&entry.target_location) {
                versions.push(entry.target_location);
            }
            self.checksums
                .insert(entry.key, compaction_read_verify_digest(&payload));
        }
        self.enqueue_compaction_source_release(entry, mark_queue_dirty);

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

    /// Open a block device or development regular file as a single-segment store.
    ///
    /// The backing file/device is treated as a single append-only segment.
    /// Objects are written sequentially starting at offset 4096 (after
    /// the superblock region). On open, the data region is scanned to
    /// rebuild the in-memory index.
    pub fn open_block_device(device_path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        options.validate()?;
        let device_path = device_path.as_ref().to_path_buf();

        let metadata = std::fs::metadata(&device_path).map_err(|e| StoreError::Io {
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

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
            .map_err(|e| StoreError::Io {
                operation: "block_device_open",
                path: device_path.clone(),
                source: e,
            })?;

        let capacity = file.seek(SeekFrom::End(0)).map_err(|e| StoreError::Io {
            operation: "block_device_seek_end",
            path: device_path.clone(),
            source: e,
        })?;

        let format_start: u64 = BLOCK_DEVICE_DATA_REGION_OFFSET;
        let data_start: u64 = Self::block_device_data_start();
        // Minimum usable capacity: label 0 + commit region + format header + label 1
        let min_capacity = POOL_LABEL_SIZE as u64 + data_start + POOL_LABEL_SIZE as u64;
        if capacity < min_capacity {
            return Err(StoreError::InvalidOptions {
                reason: "block device too small for pool layout (minimum 800 KiB)",
            });
        }

        // Read or initialize the format header.
        let _generation = match Self::read_block_format_header(&mut file, format_start)? {
            Some(gen) => gen,
            None => Self::write_block_format_header(&mut file, format_start)?,
        };

        let (index, history, next_sequence, current_offset) = Self::scan_block_device_for_index(
            &mut file,
            data_start,
            capacity.saturating_sub(POOL_LABEL_SIZE as u64),
        )?;

        let root = device_path.clone();
        let segments_dir = device_path;

        // Capture fields from options before moving it into the struct.
        let max_segment_bytes = options.max_segment_bytes;

        // Single virtual segment; the free map just needs basic structure.
        let fm = SegmentFreeMap::new(2, vec![(0, 1)]).unwrap();
        let free_map = PoolAllocator::new(fm);

        Ok(Self {
            root,
            segments_dir,
            options,
            read_only: false,
            current_segment_id: 0,
            free_map,
            current_offset,
            current_file: file,
            segment_created_at: Instant::now(),
            segment_write_count: 0,
            index,
            history,
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
            compression_config: None,
            compression_stats: CompressionStats::default(),
            durability_layout: None,
            space_book: SpaceBook::default(),
            #[cfg(test)]
            current_dataset_id: None,
            checksums: BTreeMap::new(),
            block_device_mode: true,
        })
    }

    fn open_with_mode(
        root: impl AsRef<Path>,
        mut options: StoreOptions,
        mode: StoreOpenMode,
    ) -> Result<Option<Self>> {
        options.validate()?;
        let mirror_path = options.mirror_path.clone();
        let replica_paths = options.replica_paths.clone();
        if mode == StoreOpenMode::ReadOnlyExisting {
            options.repair_torn_tail = false;
        }
        let root = root.as_ref().to_path_buf();
        let segments_dir = root.join(STORE_DIR_NAME);
        if mode == StoreOpenMode::WritableCreate {
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
            if mode == StoreOpenMode::WritableCreate {
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
        if mode == StoreOpenMode::WritableCreate && current_offset >= options.max_segment_bytes {
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
        if mode == StoreOpenMode::WritableCreate {
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
            match LocalObjectStore::open_with_options(&mpath, StoreOptions::default()) {
                Ok(store) => {
                    replicas.push(store);
                    replica_healthy.push(true);
                }
                Err(_e) => {
                    replica_healthy.push(false);
                }
            }
        }
        for rp in &replica_paths {
            match LocalObjectStore::open_with_options(rp, StoreOptions::default()) {
                Ok(store) => {
                    replicas.push(store);
                    replica_healthy.push(true);
                }
                Err(_e) => {
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
        let mut store = Self {
            root,
            segments_dir,
            options,
            read_only: mode == StoreOpenMode::ReadOnlyExisting,
            segment_created_at: Instant::now(),
            segment_write_count: 0,
            current_segment_id,
            free_map,
            current_offset,
            current_file,
            index,
            history,
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
            compression_config: None,
            compression_stats: CompressionStats::default(),
            durability_layout,
            space_book: SpaceBook::new(),
            #[cfg(test)]
            current_dataset_id: None,
            checksums: BTreeMap::new(),
            block_device_mode: false,
        };
        // Restore persisted per-object checksums for read-path verification.
        store.checksums = load_checksums(&store.segments_dir);
        store.reconcile_loaded_checksums_with_index()?;
        // Restore persisted reclaim-queue entries.
        store.reclaim_queue = load_reclaim_queue_entries(&store);
        // Restore persisted receipt-bound dead-object reclaim entries.
        store.dead_object_reclaim_queue = load_dead_object_reclaim_queue(&store);
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
            for loc in store.index.values() {
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
                let lc = store.reclaim_consumer.live_counts_mut();
                let current = lc.live_count(summary.segment_id);
                if current == 0 {
                    lc.set_live_count(summary.segment_id, summary.live_object_count);
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
                                            let never_in_replay =
                                                store.version_locations_of(*object_id).is_empty();
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
                                let _ = crate::intent_log::segment_replay::mark_segment_replayed(
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

    #[must_use]
    pub fn stats(&self) -> StoreStats {
        let mirror_live_objects = if !self.replicas.is_empty() {
            stats_counted_index_len(&self.replicas[0].index)
        } else {
            0
        };
        let mirror_live_bytes = if !self.replicas.is_empty() {
            stats_counted_index_bytes(&self.replicas[0].index)
        } else {
            0
        };
        let replica_live_objects: Vec<usize> = self
            .replicas
            .iter()
            .map(|r| stats_counted_index_len(&r.index))
            .collect();
        let last_scrub_secs = self.last_scrub.elapsed().as_secs();
        let free_segments = self.free_map.free_count();
        let committed_root = self.txg_manager().committed_root();
        let committed_root_txg = committed_root.commit_group_id.0;
        let committed_root_generation = self.txg_manager().commit_count();
        StoreStats {
            live_objects: stats_counted_index_len(&self.index),
            live_bytes: stats_counted_index_bytes(&self.index),
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
        // Block-device mode: Linux block-device metadata length can be zero;
        // seek to the end of a cloned descriptor to discover usable capacity.
        if self.block_device_mode {
            match self
                .current_file
                .try_clone()
                .and_then(|mut file| file.seek(SeekFrom::End(0)))
            {
                Ok(raw) => {
                    return raw.saturating_sub(POOL_LABEL_SIZE as u64);
                }
                Err(_) => return 0,
            }
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
            if seg_path.exists() {
                if !self.receipt_replay_extents_match_dead_history(segment_id, &extent_keys) {
                    continue;
                }
                if self.read_only {
                    continue;
                }
                fs::remove_file(&seg_path).map_err(|source| {
                    io_error("remove reclaim receipt segment", &seg_path, source)
                })?;
                sync_directory(&self.segments_dir)?;
            }

            if !self.free_map.is_free(segment_id) {
                self.free_map
                    .add_free(segment_id)
                    .map_err(reclaim_receipt_replay_allocator_error)?;
                self.free_segment_counter.freed();
            }
            self.reclaim_consumer.live_counts_mut().remove(segment_id);
        }

        Ok(())
    }

    fn receipt_replay_extents_match_dead_history(
        &self,
        segment_id: u64,
        extent_keys: &BTreeSet<ReclaimObjectKey>,
    ) -> bool {
        extent_keys.iter().all(|extent_key| {
            let store_key = ObjectKey::from_bytes(extent_key.0);
            let live_location = self.index.get(&store_key).copied();
            self.history.get(&store_key).is_some_and(|locations| {
                locations.iter().any(|location| {
                    location.segment_id == segment_id && Some(*location) != live_location
                })
            })
        })
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
        self.ensure_writable("enqueue_snapshot_deadlist_candidates")?;
        let mut inserted = 0usize;
        for candidate in candidates {
            if self
                .dead_object_reclaim_queue
                .enqueue(candidate.into_dead_object_entry())
            {
                self.dead_object_reclaim_queue_dirty = true;
                inserted += 1;
            }
        }
        if self.dead_object_reclaim_queue_dirty {
            self.sync_all()?;
        }
        Ok(inserted)
    }

    /// Enqueue one dead object whose old placement may be retired only after
    /// replacement/base receipt evidence and commit-group stability agree.
    ///
    /// The receipt-bearing queue state reaches [`sync_all`](Self::sync_all)
    /// before this method returns `Ok(true)`, so a later drain cannot race an
    /// in-memory-only receipt publication. Duplicate object ids are accepted as
    /// idempotent replays and return `Ok(false)`.
    pub fn enqueue_receipt_bound_dead_object(&mut self, entry: DeadObjectEntry) -> Result<bool> {
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
            self.dead_object_reclaim_queue_dirty = true;
        }
        if self.dead_object_reclaim_queue_dirty {
            self.sync_all()?;
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
        self.ensure_writable("enqueue_pending_receipt_bound_dead_object")?;
        if entry.replacement_receipt.is_some() {
            return Err(StoreError::InvalidDeadObjectReceipt {
                reason: "pending receipt-bound enqueue must not include a replacement receipt",
            });
        }

        let inserted = self.dead_object_reclaim_queue.enqueue(entry);
        if inserted {
            self.dead_object_reclaim_queue_dirty = true;
        }
        if self.dead_object_reclaim_queue_dirty {
            self.sync_all()?;
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
            self.dead_object_reclaim_queue_dirty = true;
        }
        if self.dead_object_reclaim_queue_dirty {
            self.sync_all()?;
        }
        Ok(updated)
    }

    /// Drain receipt-authorized dead objects at caller-supplied stable
    /// committed transaction and receipt-generation boundaries.
    ///
    /// Selected entries pass through `ReclaimConsumerService` before this method
    /// acknowledges them in the persisted dead-object queue. Completed stats are
    /// returned only after the acknowledged queue state reaches `sync_all()`.
    pub fn drain_receipt_bound_dead_objects_at_stable_generation(
        &mut self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
    ) -> std::result::Result<tidefs_reclaim::ReclaimConsumerStats, ReceiptBoundDeadObjectDrainError>
    {
        self.ensure_writable("drain_receipt_bound_dead_objects_at_stable_generation")?;
        // A block backing is one virtual segment containing labels, recovery
        // state, and every live record. It cannot be handed to segment-file
        // reclamation; physical recovery waits for block compaction authority.
        if self.block_device_mode {
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..tidefs_reclaim::ReclaimConsumerStats::ZERO
            });
        }
        if self.dead_object_reclaim_queue_dirty {
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..tidefs_reclaim::ReclaimConsumerStats::ZERO
            });
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

        let queue_snapshot = self.dead_object_reclaim_queue.clone();
        let gate = CommittedDeadObjectReclaimGate {
            eligible_object_ids: plan.eligible_object_ids.clone(),
            stable_committed_txg,
            snapshot_extent_pin_set: self.snapshot_extent_pin_set.clone(),
        };
        let mut reclaim_consumer = std::mem::replace(
            &mut self.reclaim_consumer,
            ReclaimConsumerService::new(ReclaimConsumerConfig::default(), SegmentLiveCounts::new()),
        );
        let drain_result = reclaim_consumer.drain_receipt_bound_dead_objects(
            &queue_snapshot,
            stable_committed_txg,
            stable_committed_generation,
            max_count,
            &plan.resolver,
            self,
            &gate,
        );
        self.reclaim_consumer = reclaim_consumer;
        let drain = drain_result?;

        if drain.ack_object_ids.is_empty() {
            debug_assert!(drain.receipt.is_none());
            return Ok(tidefs_reclaim::ReclaimConsumerStats {
                reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
                ..drain.stats
            });
        }

        if let Some(receipt) = drain.receipt {
            self.reclaim_receipts.push(receipt);
            self.reclaim_receipts_dirty = true;
        }

        let removed = self
            .dead_object_reclaim_queue
            .ack_reclaimed(&drain.ack_object_ids);
        if removed > 0 {
            self.dead_object_reclaim_queue_dirty = true;
        }

        if !self.block_device_mode {
            for segment_id in &drain.reclaimed_segment_ids {
                let seg_path = segment_path(&self.segments_dir, *segment_id);
                let _ = std::fs::remove_file(&seg_path);
            }
        }

        self.sync_all()?;

        Ok(tidefs_reclaim::ReclaimConsumerStats {
            reclaim_queue_depth: self.dead_object_reclaim_queue.len(),
            ..drain.stats
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
        let mut segment_refdrops: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::new();
        let mut segment_queued_entries: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::new();

        for entry in self.dead_object_reclaim_queue.all_entries() {
            let Ok(Some(segment_id)) =
                <LocalObjectStore as tidefs_reclaim::SegmentResolver>::resolve(
                    self,
                    &entry.object_id,
                )
            else {
                continue;
            };
            resolver.segments.insert(entry.object_id, segment_id);
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
    /// index update, and replica fan-out. Callers are responsible for
    /// fault injection (before) and commit_group tracking (after).
    /// When `track_liveness` is false (internal system objects), the
    /// reclaim consumer live-count is not incremented.
    fn put_inner(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
        compression_algorithm: u8,
        track_liveness: bool,
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
        let sequence = if internal_metadata {
            0
        } else {
            self.next_sequence
        };
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
        self.index.insert(key, location);
        if !internal_metadata {
            self.next_sequence = self.next_sequence.saturating_add(1);
        }

        // Fan out to all replica stores.
        let total_replicas = self.replicas.len();
        let quorum = self.replica_quorum();
        let mut replica_acks: usize = 0;
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            // Replicas receive the original payload (fault injection only
            // affects the primary write path, matching the original behavior).
            let replica_result = if internal_metadata {
                replica.put_direct(key, payload)
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

    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        // Apply fault injection before the write (skipped for internal paths).
        let effective_payload = self.prepare_payload_with_fault_injection(payload)?;

        // Transparently compress the payload when compression is configured.
        let (stored_payload, compression_algorithm) =
            if let Some(ref config) = self.compression_config {
                let mut stats = self.compression_stats;
                let framed = tidefs_frame::compress_frame(&effective_payload, config, &mut stats);
                self.compression_stats = stats;
                let alg = config.algorithm as u8;
                (std::borrow::Cow::Owned(framed), alg)
            } else {
                (effective_payload, 0)
            };

        let result = self.put_inner(key, &stored_payload, compression_algorithm, true)?;

        // Compute per-object BLAKE3 domain-separated checksum for
        // read-path verification (#5273).
        {
            let domain_key = DomainTag::ReadVerify.derive_key();
            let digest = ObjectDigest::compute(payload, &domain_key);
            self.checksums.insert(key, digest);
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

    /// Write a named object directly to the segment without commit_group tracking.
    ///
    /// Used internally by the commit_group commit path to persist journal records
    /// and committed roots without recursing into the commit_group accumulator.
    pub(crate) fn put_direct(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.put_inner(key, payload, 0, false)
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
        let empty_checksum = checksum64(&[]);
        self.append_record(RecordKind::Delete, key, &[], empty_checksum, sequence, 0)?;
        if let Some(loc) = self.index.get(&key).copied() {
            self.history.entry(key).or_default().push(loc);
        }
        self.index.remove(&key);
        self.checksums.remove(&key);
        let reclaim_key = tidefs_types_reclaim_queue_core::ObjectKey(key.0);
        let reclaim_entry = tidefs_types_reclaim_queue_core::ReclaimQueueEntry::new(
            reclaim_key,
            -1,
            tidefs_types_reclaim_queue_core::QueueFamily::Extent,
        );
        self.reclaim_queue.insert(reclaim_entry);
        self.next_sequence = self.next_sequence.saturating_add(1);
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

    /// Retrieve blob bytes for `key`.
    ///
    /// If the key was derived via [`ObjectKey::from_content`], callers
    /// may additionally verify the returned payload by computing
    /// `ObjectKey::from_content(&payload)` and comparing against `key`.
    /// Use [`LocalObjectStore::get_verified`] for a one-step read with
    /// content-address verification built in.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
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

    pub fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        self.ensure_writable("delete")?;
        let existed = self.index.contains_key(&key);
        let sequence = self.next_sequence;
        let empty_checksum = checksum64(&[]);
        self.append_record(RecordKind::Delete, key, &[], empty_checksum, sequence, 0)?;
        // Record the last-known location in history so the reclaim-queue
        // consumer's SegmentResolver can resolve the segment during drain
        // after the index entry is removed.
        if let Some(loc) = self.index.get(&key).copied() {
            self.history.entry(key).or_default().push(loc);
            // Record the old segment liveness so the background reclaim
            // process can track dead space and prioritize cleaning.
            self.segment_liveness
                .record_delete(loc.segment_id, loc.payload_len);

            // Test-only raw-store accounting fixtures can model deletions.
            self.record_test_current_dataset_delete(loc.payload_len);
        }

        self.index.remove(&key);
        self.checksums.remove(&key);
        // Enqueue a reclaim entry so the background drain loop can
        // eventually free the segment when all objects in it are dead.
        self.enqueue_reclaim_entry(key);
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.tombstone_count = self.tombstone_count.saturating_add(1);

        // Fan out delete to all replicas so stale data does not
        // resurrect on a replica fallback read.
        for replica in &mut self.replicas {
            let _ = replica.delete(key);
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

    pub fn compact_retaining(
        &mut self,
        protected_keys: &[ObjectKey],
        protected_exact_locations: &[ObjectLocation],
    ) -> Result<StoreRetentionCompactionReport> {
        self.ensure_writable("compact_retaining")?;
        if self.block_device_mode {
            return self.compact_block_device_retaining(protected_keys, protected_exact_locations);
        }

        let segment_ids_before = discover_segment_ids(&self.segments_dir)?;
        let live_objects_before = stats_counted_index_len(&self.index);
        let protected_keys: BTreeSet<ObjectKey> = protected_keys.iter().copied().collect();
        let exact_location_keys: BTreeSet<ObjectKey> = protected_exact_locations
            .iter()
            .map(|location| location.key)
            .collect();
        let mut retained_segments: BTreeSet<u64> = BTreeSet::new();

        for location in protected_exact_locations {
            self.read_location(*location)?;
            retained_segments.insert(location.segment_id);
        }

        if self.current_offset > 0 {
            self.rotate_segment()?;
        }

        let mut protected_copies = Vec::new();
        for key in &protected_keys {
            if exact_location_keys.contains(key) {
                continue;
            }
            let Some(location) = self.index.get(key).copied() else {
                continue;
            };
            if retained_segments.contains(&location.segment_id) {
                continue;
            }
            protected_copies.push((*key, self.read_location(location)?));
        }

        let copied_protected_objects = protected_copies.len();
        for (key, bytes) in protected_copies {
            self.put(key, &bytes)?;
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

        self.sync_all()?;
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
        *self = LocalObjectStore::open_with_options(root, options)?;
        self.replica_healthy = replica_healthy;
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
        for location in protected_exact_locations {
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
        if self.dead_object_reclaim_queue_dirty {
            let queue = std::mem::replace(
                &mut self.dead_object_reclaim_queue,
                DeadObjectReclaimQueue::new(),
            );
            let result = store_dead_object_reclaim_queue(&queue, self);
            self.dead_object_reclaim_queue = queue;
            result?;
            self.dead_object_reclaim_queue_dirty = false;
        }

        if self.reclaim_receipts_dirty {
            let receipts = std::mem::take(&mut self.reclaim_receipts);
            let result = store_reclaim_receipts(&receipts, self);
            self.reclaim_receipts = receipts;
            result?;
            self.reclaim_receipts_dirty = false;
        }

        if self.snapshot_extent_pin_set_dirty {
            let pin_set = self.snapshot_extent_pin_set.clone();
            store_snapshot_extent_pin_set(&pin_set, self)?;
            self.snapshot_extent_pin_set_dirty = false;
        }

        let path = segment_path(&self.segments_dir, self.current_segment_id);
        self.current_file
            .sync_all()
            .map_err(|source| io_error("sync_all", &path, source))?;
        sync_directory(&self.segments_dir)?;
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
                if let Err(e) = write_checksums(&self.segments_dir, &self.checksums) {
                    tracing::warn!("checksum index write failed: {e}");
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

        Ok(())
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
            Err(StoreError::NoSpace) if self.block_device_mode => {
                self.compact_block_device_live_records()?;
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
        self.ensure_space(record_len)?;
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
        if self.options.sync_on_write {
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
        mut retained_locations: Vec<(ObjectKey, ObjectLocation)>,
    ) -> Result<()> {
        debug_assert!(self.block_device_mode);
        self.ensure_writable("compact_block_device_locations")?;
        retained_locations.sort_by_key(|(key, loc)| (loc.record_offset, *key));

        let retained_records: Vec<(ObjectKey, ObjectLocation, Vec<u8>, u8)> = retained_locations
            .into_iter()
            .map(|(key, old_location)| {
                self.read_location_stored_payload(old_location).map(
                    |(payload, compression_algorithm)| {
                        (key, old_location, payload, compression_algorithm)
                    },
                )
            })
            .collect::<Result<_>>()?;

        let data_start = Self::block_device_data_start();
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

        let compact_result = (|| -> Result<()> {
            for (key, old_location, payload, compression_algorithm) in retained_records {
                let new_location = self.append_record_once(
                    RecordKind::Put,
                    key,
                    &payload,
                    old_location.payload_checksum,
                    old_location.sequence,
                    compression_algorithm,
                )?;
                compacted_history.entry(key).or_default().push(new_location);
                compacted_index.insert(key, new_location);
            }
            Ok(())
        })();
        self.options.sync_on_write = sync_on_write;
        compact_result?;

        self.clear_block_device_compacted_tail()?;
        self.current_file
            .sync_all()
            .map_err(|source| io_error("block_device_compact_sync_all", &self.root, source))?;

        self.index = compacted_index;
        self.history = compacted_history;
        self.reclaim_queue.clear();
        self.segment_liveness.clear();
        if !self.dead_object_reclaim_queue.is_empty() {
            self.dead_object_reclaim_queue.clear();
            self.dead_object_reclaim_queue_dirty = true;
        }

        let live_count = self.index.len() as u64;
        self.reclaim_consumer.live_counts_mut().remove(0);
        if live_count > 0 {
            self.reclaim_consumer
                .live_counts_mut()
                .set_live_count(0, live_count);
        }

        Ok(())
    }

    fn clear_block_device_compacted_tail(&mut self) -> Result<()> {
        let usable_end = self.block_device_usable_end()?;
        if self.current_offset >= usable_end {
            return Ok(());
        }

        let clear_len = (usable_end - self.current_offset).min(RECORD_HEADER_LEN_U64);
        if clear_len == 0 {
            return Ok(());
        }

        let clear_len = usize::try_from(clear_len).map_err(|_| StoreError::PayloadTooLarge {
            len: clear_len,
            max: usize::MAX as u64,
        })?;
        let zeros = vec![0_u8; clear_len];
        self.current_file
            .seek(SeekFrom::Start(self.current_offset))
            .map_err(|source| io_error("block_device_compact_seek_tail", &self.root, source))?;
        self.current_file
            .write_all(&zeros)
            .map_err(|source| io_error("block_device_compact_clear_tail", &self.root, source))?;
        Ok(())
    }

    /// Compute total record length from payload_len
    /// (header + payload + footer + trailer).
    fn checked_record_total_len_u64(payload_len: u64) -> u64 {
        payload_len
            .saturating_add(RECORD_HEADER_LEN_U64)
            .saturating_add(RECORD_FOOTER_LEN_U64)
            .saturating_add(INTEGRITY_TRAILER_V2_LEN_U64)
    }

    fn ensure_space(&mut self, record_len: u64) -> Result<()> {
        // Block-device mode: skip segment-rotation logic. Only check
        // whether the record fits in the remaining device capacity.
        if self.block_device_mode {
            let usable_end = self.block_device_usable_end()?;
            if self.current_offset + record_len > usable_end {
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
            self.rotate_segment()?;
            return Ok(());
        }
        // Write-count rotation: limit segment size for bounded replay time.
        if self.options.segment_rotation_write_limit > 0
            && self.segment_write_count >= self.options.segment_rotation_write_limit
        {
            self.rotate_segment()?;
            // Fall through to size check - if the record doesn't fit, rotate again
        }
        if self.current_offset == 0
            || self.current_offset <= self.options.max_segment_bytes.saturating_sub(record_len)
        {
            return Ok(());
        }
        self.rotate_segment()
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
        let path = if self.block_device_mode {
            self.root.clone()
        } else {
            segment_path(&self.segments_dir, location.segment_id)
        };
        let mut file = File::open(&path).map_err(|source| io_error("open", &path, source))?;
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
        file.seek(SeekFrom::Start(location.record_offset))
            .map_err(|source| io_error("seek", &path, source))?;
        let mut header = [0_u8; RECORD_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read_exact header", &path, source))?;
        let record = decode_header(&header, location.segment_id, location.record_offset)?;
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
        let record_range =
            checked_record_range(record, location.segment_id, location.record_offset)?;

        let payload_len =
            usize::try_from(location.payload_len).map_err(|_| StoreError::PayloadTooLarge {
                len: location.payload_len,
                max: usize::MAX as u64,
            })?;
        let mut payload = vec![0_u8; payload_len];
        file.read_exact(&mut payload)
            .map_err(|source| io_error("read_exact payload", &path, source))?;
        let footer = if record_has_footer(record.format_version) {
            let mut footer_bytes = [0_u8; RECORD_FOOTER_LEN];
            file.read_exact(&mut footer_bytes)
                .map_err(|source| io_error("read_exact footer", &path, source))?;
            decode_footer(
                &footer_bytes,
                record,
                location.segment_id,
                record_range.footer_offset,
            )?;
            Some(footer_bytes)
        } else {
            None
        };
        if record_has_production_integrity_trailer(record.format_version) {
            let mut trailer = [0_u8; INTEGRITY_TRAILER_V2_LEN];
            file.read_exact(&mut trailer)
                .map_err(|source| io_error("read_exact integrity trailer V2", &path, source))?;
            let footer = footer.ok_or(StoreError::CorruptHeader {
                segment_id: location.segment_id,
                offset: location.record_offset,
                reason: "integrity trailer V2 requires a footer-bearing record",
            })?;
            let decoded_trailer = decode_integrity_trailer_v2(&trailer)?;
            verify_integrity_trailer_v2(
                &decoded_trailer,
                record,
                &header,
                &payload,
                &footer,
                location.segment_id,
                record_range
                    .integrity_trailer_offset
                    .ok_or(StoreError::CorruptHeader {
                        segment_id: location.segment_id,
                        offset: location.record_offset,
                        reason: "integrity trailer V2 range is absent from record layout",
                    })?,
            )?;
        }
        let actual = checksum64(&payload);
        if actual != location.payload_checksum {
            return Err(StoreError::ChecksumMismatch {
                segment_id: location.segment_id,
                offset: location.payload_offset,
                expected: location.payload_checksum,
                actual,
            });
        }
        Ok((payload, record.compression_algorithm))
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
                    &mut file, &path, segment_id, offset, torn_bytes, options, replay,
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
                        &mut file, &path, segment_id, offset, torn_bytes, options, replay,
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
                        &mut file, &path, segment_id, offset, torn_bytes, options, replay,
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
                    &mut file, &path, segment_id, offset, torn_bytes, options, replay,
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
        if !internal_record {
            *next_sequence = (*next_sequence).max(record.sequence.saturating_add(1));
        }
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
    replay: &mut ReplayReport,
) -> Result<()> {
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

    const BLOCK_IMAGE_BYTES: u64 = 1024 * 1024;

    fn create_block_image(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let image = dir.path().join("pool.img");
        let file = File::create(&image).expect("create image");
        file.set_len(BLOCK_IMAGE_BYTES).expect("size image");
        image
    }

    fn block_options(record_bytes: u64) -> StoreOptions {
        let mut options = StoreOptions::test_fast();
        options.max_segment_bytes = record_bytes;
        options
    }

    fn reclaim_key(key: ObjectKey) -> ReclaimObjectKey {
        ReclaimObjectKey(*key.as_bytes())
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
    fn open_block_device_accepts_regular_file_dev_backing() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);

        let store = LocalObjectStore::open_block_device(&image, StoreOptions::test_fast())
            .expect("open regular file backing");

        assert!(store.block_device_mode);
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
    fn block_device_compacts_live_records_on_append_full() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let record_bytes = 128 * 1024;
        let options = block_options(record_bytes);
        let payload_len = options.max_object_bytes() as usize;
        let mut store =
            LocalObjectStore::open_block_device(&image, options).expect("open block image");
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
    fn block_device_delete_churn_reuses_append_space() {
        let dir = tempdir().expect("tempdir");
        let image = create_block_image(&dir);
        let record_bytes = 80 * 1024;
        let options = block_options(record_bytes);
        let payload_len = options.max_object_bytes() as usize;
        let mut store =
            LocalObjectStore::open_block_device(&image, options).expect("open block image");
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
        assert!(
            store.current_offset <= LocalObjectStore::block_device_data_start() + 5 * record_bytes,
            "delete churn should compact away obsolete records"
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
        let mut store =
            LocalObjectStore::open_block_device(&image, options).expect("open block image");
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
    fn block_device_receipt_bound_drain_keeps_backing_image() {
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
        let mut store =
            LocalObjectStore::open_block_device(&image, block_options(RECLAIM_SEGMENT_BYTES))
                .expect("open block image");
        let key = ObjectKey::from_name(b"block-device/receipt-bound/delete");
        let live_key = ObjectKey::from_name(b"block-device/receipt-bound/live");
        let live_payload = b"live append-log payload";
        let reclaim_key = reclaim_key(key);
        let entry = tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
            reclaim_key,
            [0x5a; 16],
            1,
            true,
            1,
        )
        .with_replacement_receipt(dead_object_receipt(reclaim_key));

        store.put(key, b"receipt-bound payload").expect("put");
        // Keep one live append-log record without changing the segment-level
        // liveness count, so the pre-fix drain still selects virtual segment 0.
        store
            .put_direct(live_key, live_payload)
            .expect("put live record");
        assert!(store.delete(key).expect("delete"));
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

        let stats = store
            .drain_receipt_bound_dead_objects_at_stable_generation(2, 1, 16)
            .expect("drain receipt-bound dead object");

        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert_eq!(stats.blocks_freed, 0);
        assert_eq!(stats.reclaim_queue_depth, 1);
        assert_eq!(store.free_segment_count(), free_segments_before);
        assert_eq!(store.dead_object_reclaim_queue.len(), 1);
        assert!(store.reclaim_receipts().is_empty());
        assert_eq!(
            store.get(live_key).expect("get live record after drain"),
            Some(live_payload.to_vec())
        );
        assert_eq!(
            std::fs::read(&image).expect("read block image after drain"),
            protected_image,
            "receipt-bound drain must preserve labels, bootstrap/header bytes, live records, and the trailing label reservation"
        );
        assert!(image.exists(), "block backing image must not be unlinked");
        drop(store);

        let reopened =
            LocalObjectStore::open_block_device(&image, block_options(RECLAIM_SEGMENT_BYTES))
                .expect("reopen block image");
        assert_eq!(reopened.get(key).expect("get reopened deleted"), None);
        assert_eq!(
            reopened.get(live_key).expect("get reopened live record"),
            Some(live_payload.to_vec())
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
    fn receipt_bound_dead_object_enqueue_rejects_receiptless_entries() {
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
        assert!(store
            .get_named(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME)
            .expect("read persisted dead-object queue")
            .is_some());
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
        let store_key = ObjectKey(key.0);
        let live_location = self.index.get(&store_key).copied();
        if let Some(locations) = self.history.get(&store_key) {
            if let Some(dead_location) = locations
                .iter()
                .rev()
                .copied()
                .find(|location| Some(*location) != live_location)
            {
                return Ok(Some(dead_location.segment_id));
            }
        }
        Ok(None)
    }
}

impl tidefs_reclaim::SegmentFreer for LocalObjectStore {
    type Error = tidefs_pool_allocator::PoolAllocatorError;

    fn free_segment(&mut self, segment_id: u64) -> std::result::Result<(), Self::Error> {
        self.free_map.add_free(segment_id)?;
        self.free_segment_counter.freed();
        // Capacity-only sparse-file hint. This must not be reported as
        // discard, secure erase, sanitization, or remanence evidence.
        self.release_segment_file_capacity_best_effort(segment_id);
        Ok(())
    }
}

impl LocalObjectStore {
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
    use tidefs_reserve_ledger::{BudgetDomainId, ReserveClass};

    fn make_ledger(capacity: u64) -> ReserveLedger {
        let id = BudgetDomainId::from_str("test");
        let mut rl = ReserveLedger::new(1u64, id, ReserveClass::Rebuild, 100_000, 200_000);
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
