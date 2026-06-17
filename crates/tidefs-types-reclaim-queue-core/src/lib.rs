#![no_std]
#![forbid(unsafe_code)]

//! Authority type definitions for refcount delta-based incremental data
//! cleanup queues.
//!
//! Implements Phase 1 of the reclaim queue design from
//! [`docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`] with four core types:
//!
//! - [`QueueFamily`] — discriminant distinguishing the four queue families
//!   (extent, locator, rebake, inode tombstone)
//! - [`ReclaimQueueEntry`] — per-dataset deferred reclamation entry:
//!   `(object_key, delta, family)` tuple persisted in a B-tree
//! - [`ReclaimStats`] — per-tick processing statistics: entries processed,
//!   freed, stale-deltas skipped, commit_group commits issued, underflows detected
//! - [`ReclaimIntegrityError`] — error type for refcount underflow,
//!   stale-delta resurrection, queue-family mismatches, and missing
//!   keys detected during batch processing
//!
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: deferred frees use `bpobj` (block_ref object) — an opaque,
//!   untyped deferred-free linked list processed in unpredictable order
//!   during `dsl_scan`.  TideFS improves on this with a sorted, budgeted,
//!   persistent B-tree queue that guarantees deterministic key-order
//!   processing and explicit per-tick budget control.
//! - **Ceph**: PG logs are append-only mutation journals used for
//!   recovery, not space reclamation.  Ceph has no equivalent of the
//!   reclaim delta queue; space reclamation is implicit via OSD-level
//!   snap trimming which scans full object indexes.  TideFS decouples
//!   delta recording (O(1) per mutation) from reclamation processing
//!   (O(budget) per tick), avoiding full-dataset scans.
//!
//! [`docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`]:
//!     https://forgejo/forgeadmin/tidefs/docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md

use core::fmt;

// alloc is always available in tests; crate is no_std
extern crate alloc;

/// Design spec reference constant for runtime assertions.
pub const RECLAIM_QUEUE_SPEC: &str = "tidefs-reclaim-queue-v1-design-1180";

// ---------------------------------------------------------------------------
// ObjectKey — B-tree key type for reclaim queue entries
// ---------------------------------------------------------------------------

/// Object-level key used to index reclaim queue B-tree entries.
///
/// Must be identical to the `ObjectKey` type used by the per-dataset
/// extent refcount B-tree so that the same B-tree code can service
/// both structures (design spec §2.1).
///
/// This definition mirrors the `ObjectKey` in `tidefs-local-object-store`;
/// when the runtime reclaim processor is built (Phase 2+), the integration
/// layer will provide zero-cost conversion between the two.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ObjectKey(pub [u8; 32]);

impl ObjectKey {
    /// Sentinel value for an empty / unset object key.
    pub const NONE: Self = ObjectKey([0u8; 32]);

    /// Returns `true` if this key is the sentinel.
    #[must_use]
    pub fn is_none(self) -> bool {
        self == Self::NONE
    }

    /// Returns `true` if this key is non-sentinel.
    #[must_use]
    pub fn is_some(self) -> bool {
        !self.is_none()
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..")
    }
}

// ---------------------------------------------------------------------------
// QueueFamily — four queue families per design spec §3
// ---------------------------------------------------------------------------

/// Discriminant for the four reclaim queue families.
///
/// Each family targets a different class of dead data and has distinct
/// processing logic.  The discriminant is embedded in [`ReclaimQueueEntry`]
/// so that a single B-tree can host multiple logical queues by partitioning
/// on `family`, or separate B-trees can be used with implicit family
/// assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub enum QueueFamily {
    /// Extent reclaim queue (§3.1): freed extent payloads.
    /// Triggered by `locator.refcount` decremented to 0 on truncate,
    /// delete, or overwrite.
    #[default]
    Extent = 0,

    /// Locator reclaim queue (§3.2): freed extent IDs.
    /// Triggered after the locator table entry is deleted (extent fully
    /// dead).  Enqueues shard object keys into the rebake queue if
    /// erasure-coded parity shards exist.
    Locator = 1,

    /// Rebake queue (§3.3): pending erasure-coding parity recomputation.
    /// Triggered when a data shard is freed while parity shards remain
    /// alive in the stripe.
    Rebake = 2,

    /// Inode tombstone queue (§3.4): deleted inodes awaiting compaction.
    /// Triggered when inode `nlink` reaches 0 and all open handles are
    /// closed.
    InodeTombstone = 3,
}

impl QueueFamily {
    /// Number of queue families.
    pub const COUNT: usize = 4;

    /// Stable name string for logging / diagnostic output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            QueueFamily::Extent => "extent",
            QueueFamily::Locator => "locator",
            QueueFamily::Rebake => "rebake",
            QueueFamily::InodeTombstone => "inode_tombstone",
        }
    }

    /// Returns `true` if this family's processing may produce physical
    /// space reclamation (i.e. moves data to the deadlist).
    #[must_use]
    pub const fn produces_deadlist_entries(self) -> bool {
        matches!(self, QueueFamily::Extent)
    }

    /// Return the wire-format discriminant for this queue family.
    #[must_use]
    pub const fn to_discriminant(self) -> u16 {
        self as u16
    }

    /// Decode a `QueueFamily` from its wire-format discriminant.
    ///
    /// Returns `None` if the discriminant is unknown.
    #[must_use]
    pub const fn from_discriminant(d: u16) -> Option<Self> {
        match d {
            0 => Some(Self::Extent),
            1 => Some(Self::Locator),
            2 => Some(Self::Rebake),
            3 => Some(Self::InodeTombstone),
            _ => None,
        }
    }

    /// Returns `true` if this family's processing requires the locator
    /// table to be available.
    #[must_use]
    pub const fn requires_locator_table(self) -> bool {
        matches!(
            self,
            QueueFamily::Extent | QueueFamily::Locator | QueueFamily::Rebake
        )
    }
}

impl fmt::Display for QueueFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueEntry — per-dataset deferred reclamation entry
// ---------------------------------------------------------------------------

/// A single entry in a dataset's persistent reclaim queue B-tree.
///
/// Stored as a B-tree leaf value keyed by `ObjectKey` (design spec §2.1).
/// Entries are appended atomically within the same commit_group as the refcount
/// decrement that produced them.
///
/// ## Serialisation shape
///
/// When persisted, entries are stored with their `ObjectKey` as the B-tree
/// key and `(delta, family)` as the value payload.  This allows the B-tree
/// to efficiently batch-extract entries in deterministic key order via
/// `scan(start_after=None, max_items=N)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimQueueEntry {
    /// The object key whose refcount changed.
    pub object_key: ObjectKey,

    /// Delta to apply: negative for decrement, positive for increment
    /// (a CoW clone adds a reference before the new locator is written).
    pub delta: i64,

    /// Queue family this entry belongs to — determines the processing
    /// pipeline that will consume it.
    pub family: QueueFamily,
}

impl ReclaimQueueEntry {
    /// Create a new reclaim queue entry with the given key, delta, and family.
    #[must_use]
    pub const fn new(object_key: ObjectKey, delta: i64, family: QueueFamily) -> Self {
        Self {
            object_key,
            delta,
            family,
        }
    }

    /// Returns `true` if this entry is a decrement (delta < 0).
    #[must_use]
    pub const fn is_decrement(self) -> bool {
        self.delta < 0
    }

    /// Returns `true` if this entry is an increment (delta > 0).
    ///
    /// Increments occur when a snapshot or clone holds a reference
    /// after the original delete, requiring a delta cancellation.
    #[must_use]
    pub const fn is_increment(self) -> bool {
        self.delta > 0
    }

    /// Returns `true` if this entry is a no-op (delta == 0).
    #[must_use]
    pub const fn is_zero_delta(self) -> bool {
        self.delta == 0
    }

    /// Absolute value of the delta, as a u64 for display / budget calculations.
    #[must_use]
    pub const fn delta_abs(self) -> u64 {
        if self.delta >= 0 {
            self.delta as u64
        } else {
            // Safety: i64::MIN.abs() would overflow; for a queue entry,
            // delta magnitudes are realistic (bounded by extent sizes),
            // but we guard with wrapping_abs for formal correctness.
            self.delta.wrapping_abs() as u64
        }
    }
    /// Size of a single encoded entry in bytes: 32 (object_key) + 8 (delta) + 2 (family).
    pub const ENCODED_SIZE: usize = 42;

    /// Encode this entry into a fixed-size byte array.
    ///
    /// Format (little-endian):
    /// - 32 bytes: object_key raw bytes
    /// - 8 bytes: delta (i64 LE)
    /// - 2 bytes: family discriminant (u16 LE)
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..32].copy_from_slice(&self.object_key.0);
        buf[32..40].copy_from_slice(&self.delta.to_le_bytes());
        buf[40..42].copy_from_slice(&(self.family.to_discriminant()).to_le_bytes());
        buf
    }

    /// Decode an entry from a fixed-size byte slice.
    ///
    /// # Errors
    ///
    /// Returns `ReclaimQueueEntryDecodeError::UnknownFamily` if the
    /// family discriminant does not match a known [`QueueFamily`].
    pub fn decode(buf: &[u8; Self::ENCODED_SIZE]) -> Result<Self, ReclaimQueueEntryDecodeError> {
        let object_key = ObjectKey(buf[0..32].try_into().unwrap());
        let delta = i64::from_le_bytes(buf[32..40].try_into().unwrap());
        let family_disc = u16::from_le_bytes(buf[40..42].try_into().unwrap());
        let family = QueueFamily::from_discriminant(family_disc)
            .ok_or(ReclaimQueueEntryDecodeError::UnknownFamily { found: family_disc })?;
        Ok(Self {
            object_key,
            delta,
            family,
        })
    }
}

impl Default for ReclaimQueueEntry {
    fn default() -> Self {
        Self {
            object_key: ObjectKey::NONE,
            delta: 0,
            family: QueueFamily::default(),
        }
    }
}

impl fmt::Display for ReclaimQueueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReclaimQueueEntry(key={} delta={:+} family={})",
            self.object_key, self.delta, self.family
        )
    }
}

// ---------------------------------------------------------------------------
// ReclaimStats — per-tick processing statistics
// ---------------------------------------------------------------------------

/// Per-tick statistics returned by the reclaim processor after each
/// budgeted batch (design spec §4.1).
///
/// These counters are reset per-tick and aggregated into higher-level
/// observability metrics (prometheus counters, pool health reports).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    /// Total queue entries examined this tick.
    pub processed: usize,

    /// Entries whose locators reached `refcount == 0` and were moved
    /// to the deadlist.
    pub freed: usize,

    /// Entries for still-alive locators (refcount > 0 after applying
    /// delta).  These are stale deltas typically caused by snapshot
    /// or clone references outliving the original delete.
    pub stale: usize,

    /// Number of commit_group commits issued during this tick (one commit per
    /// batch, potentially zero if no entries were processed).
    pub commits: usize,

    /// Refcount integrity violations detected: the delta would have
    /// caused a refcount underflow.  These entries are left in the
    /// queue and surfaced as [`ReclaimIntegrityError::RefcountUnderflow`].
    pub underflows: usize,
}

impl ReclaimStats {
    /// Zero-valued stats — starting state for a new tick.
    pub const ZERO: Self = ReclaimStats {
        processed: 0,
        freed: 0,
        stale: 0,
        commits: 0,
        underflows: 0,
    };

    /// Returns `true` if no work was done this tick.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.processed == 0
    }

    /// Total number of "useful" actions (freed + stale, excluding
    /// underflows which are error conditions).
    #[must_use]
    pub const fn useful_actions(self) -> usize {
        self.freed + self.stale
    }

    /// Fraction of processed entries that resulted in a free (0.0–1.0)
    /// as a fixed-point value multiplied by 1_000_000.
    #[must_use]
    pub const fn free_rate_ppm(self) -> u64 {
        if self.processed == 0 {
            return 0;
        }
        (self.freed as u64 * 1_000_000) / self.processed as u64
    }

    /// Accumulate another stats snapshot into this one.
    pub fn accumulate(&mut self, other: ReclaimStats) {
        self.processed += other.processed;
        self.freed += other.freed;
        self.stale += other.stale;
        self.commits += other.commits;
        self.underflows += other.underflows;
    }
}

impl core::ops::Add for ReclaimStats {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out.accumulate(rhs);
        out
    }
}

impl core::ops::AddAssign for ReclaimStats {
    fn add_assign(&mut self, rhs: Self) {
        self.accumulate(rhs);
    }
}

impl fmt::Display for ReclaimStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "processed={} freed={} stale={} commits={} underflows={}",
            self.processed, self.freed, self.stale, self.commits, self.underflows
        )
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ReclaimQueueEntryDecodeError -- per-entry decode failure
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a single reclaim queue entry
/// from its wire-format encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimQueueEntryDecodeError {
    /// The queue family discriminant does not match any known variant.
    UnknownFamily { found: u16 },
}

impl fmt::Display for ReclaimQueueEntryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFamily { found } => {
                write!(f, "unknown reclaim queue family discriminant: {found}")
            }
        }
    }
}

// ReclaimIntegrityError — error types for reclaim processing
// ---------------------------------------------------------------------------

/// Errors detected during reclaim queue batch processing.
///
/// When any of these errors are surfaced, the offending entry is *left*
/// in the queue (not deleted), the error is logged, and an integrity
/// alert is raised via the online verifier (#588 integrity chain).
/// The reclaim processor continues processing subsequent entries —
/// errors are non-fatal to the overall tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimIntegrityError {
    /// A delta would cause the refcount to drop below zero.
    ///
    /// This indicates either a doubled decrement (the same extent was
    /// freed twice) or a missing increment (a clone/snapshot reference
    /// was never recorded).  Both are refcount integrity bugs.
    RefcountUnderflow {
        /// The object key whose refcount would underflow.
        object_key: ObjectKey,
        /// Current refcount before the delta was applied.
        current_refcount: u64,
        /// The delta that would have caused the underflow.
        delta: i64,
    },

    /// A stale delta was applied to an object whose current refcount
    /// was not consistent with the expected value.
    ///
    /// This can occur when a snapshot clone increments the refcount
    /// between the time the delta was enqueued and the time it was
    /// processed, but the processor expected a different starting count.
    StaleDeltaResurrection {
        object_key: ObjectKey,
        /// The refcount the processor expected.
        expected_refcount: u64,
        /// The refcount actually found in the refcount B-tree.
        actual_refcount: u64,
        /// The delta that was being applied.
        delta: i64,
    },

    /// The queue family discriminant on an entry does not match the
    /// queue it was read from.
    ///
    /// This indicates either a serialisation or routing error, where an
    /// entry from one logical queue was mixed into another.
    QueueFamilyMismatch {
        object_key: ObjectKey,
        /// Family the entry claims to belong to.
        entry_family: QueueFamily,
        /// Family of the queue being processed.
        expected_family: QueueFamily,
    },

    /// An entry's object key was not found in the refcount B-tree.
    ///
    /// This is not necessarily an error — it may mean the object was
    /// already fully reclaimed by a prior tick that raced with this
    /// one.  The reclaim processor should treat this as a no-op and
    /// remove the entry from the queue.
    ObjectKeyNotFound { object_key: ObjectKey },
}

impl ReclaimIntegrityError {
    /// Human-readable error category for metrics / alert routing.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            ReclaimIntegrityError::RefcountUnderflow { .. } => "refcount_underflow",
            ReclaimIntegrityError::StaleDeltaResurrection { .. } => "stale_delta_resurrection",
            ReclaimIntegrityError::QueueFamilyMismatch { .. } => "queue_family_mismatch",
            ReclaimIntegrityError::ObjectKeyNotFound { .. } => "object_key_not_found",
        }
    }

    /// Returns `true` if this error is fatal (processing should stop).
    ///
    /// `RefcountUnderflow` is the only fatal error because continuing
    /// could propagate corrupted refcount state.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, ReclaimIntegrityError::RefcountUnderflow { .. })
    }

    /// Returns `true` if this error is recoverable (processing can
    /// skip the entry and continue).
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        !self.is_fatal()
    }

    /// The object key involved in this error, for diagnostic correlation.
    #[must_use]
    pub const fn object_key(self) -> ObjectKey {
        match self {
            ReclaimIntegrityError::RefcountUnderflow { object_key, .. }
            | ReclaimIntegrityError::StaleDeltaResurrection { object_key, .. }
            | ReclaimIntegrityError::QueueFamilyMismatch { object_key, .. }
            | ReclaimIntegrityError::ObjectKeyNotFound { object_key } => object_key,
        }
    }
}

impl fmt::Display for ReclaimIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefcountUnderflow {
                object_key,
                current_refcount,
                delta,
            } => write!(
                f,
                "refcount underflow: key={object_key} current_refcount={current_refcount} delta={delta:+}"
            ),
            Self::StaleDeltaResurrection {
                object_key,
                expected_refcount,
                actual_refcount,
                delta,
            } => write!(
                f,
                "stale delta resurrection: key={object_key} expected_refcount={expected_refcount} actual_refcount={actual_refcount} delta={delta:+}"
            ),
            Self::QueueFamilyMismatch {
                object_key,
                entry_family,
                expected_family,
            } => write!(
                f,
                "queue family mismatch: key={object_key} entry_family={entry_family} expected_family={expected_family}"
            ),
            Self::ObjectKeyNotFound { object_key } => {
                write!(f, "object key not found in refcount B-tree: key={object_key}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// QueueBudget — configuration for per-tick processing limits
// ---------------------------------------------------------------------------

/// Per-dataset reclaim processing budget (design spec §4.3).
///
/// Controls how many queue entries the reclaim processor consumes per
/// tick, bounding mount-time stalls and providing predictable latency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueBudget {
    /// Maximum number of queue entries to process per tick.
    pub max_entries_per_tick: usize,

    /// Maximum entries to pull in a single batch (commit granularity).
    pub max_batch_size: usize,

    /// Queue entry count threshold for pressure-driven ticks (§7.2).
    /// When the queue exceeds this size, the next tick fires immediately
    /// with an increased budget.
    pub pressure_threshold: usize,

    /// Multiplier applied to `max_entries_per_tick` during pressure-driven
    /// ticks.  E.g. 2.0 means double the budget.
    pub pressure_budget_multiplier: u8,
}

impl Default for QueueBudget {
    fn default() -> Self {
        Self {
            max_entries_per_tick: 256,
            max_batch_size: 1024,
            pressure_threshold: 1000,
            pressure_budget_multiplier: 2,
        }
    }
}

impl QueueBudget {
    /// Returns the effective budget during normal (non-pressure) operation.
    #[must_use]
    pub const fn normal_budget(self) -> usize {
        self.max_entries_per_tick
    }

    /// Returns the effective budget during pressure-driven operation.
    #[must_use]
    pub const fn pressure_budget(self) -> usize {
        self.max_entries_per_tick * self.pressure_budget_multiplier as usize
    }

    /// Returns `true` if a queue of `queue_size` entries should trigger
    /// pressure-driven processing.
    #[must_use]
    pub const fn is_pressure_active(self, queue_size: usize) -> bool {
        queue_size >= self.pressure_threshold
    }
}

// ---------------------------------------------------------------------------
// DeadObjectReceiptPolicy -- replacement/base placement receipt policy
// ---------------------------------------------------------------------------

/// Redundancy policy identity carried by replacement/base receipt evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadObjectReceiptPolicy {
    /// Full replicas on distinct placement targets.
    Replicated { copies: u8 },
    /// One erasure stripe with data plus parity shard targets.
    Erasure { data_shards: u8, parity_shards: u8 },
}

impl Default for DeadObjectReceiptPolicy {
    fn default() -> Self {
        Self::Replicated { copies: 1 }
    }
}

impl DeadObjectReceiptPolicy {
    const REPLICATED_DISCRIMINANT: u8 = 0;
    const ERASURE_DISCRIMINANT: u8 = 1;
    const ENCODED_SIZE: usize = 3;

    /// Number of physical targets required by this policy.
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

    /// True when the policy can describe a usable receipt placement.
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

    #[must_use]
    pub const fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        match self {
            Self::Replicated { copies } => [Self::REPLICATED_DISCRIMINANT, copies, 0],
            Self::Erasure {
                data_shards,
                parity_shards,
            } => [Self::ERASURE_DISCRIMINANT, data_shards, parity_shards],
        }
    }

    pub fn decode(buf: [u8; Self::ENCODED_SIZE]) -> Result<Self, DeadObjectEntryDecodeError> {
        match buf[0] {
            Self::REPLICATED_DISCRIMINANT => {
                if buf[2] != 0 {
                    return Err(
                        DeadObjectEntryDecodeError::InvalidReceiptPolicyReservedByte {
                            found: buf[2],
                        },
                    );
                }
                Ok(Self::Replicated { copies: buf[1] })
            }
            Self::ERASURE_DISCRIMINANT => Ok(Self::Erasure {
                data_shards: buf[1],
                parity_shards: buf[2],
            }),
            found => Err(DeadObjectEntryDecodeError::UnknownReceiptPolicy { found }),
        }
    }
}

/// Replacement/base placement receipt evidence required before receipt-bound
/// dead-object reclaim may retire old physical storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadObjectReplacementReceipt {
    /// Logical object key covered by the replacement/base receipt.
    pub object_key: ObjectKey,
    /// Placement or membership epoch when the receipt was issued.
    pub receipt_epoch: u64,
    /// Monotonic receipt write generation. Zero is the compatibility/synthetic
    /// sentinel and does not authorize reclaim.
    pub receipt_generation: u64,
    /// Redundancy policy identity in force for the replacement placement.
    pub redundancy_policy: DeadObjectReceiptPolicy,
    /// Logical payload length covered by this receipt.
    pub payload_len: u64,
    /// BLAKE3 digest of the logical payload.
    pub payload_digest: [u8; 32],
    /// Number of physical targets recorded by the placement receipt.
    pub target_count: u16,
}

impl DeadObjectReplacementReceipt {
    pub const ENCODED_SIZE: usize = 32 + 8 + 8 + DeadObjectReceiptPolicy::ENCODED_SIZE + 8 + 32 + 2;

    #[must_use]
    pub const fn new(
        object_key: ObjectKey,
        receipt_epoch: u64,
        receipt_generation: u64,
        redundancy_policy: DeadObjectReceiptPolicy,
        payload_len: u64,
        payload_digest: [u8; 32],
        target_count: u16,
    ) -> Self {
        Self {
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            target_count,
        }
    }

    #[must_use]
    pub const fn replicated(
        object_key: ObjectKey,
        receipt_epoch: u64,
        receipt_generation: u64,
        copies: u8,
        payload_len: u64,
        payload_digest: [u8; 32],
    ) -> Self {
        let redundancy_policy = DeadObjectReceiptPolicy::Replicated { copies };
        Self::new(
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            redundancy_policy.target_width(),
        )
    }

    /// Construct an erasure-coded dead-object replacement receipt.
    #[must_use]
    pub const fn erasure(
        object_key: ObjectKey,
        receipt_epoch: u64,
        receipt_generation: u64,
        data_shards: u8,
        parity_shards: u8,
        payload_len: u64,
        payload_digest: [u8; 32],
    ) -> Self {
        let redundancy_policy = DeadObjectReceiptPolicy::Erasure {
            data_shards,
            parity_shards,
        };
        let target_count = redundancy_policy.target_width();
        Self::new(
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            target_count,
        )
    }

    /// True when this evidence is the legacy compatibility placeholder rather
    /// than a durable placement receipt.
    #[must_use]
    pub const fn is_synthetic(self) -> bool {
        self.receipt_generation == 0
    }

    /// True when this receipt can authorize reclaim for `object_key`.
    #[must_use]
    pub fn authorizes_reclaim_for(self, object_key: ObjectKey) -> bool {
        !self.is_synthetic()
            && self.object_key.0 == object_key.0
            && self.redundancy_policy.is_well_formed()
            && self.target_count >= self.redundancy_policy.target_width()
    }

    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..32].copy_from_slice(&self.object_key.0);
        buf[32..40].copy_from_slice(&self.receipt_epoch.to_le_bytes());
        buf[40..48].copy_from_slice(&self.receipt_generation.to_le_bytes());
        buf[48..51].copy_from_slice(&self.redundancy_policy.encode());
        buf[51..59].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[59..91].copy_from_slice(&self.payload_digest);
        buf[91..93].copy_from_slice(&self.target_count.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; Self::ENCODED_SIZE]) -> Result<Self, DeadObjectEntryDecodeError> {
        let object_key = ObjectKey(buf[0..32].try_into().unwrap());
        let receipt_epoch = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let receipt_generation = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let redundancy_policy = DeadObjectReceiptPolicy::decode(buf[48..51].try_into().unwrap())?;
        let payload_len = u64::from_le_bytes(buf[51..59].try_into().unwrap());
        let payload_digest = buf[59..91].try_into().unwrap();
        let target_count = u16::from_le_bytes(buf[91..93].try_into().unwrap());

        Ok(Self {
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            target_count,
        })
    }
}

// ---------------------------------------------------------------------------
// DeadObjectEntry -- commit_group-anchored dead-object reclaim entry
// ---------------------------------------------------------------------------

/// An entry in the persistent dead-object reclaim queue.
///
/// Tracks objects whose space can be reclaimed only after the stable
/// committed commit_group advances past the object's `death_commit_group`.  This ensures
/// that any concurrent readers operating at an older commit_group can still
/// access the object's data before it is freed.
///
/// When `eligible` is `false`, the entry is held back even if its
/// `death_commit_group` is below the stable committed commit_group -- typically because a
/// snapshot or clone still references the object.  Receipt-bound reclaim also
/// requires replacement/base placement receipt evidence, so decoded legacy
/// entries without that evidence stay queued until a receipt-aware caller
/// attaches it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadObjectEntry {
    /// Object identifier for the dead object.
    pub object_id: ObjectKey,
    /// UUID of the dataset that owned this object.
    pub dataset_uuid: [u8; 16],
    /// Transaction group in which the object became dead.
    pub death_commit_group: u64,
    /// Whether this entry is eligible for reclamation.
    /// Set to `false` while snapshots or clones hold references.
    pub eligible: bool,
    /// Transaction group at which this entry was enqueued.
    pub enqueued_at_txg: u64,
    /// Replacement/base placement receipt evidence that authorizes retiring
    /// this dead object's old physical placement.
    pub replacement_receipt: Option<DeadObjectReplacementReceipt>,
}

impl DeadObjectEntry {
    /// Create a new dead-object entry.
    #[must_use]
    pub const fn new(
        object_id: ObjectKey,
        dataset_uuid: [u8; 16],
        death_commit_group: u64,
        eligible: bool,
        enqueued_at_txg: u64,
    ) -> Self {
        Self {
            object_id,
            dataset_uuid,
            death_commit_group,
            eligible,
            enqueued_at_txg,
            replacement_receipt: None,
        }
    }

    /// Attach replacement/base receipt evidence to this dead-object entry.
    #[must_use]
    pub const fn with_replacement_receipt(
        mut self,
        replacement_receipt: DeadObjectReplacementReceipt,
    ) -> Self {
        self.replacement_receipt = Some(replacement_receipt);
        self
    }

    /// Returns `true` if this entry is eligible for reclamation given
    /// a stable committed commit_group.
    ///
    /// An entry is reclaimable when `eligible` is `true` and
    /// `death_commit_group` is strictly less than `stable_committed_txg`.
    #[must_use]
    pub const fn is_reclaimable(self, stable_committed_txg: u64) -> bool {
        self.eligible && self.death_commit_group < stable_committed_txg
    }

    /// Returns `true` when the normal txg/eligibility gate and replacement
    /// receipt evidence both authorize reclaim.
    #[must_use]
    pub fn is_receipt_bound_reclaimable(self, stable_committed_txg: u64) -> bool {
        if !self.is_reclaimable(stable_committed_txg) {
            return false;
        }
        match self.replacement_receipt {
            Some(receipt) => receipt.authorizes_reclaim_for(self.object_id),
            None => false,
        }
    }

    /// Size of a legacy v1 encoded entry in bytes.
    /// object_id(32) + dataset_uuid(16) + death_commit_group(8) + eligible(1) +
    /// enqueued_at_txg(8) = 65 bytes.
    pub const ENCODED_SIZE_V1: usize = 65;

    /// Size of a v2 encoded entry in bytes.
    /// v1 fields + replacement receipt presence flag + receipt evidence.
    pub const ENCODED_SIZE: usize =
        Self::ENCODED_SIZE_V1 + 1 + DeadObjectReplacementReceipt::ENCODED_SIZE;

    /// Encode this entry into a fixed-size byte array.
    ///
    /// Format (little-endian):
    /// - 32 bytes: object_id raw bytes
    /// - 16 bytes: dataset_uuid raw bytes
    /// - 8 bytes: death_commit_group (u64 LE)
    /// - 1 byte: eligible flag (0 or 1)
    /// - 8 bytes: enqueued_at_txg (u64 LE)
    /// - 1 byte: replacement receipt presence (0 or 1)
    /// - 93 bytes: replacement receipt evidence, zeroed when absent
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..32].copy_from_slice(&self.object_id.0);
        buf[32..48].copy_from_slice(&self.dataset_uuid);
        buf[48..56].copy_from_slice(&self.death_commit_group.to_le_bytes());
        buf[56] = u8::from(self.eligible);
        buf[57..65].copy_from_slice(&self.enqueued_at_txg.to_le_bytes());
        if let Some(receipt) = self.replacement_receipt {
            buf[65] = 1;
            buf[66..159].copy_from_slice(&receipt.encode());
        }
        buf
    }

    /// Decode an entry from a fixed-size byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DeadObjectEntryDecodeError`] when a boolean flag or receipt
    /// policy discriminant is malformed.
    pub fn decode(buf: &[u8; Self::ENCODED_SIZE]) -> Result<Self, DeadObjectEntryDecodeError> {
        let mut entry = Self::decode_v1(
            buf[0..Self::ENCODED_SIZE_V1]
                .try_into()
                .expect("v2 entry contains v1 prefix"),
        )?;

        let replacement_receipt = match buf[65] {
            0 => {
                if buf[66..159].iter().any(|byte| *byte != 0) {
                    return Err(DeadObjectEntryDecodeError::UnexpectedReceiptBytes);
                }
                None
            }
            1 => Some(DeadObjectReplacementReceipt::decode(
                buf[66..159].try_into().unwrap(),
            )?),
            found => return Err(DeadObjectEntryDecodeError::InvalidReceiptFlag { found }),
        };
        entry.replacement_receipt = replacement_receipt;
        Ok(entry)
    }

    /// Decode a legacy v1 entry that has no replacement receipt evidence.
    pub fn decode_v1(
        buf: &[u8; Self::ENCODED_SIZE_V1],
    ) -> Result<Self, DeadObjectEntryDecodeError> {
        let object_id = ObjectKey(buf[0..32].try_into().unwrap());
        let dataset_uuid = buf[32..48].try_into().unwrap();
        let death_commit_group = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let eligible_byte = buf[56];
        let eligible = match eligible_byte {
            0 => false,
            1 => true,
            _ => {
                return Err(DeadObjectEntryDecodeError::InvalidEligibleByte {
                    found: eligible_byte,
                })
            }
        };
        let enqueued_at_txg = u64::from_le_bytes(buf[57..65].try_into().unwrap());
        Ok(Self {
            object_id,
            dataset_uuid,
            death_commit_group,
            eligible,
            enqueued_at_txg,
            replacement_receipt: None,
        })
    }
}

impl Default for DeadObjectEntry {
    fn default() -> Self {
        Self {
            object_id: ObjectKey::NONE,
            dataset_uuid: [0u8; 16],
            death_commit_group: 0,
            eligible: false,
            enqueued_at_txg: 0,
            replacement_receipt: None,
        }
    }
}

impl fmt::Display for DeadObjectEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeadObjectEntry(object_id={} death_commit_group={} eligible={} enqueued_at={} replacement_receipt={})",
            self.object_id,
            self.death_commit_group,
            self.eligible,
            self.enqueued_at_txg,
            self.replacement_receipt.is_some()
        )
    }
}

// ---------------------------------------------------------------------------
// DeadObjectEntryDecodeError -- per-entry decode failure
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a single dead-object entry
/// from its wire-format encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadObjectEntryDecodeError {
    /// The eligible byte was neither 0 (false) nor 1 (true).
    InvalidEligibleByte { found: u8 },
    /// The replacement receipt presence byte was neither 0 (false) nor 1 (true).
    InvalidReceiptFlag { found: u8 },
    /// The replacement receipt policy discriminant is unknown.
    UnknownReceiptPolicy { found: u8 },
    /// A replicated receipt policy carried nonzero reserved bytes.
    InvalidReceiptPolicyReservedByte { found: u8 },
    /// Receipt bytes were present while the replacement receipt flag was absent.
    UnexpectedReceiptBytes,
}

impl fmt::Display for DeadObjectEntryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEligibleByte { found } => {
                write!(f, "invalid eligible byte in dead-object entry: {found}")
            }
            Self::InvalidReceiptFlag { found } => {
                write!(f, "invalid receipt flag in dead-object entry: {found}")
            }
            Self::UnknownReceiptPolicy { found } => {
                write!(f, "unknown dead-object receipt policy: {found}")
            }
            Self::InvalidReceiptPolicyReservedByte { found } => {
                write!(
                    f,
                    "invalid dead-object receipt policy reserved byte: {found}"
                )
            }
            Self::UnexpectedReceiptBytes => {
                f.write_str("unexpected receipt bytes in receipt-less dead-object entry")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueError -- errors from dead-object reclaim queue operations
// ---------------------------------------------------------------------------

/// Errors surfaced by dead-object reclaim queue operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimQueueError {
    /// Attempted to enqueue an entry with an object ID already present.
    DuplicateObjectId { object_id: ObjectKey },
    /// An entry's dataset UUID does not match the expected dataset.
    DatasetUuidMismatch {
        object_id: ObjectKey,
        expected: [u8; 16],
        found: [u8; 16],
    },
    /// An entry to ack was not found in the queue.
    EntryNotFound { object_id: ObjectKey },
}

impl fmt::Display for ReclaimQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateObjectId { object_id } => {
                write!(f, "duplicate object ID in reclaim queue: {object_id}")
            }
            Self::DatasetUuidMismatch { object_id, .. } => {
                write!(f, "dataset UUID mismatch for object {object_id}")
            }
            Self::EntryNotFound { object_id } => {
                write!(f, "entry not found in reclaim queue: {object_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ── ObjectKey ─────────────────────────────────────────────────────

    #[test]
    fn object_key_none_sentinel() {
        assert_eq!(ObjectKey::NONE, ObjectKey([0u8; 32]));
        assert!(ObjectKey::NONE.is_none());
        assert!(!ObjectKey::NONE.is_some());
    }

    #[test]
    fn object_key_some() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        let ok = ObjectKey(key);
        assert!(ok.is_some());
        assert!(!ok.is_none());
    }

    #[test]
    fn object_key_display() {
        let mut key = [0u8; 32];
        key[0] = 0xDE;
        key[1] = 0xAD;
        key[2] = 0xBE;
        key[3] = 0xEF;
        let ok = ObjectKey(key);
        let s = format!("{ok}");
        assert!(s.starts_with("deadbeef"));
        assert!(s.ends_with(".."));
    }

    #[test]
    fn object_key_ordering() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1;
        assert!(ObjectKey(a) < ObjectKey(b));
    }

    // ── QueueFamily ───────────────────────────────────────────────────

    #[test]
    fn queue_family_as_str() {
        assert_eq!(QueueFamily::Extent.as_str(), "extent");
        assert_eq!(QueueFamily::Locator.as_str(), "locator");
        assert_eq!(QueueFamily::Rebake.as_str(), "rebake");
        assert_eq!(QueueFamily::InodeTombstone.as_str(), "inode_tombstone");
    }

    #[test]
    fn queue_family_display() {
        assert_eq!(format!("{}", QueueFamily::Extent), "extent");
        assert_eq!(format!("{}", QueueFamily::Locator), "locator");
    }

    #[test]
    fn queue_family_deadlist_producer() {
        assert!(QueueFamily::Extent.produces_deadlist_entries());
        assert!(!QueueFamily::Locator.produces_deadlist_entries());
        assert!(!QueueFamily::Rebake.produces_deadlist_entries());
        assert!(!QueueFamily::InodeTombstone.produces_deadlist_entries());
    }

    #[test]
    fn queue_family_requires_locator_table() {
        assert!(QueueFamily::Extent.requires_locator_table());
        assert!(QueueFamily::Locator.requires_locator_table());
        assert!(QueueFamily::Rebake.requires_locator_table());
        assert!(!QueueFamily::InodeTombstone.requires_locator_table());
    }

    #[test]
    fn queue_family_default_is_extent() {
        assert_eq!(QueueFamily::default(), QueueFamily::Extent);
    }

    #[test]
    fn queue_family_count() {
        assert_eq!(QueueFamily::COUNT, 4);
    }

    // ── ReclaimQueueEntry ─────────────────────────────────────────────

    #[test]
    fn reclaim_queue_entry_new() {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        let entry = ReclaimQueueEntry::new(ObjectKey(key), -1, QueueFamily::Extent);
        assert_eq!(entry.delta, -1);
        assert_eq!(entry.family, QueueFamily::Extent);
        assert!(entry.is_decrement());
        assert!(!entry.is_increment());
        assert!(!entry.is_zero_delta());
        assert_eq!(entry.delta_abs(), 1);
    }

    #[test]
    fn reclaim_queue_entry_increment() {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        let entry = ReclaimQueueEntry::new(ObjectKey(key), 3, QueueFamily::Extent);
        assert!(!entry.is_decrement());
        assert!(entry.is_increment());
        assert_eq!(entry.delta_abs(), 3);
    }

    #[test]
    fn reclaim_queue_entry_zero_delta() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, 0, QueueFamily::Extent);
        assert!(entry.is_zero_delta());
        assert!(!entry.is_decrement());
        assert!(!entry.is_increment());
        assert_eq!(entry.delta_abs(), 0);
    }

    #[test]
    fn reclaim_queue_entry_default() {
        let entry = ReclaimQueueEntry::default();
        assert_eq!(entry.object_key, ObjectKey::NONE);
        assert_eq!(entry.delta, 0);
        assert_eq!(entry.family, QueueFamily::Extent);
        assert!(entry.is_zero_delta());
    }

    #[test]
    fn reclaim_queue_entry_display() {
        let mut key = [0u8; 32];
        key[0] = 0xAA;
        let entry = ReclaimQueueEntry::new(ObjectKey(key), -2, QueueFamily::Locator);
        let s = format!("{entry}");
        assert!(s.contains("ReclaimQueueEntry"));
        assert!(s.contains("locator"));
        assert!(s.contains("-2"));
    }

    #[test]
    fn reclaim_queue_entry_delta_abs_large_negative() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, -4096, QueueFamily::Extent);
        assert_eq!(entry.delta_abs(), 4096);
    }

    // ── ReclaimStats ──────────────────────────────────────────────────

    #[test]
    fn reclaim_stats_zero() {
        let s = ReclaimStats::ZERO;
        assert!(s.is_idle());
        assert_eq!(s.useful_actions(), 0);
        assert_eq!(s.free_rate_ppm(), 0);
    }

    #[test]
    fn reclaim_stats_not_idle() {
        let s = ReclaimStats {
            processed: 10,
            freed: 5,
            stale: 3,
            commits: 1,
            underflows: 2,
        };
        assert!(!s.is_idle());
        assert_eq!(s.useful_actions(), 8);
    }

    #[test]
    fn reclaim_stats_free_rate() {
        let s = ReclaimStats {
            processed: 100,
            freed: 25,
            ..ReclaimStats::ZERO
        };
        assert_eq!(s.free_rate_ppm(), 250_000);
    }

    #[test]
    fn reclaim_stats_free_rate_zero_denominator() {
        assert_eq!(ReclaimStats::ZERO.free_rate_ppm(), 0);
    }

    #[test]
    fn reclaim_stats_accumulate() {
        let mut s = ReclaimStats {
            processed: 10,
            freed: 3,
            stale: 2,
            commits: 1,
            underflows: 0,
        };
        s.accumulate(ReclaimStats {
            processed: 5,
            freed: 2,
            stale: 1,
            commits: 1,
            underflows: 1,
        });
        assert_eq!(s.processed, 15);
        assert_eq!(s.freed, 5);
        assert_eq!(s.stale, 3);
        assert_eq!(s.commits, 2);
        assert_eq!(s.underflows, 1);
    }

    #[test]
    fn reclaim_stats_add_operator() {
        let s1 = ReclaimStats {
            processed: 5,
            freed: 2,
            ..ReclaimStats::ZERO
        };
        let s2 = ReclaimStats {
            processed: 3,
            freed: 1,
            stale: 1,
            ..ReclaimStats::ZERO
        };
        let s3 = s1 + s2;
        assert_eq!(s3.processed, 8);
        assert_eq!(s3.freed, 3);
    }

    #[test]
    fn reclaim_stats_add_assign() {
        let mut s = ReclaimStats {
            processed: 1,
            ..ReclaimStats::ZERO
        };
        s += ReclaimStats {
            processed: 2,
            ..ReclaimStats::ZERO
        };
        assert_eq!(s.processed, 3);
    }

    #[test]
    fn reclaim_stats_display() {
        let s = ReclaimStats {
            processed: 100,
            freed: 30,
            stale: 40,
            commits: 2,
            underflows: 0,
        };
        let disp = format!("{s}");
        assert!(disp.contains("processed=100"));
        assert!(disp.contains("freed=30"));
        assert!(disp.contains("stale=40"));
    }

    // ── ReclaimIntegrityError ─────────────────────────────────────────

    #[test]
    fn integrity_error_refcount_underflow_is_fatal() {
        let err = ReclaimIntegrityError::RefcountUnderflow {
            object_key: ObjectKey::NONE,
            current_refcount: 0,
            delta: -1,
        };
        assert!(err.is_fatal());
        assert!(!err.is_recoverable());
        assert_eq!(err.category(), "refcount_underflow");
        assert_eq!(err.object_key(), ObjectKey::NONE);
    }

    #[test]
    fn integrity_error_stale_delta_is_recoverable() {
        let err = ReclaimIntegrityError::StaleDeltaResurrection {
            object_key: ObjectKey::NONE,
            expected_refcount: 1,
            actual_refcount: 2,
            delta: -1,
        };
        assert!(!err.is_fatal());
        assert!(err.is_recoverable());
        assert_eq!(err.category(), "stale_delta_resurrection");
    }

    #[test]
    fn integrity_error_queue_family_mismatch_category() {
        let err = ReclaimIntegrityError::QueueFamilyMismatch {
            object_key: ObjectKey::NONE,
            entry_family: QueueFamily::Locator,
            expected_family: QueueFamily::Extent,
        };
        assert!(!err.is_fatal());
        assert_eq!(err.category(), "queue_family_mismatch");
    }

    #[test]
    fn integrity_error_object_key_not_found() {
        let err = ReclaimIntegrityError::ObjectKeyNotFound {
            object_key: ObjectKey::NONE,
        };
        assert!(!err.is_fatal());
        assert_eq!(err.category(), "object_key_not_found");
    }

    #[test]
    fn integrity_error_display_underflow() {
        let err = ReclaimIntegrityError::RefcountUnderflow {
            object_key: ObjectKey::NONE,
            current_refcount: 0,
            delta: -1,
        };
        let s = format!("{err}");
        assert!(s.contains("refcount underflow"));
        assert!(s.contains("current_refcount=0"));
        assert!(s.contains("-1"));
    }

    #[test]
    fn integrity_error_display_stale() {
        let err = ReclaimIntegrityError::StaleDeltaResurrection {
            object_key: ObjectKey::NONE,
            expected_refcount: 1,
            actual_refcount: 2,
            delta: -1,
        };
        let s = format!("{err}");
        assert!(s.contains("stale delta resurrection"));
        assert!(s.contains("expected_refcount=1"));
        assert!(s.contains("actual_refcount=2"));
    }

    #[test]
    fn integrity_error_display_family_mismatch() {
        let err = ReclaimIntegrityError::QueueFamilyMismatch {
            object_key: ObjectKey::NONE,
            entry_family: QueueFamily::Locator,
            expected_family: QueueFamily::Extent,
        };
        let s = format!("{err}");
        assert!(s.contains("queue family mismatch"));
        assert!(s.contains("locator"));
        assert!(s.contains("extent"));
    }

    #[test]
    fn integrity_error_display_key_not_found() {
        let err = ReclaimIntegrityError::ObjectKeyNotFound {
            object_key: ObjectKey::NONE,
        };
        let s = format!("{err}");
        assert!(s.contains("object key not found"));
    }

    // ── QueueBudget ───────────────────────────────────────────────────

    #[test]
    fn queue_budget_default() {
        let b = QueueBudget::default();
        assert_eq!(b.max_entries_per_tick, 256);
        assert_eq!(b.max_batch_size, 1024);
        assert_eq!(b.pressure_threshold, 1000);
        assert_eq!(b.pressure_budget_multiplier, 2);
    }

    #[test]
    fn queue_budget_pressure_active() {
        let b = QueueBudget::default();
        assert!(!b.is_pressure_active(999));
        assert!(b.is_pressure_active(1000));
        assert!(b.is_pressure_active(5000));
    }

    #[test]
    fn queue_budget_pressure_budget() {
        let b = QueueBudget::default();
        assert_eq!(b.normal_budget(), 256);
        assert_eq!(b.pressure_budget(), 512);
    }

    #[test]
    fn queue_budget_custom_multiplier() {
        let b = QueueBudget {
            pressure_budget_multiplier: 4,
            ..Default::default()
        };
        assert_eq!(b.pressure_budget(), 1024);
    }

    // ── Saturation / edge cases ───────────────────────────────────────

    #[test]
    fn reclaim_stats_free_rate_full() {
        let s = ReclaimStats {
            processed: 100,
            freed: 100,
            ..ReclaimStats::ZERO
        };
        assert_eq!(s.free_rate_ppm(), 1_000_000);
    }

    #[test]
    fn reclaim_queue_entry_delta_i64_min_abs() {
        // i64::MIN.abs() would panic; wrapping_abs guards against it.
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, i64::MIN, QueueFamily::Extent);
        // wrapping_abs of MIN = MIN (still negative in unsigned view,
        // but the cast to u64 wraps to 2^63).
        assert_eq!(entry.delta_abs(), 9223372036854775808);
    }

    #[test]
    fn object_key_none_self_consistent() {
        let k = ObjectKey([0u8; 32]);
        assert!(k.is_none());
        // Only the zero key is none.
        let mut partial = [0u8; 32];
        partial[31] = 1;
        assert!(!ObjectKey(partial).is_none());
    }

    #[test]
    fn reclaim_stats_accumulate_never_panics() {
        let mut s = ReclaimStats::ZERO;
        // accumulate zero should be a no-op
        s.accumulate(ReclaimStats::ZERO);
        assert_eq!(s, ReclaimStats::ZERO);

        // accumulate large values
        s.accumulate(ReclaimStats {
            processed: usize::MAX,
            freed: usize::MAX,
            stale: usize::MAX,
            commits: usize::MAX,
            underflows: usize::MAX,
        });
        // saturating add wraps in debug (overflow panic in Rust on debug
        // builds for usize additions).  These assertions verify the
        // Add behaviour without requiring saturating_add.
        assert!(s.processed == usize::MAX);
        assert!(s.freed == usize::MAX);
    }
    // -- ReclaimQueueEntry encode/decode round-trip --

    #[test]
    fn entry_encode_decode_roundtrip_extent() {
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&0xDEADBEEF_CAFEBABEu64.to_le_bytes());
        let entry = ReclaimQueueEntry::new(ObjectKey(key), -42, QueueFamily::Extent);
        let encoded = entry.encode();
        let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn entry_encode_decode_all_families() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        for family in [
            QueueFamily::Extent,
            QueueFamily::Locator,
            QueueFamily::Rebake,
            QueueFamily::InodeTombstone,
        ] {
            let entry = ReclaimQueueEntry::new(ObjectKey(key), -1, family);
            let encoded = entry.encode();
            let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
            assert_eq!(decoded, entry, "round-trip failed for {family}");
        }
    }

    #[test]
    fn entry_encode_decode_zero_delta() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, 0, QueueFamily::Extent);
        let encoded = entry.encode();
        let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.is_zero_delta());
    }

    #[test]
    fn entry_encode_decode_positive_delta() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, 4096, QueueFamily::Locator);
        let encoded = entry.encode();
        let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.is_increment());
    }

    #[test]
    fn entry_encode_decode_max_delta() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, i64::MAX, QueueFamily::Extent);
        let encoded = entry.encode();
        let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(decoded.delta, i64::MAX);
    }

    #[test]
    fn entry_encode_decode_min_delta() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, i64::MIN, QueueFamily::Extent);
        let encoded = entry.encode();
        let decoded = ReclaimQueueEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(decoded.delta, i64::MIN);
    }

    #[test]
    fn entry_encode_size_is_42_bytes() {
        let entry = ReclaimQueueEntry::new(ObjectKey::NONE, 0, QueueFamily::Extent);
        let encoded = entry.encode();
        assert_eq!(encoded.len(), 42);
        assert_eq!(ReclaimQueueEntry::ENCODED_SIZE, 42);
    }

    #[test]
    fn entry_decode_rejects_unknown_family() {
        let mut buf = [0u8; 42];
        buf[40..42].copy_from_slice(&99u16.to_le_bytes());
        let result = ReclaimQueueEntry::decode(&buf);
        assert_eq!(
            result,
            Err(ReclaimQueueEntryDecodeError::UnknownFamily { found: 99 })
        );
    }

    // ── DeadObjectEntry ──────────────────────────────────────────────────

    fn dead_object_key(byte: u8) -> ObjectKey {
        let mut key = [0u8; 32];
        key[0] = byte;
        ObjectKey(key)
    }

    fn receipt_for(key: ObjectKey) -> DeadObjectReplacementReceipt {
        let mut digest = [0u8; 32];
        digest[0] = key.0[0];
        DeadObjectReplacementReceipt::replicated(key, 7, 1, 2, 4096, digest)
    }

    #[test]
    fn dead_object_entry_new() {
        let mut oid = [0u8; 32];
        oid[0] = 0x42;
        let uuid = [0xAAu8; 16];
        let entry = DeadObjectEntry::new(ObjectKey(oid), uuid, 100, true, 95);
        assert_eq!(entry.object_id.0[0], 0x42);
        assert_eq!(entry.dataset_uuid, [0xAAu8; 16]);
        assert_eq!(entry.death_commit_group, 100);
        assert!(entry.eligible);
        assert_eq!(entry.enqueued_at_txg, 95);
        assert_eq!(entry.replacement_receipt, None);
    }

    #[test]
    fn dead_object_entry_is_reclaimable() {
        let entry = DeadObjectEntry::new(ObjectKey::NONE, [0u8; 16], 10, true, 5);
        // death_commit_group (10) < stable (15), eligible = true
        assert!(entry.is_reclaimable(15));
        // death_commit_group (10) >= stable (10) -- must be strictly less
        assert!(!entry.is_reclaimable(10));
        // death_commit_group (10) < stable (5) is false
        assert!(!entry.is_reclaimable(5));
    }

    #[test]
    fn dead_object_entry_not_eligible_regardless_of_txg() {
        let entry = DeadObjectEntry::new(ObjectKey::NONE, [0u8; 16], 5, false, 1);
        // eligible=false blocks reclaim even though death_commit_group << stable
        assert!(!entry.is_reclaimable(100));
        assert!(!entry.is_reclaimable(10));
    }

    #[test]
    fn replacement_receipt_authorizes_reclaim_for_matching_key() {
        let key = dead_object_key(0x33);
        let receipt = receipt_for(key);

        assert!(receipt.authorizes_reclaim_for(key));
        assert!(!receipt.authorizes_reclaim_for(dead_object_key(0x44)));
    }

    #[test]
    fn receipt_policy_validation_rejects_malformed_or_under_width() {
        let key = dead_object_key(0x34);
        let digest = [0xAB; 32];
        let synthetic = DeadObjectReplacementReceipt::replicated(key, 7, 0, 2, 4096, digest);
        let malformed = DeadObjectReplacementReceipt::new(
            key,
            7,
            1,
            DeadObjectReceiptPolicy::Replicated { copies: 0 },
            4096,
            digest,
            0,
        );
        let under_width = DeadObjectReplacementReceipt::new(
            key,
            7,
            1,
            DeadObjectReceiptPolicy::Erasure {
                data_shards: 2,
                parity_shards: 1,
            },
            4096,
            digest,
            2,
        );

        assert!(!synthetic.authorizes_reclaim_for(key));
        assert!(!malformed.authorizes_reclaim_for(key));
        assert!(!under_width.authorizes_reclaim_for(key));
    }

    #[test]
    fn dead_object_entry_receipt_bound_reclaim_requires_evidence() {
        let key = dead_object_key(0x35);
        let entry = DeadObjectEntry::new(key, [0u8; 16], 10, true, 9);
        assert!(entry.is_reclaimable(11));
        assert!(!entry.is_receipt_bound_reclaimable(11));

        let receipt_bound = entry.with_replacement_receipt(receipt_for(key));
        assert!(receipt_bound.is_receipt_bound_reclaimable(11));
        assert!(!receipt_bound.is_receipt_bound_reclaimable(10));
    }

    #[test]
    fn dead_object_entry_default() {
        let entry = DeadObjectEntry::default();
        assert_eq!(entry.object_id, ObjectKey::NONE);
        assert_eq!(entry.dataset_uuid, [0u8; 16]);
        assert_eq!(entry.death_commit_group, 0);
        assert!(!entry.eligible);
        assert_eq!(entry.enqueued_at_txg, 0);
        assert_eq!(entry.replacement_receipt, None);
    }

    #[test]
    fn dead_object_entry_display() {
        let entry = DeadObjectEntry::new(ObjectKey::NONE, [0u8; 16], 42, true, 30);
        let s = format!("{entry}");
        assert!(s.contains("DeadObjectEntry"));
        assert!(s.contains("death_commit_group=42"));
        assert!(s.contains("eligible=true"));
    }

    #[test]
    fn dead_object_entry_encode_decode_roundtrip() {
        let mut oid = [0u8; 32];
        oid[0..8].copy_from_slice(&0xDEADBEEF_CAFEBABEu64.to_le_bytes());
        let uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let entry = DeadObjectEntry::new(ObjectKey(oid), uuid, 500, true, 490)
            .with_replacement_receipt(receipt_for(ObjectKey(oid)));
        let encoded = entry.encode();
        let decoded = DeadObjectEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);

        // also test with eligible=false
        let entry2 = DeadObjectEntry::new(ObjectKey(oid), uuid, 500, false, 490);
        let encoded2 = entry2.encode();
        let decoded2 = DeadObjectEntry::decode(&encoded2).unwrap();
        assert_eq!(decoded2, entry2);
    }

    #[test]
    fn dead_object_entry_legacy_decode_has_no_receipt_evidence() {
        let mut legacy = [0u8; DeadObjectEntry::ENCODED_SIZE_V1];
        legacy[0] = 0x36;
        legacy[48..56].copy_from_slice(&10u64.to_le_bytes());
        legacy[56] = 1;
        legacy[57..65].copy_from_slice(&9u64.to_le_bytes());

        let decoded = DeadObjectEntry::decode_v1(&legacy).unwrap();
        assert_eq!(decoded.object_id, dead_object_key(0x36));
        assert!(decoded.is_reclaimable(11));
        assert!(!decoded.is_receipt_bound_reclaimable(11));
        assert_eq!(decoded.replacement_receipt, None);
    }

    #[test]
    fn dead_object_entry_encode_size_is_current_v2() {
        let entry = DeadObjectEntry::default();
        let encoded = entry.encode();
        assert_eq!(DeadObjectEntry::ENCODED_SIZE_V1, 65);
        assert_eq!(DeadObjectReplacementReceipt::ENCODED_SIZE, 93);
        assert_eq!(encoded.len(), 159);
        assert_eq!(DeadObjectEntry::ENCODED_SIZE, 159);
    }

    #[test]
    fn dead_object_entry_decode_rejects_invalid_eligible_byte() {
        let mut buf = [0u8; DeadObjectEntry::ENCODED_SIZE_V1];
        buf[56] = 99; // not 0 or 1
        let result = DeadObjectEntry::decode_v1(&buf);
        assert_eq!(
            result,
            Err(DeadObjectEntryDecodeError::InvalidEligibleByte { found: 99 })
        );
    }

    #[test]
    fn dead_object_entry_decode_rejects_invalid_receipt_flag() {
        let mut buf = DeadObjectEntry::default().encode();
        buf[65] = 99;
        let result = DeadObjectEntry::decode(&buf);
        assert_eq!(
            result,
            Err(DeadObjectEntryDecodeError::InvalidReceiptFlag { found: 99 })
        );
    }

    #[test]
    fn dead_object_entry_decode_rejects_unknown_receipt_policy() {
        let key = dead_object_key(0x37);
        let entry = DeadObjectEntry::new(key, [0u8; 16], 10, true, 9)
            .with_replacement_receipt(receipt_for(key));
        let mut buf = entry.encode();
        buf[65] = 1;
        buf[66 + 48] = 99;
        let result = DeadObjectEntry::decode(&buf);
        assert_eq!(
            result,
            Err(DeadObjectEntryDecodeError::UnknownReceiptPolicy { found: 99 })
        );
    }

    #[test]
    fn dead_object_entry_decode_rejects_replicated_policy_reserved_byte() {
        let key = dead_object_key(0x38);
        let entry = DeadObjectEntry::new(key, [0u8; 16], 10, true, 9)
            .with_replacement_receipt(receipt_for(key));
        let mut buf = entry.encode();
        buf[66 + 50] = 99;
        let result = DeadObjectEntry::decode(&buf);
        assert_eq!(
            result,
            Err(DeadObjectEntryDecodeError::InvalidReceiptPolicyReservedByte { found: 99 })
        );
    }

    #[test]
    fn dead_object_entry_decode_rejects_absent_receipt_with_payload_bytes() {
        let mut buf = DeadObjectEntry::default().encode();
        buf[66] = 1;
        let result = DeadObjectEntry::decode(&buf);
        assert_eq!(
            result,
            Err(DeadObjectEntryDecodeError::UnexpectedReceiptBytes)
        );
    }

    #[test]
    fn dead_object_entry_encode_decode_max_txg() {
        let entry = DeadObjectEntry::new(ObjectKey::NONE, [0u8; 16], u64::MAX, true, u64::MAX);
        let encoded = entry.encode();
        let decoded = DeadObjectEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.death_commit_group, u64::MAX);
        assert_eq!(decoded.enqueued_at_txg, u64::MAX);
    }

    // ── DeadObjectEntryDecodeError ───────────────────────────────────────

    #[test]
    fn dead_object_entry_decode_error_display() {
        let err = DeadObjectEntryDecodeError::InvalidEligibleByte { found: 42 };
        let s = format!("{err}");
        assert!(s.contains("42"));
        assert!(!s.is_empty());
    }

    // ── ReclaimQueueError ───────────────────────────────────────────────

    #[test]
    fn reclaim_queue_error_display_duplicate() {
        let err = ReclaimQueueError::DuplicateObjectId {
            object_id: ObjectKey([0xABu8; 32]),
        };
        let s = format!("{err}");
        assert!(s.contains("duplicate"));
        assert!(!s.is_empty());
    }

    #[test]
    fn reclaim_queue_error_display_uuid_mismatch() {
        let err = ReclaimQueueError::DatasetUuidMismatch {
            object_id: ObjectKey([0x01u8; 32]),
            expected: [0xAAu8; 16],
            found: [0xBBu8; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("UUID mismatch"));
        assert!(!s.is_empty());
    }

    #[test]
    fn reclaim_queue_error_display_entry_not_found() {
        let err = ReclaimQueueError::EntryNotFound {
            object_id: ObjectKey([0x10u8; 32]),
        };
        let s = format!("{err}");
        assert!(s.contains("not found"));
        assert!(!s.is_empty());
    }
}
