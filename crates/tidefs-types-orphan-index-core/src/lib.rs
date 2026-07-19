// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Authority type definitions for the persistent orphan index.
//!
//! Implements the narrow source-owned orphan-index type vocabulary with five
//! core types:
//!
//! - [`OrphanKey`] — B-tree key: 8-byte big-endian inode ID
//! - [`OrphanCursor`] — crash-recovery cursor for resumable batch processing
//! - [`OrphanRecoveryStats`] — per-batch recovery statistics
//! - [`OrphanIntegrityError`] — error type for recovery anomalies
//! - [`OrphanRecoveryBudget`] — per-tick processing limits
//!
//! ## Orphan index model
//!
//! The index is a persistent B+tree keyed by inode ID. The cursor enables
//! recovery passes to resume from the last processed key, and budgeted batch
//! processing keeps orphan discovery scoped to orphan entries rather than
//! unrelated inode state.
//!
use core::fmt;

// alloc is always available in tests; crate is no_std
extern crate alloc;

use alloc::vec::Vec;

/// Design spec reference constant for runtime assertions.
pub const ORPHAN_INDEX_SPEC: &str = "tidefs-orphan-index-v1-design-1207";

// ---------------------------------------------------------------------------
// OrphanKey — B-tree key type for the orphan index
// ---------------------------------------------------------------------------

/// 8-byte big-endian inode ID used as the B-tree key in the orphan index.
///
/// Big-endian encoding ensures natural numerical ordering for cursor-based
/// range scans.  The B-tree is key-only (zero-byte values); presence of
/// a key means "this inode is orphaned (nlink == 0)."
///
/// ## Design spec reference
///
/// §3.2: key is `inode_id_be_u64` (8 bytes, big-endian).
/// §3.3: value is empty (0 bytes).
///
/// ## Ord implementation
///
/// `Ord` is derived and compares the raw `[u8; 8]` lexicographically,
/// which matches big-endian integer ordering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct OrphanKey(pub [u8; 8]);

impl OrphanKey {
    /// Sentinel value for an empty / unset orphan key.
    pub const NONE: Self = OrphanKey([0u8; 8]);

    /// Construct an `OrphanKey` from a `u64` inode ID, encoding in big-endian.
    #[must_use]
    pub const fn from_inode_id(inode_id: u64) -> Self {
        OrphanKey(inode_id.to_be_bytes())
    }

    /// Decode the inode ID from this key (big-endian → native).
    #[must_use]
    pub const fn to_inode_id(self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    /// Returns `true` if this key is the sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
            && self.0[6] == 0
            && self.0[7] == 0
    }

    /// Returns `true` if this key is non-sentinel.
    #[must_use]
    pub const fn is_some(self) -> bool {
        !self.is_none()
    }

    /// Returns the next key in numerical order (inode_id + 1).
    ///
    /// Used by cursor advancement.  Saturates at `u64::MAX` (the B-tree
    /// has no key beyond this).
    #[must_use]
    pub const fn next(self) -> Self {
        let id = self.to_inode_id();
        OrphanKey::from_inode_id(id.saturating_add(1))
    }

    /// Returns the previous key in numerical order (inode_id - 1).
    ///
    /// Saturates at 0.
    #[must_use]
    pub const fn prev(self) -> Self {
        let id = self.to_inode_id();
        OrphanKey::from_inode_id(id.saturating_sub(1))
    }
}

impl fmt::Display for OrphanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inode:{}", self.to_inode_id())
    }
}

impl From<u64> for OrphanKey {
    fn from(inode_id: u64) -> Self {
        OrphanKey::from_inode_id(inode_id)
    }
}

impl From<OrphanKey> for u64 {
    fn from(key: OrphanKey) -> Self {
        key.to_inode_id()
    }
}

// ---------------------------------------------------------------------------
// OrphanCursor — crash-recovery cursor for resumable batch processing
// ---------------------------------------------------------------------------

/// Persistent cursor tracking progress through the orphan index during
/// mount-time crash recovery.
///
/// The cursor is stored as `orphan_recovery_cursor: u64` in the dataset
/// metadata record.  On mount, recovery resumes from `cursor + 1`.
/// After each batch commit_group commit, the cursor advances past the last
/// processed inode.
///
/// ## Design spec reference
///
/// §5.3: cursor persisted as dataset metadata field; recovery begins at
/// `orphan_recovery_cursor + 1`; updated after each batch commit_group commit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OrphanCursor {
    /// The inode_id of the last successfully reclaimed orphan, or 0 if
    /// recovery has not started (or has completed and wrapped).
    ///
    /// On the next recovery pass, processing starts at `position + 1`.
    /// This means inode_id 0 is never a valid orphan (reserved as the
    /// "cursor at start" sentinel).
    pub position: u64,
}

impl OrphanCursor {
    /// Cursor at the start of recovery (position 0, meaning "start at inode 1").
    pub const START: Self = OrphanCursor { position: 0 };

    /// The next inode ID to process (position + 1).
    ///
    /// Saturates at `u64::MAX`.
    #[must_use]
    pub const fn next_inode(self) -> u64 {
        self.position.saturating_add(1)
    }

    /// Advance the cursor past `inode_id`.
    ///
    /// If `inode_id` is greater than the current position, the cursor
    /// moves forward.  If it's less than or equal, the cursor is unchanged
    /// (backwards movement is not allowed — prevents double-processing).
    #[must_use]
    pub fn advance_past(self, inode_id: u64) -> Self {
        if inode_id > self.position {
            OrphanCursor { position: inode_id }
        } else {
            self
        }
    }

    /// Returns `true` if the cursor has not moved from the start.
    #[must_use]
    pub const fn is_at_start(self) -> bool {
        self.position == 0
    }

    /// Returns `true` if the cursor has reached the maximum possible
    /// position (all inodes up to u64::MAX processed).
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.position == u64::MAX
    }

    /// Returns the `OrphanKey` for the next inode to process.
    #[must_use]
    pub fn next_key(self) -> OrphanKey {
        OrphanKey::from_inode_id(self.next_inode())
    }
}

impl fmt::Display for OrphanCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_exhausted() {
            write!(f, "exhausted")
        } else if self.is_at_start() {
            write!(f, "start")
        } else {
            write!(f, "inode:{}", self.position)
        }
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// OrphanReplayWatermark — durable cursor for reclaim gating
// ---------------------------------------------------------------------------

/// A durable watermark representing the furthest inode_id whose orphan state
/// has been replayed and committed.
///
/// Reclaim (dead-object queue and freed-extent ledger) compares against this
/// watermark before releasing objects or extents.  When the watermark covers a
/// given inode_id, orphan recovery for that inode has been durably committed
/// and it is safe to reclaim its associated storage.  When the watermark is
/// below the inode_id, reclaim must wait — the orphan entry may not yet have
/// been replayed after a crash.
///
/// Design spec §5.3: durable cursor persisted with orphan index commit_group;
/// reclaim gates compare inode_id against the committed watermark position.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OrphanReplayWatermark {
    /// The highest inode_id whose orphan state has been durably committed.
    /// Position 0 means no orphans have been replayed yet (the "start"
    /// sentinel, matching OrphanCursor::START).
    pub position: u64,
}

impl OrphanReplayWatermark {
    /// Watermark at the start of recovery (position 0, meaning "no orphans
    /// replayed yet").  Reclaim with this watermark blocks all releases.
    pub const NONE: Self = OrphanReplayWatermark { position: 0 };

    /// Build a watermark from an OrphanCursor.
    #[must_use]
    pub const fn from_cursor(cursor: OrphanCursor) -> Self {
        OrphanReplayWatermark {
            position: cursor.position,
        }
    }

    /// Returns true when the watermark is at the start sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.position == 0
    }

    /// Returns true when the watermark has been advanced past (or equal to)
    /// the given inode_id, meaning orphan recovery for that inode has been
    /// durably committed and reclaim may proceed.
    #[must_use]
    pub const fn covers(self, inode_id: u64) -> bool {
        self.position >= inode_id
    }

    /// Advance the watermark to at least position, returning a new watermark.
    ///
    /// Never moves backwards — the watermark is monotonic.
    #[must_use]
    pub const fn advance_past(self, position: u64) -> Self {
        OrphanReplayWatermark {
            position: if position > self.position {
                position
            } else {
                self.position
            },
        }
    }

    /// Convert this watermark back into an OrphanCursor.
    #[must_use]
    pub const fn to_cursor(self) -> OrphanCursor {
        OrphanCursor {
            position: self.position,
        }
    }
}

impl fmt::Display for OrphanReplayWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "watermark:inode:{}", self.position)
    }
}

// ---------------------------------------------------------------------------
// OrphanLogRecoveryReport — operator-visible log replay classification
// ---------------------------------------------------------------------------

/// Classification for orphan-log recovery reporting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OrphanLogRecoveryClass {
    /// Log replay found no corrupt records and no incomplete tail.
    #[default]
    Clean,
    /// One or more complete records failed checksum verification.
    CorruptOrphanLog,
    /// The log ended before all header-declared records were replayed.
    IncompleteReplay,
    /// Both checksum corruption and an incomplete tail were observed.
    CorruptAndIncomplete,
}

impl fmt::Display for OrphanLogRecoveryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::CorruptOrphanLog => f.write_str("corrupt orphan log"),
            Self::IncompleteReplay => f.write_str("incomplete replay"),
            Self::CorruptAndIncomplete => f.write_str("corrupt orphan log and incomplete replay"),
        }
    }
}

/// Tail evidence recorded when an orphan log ends before the entry count from
/// its durable header has been fully replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanLogIncompleteTail {
    /// Zero-based index of the first record that could not be fully replayed.
    pub next_entry_index: usize,
    /// Number of bytes present for the incomplete record.
    pub bytes_available: usize,
    /// Number of bytes required for one complete log record.
    pub record_bytes: usize,
    /// Number of header-declared entries that were not fully replayed.
    pub missing_entries: usize,
}

impl OrphanLogIncompleteTail {
    /// Build incomplete-tail evidence from a log scan position.
    #[must_use]
    pub const fn new(
        next_entry_index: usize,
        bytes_available: usize,
        record_bytes: usize,
        expected_entries: usize,
    ) -> Self {
        let missing_entries = expected_entries.saturating_sub(next_entry_index);
        Self {
            next_entry_index,
            bytes_available,
            record_bytes,
            missing_entries,
        }
    }
}

impl fmt::Display for OrphanLogIncompleteTail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "entry_index={} bytes_available={} record_bytes={} missing_entries={}",
            self.next_entry_index, self.bytes_available, self.record_bytes, self.missing_entries
        )
    }
}

/// Report returned by orphan-log replay for operator-visible recovery status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanLogRecoveryReport {
    /// Number of records declared in the durable log header.
    pub expected_entries: usize,
    /// Number of records that were fully replayed into the recovered index.
    pub replayed_entries: usize,
    /// Inode IDs from complete records whose checksum verification failed.
    pub corrupted_inodes: Vec<u64>,
    /// Evidence for an incomplete tail, when crash interrupted log append.
    pub incomplete_tail: Option<OrphanLogIncompleteTail>,
    /// Durable replay watermark recovered from the log header.
    pub watermark: OrphanReplayWatermark,
}

impl OrphanLogRecoveryReport {
    /// Construct an empty report for a log with the given header state.
    #[must_use]
    pub fn new(expected_entries: usize, watermark: OrphanReplayWatermark) -> Self {
        Self {
            expected_entries,
            replayed_entries: 0,
            corrupted_inodes: Vec::new(),
            incomplete_tail: None,
            watermark,
        }
    }

    /// Build a clean report.
    #[must_use]
    pub fn clean(
        expected_entries: usize,
        replayed_entries: usize,
        watermark: OrphanReplayWatermark,
    ) -> Self {
        Self {
            expected_entries,
            replayed_entries,
            corrupted_inodes: Vec::new(),
            incomplete_tail: None,
            watermark,
        }
    }

    /// Return the operator-facing recovery classification.
    #[must_use]
    pub fn class(&self) -> OrphanLogRecoveryClass {
        match (
            self.corrupted_inodes.is_empty(),
            self.incomplete_tail.is_none(),
        ) {
            (true, true) => OrphanLogRecoveryClass::Clean,
            (false, true) => OrphanLogRecoveryClass::CorruptOrphanLog,
            (true, false) => OrphanLogRecoveryClass::IncompleteReplay,
            (false, false) => OrphanLogRecoveryClass::CorruptAndIncomplete,
        }
    }

    /// Returns true when checksum failures were observed.
    #[must_use]
    pub fn has_corrupt_log(&self) -> bool {
        !self.corrupted_inodes.is_empty()
    }

    /// Returns true when the header-declared log could not be fully replayed.
    #[must_use]
    pub const fn has_incomplete_replay(&self) -> bool {
        self.incomplete_tail.is_some()
    }

    /// Returns true when the log replay has no operator-visible anomalies.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.class() == OrphanLogRecoveryClass::Clean
    }
}

impl fmt::Display for OrphanLogRecoveryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orphan log recovery: class={} replayed={}/{} corrupted={} watermark={}",
            self.class(),
            self.replayed_entries,
            self.expected_entries,
            self.corrupted_inodes.len(),
            self.watermark
        )?;
        if let Some(tail) = self.incomplete_tail {
            write!(f, " incomplete_tail=[{tail}]")?;
        }
        Ok(())
    }
}

// OrphanRecoveryStats — per-batch recovery statistics
// ---------------------------------------------------------------------------

/// Per-batch statistics returned by the orphan recovery processor after
/// each budgeted tick (design spec §5.2).
///
/// These counters are reset per-tick and aggregated into higher-level
/// observability metrics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrphanRecoveryStats {
    /// Total orphan index entries examined this tick.
    pub scanned: usize,

    /// Inodes successfully reclaimed (extents freed, inode destroyed).
    pub reclaimed: usize,

    /// Entries whose inode_id was not found in the inode table or whose
    /// nlink was no longer 0 (stale entries).  These are removed from
    /// the index without freeing extents.
    pub stale: usize,

    /// Entries where extents were already freed (idempotent re-processing
    /// after a crash that committed extent reclamation but not cursor
    /// advancement).
    pub already_freed: usize,

    /// Number of commit_group commits issued during this tick (one commit per
    /// batch, potentially zero if no entries were processed).
    pub commits: usize,

    /// Integrity violations detected (inode table corruption, refcount
    /// inconsistencies, etc.).
    pub integrity_errors: usize,
}

impl OrphanRecoveryStats {
    /// Zero-valued stats — starting state for a new tick.
    pub const ZERO: Self = OrphanRecoveryStats {
        scanned: 0,
        reclaimed: 0,
        stale: 0,
        already_freed: 0,
        commits: 0,
        integrity_errors: 0,
    };

    /// Returns `true` if no work was done this tick.
    #[must_use]
    pub fn is_idle(self) -> bool {
        self.scanned == 0
    }

    /// Total number of "useful" actions (reclaimed + stale + already_freed,
    /// excluding integrity_errors which are error conditions).
    #[must_use]
    pub const fn useful_actions(self) -> usize {
        self.reclaimed + self.stale + self.already_freed
    }

    /// Fraction of scanned entries that resulted in a reclaim (0.0–1.0)
    /// as a fixed-point value multiplied by 1_000_000.
    #[must_use]
    pub const fn reclaim_rate_ppm(self) -> u64 {
        if self.scanned == 0 {
            return 0;
        }
        (self.reclaimed as u64 * 1_000_000) / self.scanned as u64
    }

    /// Accumulate another stats snapshot into this one.
    pub fn accumulate(&mut self, other: OrphanRecoveryStats) {
        self.scanned += other.scanned;
        self.reclaimed += other.reclaimed;
        self.stale += other.stale;
        self.already_freed += other.already_freed;
        self.commits += other.commits;
        self.integrity_errors += other.integrity_errors;
    }
}

impl core::ops::Add for OrphanRecoveryStats {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out.accumulate(rhs);
        out
    }
}

impl core::ops::AddAssign for OrphanRecoveryStats {
    fn add_assign(&mut self, rhs: Self) {
        self.accumulate(rhs);
    }
}

impl fmt::Display for OrphanRecoveryStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scanned={} reclaimed={} stale={} already_freed={} commits={} errors={}",
            self.scanned,
            self.reclaimed,
            self.stale,
            self.already_freed,
            self.commits,
            self.integrity_errors
        )
    }
}

// ---------------------------------------------------------------------------
// OrphanIntegrityError — error types for orphan recovery
// ---------------------------------------------------------------------------

/// Errors detected during orphan recovery batch processing.
///
/// When any of these errors are surfaced, the offending entry is *left*
/// in the index (not deleted), the error is logged, and an integrity
/// alert is raised via the online verifier.  Recovery continues with
/// subsequent entries — errors are non-fatal to the overall tick unless
/// marked otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanIntegrityError {
    /// The inode referenced by the orphan key was not found in the
    /// inode table.  This indicates either index corruption or a bug
    /// in the inode table management.
    InodeNotFound {
        /// The orphan key whose inode could not be located.
        inode_id: u64,
    },

    /// The inode exists but its nlink is not 0, meaning this entry
    /// should have been removed when nlink became non-zero.
    /// This indicates a transactional consistency bug.
    StaleNlink {
        /// The inode ID of the stale entry.
        inode_id: u64,
        /// Expected nlink (0 for an orphan).
        expected_nlink: u32,
        /// Actual nlink found in the inode record.
        actual_nlink: u32,
    },

    /// The inode's extents are already freed (refcounts are 0) despite
    /// the orphan entry still existing.  This is a stale entry after
    /// a crash that committed extent reclamation but not cursor advancement
    /// — it is recoverable and the entry should be removed.
    ExtentAlreadyFreed {
        /// The inode ID whose extents are already gone.
        inode_id: u64,
    },

    /// Recovery was interrupted mid-batch (commit_group commit failure, I/O error,
    /// or administrative signal).  The cursor position marks where to
    /// resume.
    RecoveryInterrupted {
        /// The cursor position at time of interruption.
        cursor_position: u64,
    },

    /// Refcount integrity violation: applying the extent reclamation
    /// would cause a refcount underflow.  This indicates a refcount
    /// accounting bug — the same extent was freed twice or a clone
    /// reference was never recorded.
    RefcountUnderflow {
        /// The inode whose extent reclamation caused the underflow.
        inode_id: u64,
        /// The extent key that would have underflowed.
        extent_key: [u8; 32],
        /// Current refcount before the delta was applied.
        current_refcount: u64,
        /// The delta that would have caused the underflow.
        delta: i64,
    },
}

impl OrphanIntegrityError {
    /// Human-readable error category for metrics / alert routing.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            OrphanIntegrityError::InodeNotFound { .. } => "inode_not_found",
            OrphanIntegrityError::StaleNlink { .. } => "stale_nlink",
            OrphanIntegrityError::ExtentAlreadyFreed { .. } => "extent_already_freed",
            OrphanIntegrityError::RecoveryInterrupted { .. } => "recovery_interrupted",
            OrphanIntegrityError::RefcountUnderflow { .. } => "refcount_underflow",
        }
    }

    /// Returns `true` if this error is fatal (recovery should stop).
    ///
    /// `RefcountUnderflow` and `InodeNotFound` are fatal because
    /// continuing could propagate corrupted state.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            OrphanIntegrityError::RefcountUnderflow { .. }
                | OrphanIntegrityError::InodeNotFound { .. }
        )
    }

    /// Returns `true` if this error is recoverable (processing can
    /// skip the entry and continue).
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        !self.is_fatal()
    }

    /// The inode ID involved in this error, for diagnostic correlation.
    #[must_use]
    pub const fn inode_id(self) -> Option<u64> {
        match self {
            OrphanIntegrityError::InodeNotFound { inode_id }
            | OrphanIntegrityError::StaleNlink { inode_id, .. }
            | OrphanIntegrityError::ExtentAlreadyFreed { inode_id }
            | OrphanIntegrityError::RefcountUnderflow { inode_id, .. } => Some(inode_id),
            OrphanIntegrityError::RecoveryInterrupted { .. } => None,
        }
    }
}

impl fmt::Display for OrphanIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InodeNotFound { inode_id } => {
                write!(f, "inode not found in inode table: inode_id={inode_id}")
            }
            Self::StaleNlink {
                inode_id,
                expected_nlink,
                actual_nlink,
            } => write!(
                f,
                "stale nlink: inode_id={inode_id} expected={expected_nlink} actual={actual_nlink}"
            ),
            Self::ExtentAlreadyFreed { inode_id } => {
                write!(f, "extents already freed: inode_id={inode_id}")
            }
            Self::RecoveryInterrupted { cursor_position } => {
                write!(f, "recovery interrupted at cursor_position={cursor_position}")
            }
            Self::RefcountUnderflow {
                inode_id,
                current_refcount,
                delta,
                ..
            } => write!(
                f,
                "refcount underflow: inode_id={inode_id} current_refcount={current_refcount} delta={delta:+}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// OrphanRecoveryBudget — configuration for per-tick processing limits
// ---------------------------------------------------------------------------

/// Per-dataset orphan recovery processing budget (design spec §5.2).
///
/// Controls how many orphan index entries the recovery processor consumes
/// per tick, bounding mount-time stalls and providing predictable latency.
///
/// ## Design spec reference
///
/// §5.2 guarantee 1: bounded memory — at most `N` inode records loaded
/// simultaneously; batch size configurable (default 1024).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanRecoveryBudget {
    /// Maximum number of orphan entries to process per tick.
    pub max_orphans_per_tick: usize,

    /// Maximum entries to pull in a single batch (commit granularity).
    pub max_batch_size: usize,

    /// Maximum bytes of extent data to free per tick.
    /// Set to 0 for no byte-based limit.
    pub max_bytes_per_tick: u64,

    /// Maximum wall-clock time per tick in milliseconds.
    /// Set to 0 for no time-based limit.
    pub max_ms_per_tick: u64,

    /// Orphan count threshold for fast-track processing.
    /// When the index exceeds this size, the next tick fires immediately
    /// with an increased budget (avoiding unbounded mount delay).
    pub pressure_threshold: usize,

    /// Multiplier applied to `max_orphans_per_tick` during pressure-driven
    /// ticks.  E.g. 2 means double the budget.
    pub pressure_budget_multiplier: u8,
}

impl Default for OrphanRecoveryBudget {
    fn default() -> Self {
        Self {
            max_orphans_per_tick: 1024,
            max_batch_size: 256,
            max_bytes_per_tick: 64 * 1024 * 1024, // 64 MiB
            max_ms_per_tick: 100,
            pressure_threshold: 5000,
            pressure_budget_multiplier: 4,
        }
    }
}

impl OrphanRecoveryBudget {
    /// Returns the effective budget during normal (non-pressure) operation.
    #[must_use]
    pub const fn normal_budget(self) -> usize {
        self.max_orphans_per_tick
    }

    /// Returns the effective budget during pressure-driven operation.
    #[must_use]
    pub const fn pressure_budget(self) -> usize {
        self.max_orphans_per_tick * self.pressure_budget_multiplier as usize
    }

    /// Returns `true` if an index with `orphan_count` entries should
    /// trigger pressure-driven processing.
    #[must_use]
    pub const fn is_pressure_active(self, orphan_count: usize) -> bool {
        orphan_count >= self.pressure_threshold
    }

    /// Returns `true` if byte-based limiting is enabled.
    #[must_use]
    pub const fn has_byte_limit(self) -> bool {
        self.max_bytes_per_tick > 0
    }

    /// Returns `true` if time-based limiting is enabled.
    #[must_use]
    pub const fn has_time_limit(self) -> bool {
        self.max_ms_per_tick > 0
    }
}

// ---------------------------------------------------------------------------
// OrphanRecoveryOutcome — result of one recovery batch
// ---------------------------------------------------------------------------

/// Outcome of a single bounded-batch recovery pass.
///
/// Returned by `recover_orphans()` (Phase 2+ implementation).  The
/// structure is defined here because the stats and cursor types are
/// needed by callers for progress reporting and observability.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrphanRecoveryOutcome {
    /// Statistics for this batch.
    pub stats: OrphanRecoveryStats,

    /// Cursor position after this batch completed (or where to resume
    /// on next tick).
    pub cursor: OrphanCursor,

    /// `true` if the entire orphan index has been processed.
    pub exhausted: bool,

    /// Inode IDs collected in this batch for reclamation.
    pub inode_ids: Vec<u64>,
}

impl OrphanRecoveryOutcome {
    /// Create a new outcome from stats, cursor, and inode IDs.
    #[must_use]
    pub fn new(
        stats: OrphanRecoveryStats,
        cursor: OrphanCursor,
        exhausted: bool,
        inode_ids: Vec<u64>,
    ) -> Self {
        Self {
            stats,
            cursor,
            exhausted,
            inode_ids,
        }
    }

    /// Returns `true` if this batch processed any entries.
    #[must_use]
    pub fn made_progress(self) -> bool {
        !self.stats.is_idle()
    }

    /// Returns `true` if this batch was completely idle (no entries
    /// processed, no errors).
    #[must_use]
    pub fn is_idle(self) -> bool {
        self.stats.is_idle()
    }
}

impl fmt::Display for OrphanRecoveryOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OrphanRecoveryOutcome(stats=[{}] cursor={} exhausted={} ids={:?})",
            self.stats, self.cursor, self.exhausted, self.inode_ids
        )
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// OrphanIndexRoot — newtype wrapper for the orphan index B-tree root pointer
// ---------------------------------------------------------------------------

/// Newtype wrapper around the orphan index's numeric root lane.
///
/// The orphan index is a B+tree keyed by [`OrphanKey`] with zero-byte values.
/// This newtype distinguishes the orphan index root from other B-tree roots
/// (feature flags, cleanup work queues, etc.) at the type level.
///
/// ## Design spec reference
///
/// §3.1: orphan index stored as a per-dataset B+tree; root pointer stored
/// in dataset metadata record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct OrphanIndexRoot(pub u64);

impl OrphanIndexRoot {
    /// Sentinel value for an empty (uninitialized) orphan index.
    pub const EMPTY: Self = OrphanIndexRoot(0);

    /// Returns `true` if this root pointer is the empty sentinel.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this root pointer is set (non-empty).
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for OrphanIndexRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "empty")
        } else {
            write!(f, "root:{}", self.0)
        }
    }
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ── OrphanKey ─────────────────────────────────────────────────────

    #[test]
    fn orphan_key_from_inode_id() {
        let key = OrphanKey::from_inode_id(42);
        assert_eq!(key.to_inode_id(), 42);

        // Big-endian encoding: byte[7] = LSB
        assert_eq!(key.0[7], 42);
        assert_eq!(key.0[0], 0);
        assert_eq!(key.0[1], 0);
        assert_eq!(key.0[2], 0);
        assert_eq!(key.0[3], 0);
        assert_eq!(key.0[4], 0);
        assert_eq!(key.0[5], 0);
        assert_eq!(key.0[6], 0);
    }

    #[test]
    fn orphan_key_none_sentinel() {
        assert_eq!(OrphanKey::NONE, OrphanKey([0u8; 8]));
        assert!(OrphanKey::NONE.is_none());
        assert!(!OrphanKey::NONE.is_some());
        assert_eq!(OrphanKey::NONE.to_inode_id(), 0);
    }

    #[test]
    fn orphan_key_some() {
        let key = OrphanKey::from_inode_id(1);
        assert!(key.is_some());
        assert!(!key.is_none());
    }

    #[test]
    fn orphan_key_ordering() {
        let a = OrphanKey::from_inode_id(10);
        let b = OrphanKey::from_inode_id(20);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, OrphanKey::from_inode_id(10));
    }

    #[test]
    fn orphan_key_display() {
        let key = OrphanKey::from_inode_id(12345);
        assert_eq!(format!("{key}"), "inode:12345");
    }

    #[test]
    fn orphan_key_next() {
        let key = OrphanKey::from_inode_id(42);
        let next = key.next();
        assert_eq!(next.to_inode_id(), 43);
    }

    #[test]
    fn orphan_key_next_saturate() {
        let key = OrphanKey::from_inode_id(u64::MAX);
        let next = key.next();
        assert_eq!(next.to_inode_id(), u64::MAX);
    }

    #[test]
    fn orphan_key_prev() {
        let key = OrphanKey::from_inode_id(42);
        let prev = key.prev();
        assert_eq!(prev.to_inode_id(), 41);
    }

    #[test]
    fn orphan_key_prev_saturate() {
        let key = OrphanKey::from_inode_id(0);
        let prev = key.prev();
        assert_eq!(prev.to_inode_id(), 0);
    }

    #[test]
    fn orphan_key_from_u64() {
        let key: OrphanKey = 100u64.into();
        assert_eq!(key.to_inode_id(), 100);
    }

    #[test]
    fn u64_from_orphan_key() {
        let key = OrphanKey::from_inode_id(200);
        let id: u64 = key.into();
        assert_eq!(id, 200);
    }

    #[test]
    fn orphan_key_default_is_none() {
        assert_eq!(OrphanKey::default(), OrphanKey::NONE);
    }

    #[test]
    fn orphan_key_big_endian_ordering_matches_integer() {
        // 0x00000000000000FF < 0x0000000000000100 in big-endian
        let small = OrphanKey::from_inode_id(255);
        let large = OrphanKey::from_inode_id(256);
        assert!(small < large);
    }

    #[test]
    fn orphan_key_is_none_only_zero() {
        for i in 0..8 {
            let mut bytes = [0u8; 8];
            bytes[i] = 1;
            let key = OrphanKey(bytes);
            assert!(!key.is_none(), "byte {i} set should not be NONE");
        }
    }

    // ── OrphanCursor ──────────────────────────────────────────────────

    #[test]
    fn orphan_cursor_start() {
        let c = OrphanCursor::START;
        assert!(c.is_at_start());
        assert!(!c.is_exhausted());
        assert_eq!(c.next_inode(), 1);
    }

    #[test]
    fn orphan_cursor_default_is_start() {
        assert_eq!(OrphanCursor::default(), OrphanCursor::START);
    }

    #[test]
    fn orphan_cursor_advance_past() {
        let c = OrphanCursor::START;
        let c = c.advance_past(42);
        assert_eq!(c.position, 42);
        assert_eq!(c.next_inode(), 43);
    }

    #[test]
    fn orphan_cursor_advance_past_no_backwards() {
        let c = OrphanCursor { position: 100 };
        let c = c.advance_past(50);
        assert_eq!(c.position, 100); // unchanged
    }

    #[test]
    fn orphan_cursor_advance_past_equal() {
        let c = OrphanCursor { position: 100 };
        let c = c.advance_past(100);
        assert_eq!(c.position, 100); // no change for equal
    }

    #[test]
    fn orphan_cursor_is_exhausted() {
        let c = OrphanCursor { position: u64::MAX };
        assert!(c.is_exhausted());
        assert!(!c.is_at_start());
        assert_eq!(c.next_inode(), u64::MAX); // saturates
    }

    #[test]
    fn orphan_cursor_next_key() {
        let c = OrphanCursor { position: 5 };
        let key = c.next_key();
        assert_eq!(key.to_inode_id(), 6);
    }

    #[test]
    fn orphan_cursor_next_key_at_max() {
        let c = OrphanCursor { position: u64::MAX };
        let key = c.next_key();
        assert_eq!(key.to_inode_id(), u64::MAX); // saturates
    }

    #[test]
    fn orphan_cursor_display() {
        assert_eq!(format!("{}", OrphanCursor::START), "start");
        assert_eq!(format!("{}", OrphanCursor { position: 42 }), "inode:42");
        assert_eq!(
            format!("{}", OrphanCursor { position: u64::MAX }),
            "exhausted"
        );
    }

    // ── OrphanRecoveryStats ──────────────────────────────────────────

    #[test]
    fn orphan_recovery_stats_zero() {
        let s = OrphanRecoveryStats::ZERO;
        assert!(s.is_idle());
        assert_eq!(s.useful_actions(), 0);
        assert_eq!(s.reclaim_rate_ppm(), 0);
    }

    #[test]
    fn orphan_recovery_stats_not_idle() {
        let s = OrphanRecoveryStats {
            scanned: 10,
            reclaimed: 5,
            stale: 2,
            already_freed: 1,
            commits: 1,
            integrity_errors: 2,
        };
        assert!(!s.is_idle());
        assert_eq!(s.useful_actions(), 8);
    }

    #[test]
    fn orphan_recovery_stats_reclaim_rate() {
        let s = OrphanRecoveryStats {
            scanned: 100,
            reclaimed: 25,
            ..OrphanRecoveryStats::ZERO
        };
        assert_eq!(s.reclaim_rate_ppm(), 250_000);
    }

    #[test]
    fn orphan_recovery_stats_reclaim_rate_zero_denom() {
        assert_eq!(OrphanRecoveryStats::ZERO.reclaim_rate_ppm(), 0);
    }

    #[test]
    fn orphan_recovery_stats_accumulate() {
        let mut s = OrphanRecoveryStats {
            scanned: 10,
            reclaimed: 3,
            stale: 2,
            already_freed: 1,
            commits: 1,
            integrity_errors: 0,
        };
        s.accumulate(OrphanRecoveryStats {
            scanned: 5,
            reclaimed: 2,
            stale: 1,
            already_freed: 0,
            commits: 1,
            integrity_errors: 1,
        });
        assert_eq!(s.scanned, 15);
        assert_eq!(s.reclaimed, 5);
        assert_eq!(s.stale, 3);
        assert_eq!(s.already_freed, 1);
        assert_eq!(s.commits, 2);
        assert_eq!(s.integrity_errors, 1);
    }

    #[test]
    fn orphan_recovery_stats_add_operator() {
        let s1 = OrphanRecoveryStats {
            scanned: 5,
            reclaimed: 2,
            ..OrphanRecoveryStats::ZERO
        };
        let s2 = OrphanRecoveryStats {
            scanned: 3,
            reclaimed: 1,
            stale: 1,
            ..OrphanRecoveryStats::ZERO
        };
        let s3 = s1 + s2;
        assert_eq!(s3.scanned, 8);
        assert_eq!(s3.reclaimed, 3);
    }

    #[test]
    fn orphan_recovery_stats_add_assign() {
        let mut s = OrphanRecoveryStats {
            scanned: 1,
            ..OrphanRecoveryStats::ZERO
        };
        s += OrphanRecoveryStats {
            scanned: 2,
            ..OrphanRecoveryStats::ZERO
        };
        assert_eq!(s.scanned, 3);
    }

    #[test]
    fn orphan_recovery_stats_display() {
        let s = OrphanRecoveryStats {
            scanned: 100,
            reclaimed: 30,
            stale: 40,
            already_freed: 5,
            commits: 2,
            integrity_errors: 0,
        };
        let disp = format!("{s}");
        assert!(disp.contains("scanned=100"));
        assert!(disp.contains("reclaimed=30"));
        assert!(disp.contains("stale=40"));
        assert!(disp.contains("already_freed=5"));
    }

    #[test]
    fn orphan_recovery_stats_full_reclaim_rate() {
        let s = OrphanRecoveryStats {
            scanned: 100,
            reclaimed: 100,
            ..OrphanRecoveryStats::ZERO
        };
        assert_eq!(s.reclaim_rate_ppm(), 1_000_000);
    }

    // ── OrphanIntegrityError ──────────────────────────────────────────

    #[test]
    fn integrity_error_inode_not_found_is_fatal() {
        let err = OrphanIntegrityError::InodeNotFound { inode_id: 42 };
        assert!(err.is_fatal());
        assert!(!err.is_recoverable());
        assert_eq!(err.category(), "inode_not_found");
        assert_eq!(err.inode_id(), Some(42));
    }

    #[test]
    fn integrity_error_refcount_underflow_is_fatal() {
        let err = OrphanIntegrityError::RefcountUnderflow {
            inode_id: 7,
            extent_key: [0u8; 32],
            current_refcount: 0,
            delta: -1,
        };
        assert!(err.is_fatal());
        assert_eq!(err.category(), "refcount_underflow");
        assert_eq!(err.inode_id(), Some(7));
    }

    #[test]
    fn integrity_error_stale_nlink_is_recoverable() {
        let err = OrphanIntegrityError::StaleNlink {
            inode_id: 10,
            expected_nlink: 0,
            actual_nlink: 1,
        };
        assert!(!err.is_fatal());
        assert!(err.is_recoverable());
        assert_eq!(err.category(), "stale_nlink");
    }

    #[test]
    fn integrity_error_extent_already_freed_is_recoverable() {
        let err = OrphanIntegrityError::ExtentAlreadyFreed { inode_id: 5 };
        assert!(!err.is_fatal());
        assert!(err.is_recoverable());
        assert_eq!(err.category(), "extent_already_freed");
    }

    #[test]
    fn integrity_error_recovery_interrupted_is_recoverable() {
        let err = OrphanIntegrityError::RecoveryInterrupted {
            cursor_position: 100,
        };
        assert!(!err.is_fatal());
        assert!(err.is_recoverable());
        assert_eq!(err.category(), "recovery_interrupted");
        assert_eq!(err.inode_id(), None);
    }

    #[test]
    fn integrity_error_display_inode_not_found() {
        let err = OrphanIntegrityError::InodeNotFound { inode_id: 42 };
        let s = format!("{err}");
        assert!(s.contains("inode not found"));
        assert!(s.contains("42"));
    }

    #[test]
    fn integrity_error_display_stale_nlink() {
        let err = OrphanIntegrityError::StaleNlink {
            inode_id: 10,
            expected_nlink: 0,
            actual_nlink: 1,
        };
        let s = format!("{err}");
        assert!(s.contains("stale nlink"));
        assert!(s.contains("expected=0"));
        assert!(s.contains("actual=1"));
    }

    #[test]
    fn integrity_error_display_extent_already_freed() {
        let err = OrphanIntegrityError::ExtentAlreadyFreed { inode_id: 5 };
        let s = format!("{err}");
        assert!(s.contains("extents already freed"));
    }

    #[test]
    fn integrity_error_display_recovery_interrupted() {
        let err = OrphanIntegrityError::RecoveryInterrupted {
            cursor_position: 100,
        };
        let s = format!("{err}");
        assert!(s.contains("recovery interrupted"));
        assert!(s.contains("100"));
    }

    #[test]
    fn integrity_error_display_refcount_underflow() {
        let err = OrphanIntegrityError::RefcountUnderflow {
            inode_id: 7,
            extent_key: [0u8; 32],
            current_refcount: 0,
            delta: -1,
        };
        let s = format!("{err}");
        assert!(s.contains("refcount underflow"));
        assert!(s.contains("current_refcount=0"));
        assert!(s.contains("-1"));
    }

    // ── OrphanRecoveryBudget ──────────────────────────────────────────

    #[test]
    fn orphan_recovery_budget_default() {
        let b = OrphanRecoveryBudget::default();
        assert_eq!(b.max_orphans_per_tick, 1024);
        assert_eq!(b.max_batch_size, 256);
        assert_eq!(b.max_bytes_per_tick, 64 * 1024 * 1024);
        assert_eq!(b.max_ms_per_tick, 100);
        assert_eq!(b.pressure_threshold, 5000);
        assert_eq!(b.pressure_budget_multiplier, 4);
    }

    #[test]
    fn orphan_recovery_budget_pressure_active() {
        let b = OrphanRecoveryBudget::default();
        assert!(!b.is_pressure_active(4999));
        assert!(b.is_pressure_active(5000));
        assert!(b.is_pressure_active(10000));
    }

    #[test]
    fn orphan_recovery_budget_pressure_budget() {
        let b = OrphanRecoveryBudget::default();
        assert_eq!(b.normal_budget(), 1024);
        assert_eq!(b.pressure_budget(), 4096);
    }

    #[test]
    fn orphan_recovery_budget_custom_multiplier() {
        let b = OrphanRecoveryBudget {
            pressure_budget_multiplier: 8,
            ..Default::default()
        };
        assert_eq!(b.pressure_budget(), 8192);
    }

    #[test]
    fn orphan_recovery_budget_has_byte_limit() {
        let b = OrphanRecoveryBudget::default();
        assert!(b.has_byte_limit());

        let b2 = OrphanRecoveryBudget {
            max_bytes_per_tick: 0,
            ..Default::default()
        };
        assert!(!b2.has_byte_limit());
    }

    #[test]
    fn orphan_recovery_budget_has_time_limit() {
        let b = OrphanRecoveryBudget::default();
        assert!(b.has_time_limit());

        let b2 = OrphanRecoveryBudget {
            max_ms_per_tick: 0,
            ..Default::default()
        };
        assert!(!b2.has_time_limit());
    }

    // ── OrphanRecoveryOutcome ─────────────────────────────────────────

    #[test]
    fn orphan_recovery_outcome_new() {
        let outcome = OrphanRecoveryOutcome::new(
            OrphanRecoveryStats {
                scanned: 5,
                reclaimed: 3,
                ..OrphanRecoveryStats::ZERO
            },
            OrphanCursor { position: 10 },
            false,
            Vec::new(),
        );
        let o = outcome.clone();
        assert!(o.made_progress());
        let o = outcome.clone();
        assert!(!o.is_idle());
        assert!(!outcome.exhausted);
    }

    #[test]
    fn orphan_recovery_outcome_default() {
        let outcome = OrphanRecoveryOutcome::default();
        let o = outcome.clone();
        assert!(!o.made_progress());
        let o = outcome.clone();
        assert!(o.is_idle());
        assert!(!outcome.exhausted);
    }

    #[test]
    fn orphan_recovery_outcome_exhausted() {
        let outcome = OrphanRecoveryOutcome::new(
            OrphanRecoveryStats::ZERO,
            OrphanCursor { position: u64::MAX },
            true,
            Vec::new(),
        );
        assert!(outcome.exhausted);
        let o = outcome.clone();
        assert!(o.is_idle());
    }

    #[test]
    fn orphan_recovery_outcome_display() {
        let outcome = OrphanRecoveryOutcome::new(
            OrphanRecoveryStats {
                scanned: 1,
                reclaimed: 1,
                ..OrphanRecoveryStats::ZERO
            },
            OrphanCursor { position: 5 },
            false,
            Vec::new(),
        );
        let s = format!("{outcome}");
        assert!(s.contains("OrphanRecoveryOutcome"));
        assert!(s.contains("scanned=1"));
        assert!(s.contains("exhausted=false"));
        assert!(s.contains("ids=[]"));
    }

    // ── Saturation / edge cases ───────────────────────────────────────

    #[test]
    fn orphan_key_max_u64() {
        let key = OrphanKey::from_inode_id(u64::MAX);
        assert_eq!(key.to_inode_id(), u64::MAX);
        assert!(key.is_some());
        // next() saturates
        assert_eq!(key.next().to_inode_id(), u64::MAX);
        // prev() works
        assert_eq!(key.prev().to_inode_id(), u64::MAX - 1);
    }

    #[test]
    fn orphan_cursor_chain_advance() {
        let c = OrphanCursor::START
            .advance_past(10)
            .advance_past(20)
            .advance_past(15) // backtrack, ignored
            .advance_past(30);
        assert_eq!(c.position, 30);
    }

    #[test]
    fn orphan_recovery_stats_accumulate_zero_is_noop() {
        let mut s = OrphanRecoveryStats {
            scanned: 10,
            reclaimed: 3,
            ..OrphanRecoveryStats::ZERO
        };
        s.accumulate(OrphanRecoveryStats::ZERO);
        assert_eq!(s.scanned, 10);
        assert_eq!(s.reclaimed, 3);
    }

    #[test]
    fn orphan_recovery_outcome_new_made_progress_false_when_idle() {
        let outcome = OrphanRecoveryOutcome::new(
            OrphanRecoveryStats::ZERO,
            OrphanCursor::START,
            false,
            Vec::new(),
        );
        let o = outcome.clone();
        assert!(!o.made_progress());
    }

    // ── OrphanReplayWatermark ─────────────────────────────────────────

    #[test]
    fn orphan_replay_watermark_none() {
        let w = OrphanReplayWatermark::NONE;
        assert!(w.is_none());
        assert_eq!(w.position, 0);
        assert!(!w.covers(1));
        assert!(w.covers(0));
    }

    #[test]
    fn orphan_replay_watermark_from_cursor() {
        let c = OrphanCursor { position: 42 };
        let w = OrphanReplayWatermark::from_cursor(c);
        assert!(!w.is_none());
        assert_eq!(w.position, 42);
        assert!(w.covers(42));
        assert!(w.covers(10));
        assert!(!w.covers(100));
    }

    #[test]
    fn orphan_replay_watermark_default_is_none() {
        assert_eq!(
            OrphanReplayWatermark::default(),
            OrphanReplayWatermark::NONE
        );
    }

    #[test]
    fn orphan_replay_watermark_advance_past() {
        let w = OrphanReplayWatermark { position: 10 };
        let w2 = w.advance_past(5);
        assert_eq!(w2.position, 10); // no backward movement
        let w3 = w.advance_past(20);
        assert_eq!(w3.position, 20);
        let w4 = w.advance_past(10);
        assert_eq!(w4.position, 10); // equal does not advance
    }

    #[test]
    fn orphan_replay_watermark_to_cursor_roundtrip() {
        let c = OrphanCursor { position: 77 };
        let w = OrphanReplayWatermark::from_cursor(c);
        let c2 = w.to_cursor();
        assert_eq!(c, c2);
    }

    #[test]
    fn orphan_replay_watermark_display() {
        assert_eq!(
            format!("{}", OrphanReplayWatermark::NONE),
            "watermark:inode:0"
        );
        assert_eq!(
            format!("{}", OrphanReplayWatermark { position: 100 }),
            "watermark:inode:100"
        );
    }

    #[test]
    fn orphan_log_recovery_report_classifies_clean() {
        let report = OrphanLogRecoveryReport::clean(2, 2, OrphanReplayWatermark { position: 10 });
        assert_eq!(report.class(), OrphanLogRecoveryClass::Clean);
        assert!(report.is_clean());
        assert!(!report.has_corrupt_log());
        assert!(!report.has_incomplete_replay());
    }

    #[test]
    fn orphan_log_recovery_report_classifies_corrupt_log() {
        let mut report = OrphanLogRecoveryReport::new(2, OrphanReplayWatermark::NONE);
        report.replayed_entries = 1;
        report.corrupted_inodes.push(42);
        assert_eq!(report.class(), OrphanLogRecoveryClass::CorruptOrphanLog);
        assert!(report.has_corrupt_log());
        assert!(!report.has_incomplete_replay());
        assert!(format!("{report}").contains("corrupt orphan log"));
    }

    #[test]
    fn orphan_log_recovery_report_classifies_incomplete_replay() {
        let mut report = OrphanLogRecoveryReport::new(3, OrphanReplayWatermark::NONE);
        report.replayed_entries = 1;
        report.incomplete_tail = Some(OrphanLogIncompleteTail::new(1, 12, 56, 3));
        assert_eq!(report.class(), OrphanLogRecoveryClass::IncompleteReplay);
        assert_eq!(report.incomplete_tail.unwrap().missing_entries, 2);
        assert!(report.has_incomplete_replay());
        assert!(format!("{report}").contains("incomplete replay"));
    }

    #[test]
    fn orphan_log_recovery_report_classifies_corrupt_and_incomplete() {
        let mut report = OrphanLogRecoveryReport::new(3, OrphanReplayWatermark::NONE);
        report.corrupted_inodes.push(7);
        report.incomplete_tail = Some(OrphanLogIncompleteTail::new(2, 4, 56, 3));
        assert_eq!(report.class(), OrphanLogRecoveryClass::CorruptAndIncomplete);
        assert!(report.has_corrupt_log());
        assert!(report.has_incomplete_replay());
    }

    #[test]
    fn orphan_replay_watermark_covers_boundary() {
        let w = OrphanReplayWatermark { position: 7 };
        assert!(w.covers(7));
        assert!(w.covers(6));
        assert!(!w.covers(8));
    }

    #[test]
    fn orphan_replay_watermark_none_covers_nothing() {
        let w = OrphanReplayWatermark::NONE;
        // Position 0 covers inode 0 (sentinel, never a real orphan)
        assert!(w.covers(0));
        // But does NOT cover real orphan inodes (1+)
        assert!(!w.covers(1));
        assert!(!w.covers(u64::MAX));
    }

    // ── OrphanIndexRoot ───────────────────────────────────────────────

    #[test]
    fn orphan_index_root_empty() {
        let root = OrphanIndexRoot::EMPTY;
        assert!(root.is_empty());
        assert!(!root.is_present());
        assert_eq!(root.0, 0);
    }

    #[test]
    fn orphan_index_root_default_is_empty() {
        assert_eq!(OrphanIndexRoot::default(), OrphanIndexRoot::EMPTY);
    }

    #[test]
    fn orphan_index_root_present() {
        let root = OrphanIndexRoot(42);
        assert!(!root.is_empty());
        assert!(root.is_present());
        assert_eq!(root.0, 42);
    }

    #[test]
    fn orphan_index_root_display_empty() {
        assert_eq!(format!("{}", OrphanIndexRoot::EMPTY), "empty");
    }

    #[test]
    fn orphan_index_root_display_nonempty() {
        let root = OrphanIndexRoot(12345);
        assert_eq!(format!("{root}"), "root:12345");
    }
}
