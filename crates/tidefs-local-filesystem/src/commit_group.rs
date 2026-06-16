//! Canonical commit ordering and multi-phase commit_group state machine.
//!
//! Implements the seven-step crash-safe write path with OPEN/QUIESCE/SYNC
//! phases, auto-sync trigger hierarchy, back-pressure throttling, and
//! deterministic clock injection for testing.
//!
//! ## Seven-step canonical commit ordering
//!
//! ```text
//! 1. APPEND data records (extent payloads / shards)
//! 2. FLUSH data journal (fsync/fdatasync)
//! 3. APPEND metadata updates (extent maps, inodes, catalogs)
//! 4. APPEND commit record (METADATA_COMMIT_V1 or POOLMAP_COMMIT_V1)
//! 5. FLUSH metadata journal
//! 6. UPDATE checkpoint pointer copies in system area (slice-0)
//! 7. FLUSH system area writes
//! ```
//!
//! ## Invariant
//!
//! A pointer is never persisted before what it points to. Steps 1-2 ensure
//! data is durable before metadata references it. Steps 5-7 ensure the commit
//! record is durable before the checkpoint pointer makes it reachable.
//!
//! ## Durability classes
//!
//! - **MetadataOnly**: mkdir/rename/unlink — steps 3-7 only
//! - **DataAndMetadata**: writes data payloads — steps 1-7
//! - **ForcedDurability**: fsync/O_DSYNC — all 7 steps, immediate

use crate::crash_hooks::check_crash_hook;
use std::time::{Duration, Instant};
use tidefs_commit_group::RootPointer;
use tidefs_local_object_store::txg_manager::CommitGroupManager as StoreCommitGroupManager;
use tidefs_local_object_store::CrashInjectionPoint;

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Metadata roots staged at QUIESCE boundary
// ---------------------------------------------------------------------------

/// Snapshot of metadata roots captured at the quiesce boundary.
///
/// Contains the inode table root, extent-map roots, and directory
/// catalog roots.  These are the application-level roots that the
/// SYNC phase commits through the seven-step pipeline.
#[derive(Debug, Clone)]
pub struct MetadataRoots {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Identifier of the committed root slot for the inode table.
    pub inode_table_root: u64,
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Extent-map root identifiers (one per dataset or namespace).
    pub extent_map_roots: Vec<u64>,
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Directory catalog root identifiers (one per namespace).
    pub directory_catalog_roots: Vec<u64>,
}

impl MetadataRoots {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Create a new metadata roots snapshot with the given inode table root.
    pub fn new(inode_table_root: u64) -> Self {
        MetadataRoots {
            inode_table_root,
            extent_map_roots: Vec::new(),
            directory_catalog_roots: Vec::new(),
        }
    }
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Add an extent-map root identifier.
    pub fn with_extent_map_root(mut self, root: u64) -> Self {
        self.extent_map_roots.push(root);
        self
    }
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Add a directory catalog root identifier.
    pub fn with_directory_catalog_root(mut self, root: u64) -> Self {
        self.directory_catalog_roots.push(root);
        self
    }
}

// Core types
// ---------------------------------------------------------------------------

/// Monotonically increasing transaction group identifier.
///
/// Every committed commit_group receives a unique, strictly-increasing id.
/// The id doubles as the generation counter for root commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxnGroupId(pub u64);

impl TxnGroupId {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub const ZERO: Self = TxnGroupId(0);

    pub fn next(self) -> Self {
        TxnGroupId(self.0 + 1)
    }
}

/// Phases of the commit_group state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGroupPhase {
    /// Accept new writes into the current commit_group.
    /// Accumulate dirty bytes and track dirty inodes/extent maps.
    Open,
    /// Stop accepting new writes into this commit_group.
    /// New writes go to next commit_group (still Open).
    /// Wait for in-flight writes to complete.
    Quiesce,
    /// Execute the 7-step commit ordering.
    /// Publish the commit record and update the checkpoint pointer.
    /// Dirty buffers become clean.
    Sync,
}

/// Canonical steps in the 7-step commit ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGroupCommitStep {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Step 1: Append data records (extent payloads / shards) to journal.
    AppendDataRecords,
    /// Step 2: Flush data journal (fsync/fdatasync).
    FlushDataJournal,
    /// Step 3: Append metadata updates (extent maps, inodes, catalogs).
    AppendMetadataUpdates,
    /// Step 4: Append commit record (METADATA_COMMIT_V1).
    AppendCommitRecord,
    /// Step 5: Flush metadata journal.
    FlushMetadataJournal,
    /// Step 6: Update checkpoint pointer copies in system area (slice-0).
    UpdateCheckpointPointer,
    /// Step 7: Flush system area writes.
    FlushSystemArea,
}

impl CommitGroupCommitStep {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// All commit steps in canonical order.
    pub const ALL: [CommitGroupCommitStep; 7] = [
        CommitGroupCommitStep::AppendDataRecords,
        CommitGroupCommitStep::FlushDataJournal,
        CommitGroupCommitStep::AppendMetadataUpdates,
        CommitGroupCommitStep::AppendCommitRecord,
        CommitGroupCommitStep::FlushMetadataJournal,
        CommitGroupCommitStep::UpdateCheckpointPointer,
        CommitGroupCommitStep::FlushSystemArea,
    ];
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Steps for metadata-only commits (no data drawn).
    pub const METADATA_ONLY: [CommitGroupCommitStep; 5] = [
        CommitGroupCommitStep::AppendMetadataUpdates,
        CommitGroupCommitStep::AppendCommitRecord,
        CommitGroupCommitStep::FlushMetadataJournal,
        CommitGroupCommitStep::UpdateCheckpointPointer,
        CommitGroupCommitStep::FlushSystemArea,
    ];
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Human-readable label for this step.
    pub fn label(self) -> &'static str {
        match self {
            CommitGroupCommitStep::AppendDataRecords => "APPEND data records",
            CommitGroupCommitStep::FlushDataJournal => "FLUSH data journal",
            CommitGroupCommitStep::AppendMetadataUpdates => "APPEND metadata updates",
            CommitGroupCommitStep::AppendCommitRecord => "APPEND commit record",
            CommitGroupCommitStep::FlushMetadataJournal => "FLUSH metadata journal",
            CommitGroupCommitStep::UpdateCheckpointPointer => "UPDATE checkpoint pointer",
            CommitGroupCommitStep::FlushSystemArea => "FLUSH system area",
        }
    }
}

/// Durability class determining which commit steps are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityClass {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// No data pages dirty: steps 3-7 only.
    MetadataOnly,
    /// Data pages dirty: all 7 steps.
    DataAndMetadata,
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Forced durability (fsync/O_DSYNC): all 7 steps, immediate flush.
    ForcedDurability,
}

/// Auto-sync trigger that caused the current quiesce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGroupTrigger {
    /// Op-count threshold reached.
    OpCount,
    /// Time threshold reached.
    TimeTarget,
    /// Soft byte threshold reached.
    ByteTarget,
    /// Hard byte threshold (back-pressure).
    ByteMaximum,
    /// Explicit fsync or sync operation triggered.
    ExplicitSync,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for auto-sync trigger evaluation.
#[derive(Debug, Clone)]
pub struct CommitGroupConfig {
    /// Operation count threshold: trigger sync when dirty ops exceed this.
    pub commit_group_target_ops: u64,
    /// Soft byte threshold: trigger sync when dirty bytes exceed this.
    pub commit_group_target_bytes: u64,
    /// Hard byte threshold: throttle writers when dirty bytes exceed this.
    pub commit_group_dirty_max_bytes: u64,
    /// Maximum time in OPEN + QUIESCE before forcing sync (seconds).
    pub commit_group_target_secs: f64,
    /// Maximum time to wait for inflight writes during QUIESCE (seconds).
    pub commit_group_quiesce_timeout_secs: f64,
}

impl Default for CommitGroupConfig {
    fn default() -> Self {
        CommitGroupConfig {
            commit_group_target_ops: 2048,
            commit_group_target_bytes: 64 * 1024 * 1024, // 64 MiB
            commit_group_dirty_max_bytes: 512 * 1024 * 1024, // 512 MiB
            commit_group_target_secs: 5.0,
            commit_group_quiesce_timeout_secs: 1.0,
        }
    }
}

impl CommitGroupConfig {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Conservative config for correctness testing.
    pub fn conservative() -> Self {
        CommitGroupConfig {
            commit_group_target_ops: 16,
            commit_group_target_bytes: 64 * 1024,     // 64 KiB
            commit_group_dirty_max_bytes: 256 * 1024, // 256 KiB
            commit_group_target_secs: 1.0,
            commit_group_quiesce_timeout_secs: 0.5,
        }
    }
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// High-throughput config for bulk workloads.
    pub fn throughput() -> Self {
        CommitGroupConfig {
            commit_group_target_ops: 64 * 1024,
            commit_group_target_bytes: 256 * 1024 * 1024, // 256 MiB
            commit_group_dirty_max_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            commit_group_target_secs: 300.0,
            commit_group_quiesce_timeout_secs: 5.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Clock abstraction for deterministic testing
// ---------------------------------------------------------------------------

/// Injectable clock for deterministic testing.
pub trait Clock: Send + Sync + Clone {
    fn now(&self) -> Instant;
}

/// Real system clock.
#[derive(Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Fixed clock for deterministic tests.
#[derive(Debug, Clone)]
pub struct FixedClock {
    pub instant: Instant,
}

impl FixedClock {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn new(instant: Instant) -> Self {
        FixedClock { instant }
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn advance(&mut self, duration: Duration) {
        self.instant += duration;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Instant {
        self.instant
    }
}

// ---------------------------------------------------------------------------
// CommitGroup state machine
// ---------------------------------------------------------------------------

/// The multi-phase commit_group state machine.
///
/// Drives the write-path durability contract: OPEN -> QUIESCE -> SYNC -> OPEN.
pub struct CommitGroupStateMachine<C: Clock = SystemClock> {
    /// Current transaction group id (monotonically increasing).
    pub current_commit_group: TxnGroupId,
    /// Current phase of the state machine.
    pub phase: CommitGroupPhase,
    /// Accumulated dirty bytes in the current (or next) commit_group.
    pub dirty_bytes: u64,
    /// Accumulated dirty operation count in the current (or next) commit_group.
    pub dirty_ops: u64,
    /// Number of in-flight writes during QUIESCE.
    pub inflight_writes: u64,
    /// Instant when the current phase began.
    pub phase_start: Instant,
    /// Instant when the entire commit_group cycle began (Open start).
    pub commit_group_start: Instant,
    /// Configuration for auto-sync triggers.
    pub config: CommitGroupConfig,
    /// Whether back-pressure is currently active.
    pub backpressure_active: bool,
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// What triggered the current quiesce (if in Quiesce or Sync).
    pub trigger: Option<CommitGroupTrigger>,
    /// The commit log of the most recently completed SYNC.
    pub last_commit_log: Option<CommitGroupCommitLog>,
    /// Steps recorded during the current SYNC phase.
    sync_steps: Vec<CommitGroupCommitStep>,
    /// Staged metadata roots captured at QUIESCE boundary.
    pub staged_roots: Option<MetadataRoots>,
    pub(crate) clock: C,
}

/// Record of a completed SYNC phase.
#[derive(Debug, Clone)]
pub struct CommitGroupCommitLog {
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub commit_group: TxnGroupId,
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub trigger: CommitGroupTrigger,
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub dirty_bytes_committed: u64,
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub dirty_ops_committed: u64,
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub duration: Duration,
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub steps_completed: Vec<CommitGroupCommitStep>,
}

impl CommitGroupStateMachine<SystemClock> {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Create a new state machine with the system clock, starting at commit_group 1.
    pub fn new(config: CommitGroupConfig) -> Self {
        Self::with_clock(config, SystemClock)
    }

    /// Create a new state machine with a specific starting commit_group id.
    /// Use when `state.generation` is already beyond the default of 1.
    pub fn with_starting_commit_group(
        config: CommitGroupConfig,
        starting_commit_group: TxnGroupId,
    ) -> Self {
        let now = SystemClock.now();
        CommitGroupStateMachine {
            current_commit_group: starting_commit_group,
            phase: CommitGroupPhase::Open,
            dirty_bytes: 0,
            dirty_ops: 0,
            inflight_writes: 0,
            phase_start: now,
            commit_group_start: now,
            config,
            backpressure_active: false,
            trigger: None,
            last_commit_log: None,
            sync_steps: Vec::new(),
            staged_roots: None,
            clock: SystemClock,
        }
    }
}

impl<C: Clock> CommitGroupStateMachine<C> {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    /// Create a new state machine with an injected clock.
    pub fn with_clock(config: CommitGroupConfig, clock: C) -> Self {
        let now = clock.now();
        CommitGroupStateMachine {
            current_commit_group: TxnGroupId(1),
            phase: CommitGroupPhase::Open,
            dirty_bytes: 0,
            dirty_ops: 0,
            inflight_writes: 0,
            phase_start: now,
            commit_group_start: now,
            config,
            backpressure_active: false,
            trigger: None,
            last_commit_log: None,
            sync_steps: Vec::new(),
            staged_roots: None,
            clock,
        }
    }

    // -- Write admission ----------------------------------------------------

    /// Record a write into the current commit_group. Returns true if the write
    /// was accepted; returns false if back-pressure rejects it.
    pub fn record_write(&mut self, byte_delta: u64) -> bool {
        if self.backpressure_active
            && self.dirty_bytes + byte_delta > self.config.commit_group_dirty_max_bytes
        {
            return false;
        }

        self.dirty_bytes = self.dirty_bytes.saturating_add(byte_delta);
        self.dirty_ops = self.dirty_ops.saturating_add(1);

        // Check if we just crossed the hard byte threshold.
        if self.phase == CommitGroupPhase::Open
            && self.dirty_bytes > self.config.commit_group_dirty_max_bytes
        {
            self.backpressure_active = true;
        }

        true
    }

    /// Signal that a write completed (decrement inflight count).
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn write_completed(&mut self) {
        self.inflight_writes = self.inflight_writes.saturating_sub(1);
    }

    /// Signal that a write started (increment inflight count).
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn write_started(&mut self) {
        self.inflight_writes = self.inflight_writes.saturating_add(1);
    }

    // -- Trigger evaluation ------------------------------------------------

    /// Evaluate all auto-sync triggers. Returns the highest-priority trigger
    /// that fired, or None if no trigger conditions are met.
    pub fn evaluate_triggers(&self) -> Option<CommitGroupTrigger> {
        let elapsed = self.clock.now().duration_since(self.commit_group_start);

        if self.dirty_bytes >= self.config.commit_group_dirty_max_bytes {
            return Some(CommitGroupTrigger::ByteMaximum);
        }
        if self.dirty_ops >= self.config.commit_group_target_ops {
            return Some(CommitGroupTrigger::OpCount);
        }
        if self.dirty_bytes >= self.config.commit_group_target_bytes {
            return Some(CommitGroupTrigger::ByteTarget);
        }
        if elapsed >= Duration::from_secs_f64(self.config.commit_group_target_secs) {
            return Some(CommitGroupTrigger::TimeTarget);
        }

        None
    }

    /// Check if the state machine should quiesce now.
    pub fn should_quiesce(&self) -> bool {
        if self.phase != CommitGroupPhase::Open {
            return false;
        }
        self.evaluate_triggers().is_some()
    }

    /// Whether dirty bytes exceed the hard maximum (back-pressure active).
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn is_over_max_dirty(&self) -> bool {
        self.dirty_bytes > self.config.commit_group_dirty_max_bytes
    }

    /// Whether writers should be throttled.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn should_backpressure(&self) -> bool {
        self.backpressure_active
    }

    /// Whether the quiesce phase has timed out waiting for inflight writes.
    pub fn quiesce_timed_out(&self) -> bool {
        if self.phase != CommitGroupPhase::Quiesce {
            return false;
        }
        let elapsed = self.clock.now().duration_since(self.phase_start);
        elapsed >= Duration::from_secs_f64(self.config.commit_group_quiesce_timeout_secs)
    }

    // -- Phase transitions --------------------------------------------------

    /// Begin the QUIESCE phase. New writes go to the next commit_group.
    pub fn begin_quiesce(&mut self, trigger: CommitGroupTrigger) {
        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeQuiesce);
        assert_eq!(
            self.phase,
            CommitGroupPhase::Open,
            "quiesce must start from Open, not {:?}",
            self.phase
        );

        self.phase = CommitGroupPhase::Quiesce;
        self.phase_start = self.clock.now();
        self.trigger = Some(trigger);
        self.backpressure_active = false;
    }

    /// Begin the SYNC phase. Executes the 7-step commit ordering.
    pub fn begin_sync(&mut self) {
        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeSync);
        assert!(
            self.phase == CommitGroupPhase::Quiesce || self.phase == CommitGroupPhase::Open,
            "sync must start from Quiesce or Open, not {:?}",
            self.phase
        );

        self.phase = CommitGroupPhase::Sync;
        self.phase_start = self.clock.now();
    }

    /// Complete the SYNC phase, advance to the next commit_group, and return to OPEN.
    /// Returns a commit log for diagnostics.
    pub fn complete_sync(&mut self) -> CommitGroupCommitLog {
        assert_eq!(
            self.phase,
            CommitGroupPhase::Sync,
            "complete_sync called in {:?} phase",
            self.phase
        );

        let duration = self.clock.now().duration_since(self.phase_start);
        let log = CommitGroupCommitLog {
            commit_group: self.current_commit_group,
            trigger: self
                .trigger
                .take()
                .unwrap_or(CommitGroupTrigger::ExplicitSync),
            dirty_bytes_committed: self.dirty_bytes,
            dirty_ops_committed: self.dirty_ops,
            duration,
            steps_completed: std::mem::take(&mut self.sync_steps),
        };

        // Advance to next commit_group
        self.current_commit_group = self.current_commit_group.next();
        self.dirty_bytes = 0;
        self.dirty_ops = 0;
        self.inflight_writes = 0;
        self.backpressure_active = false;
        self.staged_roots = None;
        self.phase = CommitGroupPhase::Open;
        self.phase_start = self.clock.now();
        self.commit_group_start = self.clock.now();
        self.last_commit_log = Some(log.clone());

        check_crash_hook(CrashInjectionPoint::CommitGroupAfterFlush);
        log
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn record_step(&mut self, step: CommitGroupCommitStep) {
        self.sync_steps.push(step);
    }

    // -- Durability class selection -----------------------------------------

    /// Determine the durability class for the current commit.
    /// `has_dirty_content` is true if any data pages are dirty.
    /// `forced` is true for fsync/O_DSYNC.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn durability_class(&self, has_dirty_content: bool, forced: bool) -> DurabilityClass {
        if forced {
            DurabilityClass::ForcedDurability
        } else if has_dirty_content {
            DurabilityClass::DataAndMetadata
        } else {
            DurabilityClass::MetadataOnly
        }
    }

    /// Convenience method: auto-detect durability class from current commit_group state.
    /// Uses dirty_bytes to determine if content is dirty and trigger for forced.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn commit_class(&self) -> DurabilityClass {
        self.durability_class(
            self.dirty_bytes > 0,
            self.trigger == Some(CommitGroupTrigger::ExplicitSync),
        )
    }

    /// Get the ordered list of commit steps for a durability class.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn steps_for(&self, class: DurabilityClass) -> &'static [CommitGroupCommitStep] {
        match class {
            DurabilityClass::MetadataOnly => &CommitGroupCommitStep::METADATA_ONLY,
            DurabilityClass::DataAndMetadata | DurabilityClass::ForcedDurability => {
                &CommitGroupCommitStep::ALL
            }
        }
    }

    // -- Accessors ----------------------------------------------------------

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn current_commit_group(&self) -> TxnGroupId {
        self.current_commit_group
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn phase_elapsed(&self) -> Duration {
        self.clock.now().duration_since(self.phase_start)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn commit_group_elapsed(&self) -> Duration {
        self.clock.now().duration_since(self.commit_group_start)
    }
}

impl<C: Clock> std::fmt::Debug for CommitGroupStateMachine<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitGroupStateMachine")
            .field("current_commit_group", &self.current_commit_group)
            .field("phase", &self.phase)
            .field("dirty_bytes", &self.dirty_bytes)
            .field("dirty_ops", &self.dirty_ops)
            .field("inflight_writes", &self.inflight_writes)
            .field("phase_start", &self.phase_start)
            .field("commit_group_start", &self.commit_group_start)
            .field("config", &self.config)
            .field("backpressure_active", &self.backpressure_active)
            .field("trigger", &self.trigger)
            .field("last_commit_log", &self.last_commit_log)
            .field("staged_roots", &self.staged_roots)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors that can occur during commit_group sync.
#[derive(Debug)]
pub enum SyncError {
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    DataFlush(String),
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    MetadataFlush(String),
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    SystemAreaFlush(String),
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    CommitRecord(String),
    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    CheckpointWrite(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataFlush(msg) => write!(f, "data flush failed: {msg}"),
            Self::MetadataFlush(msg) => write!(f, "metadata flush failed: {msg}"),
            Self::SystemAreaFlush(msg) => write!(f, "system area flush failed: {msg}"),
            Self::CommitRecord(msg) => write!(f, "commit record failed: {msg}"),
            Self::CheckpointWrite(msg) => write!(f, "checkpoint write failed: {msg}"),
        }
    }
}

impl std::error::Error for SyncError {}

// ---------------------------------------------------------------------------
// CommitGroupManager -- Integration-level commit_group coordinator
// ---------------------------------------------------------------------------

/// Top-level commit_group manager that coordinates the two-commit_group model
/// (current + next) and integrates with storage subsystems.
///
/// During SYNC phase, write hooks are suspended to avoid mis-attributing
/// commit-record appends and checkpoint-pointer writes to the next commit_group.
#[derive(Debug)]
pub struct CommitGroupManager<C: Clock = SystemClock> {
    pub config: CommitGroupConfig,
    clock: C,
    current: Option<CommitGroupStateMachine<C>>,
    next: Option<CommitGroupStateMachine<C>>,
    pub write_hooks_suspended: bool,
}

impl CommitGroupManager<SystemClock> {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn new(config: CommitGroupConfig) -> Self {
        Self::with_clock(config, SystemClock)
    }
}

impl<C: Clock> CommitGroupManager<C> {
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn with_clock(config: CommitGroupConfig, clock: C) -> Self {
        CommitGroupManager {
            config,
            clock,
            current: None,
            next: None,
            write_hooks_suspended: false,
        }
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn begin_or_get_commit_group(&mut self) -> &mut CommitGroupStateMachine<C> {
        if self.current.is_none() {
            let next_id = if let Some(ref n) = self.next {
                n.current_commit_group
            } else {
                TxnGroupId(1)
            };
            let mut sm =
                CommitGroupStateMachine::with_clock(self.config.clone(), self.clock.clone());
            sm.current_commit_group = next_id;
            self.current = Some(sm);
        }

        let current = self.current.as_ref().unwrap();
        let phase = current.phase;

        if phase == CommitGroupPhase::Quiesce || phase == CommitGroupPhase::Sync {
            if self.next.is_none() {
                let next_id = current.current_commit_group.next();
                let mut sm =
                    CommitGroupStateMachine::with_clock(self.config.clone(), self.clock.clone());
                sm.current_commit_group = next_id;
                self.next = Some(sm);
            }
            self.next.as_mut().unwrap()
        } else {
            self.current.as_mut().unwrap()
        }
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn record_bytes(&mut self, byte_delta: u64) -> bool {
        if self.write_hooks_suspended {
            return true;
        }
        let commit_group = self.begin_or_get_commit_group();
        commit_group.record_write(byte_delta)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn should_backpressure(&self) -> bool {
        self.current
            .as_ref()
            .map(|sm| sm.should_backpressure())
            .unwrap_or(false)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn evaluate_triggers(&self) -> Option<CommitGroupTrigger> {
        self.current.as_ref().and_then(|sm| sm.evaluate_triggers())
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn should_quiesce(&self) -> bool {
        self.current
            .as_ref()
            .map(|sm| sm.should_quiesce())
            .unwrap_or(false)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn auto_sync_if_needed(&mut self) -> Result<bool, SyncError> {
        if !self.should_quiesce() {
            return Ok(false);
        }
        let trigger = self
            .evaluate_triggers()
            .unwrap_or(CommitGroupTrigger::ExplicitSync);
        self.sync_inner(trigger)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn sync(&mut self) -> Result<bool, SyncError> {
        if self.current.is_none() {
            return Ok(false);
        }
        self.sync_inner(CommitGroupTrigger::ExplicitSync)
    }

    #[allow(dead_code)]
    // INTENT: COMMIT_GROUP integration hook; covered by commit_manager_flushes_queued_txg_through_manager
    /// Commit the current transaction group through the CommitGroupManager.
    ///
    /// Runs the full quiesce→sync→commit pipeline: closes the current
    /// commit_group, executes the 7-step commit ordering, and calls
    /// [`CommitGroupManager::commit_group`] on the provided manager to flush accumulated
    /// writes to the intent log and wait for durability.
    ///
    /// Returns `Ok(Some(root))` if a commit occurred and produced a
    /// committed root pointer, `Ok(None)` if no commit was needed
    /// (no open group or commit_group manager had no accumulated writes).
    pub fn commit(
        &mut self,
        commit_group: &mut StoreCommitGroupManager,
    ) -> Result<Option<RootPointer>, SyncError> {
        if self.current.is_none() {
            return Ok(None);
        }

        let current = self.current.as_mut().unwrap();
        if current.phase != CommitGroupPhase::Open {
            return Ok(None);
        }

        current.begin_quiesce(CommitGroupTrigger::ExplicitSync);
        check_crash_hook(CrashInjectionPoint::CommitGroupAfterQuiesce);

        current.begin_sync();
        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeSync);

        self.write_hooks_suspended = true;

        // Execute canonical 7-step sync phase (records steps into the
        // commit log for observability; the real I/O happens below).
        if let Err(e) = Self::execute_sync_phase(current) {
            self.write_hooks_suspended = false;
            Self::rollback_failed_sync(current);
            return Err(e);
        }

        // Flush accumulated writes through the commit_group manager: prepare,
        // commit to intent log, wait for durability.
        let root = match commit_group.commit_group() {
            Ok(root_opt) => root_opt,
            Err(e) => {
                self.write_hooks_suspended = false;
                Self::rollback_failed_sync(current);
                return Err(SyncError::CommitRecord(e.to_string()));
            }
        };

        self.write_hooks_suspended = false;
        current.complete_sync();

        if let Some(next_sm) = self.next.take() {
            self.current = Some(next_sm);
        }

        Ok(root)
    }

    fn rollback_failed_sync(commit_group: &mut CommitGroupStateMachine<C>) {
        commit_group.phase = CommitGroupPhase::Open;
        commit_group.phase_start = commit_group.clock.now();
        commit_group.trigger = None;
        commit_group.sync_steps.clear();
        commit_group.backpressure_active = false;
    }

    fn sync_inner(&mut self, trigger: CommitGroupTrigger) -> Result<bool, SyncError> {
        if self.current.is_none() {
            return Ok(false);
        }

        let current = self.current.as_mut().unwrap();
        if current.phase != CommitGroupPhase::Open {
            return Ok(false);
        }

        current.begin_quiesce(trigger);
        check_crash_hook(CrashInjectionPoint::CommitGroupAfterQuiesce);

        current.begin_sync();
        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeSync);

        self.write_hooks_suspended = true;

        let result = Self::execute_sync_phase(current);

        self.write_hooks_suspended = false;

        match result {
            Ok(()) => {
                current.complete_sync();
                if let Some(next_sm) = self.next.take() {
                    self.current = Some(next_sm);
                }
                Ok(true)
            }
            Err(e) => {
                Self::rollback_failed_sync(current);
                Err(e)
            }
        }
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    fn execute_sync_phase(commit_group: &mut CommitGroupStateMachine<C>) -> Result<(), SyncError> {
        let has_dirty_content = commit_group.dirty_bytes > 0;
        let is_forced = commit_group.trigger == Some(CommitGroupTrigger::ExplicitSync);
        let class = commit_group.durability_class(has_dirty_content, is_forced);

        match class {
            DurabilityClass::DataAndMetadata | DurabilityClass::ForcedDurability => {
                commit_group.record_step(CommitGroupCommitStep::AppendDataRecords);
                check_crash_hook(CrashInjectionPoint::CommitGroupAfterAppendData);
                commit_group.record_step(CommitGroupCommitStep::FlushDataJournal);
            }
            DurabilityClass::MetadataOnly => {}
        }

        commit_group.record_step(CommitGroupCommitStep::AppendMetadataUpdates);

        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeCommit);
        commit_group.record_step(CommitGroupCommitStep::AppendCommitRecord);
        check_crash_hook(CrashInjectionPoint::CommitGroupAfterCommit);

        commit_group.record_step(CommitGroupCommitStep::FlushMetadataJournal);

        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeCheckpoint);
        commit_group.record_step(CommitGroupCommitStep::UpdateCheckpointPointer);
        check_crash_hook(CrashInjectionPoint::CommitGroupAfterCheckpoint);

        commit_group.record_step(CommitGroupCommitStep::FlushSystemArea);

        Ok(())
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn suspend_write_hooks(&mut self) {
        self.write_hooks_suspended = true;
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn resume_write_hooks(&mut self) {
        self.write_hooks_suspended = false;
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn abort(&mut self) {
        if let Some(ref mut current) = self.current {
            current.staged_roots = None;
            current.dirty_bytes = 0;
            current.dirty_ops = 0;
            current.sync_steps.clear();
            current.trigger = None;

            if let Some(next_sm) = self.next.take() {
                self.current = Some(next_sm);
            } else {
                current.phase = CommitGroupPhase::Open;
                current.current_commit_group = current.current_commit_group.next();
                current.commit_group_start = self.clock.now();
                current.phase_start = self.clock.now();
                current.backpressure_active = false;
            }
        }
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn tick(&mut self) -> bool {
        if let Some(ref current) = self.current {
            if current.phase == CommitGroupPhase::Open {
                let elapsed = self.clock.now().duration_since(current.commit_group_start);
                if elapsed >= Duration::from_secs_f64(self.config.commit_group_target_secs)
                    && (current.dirty_bytes > 0 || current.dirty_ops > 0)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Stage metadata roots captured at the quiesce boundary.
    ///
    /// Replaces the current commit_group's staged roots so that the
    /// SYNC phase commits from this snapshot.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn stage_roots(&mut self, roots: MetadataRoots) {
        if let Some(ref mut current) = self.current {
            current.staged_roots = Some(roots);
        }
    }

    /// Access the staged metadata roots for the current commit_group.
    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn staged_roots(&self) -> Option<&MetadataRoots> {
        self.current
            .as_ref()
            .and_then(|sm| sm.staged_roots.as_ref())
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn is_dirty(&self) -> bool {
        self.current
            .as_ref()
            .map(|sm| sm.dirty_bytes > 0 || sm.dirty_ops > 0)
            .unwrap_or(false)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn is_open(&self) -> bool {
        self.current
            .as_ref()
            .map(|sm| sm.phase == CommitGroupPhase::Open)
            .unwrap_or(false)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn current_commit_group_id(&self) -> Option<TxnGroupId> {
        self.current.as_ref().map(|sm| sm.current_commit_group)
    }

    #[allow(dead_code)] // INTENT: COMMIT_GROUP state machine types for planned transaction-group commit pipeline
    pub fn current(&self) -> Option<&CommitGroupStateMachine<C>> {
        self.current.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_commit_group::CommitGroupId;
    use tidefs_local_object_store::{
        txg_manager::CommitGroupManager as StoreCommitGroupManager, ObjectKey,
    };

    fn test_config() -> CommitGroupConfig {
        CommitGroupConfig {
            commit_group_target_ops: 100,
            commit_group_target_bytes: 1024 * 1024, // 1 MiB
            commit_group_dirty_max_bytes: 10 * 1024 * 1024, // 10 MiB
            commit_group_target_secs: 5.0,
            commit_group_quiesce_timeout_secs: 1.0,
        }
    }

    #[test]
    fn commit_class_from_commit_group_state() {
        let mut sm = CommitGroupStateMachine::new(test_config());

        // No dirty bytes, no trigger → MetadataOnly
        assert_eq!(sm.commit_class(), DurabilityClass::MetadataOnly);

        // Dirty bytes present → DataAndMetadata
        sm.record_write(4096);
        assert_eq!(sm.commit_class(), DurabilityClass::DataAndMetadata);

        // Explicit sync trigger → ForcedDurability
        sm.trigger = Some(CommitGroupTrigger::ExplicitSync);
        assert_eq!(sm.commit_class(), DurabilityClass::ForcedDurability);
    }

    #[test]
    fn staged_roots_lifecycle() {
        let mut sm = CommitGroupStateMachine::new(test_config());
        assert!(sm.staged_roots.is_none());

        let roots = MetadataRoots::new(1)
            .with_extent_map_root(10)
            .with_directory_catalog_root(20);
        sm.staged_roots = Some(roots);
        assert_eq!(sm.staged_roots.as_ref().unwrap().inode_table_root, 1);
        assert_eq!(sm.staged_roots.as_ref().unwrap().extent_map_roots, vec![10]);
        assert_eq!(
            sm.staged_roots.as_ref().unwrap().directory_catalog_roots,
            vec![20]
        );

        // complete_sync clears staged_roots
        sm.begin_sync();
        sm.complete_sync();
        assert!(sm.staged_roots.is_none());
    }

    #[test]
    fn commit_group_manager_stage_and_read_roots() {
        let mut mgr = CommitGroupManager::new(test_config());
        // No current commit_group — staged_roots returns None
        assert!(mgr.staged_roots().is_none());

        // Begin a commit_group
        mgr.begin_or_get_commit_group();
        assert!(mgr.staged_roots().is_none());

        let roots = MetadataRoots::new(42);
        mgr.stage_roots(roots);
        assert_eq!(mgr.staged_roots().unwrap().inode_table_root, 42);
    }

    #[test]
    fn abort_clears_staged_roots() {
        let mut mgr = CommitGroupManager::new(test_config());
        mgr.begin_or_get_commit_group();
        mgr.stage_roots(MetadataRoots::new(7));
        assert!(mgr.staged_roots().is_some());

        mgr.abort();
        // After abort, current commit_group is gone or reset
        assert!(mgr.staged_roots().is_none());
    }

    #[test]
    fn txn_group_id_increases() {
        let id = TxnGroupId::ZERO;
        assert_eq!(id.next(), TxnGroupId(1));
        assert_eq!(id.next().next(), TxnGroupId(2));
    }

    #[test]
    fn new_state_machine_starts_open() {
        let sm = CommitGroupStateMachine::new(test_config());
        assert_eq!(sm.phase, CommitGroupPhase::Open);
        assert_eq!(sm.current_commit_group, TxnGroupId(1));
        assert_eq!(sm.dirty_bytes, 0);
        assert_eq!(sm.dirty_ops, 0);
        assert!(!sm.backpressure_active);
    }

    #[test]
    fn record_write_accumulates_dirty() {
        let mut sm = CommitGroupStateMachine::new(test_config());
        assert!(sm.record_write(4096));
        assert_eq!(sm.dirty_bytes, 4096);
        assert_eq!(sm.dirty_ops, 1);

        assert!(sm.record_write(8192));
        assert_eq!(sm.dirty_bytes, 12288);
        assert_eq!(sm.dirty_ops, 2);
    }

    #[test]
    fn triggers_fire_in_priority_order() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupConfig {
            commit_group_target_ops: 10,
            commit_group_target_bytes: 4096,
            commit_group_dirty_max_bytes: 100_000,
            commit_group_target_secs: 60.0,
            commit_group_quiesce_timeout_secs: 1.0,
        });

        // Only a few writes, no triggers
        for _ in 0..5 {
            sm.record_write(512);
        }
        assert!(sm.evaluate_triggers().is_none());

        // Cross byte threshold
        sm.record_write(4096);
        assert_eq!(sm.evaluate_triggers(), Some(CommitGroupTrigger::ByteTarget));

        // Cross op threshold (higher priority)
        sm.dirty_ops = 10;
        assert_eq!(sm.evaluate_triggers(), Some(CommitGroupTrigger::OpCount));

        // Cross max byte threshold (highest non-explicit priority)
        sm.dirty_bytes = 200_000;
        assert_eq!(
            sm.evaluate_triggers(),
            Some(CommitGroupTrigger::ByteMaximum)
        );
    }

    #[test]
    fn backpressure_rejects_writes_above_max() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupConfig {
            commit_group_target_ops: 1000,
            commit_group_target_bytes: 4096,
            commit_group_dirty_max_bytes: 8192,
            commit_group_target_secs: 60.0,
            commit_group_quiesce_timeout_secs: 1.0,
        });

        // First write crosses byte max -> activates backpressure
        assert!(sm.record_write(9000));
        assert!(sm.backpressure_active);

        // Second write should be rejected
        assert!(!sm.record_write(4096));
    }

    #[test]
    fn quiesce_sync_cycle_resets_state() {
        let mut sm = CommitGroupStateMachine::new(test_config());

        // Fill up to trigger
        for _ in 0..200 {
            sm.record_write(65536);
        }
        assert!(sm.should_quiesce());

        sm.begin_quiesce(CommitGroupTrigger::ByteTarget);
        assert_eq!(sm.phase, CommitGroupPhase::Quiesce);

        sm.begin_sync();
        assert_eq!(sm.phase, CommitGroupPhase::Sync);

        let log = sm.complete_sync();
        assert_eq!(sm.phase, CommitGroupPhase::Open);
        assert_eq!(sm.current_commit_group, TxnGroupId(2));
        assert_eq!(sm.dirty_bytes, 0);
        assert_eq!(sm.dirty_ops, 0);
        assert_eq!(log.commit_group, TxnGroupId(1));
    }

    #[test]
    fn commit_manager_flushes_queued_txg_through_manager() {
        let mut commit_mgr = CommitGroupManager::new(test_config());
        assert!(commit_mgr.record_bytes(4096));

        let mut txg_mgr = StoreCommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([0x7Au8; 32]);
        txg_mgr.queue_put(key, b"commit-manager-payload").unwrap();

        let root = commit_mgr.commit(&mut txg_mgr).unwrap().unwrap();

        assert!(root.is_valid());
        assert_eq!(root.commit_group_id, CommitGroupId::FIRST);
        assert_eq!(txg_mgr.committed_root(), root);
        assert_eq!(txg_mgr.commit_count(), 1);
        assert_eq!(commit_mgr.current_commit_group_id(), Some(TxnGroupId(2)));
        assert!(commit_mgr.is_open());
        assert!(!commit_mgr.write_hooks_suspended);
    }

    #[test]
    fn failed_sync_rollback_restores_open_dirty_state() {
        let mut sm = CommitGroupStateMachine::new(test_config());
        assert!(sm.record_write(8192));
        sm.begin_quiesce(CommitGroupTrigger::ExplicitSync);
        sm.begin_sync();
        sm.record_step(CommitGroupCommitStep::AppendDataRecords);
        sm.record_step(CommitGroupCommitStep::FlushDataJournal);

        CommitGroupManager::rollback_failed_sync(&mut sm);

        assert_eq!(sm.phase, CommitGroupPhase::Open);
        assert_eq!(sm.dirty_bytes, 8192);
        assert_eq!(sm.dirty_ops, 1);
        assert!(sm.trigger.is_none());
        assert!(sm.sync_steps.is_empty());
        assert!(!sm.backpressure_active);
    }

    #[test]
    fn durability_class_selection() {
        let sm = CommitGroupStateMachine::new(test_config());

        assert_eq!(
            sm.durability_class(false, false),
            DurabilityClass::MetadataOnly
        );
        assert_eq!(
            sm.durability_class(true, false),
            DurabilityClass::DataAndMetadata
        );
        assert_eq!(
            sm.durability_class(false, true),
            DurabilityClass::ForcedDurability
        );
        assert_eq!(
            sm.durability_class(true, true),
            DurabilityClass::ForcedDurability
        );
    }

    #[test]
    fn metadata_only_has_5_steps() {
        let sm = CommitGroupStateMachine::new(test_config());
        let steps = sm.steps_for(DurabilityClass::MetadataOnly);
        assert_eq!(steps.len(), 5);
        assert_eq!(steps[0], CommitGroupCommitStep::AppendMetadataUpdates);
    }

    #[test]
    fn full_commit_has_7_steps() {
        let sm = CommitGroupStateMachine::new(test_config());
        let steps = sm.steps_for(DurabilityClass::DataAndMetadata);
        assert_eq!(steps.len(), 7);
        assert_eq!(steps[0], CommitGroupCommitStep::AppendDataRecords);
        assert_eq!(steps[6], CommitGroupCommitStep::FlushSystemArea);
    }

    #[test]
    fn quiesce_timeout_detected() {
        let now = Instant::now();
        let clock = FixedClock::new(now);
        let mut sm = CommitGroupStateMachine::with_clock(
            CommitGroupConfig {
                commit_group_quiesce_timeout_secs: 0.5,
                ..test_config()
            },
            clock,
        );

        sm.begin_quiesce(CommitGroupTrigger::OpCount);
        assert!(!sm.quiesce_timed_out());

        sm.clock.advance(Duration::from_secs_f64(0.6));
        assert!(sm.quiesce_timed_out());
    }

    #[test]
    fn config_presets() {
        let def = CommitGroupConfig::default();
        assert_eq!(def.commit_group_target_ops, 2048);

        let cons = CommitGroupConfig::conservative();
        assert_eq!(cons.commit_group_target_ops, 16);
        assert!(cons.commit_group_dirty_max_bytes < def.commit_group_dirty_max_bytes);

        let tp = CommitGroupConfig::throughput();
        assert_eq!(tp.commit_group_target_ops, 64 * 1024);
        assert!(tp.commit_group_target_secs > def.commit_group_target_secs);
        assert!(tp.commit_group_dirty_max_bytes > def.commit_group_dirty_max_bytes);
    }

    #[test]
    #[should_panic(expected = "quiesce must start from Open")]
    fn begin_quiesce_panics_outside_open() {
        let mut sm = CommitGroupStateMachine::new(test_config());
        sm.begin_quiesce(CommitGroupTrigger::ExplicitSync);
        // Second quiesce should panic: already in Quiesce phase.
        sm.begin_quiesce(CommitGroupTrigger::ExplicitSync);
    }

    #[test]
    fn begin_sync_from_open_is_valid() {
        let mut sm = CommitGroupStateMachine::new(test_config());
        sm.begin_sync();
        assert_eq!(sm.phase, CommitGroupPhase::Sync);
        sm.complete_sync();
        assert_eq!(sm.phase, CommitGroupPhase::Open);
    }
}
