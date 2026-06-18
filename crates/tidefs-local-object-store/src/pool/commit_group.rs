// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Canonical commit ordering and multi-phase commit_group state machine.
//!
//! Implements the design specified in
//! `docs/design/canonical-commit-ordering-commit_group-state-machine.md` (#1267).
//!
//! The commit_group state machine provides the write-path durability contract:
//! a pointer is never persisted before what it points to. It implements
//! a three-phase lifecycle (OPEN → QUIESCE → SYNC → OPEN) with four-tier
//! auto-sync triggers and back-pressure throttling.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// CommitGroupPhase
// ---------------------------------------------------------------------------

/// The three phases of a commit_group lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGroupPhase {
    /// Accepting new writes into the current commit_group.
    Open,
    /// Stop accepting writes into this commit_group; drain in-flight I/O.
    Quiesce,
    /// Execute the seven-step commit pipeline; publish new state.
    Sync,
}

// ---------------------------------------------------------------------------
// QuiesceReason
// ---------------------------------------------------------------------------

/// Reason a commit_group was quiesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceReason {
    /// Explicit `commit_group_sync()` call (fsync, O_DSYNC, pool close).
    ExplicitSync,
    /// Op-count threshold reached.
    TargetOps,
    /// Time threshold reached.
    TargetSeconds,
    /// Soft dirty-bytes threshold reached.
    TargetBytes,
    /// Hard cap on dirty bytes exceeded — back-pressure.
    DirtyMaxBytes,
}

// ---------------------------------------------------------------------------
// CommitClass
// ---------------------------------------------------------------------------

/// Durability trigger class — selects which pipeline steps to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitClass {
    /// Only metadata is dirty; skip data-journal steps 1-2.
    MetadataOnly,
    /// Both data extents and metadata are dirty; full pipeline.
    DataAndMetadata,
    /// Forced durability (fsync/O_DSYNC) for specific scope.
    ForcedDurability,
}

// ---------------------------------------------------------------------------
// SegmentStoreFamily
// ---------------------------------------------------------------------------

/// SegmentStore family classification for dirty-byte accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentStoreFamily {
    /// Pool-map journal (system area, slice-0).
    PoolMap,
    /// Metadata journal.
    Metadata,
    /// Data extent payloads.
    Data,
}

// ---------------------------------------------------------------------------
// StagedRoots
// ---------------------------------------------------------------------------

/// Placeholder for staged metadata roots held in-memory during a commit_group.
///
/// The v0.262 Python reference accumulates modified metadata in memory and
/// writes it atomically at commit time. This struct will hold the staged
/// roots once the metadata engine is wired in.
#[derive(Debug, Clone)]
pub struct StagedRoots {
    /// CommitGroup identifier these roots belong to.
    pub commit_group_id: u64,
    /// Monotonically increasing commit sequence number.
    pub commit_seq: u64,
}

// ---------------------------------------------------------------------------
// CommitGroupDirtyState
// ---------------------------------------------------------------------------

/// Dirty state accumulated during a commit_group's OPEN phase.
///
/// Tracks which inodes, extent maps, and directories have been modified,
/// along with coarse byte accounting per SegmentStore family.
#[derive(Debug, Default, Clone)]
pub struct CommitGroupDirtyState {
    /// Inodes modified during this commit_group (keyed by inode_id).
    pub dirty_inodes: BTreeSet<u64>,
    /// Extent maps modified during this commit_group (keyed by inode_id).
    pub dirty_extent_maps: BTreeSet<u64>,
    /// Directory entries added/removed/renamed (keyed by dir_inode_id).
    pub dirty_dirs: BTreeSet<u64>,

    /// Coarse byte accounting per SegmentStore family.
    pub bytes_poolmap: u64,
    pub bytes_metadata: u64,
    pub bytes_data: u64,

    /// True if any data extents were appended during this commit_group.
    pub has_data_dirty: bool,
    /// True if any metadata was modified during this commit_group.
    pub has_metadata_dirty: bool,
}

impl CommitGroupDirtyState {
    /// Total dirty bytes across all SegmentStore families.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_poolmap
            .saturating_add(self.bytes_metadata)
            .saturating_add(self.bytes_data)
    }

    /// Whether any dirty state is present.
    pub fn is_dirty(&self) -> bool {
        self.has_metadata_dirty || self.has_data_dirty
    }

    /// Reset all dirty tracking to zero/empty.
    pub fn clear(&mut self) {
        self.dirty_inodes.clear();
        self.dirty_extent_maps.clear();
        self.dirty_dirs.clear();
        self.bytes_poolmap = 0;
        self.bytes_metadata = 0;
        self.bytes_data = 0;
        self.has_data_dirty = false;
        self.has_metadata_dirty = false;
    }
}

// ---------------------------------------------------------------------------
// CommitGroupConfig
// ---------------------------------------------------------------------------

/// Configuration knobs for the commit_group manager.
#[derive(Debug, Clone)]
pub struct CommitGroupConfig {
    /// Enable commit_group batching. When `false`, every mutation commits immediately.
    pub enabled: bool,
    /// Staged operation count that triggers auto-quiesce.
    pub target_ops: u32,
    /// Elapsed time in seconds that triggers auto-quiesce. `None` disables.
    pub target_seconds: Option<f64>,
    /// Dirty padded bytes that trigger auto-quiesce. `None` disables.
    pub target_bytes: Option<u64>,
    /// Hard cap on dirty bytes before back-pressure. `None` disables.
    pub dirty_max_bytes: Option<u64>,
}

impl Default for CommitGroupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_ops: 64,
            target_seconds: None,
            target_bytes: None,
            dirty_max_bytes: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CommitGroupState
// ---------------------------------------------------------------------------

/// A commit_group object representing one transaction group.
#[derive(Debug)]
pub struct CommitGroupState {
    /// Monotonically increasing commit_group identifier.
    pub commit_group_id: u64,
    /// Current phase.
    pub phase: CommitGroupPhase,
    /// Monotonic timestamp (seconds) when this commit_group was opened.
    pub start_time: f64,
    /// Number of staged operations during this commit_group's OPEN phase.
    pub ops_staged: u64,
    /// Accumulated dirty state.
    pub dirty_state: CommitGroupDirtyState,
    /// Staged metadata roots (in-memory), if any.
    pub staged_roots: Option<StagedRoots>,
}

impl CommitGroupState {
    /// Create a new commit_group in the OPEN phase.
    pub fn new(commit_group_id: u64, now: f64) -> Self {
        Self {
            commit_group_id,
            phase: CommitGroupPhase::Open,
            start_time: now,
            ops_staged: 0,
            dirty_state: CommitGroupDirtyState::default(),
            staged_roots: None,
        }
    }

    /// Determine the commit class based on dirty state.
    pub fn commit_class(&self) -> CommitClass {
        if self.dirty_state.has_data_dirty {
            CommitClass::DataAndMetadata
        } else {
            CommitClass::MetadataOnly
        }
    }

    /// Whether this commit_group has any dirty state to commit.
    pub fn is_dirty(&self) -> bool {
        self.dirty_state.is_dirty()
    }
}

// ---------------------------------------------------------------------------
// CommitGroupTickOutcome
// ---------------------------------------------------------------------------

/// Outcome of a commit_group tick (maintenance-tick call).
#[derive(Debug)]
pub enum CommitGroupTickOutcome {
    /// No commit_group is active.
    NoCommitGroup,
    /// A commit_group exists but is not in the OPEN phase.
    NotOpen,
    /// No trigger fired.
    NoTrigger,
    /// A sync was performed.
    Synced { reason: QuiesceReason },
}

// ---------------------------------------------------------------------------
// CommitGroupClock trait and implementations
// ---------------------------------------------------------------------------

/// Clock abstraction for time-based commit_group triggers.
///
/// Allows deterministic time injection in tests via [`TestClock`].
pub trait CommitGroupClock: Send + Sync {
    /// Return the current monotonic time in seconds.
    fn now(&self) -> f64;
}

/// Real monotonic clock backed by `std::time::Instant`.
///
/// Uses an epoch-relative monotonic source. The absolute value is
/// meaningless; only deltas are used for time-threshold evaluation.
pub struct MonotonicClock {
    epoch: std::time::Instant,
}

impl MonotonicClock {
    /// Create a new monotonic clock anchored at the current instant.
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitGroupClock for MonotonicClock {
    fn now(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }
}

/// Deterministic test clock backed by an atomic f64.
///
/// Time advances only when explicitly set via [`TestClock::advance`] or
/// [`TestClock::set`].
pub struct TestClock {
    now: AtomicU64,
}

impl TestClock {
    /// Create a new test clock at time 0.0.
    pub fn new() -> Self {
        Self {
            now: AtomicU64::new(0.0_f64.to_bits()),
        }
    }

    /// Set the clock to a specific time.
    pub fn set(&self, t: f64) {
        self.now.store(t.to_bits(), Ordering::SeqCst);
    }

    /// Advance the clock by `delta` seconds.
    pub fn advance(&self, delta: f64) {
        // Use fetch_update for f64 semantics via AtomicU64
        self.now
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some((f64::from_bits(v) + delta).to_bits())
            })
            .ok();
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitGroupClock for TestClock {
    fn now(&self) -> f64 {
        f64::from_bits(self.now.load(Ordering::SeqCst))
    }
}

// ---------------------------------------------------------------------------
// CommitGroupError
// ---------------------------------------------------------------------------

/// Errors that can occur during commit_group operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitGroupError {
    /// CommitGroup batching is disabled.
    CommitGroupDisabled,
    /// No commit_group is currently active.
    NoActiveCommitGroup,
    /// A commit_group is already in SYNC — cannot begin a nested sync.
    AlreadySyncing,
    /// Back-pressure: the hard cap on dirty bytes has been reached.
    PressureThrottle,
    /// I/O error during the SYNC phase.
    SyncIo,
    /// Internal invariant violation.
    Invariant(&'static str),
}

// ---------------------------------------------------------------------------
// CommitGroupManager
// ---------------------------------------------------------------------------

/// Top-level commit_group manager embedded in Pool.
///
/// Manages the commit_group lifecycle: creates commit_groups, evaluates auto-sync triggers,
/// executes the SYNC phase, and handles write-hook suspension.
pub struct CommitGroupManager {
    config: CommitGroupConfig,
    clock: Box<dyn CommitGroupClock>,
    /// Monotonically increasing commit_group identifier counter.
    next_commit_group_id: u64,
    /// The current commit_group (if any).
    current: Option<CommitGroupState>,
    /// The next commit_group (created when writes arrive during QUIESCE/SYNC).
    next: Option<CommitGroupState>,
    /// Whether write hooks are suspended (during SYNC).
    write_hooks_suspended: bool,
}

impl std::fmt::Debug for CommitGroupManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitGroupManager")
            .field("config", &self.config)
            .field("clock", &"<dyn CommitGroupClock>")
            .field("next_commit_group_id", &self.next_commit_group_id)
            .field("current", &self.current)
            .field("next", &self.next)
            .field("write_hooks_suspended", &self.write_hooks_suspended)
            .finish()
    }
}

impl CommitGroupManager {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a new CommitGroupManager with the given config and clock.
    pub fn new(config: CommitGroupConfig, clock: Box<dyn CommitGroupClock>) -> Self {
        Self {
            config,
            clock,
            next_commit_group_id: 1,
            current: None,
            next: None,
            write_hooks_suspended: false,
        }
    }

    /// Create a CommitGroupManager with the default `MonotonicClock`.
    pub fn with_monotonic(config: CommitGroupConfig) -> Self {
        Self::new(config, Box::new(MonotonicClock::new()))
    }

    // ------------------------------------------------------------------
    // CommitGroup lifecycle
    // ------------------------------------------------------------------

    /// Get or create a commit_group for new writes.
    ///
    /// If no commit_group is active, opens a new one. If the current commit_group is in
    /// QUIESCE or SYNC, returns the next commit_group (creating one if needed).
    pub fn begin_or_get_commit_group(&mut self) -> &mut CommitGroupState {
        if !self.config.enabled {
            if self.current.is_none()
                || !matches!(self.current.as_ref().unwrap().phase, CommitGroupPhase::Open)
            {
                let now = self.clock.now();
                let id = self.next_commit_group_id;
                self.next_commit_group_id += 1;
                self.current = Some(CommitGroupState::new(id, now));
            }
            return self.current.as_mut().unwrap();
        }

        match &self.current {
            None => {
                let now = self.clock.now();
                let id = self.next_commit_group_id;
                self.next_commit_group_id += 1;
                self.current = Some(CommitGroupState::new(id, now));
                self.current.as_mut().unwrap()
            }
            Some(commit_group) if commit_group.phase == CommitGroupPhase::Open => {
                self.current.as_mut().unwrap()
            }
            Some(_) => {
                if self.next.is_none() {
                    let now = self.clock.now();
                    let id = self.next_commit_group_id;
                    self.next_commit_group_id += 1;
                    self.next = Some(CommitGroupState::new(id, now));
                }
                self.next.as_mut().unwrap()
            }
        }
    }

    /// Stage a metadata root update within the current commit_group.
    pub fn stage_roots(&mut self, roots: StagedRoots) {
        let commit_group = self.begin_or_get_commit_group();
        commit_group.staged_roots = Some(roots);
    }

    /// Record padded bytes appended to a SegmentStore family.
    ///
    /// No-ops if write hooks are suspended (during SYNC).
    pub fn record_bytes(&mut self, family: SegmentStoreFamily, bytes: u64) {
        if self.write_hooks_suspended {
            return;
        }
        let commit_group = self.begin_or_get_commit_group();
        match family {
            SegmentStoreFamily::PoolMap => {
                commit_group.dirty_state.bytes_poolmap =
                    commit_group.dirty_state.bytes_poolmap.saturating_add(bytes);
                commit_group.dirty_state.has_metadata_dirty = true;
            }
            SegmentStoreFamily::Metadata => {
                commit_group.dirty_state.bytes_metadata = commit_group
                    .dirty_state
                    .bytes_metadata
                    .saturating_add(bytes);
                commit_group.dirty_state.has_metadata_dirty = true;
            }
            SegmentStoreFamily::Data => {
                commit_group.dirty_state.bytes_data =
                    commit_group.dirty_state.bytes_data.saturating_add(bytes);
                commit_group.dirty_state.has_data_dirty = true;
            }
        }
    }

    /// Increment the staged operation count for the current commit_group.
    pub fn record_op(&mut self) {
        if self.write_hooks_suspended {
            return;
        }
        let commit_group = self.begin_or_get_commit_group();
        commit_group.ops_staged = commit_group.ops_staged.saturating_add(1);
    }

    // ------------------------------------------------------------------
    // Trigger evaluation
    // ------------------------------------------------------------------

    /// Evaluate auto-sync triggers. Returns the reason if a quiesce
    /// should be initiated, or `None` if no trigger fires.
    pub fn should_quiesce(&self) -> Option<QuiesceReason> {
        let commit_group = match &self.current {
            Some(commit_group) if commit_group.phase == CommitGroupPhase::Open => commit_group,
            _ => return None,
        };

        if !commit_group.is_dirty() {
            return None;
        }

        // 1. Hard cap: prevent unbounded growth.
        if let Some(max_bytes) = self.config.dirty_max_bytes {
            if commit_group.dirty_state.total_bytes() >= max_bytes {
                return Some(QuiesceReason::DirtyMaxBytes);
            }
        }

        // 2. Op-count threshold.
        if commit_group.ops_staged >= self.config.target_ops as u64 {
            return Some(QuiesceReason::TargetOps);
        }

        // 3. Time threshold.
        if let Some(target_s) = self.config.target_seconds {
            if self.clock.now() - commit_group.start_time >= target_s {
                return Some(QuiesceReason::TargetSeconds);
            }
        }

        // 4. Soft dirty-bytes threshold.
        if let Some(target_bytes) = self.config.target_bytes {
            if commit_group.dirty_state.total_bytes() >= target_bytes {
                return Some(QuiesceReason::TargetBytes);
            }
        }

        None
    }

    /// Evaluate auto-sync triggers and initiate QUIESCE → SYNC if any fire.
    /// Called after each pool mutation.
    pub fn auto_sync_if_needed(&mut self) {
        if self.should_quiesce().is_some() {
            self.begin_quiesce();
        }
    }

    // ------------------------------------------------------------------
    // Sync
    // ------------------------------------------------------------------

    /// Explicit sync: force QUIESCE → SYNC regardless of thresholds.
    ///
    /// Returns `true` if a commit was published (i.e., there was dirty
    /// state to commit).
    pub fn sync(&mut self) -> Result<bool, CommitGroupError> {
        if !self.config.enabled {
            return Err(CommitGroupError::CommitGroupDisabled);
        }
        let is_dirty = self.current.as_ref().map(|t| t.is_dirty()).unwrap_or(false);
        if !is_dirty {
            return Ok(false);
        }
        self.begin_quiesce();
        self.execute_sync_phase()?;
        Ok(true)
    }

    /// Begin the QUIESCE phase for the current commit_group.
    fn begin_quiesce(&mut self) {
        if let Some(ref mut commit_group) = self.current {
            if commit_group.phase == CommitGroupPhase::Open {
                commit_group.phase = CommitGroupPhase::Quiesce;
            }
        }
    }

    /// Execute the SYNC phase for the current commit_group.
    ///
    /// Performs steps 1-7 of the canonical commit pipeline
    /// (or 3-7 for metadata-only commits). In this initial implementation
    /// the actual I/O steps are performed by the caller (Pool). This method
    /// transitions the commit_group phases and manages state cleanup.
    fn execute_sync_phase(&mut self) -> Result<(), CommitGroupError> {
        let current = match self.current.as_mut() {
            Some(commit_group) if commit_group.phase == CommitGroupPhase::Quiesce => commit_group,
            Some(commit_group) if commit_group.phase == CommitGroupPhase::Sync => {
                return Err(CommitGroupError::AlreadySyncing);
            }
            _ => return Ok(()),
        };

        current.phase = CommitGroupPhase::Sync;

        self.write_hooks_suspended = true;

        // After sync: reset dirty state, recycle commit_group.
        current.dirty_state.clear();
        current.staged_roots = None;
        current.ops_staged = 0;

        self.write_hooks_suspended = false;

        // Promote next commit_group → current if one was created during QUIESCE/SYNC.
        let mut promoted = false;
        if let Some(next) = self.next.take() {
            self.current = Some(next);
            promoted = true;
        } else {
            self.current = None;
        }

        if promoted {
            if let Some(ref mut commit_group) = self.current {
                commit_group.phase = CommitGroupPhase::Open;
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Maintenance tick
    // ------------------------------------------------------------------

    /// Maintenance tick for timer-driven sync.
    ///
    /// Called by the pool's `service_background()` loop. Evaluates the
    /// time-based trigger and initiates sync if needed.
    pub fn tick(&mut self) -> CommitGroupTickOutcome {
        if self.current.is_none() {
            return CommitGroupTickOutcome::NoCommitGroup;
        }
        if self
            .current
            .as_ref()
            .map(|t| t.phase != CommitGroupPhase::Open)
            .unwrap_or(true)
        {
            return CommitGroupTickOutcome::NotOpen;
        }
        match self.should_quiesce() {
            Some(reason) => {
                self.begin_quiesce();
                let _ = self.execute_sync_phase();
                CommitGroupTickOutcome::Synced { reason }
            }
            None => CommitGroupTickOutcome::NoTrigger,
        }
    }

    // ------------------------------------------------------------------
    // Write hook suspension
    // ------------------------------------------------------------------

    /// Suspend write hooks during SYNC to avoid mis-attribution.
    pub fn suspend_write_hooks(&mut self) {
        self.write_hooks_suspended = true;
    }

    /// Resume write hooks after SYNC completes.
    pub fn resume_write_hooks(&mut self) {
        self.write_hooks_suspended = false;
    }

    // ------------------------------------------------------------------
    // Abort
    // ------------------------------------------------------------------

    /// Abort the current commit_group (drop staged state without committing).
    pub fn abort(&mut self) {
        if let Some(ref mut commit_group) = self.current {
            commit_group.dirty_state.clear();
            commit_group.staged_roots = None;
            commit_group.ops_staged = 0;
            commit_group.phase = CommitGroupPhase::Open;
        }
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Whether the commit_group is dirty (has uncommitted mutations).
    pub fn is_dirty(&self) -> bool {
        self.current.as_ref().map(|t| t.is_dirty()).unwrap_or(false)
    }

    /// Whether a commit_group is currently open (accepting writes).
    pub fn is_open(&self) -> bool {
        self.current
            .as_ref()
            .map(|t| t.phase == CommitGroupPhase::Open)
            .unwrap_or(false)
    }

    /// Whether commit_group batching is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Return the current commit_group if one is active and open.
    pub fn current_commit_group(&self) -> Option<&CommitGroupState> {
        self.current.as_ref()
    }

    /// Return the current commit_group phase, if a commit_group is active.
    pub fn current_phase(&self) -> Option<CommitGroupPhase> {
        self.current.as_ref().map(|t| t.phase)
    }

    /// Return a reference to the dirty state of the current commit_group, if any.
    pub fn dirty_state(&self) -> Option<&CommitGroupDirtyState> {
        self.current.as_ref().map(|t| &t.dirty_state)
    }

    /// Return a reference to the staged roots of the current commit_group, if any.
    pub fn staged_roots(&self) -> Option<&StagedRoots> {
        self.current.as_ref().and_then(|t| t.staged_roots.as_ref())
    }

    /// Whether write hooks are currently suspended.
    pub fn write_hooks_suspended(&self) -> bool {
        self.write_hooks_suspended
    }

    // ------------------------------------------------------------------
    // Config access
    // ------------------------------------------------------------------

    /// Return a reference to the commit_group configuration.
    pub fn config(&self) -> &CommitGroupConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CommitGroupConfig {
        CommitGroupConfig {
            enabled: true,
            target_ops: 10,
            target_seconds: None,
            target_bytes: None,
            dirty_max_bytes: None,
        }
    }

    fn test_clock() -> TestClock {
        TestClock::new()
    }

    // ── Basic lifecycle ──

    #[test]
    fn test_commit_group_stages_until_sync() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        assert!(!mgr.is_dirty());
        assert!(mgr.current_commit_group().is_none());

        {
            let commit_group = mgr.begin_or_get_commit_group();
            assert_eq!(commit_group.phase, CommitGroupPhase::Open);
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.ops_staged = 5;
        }

        assert!(mgr.is_dirty());

        let result = mgr.sync().unwrap();
        assert!(result);

        assert!(!mgr.is_dirty());
    }

    #[test]
    fn test_close_flushes_commit_group() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
        }

        assert!(mgr.is_dirty());

        let synced = mgr.sync().unwrap();
        assert!(synced);
        assert!(!mgr.is_dirty());
    }

    // ── Auto-sync triggers ──

    #[test]
    fn test_auto_sync_on_op_threshold() {
        let clock = test_clock();
        let config = CommitGroupConfig {
            target_ops: 2,
            ..test_config()
        };
        let mut mgr = CommitGroupManager::new(config, Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.ops_staged = 1;
        }
        assert_eq!(mgr.should_quiesce(), None);

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.ops_staged = 2;
        }
        assert_eq!(mgr.should_quiesce(), Some(QuiesceReason::TargetOps));
    }

    #[test]
    fn test_auto_sync_on_byte_threshold() {
        let clock = test_clock();
        let config = CommitGroupConfig {
            enabled: true,
            target_ops: u32::MAX,
            target_seconds: None,
            target_bytes: Some(1),
            dirty_max_bytes: None,
        };
        let mut mgr = CommitGroupManager::new(config, Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.bytes_metadata = 1;
            commit_group.dirty_state.has_metadata_dirty = true;
        }
        assert_eq!(mgr.should_quiesce(), Some(QuiesceReason::TargetBytes));
    }

    #[test]
    fn test_backpressure_hard_cap() {
        let clock = test_clock();
        let config = CommitGroupConfig {
            enabled: true,
            target_ops: u32::MAX,
            target_seconds: None,
            target_bytes: None,
            dirty_max_bytes: Some(4096),
        };
        let mut mgr = CommitGroupManager::new(config, Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.bytes_data = 4096;
            commit_group.dirty_state.has_data_dirty = true;
        }
        assert_eq!(mgr.should_quiesce(), Some(QuiesceReason::DirtyMaxBytes));
    }

    // ── Tick ──

    #[test]
    fn test_tick_no_commit_group() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));
        let outcome = mgr.tick();
        assert!(matches!(outcome, CommitGroupTickOutcome::NoCommitGroup));
    }

    #[test]
    fn test_tick_not_open() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));
        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
        }
        mgr.begin_quiesce();
        let outcome = mgr.tick();
        assert!(matches!(outcome, CommitGroupTickOutcome::NotOpen));
    }

    // ── Explicit sync ──

    #[test]
    fn test_explicit_sync_during_open_commit_group() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.dirty_state.bytes_metadata = 128;
            commit_group.ops_staged = 3;
        }

        assert!(mgr.is_dirty());
        let synced = mgr.sync().unwrap();
        assert!(synced);
        assert!(!mgr.is_dirty());
    }

    #[test]
    fn test_sync_no_dirty_returns_false() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        let synced = mgr.sync().unwrap();
        assert!(!synced);

        mgr.begin_or_get_commit_group();
        let synced = mgr.sync().unwrap();
        assert!(!synced);
    }

    // ── Abort ──

    #[test]
    fn test_commit_group_abort() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.dirty_state.bytes_metadata = 512;
            commit_group.ops_staged = 5;
        }

        assert!(mgr.is_dirty());
        mgr.abort();
        assert!(!mgr.is_dirty());
        assert!(mgr.is_open());
    }

    // ── Concurrent commit_group ──

    #[test]
    fn test_concurrent_commit_group() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        let commit_group1_id = mgr.begin_or_get_commit_group().commit_group_id;

        mgr.begin_quiesce();

        let commit_group2 = mgr.begin_or_get_commit_group();
        assert_ne!(commit_group2.commit_group_id, commit_group1_id);
        assert_eq!(commit_group2.phase, CommitGroupPhase::Open);

        assert!(mgr.next.is_some());
    }

    // ── Write hook suspension ──

    #[test]
    fn test_write_hook_suspension() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.dirty_state.bytes_metadata = 100;
        }

        let _ = mgr.sync();

        assert!(!mgr.write_hooks_suspended());
    }

    #[test]
    fn test_record_bytes_ignored_when_suspended() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        mgr.begin_or_get_commit_group();

        mgr.suspend_write_hooks();

        mgr.record_bytes(SegmentStoreFamily::Metadata, 500);
        assert_eq!(mgr.dirty_state().unwrap().bytes_metadata, 0);

        mgr.resume_write_hooks();

        mgr.record_bytes(SegmentStoreFamily::Metadata, 500);
        assert_eq!(mgr.dirty_state().unwrap().bytes_metadata, 500);
    }

    // ── Commit class ──

    #[test]
    fn test_commit_class_determination() {
        let clock = test_clock();
        let mut mgr = CommitGroupManager::new(test_config(), Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
        }
        assert_eq!(
            mgr.current_commit_group().unwrap().commit_class(),
            CommitClass::MetadataOnly
        );

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_data_dirty = true;
        }
        assert_eq!(
            mgr.current_commit_group().unwrap().commit_class(),
            CommitClass::DataAndMetadata
        );
    }

    // ── Default config ──

    #[test]
    fn test_default_config() {
        let cfg = CommitGroupConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.target_ops, 64);
        assert_eq!(cfg.target_seconds, None);
        assert_eq!(cfg.target_bytes, None);
        assert_eq!(cfg.dirty_max_bytes, None);
    }

    // ── CommitGroupDirtyState ──

    #[test]
    fn test_dirty_state_total_bytes() {
        let mut state = CommitGroupDirtyState::default();
        assert_eq!(state.total_bytes(), 0);
        state.bytes_poolmap = 10;
        state.bytes_metadata = 20;
        state.bytes_data = 30;
        assert_eq!(state.total_bytes(), 60);
    }

    #[test]
    fn test_dirty_state_is_dirty() {
        let state = CommitGroupDirtyState::default();
        assert!(!state.is_dirty());

        let state = CommitGroupDirtyState {
            has_metadata_dirty: true,
            ..Default::default()
        };
        assert!(state.is_dirty());
    }

    // ── TestClock ──

    #[test]
    fn test_clock_advance() {
        let clock = TestClock::new();
        assert_eq!(clock.now(), 0.0);
        clock.advance(5.0);
        assert_eq!(clock.now(), 5.0);
        clock.set(42.0);
        assert_eq!(clock.now(), 42.0);
    }

    // ── MonotonicClock ──

    #[test]
    fn test_monotonic_clock_advances() {
        let clock = MonotonicClock::new();
        let t0 = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t1 = clock.now();
        assert!(t1 > t0);
    }

    // ── CommitGroup error ──

    #[test]
    fn test_sync_when_disabled_errors() {
        let clock = test_clock();
        let config = CommitGroupConfig {
            enabled: false,
            ..test_config()
        };
        let mut mgr = CommitGroupManager::new(config, Box::new(clock));
        let result = mgr.sync();
        assert_eq!(result, Err(CommitGroupError::CommitGroupDisabled));
    }

    // ── Full trigger priority: hard cap wins ──

    #[test]
    fn test_trigger_priority_hard_cap_over_target_ops() {
        let clock = test_clock();
        let config = CommitGroupConfig {
            enabled: true,
            target_ops: 5,
            target_seconds: None,
            target_bytes: None,
            dirty_max_bytes: Some(100),
        };
        let mut mgr = CommitGroupManager::new(config, Box::new(clock));

        {
            let commit_group = mgr.begin_or_get_commit_group();
            commit_group.dirty_state.has_metadata_dirty = true;
            commit_group.dirty_state.bytes_metadata = 100;
            commit_group.ops_staged = 5;
        }

        assert_eq!(mgr.should_quiesce(), Some(QuiesceReason::DirtyMaxBytes));
    }
}
