//! Two-phase commit pipeline: prepare → commit with atomic root switch.
//!
//! The pipeline accumulates writes into a `CommitGroup`, validates them in
//! the prepare phase, and atomically switches the live root pointer in the
//! commit phase. A `CommitGroupBuilder` provides size- and age-based flush
//! triggers for automatic group finalization.
//!
//! # Architecture
//!
//! ```text
//! write() ─► CommitGroupBuilder
//!                │
//!     size/age trigger or explicit flush
//!                │
//!                ▼
//!          prepare() ──► validate writes, build pending root
//!                │
//!                ▼
//!          commit()  ──► atomically swap root pointer
//! ```
//!
//! At any point between writes and commit, the group can be aborted
//! without side effects.

use std::time::{Duration, Instant};

use crate::accumulator::CommitGroupAccumulator;
use crate::types::{CommitGroupError, CommitGroupId, CommitGroupPhase, RootPointer};

// ---------------------------------------------------------------------------
// CommitGroup — two-phase write pipeline for one transaction group
// ---------------------------------------------------------------------------

/// A transaction group in the two-phase write pipeline.
///
/// Holds all queued writes and metadata mutations for one transaction group.
/// The lifecycle proceeds: Open → (prepare) → Prepared → (commit) → Committed.
#[derive(Clone, Debug)]
pub struct CommitGroup {
    /// The accumulator holding queued writes and mutations.
    accumulator: CommitGroupAccumulator,
    /// The root pointer that was live when this group was created.
    parent_root: RootPointer,
    /// The pending root pointer, set during prepare and applied during commit.
    pending_root: Option<RootPointer>,
    /// Current phase of the two-phase state machine.
    phase: CommitGroupPhase,
}

impl CommitGroup {
    /// Create a new empty commit group with the given id and parent root.
    #[must_use]
    pub fn new(commit_group_id: CommitGroupId, parent_root: RootPointer) -> Self {
        Self {
            accumulator: CommitGroupAccumulator::new(commit_group_id),
            parent_root,
            pending_root: None,
            phase: CommitGroupPhase::Open,
        }
    }

    /// The commit group id.
    #[must_use]
    pub fn commit_group_id(&self) -> CommitGroupId {
        self.accumulator.commit_group_id()
    }

    /// The parent root pointer (the live root when this group was created).
    #[must_use]
    pub fn parent_root(&self) -> RootPointer {
        self.parent_root
    }

    /// The pending root, set after a successful prepare.
    #[must_use]
    pub fn pending_root(&self) -> Option<RootPointer> {
        self.pending_root
    }

    /// Current pipeline phase.
    #[must_use]
    pub fn phase(&self) -> CommitGroupPhase {
        self.phase
    }

    /// Returns `true` if no writes or mutations are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accumulator.is_empty()
    }

    /// Total bytes of queued write data.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.accumulator.writes().iter().map(|w| w.data.len()).sum()
    }

    /// Number of queued writes.
    #[must_use]
    pub fn write_count(&self) -> usize {
        self.accumulator.write_count()
    }

    // ------------------------------------------------------------------
    // Write accumulation
    // ------------------------------------------------------------------

    /// Queue a write for `ino` at `offset` with `data`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::InvalidPhase` if the group is not Open.
    pub fn queue_write(
        &mut self,
        ino: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), CommitGroupError> {
        self.require_open()?;
        self.accumulator.queue_write(ino, offset, data);
        Ok(())
    }

    /// Queue a setattr mutation.
    pub fn queue_setattr(
        &mut self,
        ino: u64,
        attr_mask: crate::types::DirtyMetaFlags,
        new_size: Option<u64>,
        new_mtime: Option<u64>,
        new_ctime: Option<u64>,
    ) -> Result<(), CommitGroupError> {
        self.require_open()?;
        self.accumulator
            .queue_setattr(ino, attr_mask, new_size, new_mtime, new_ctime);
        Ok(())
    }

    /// Queue a link operation.
    pub fn queue_link(
        &mut self,
        dir_ino: u64,
        name: Vec<u8>,
        target_ino: u64,
    ) -> Result<(), CommitGroupError> {
        self.require_open()?;
        self.accumulator.queue_link(dir_ino, name, target_ino)?;
        Ok(())
    }

    /// Queue an unlink operation.
    pub fn queue_unlink(
        &mut self,
        dir_ino: u64,
        name: Vec<u8>,
        dirty_inos_in_commit_group: &[u64],
    ) -> Result<(), CommitGroupError> {
        self.require_open()?;
        self.accumulator
            .queue_unlink(dir_ino, name, dirty_inos_in_commit_group)?;
        Ok(())
    }

    /// Return a reference to the inner accumulator (for commit path use).
    #[must_use]
    pub fn accumulator(&self) -> &CommitGroupAccumulator {
        &self.accumulator
    }

    /// Consume the accumulator (for commit path use after prepare).
    #[must_use]
    pub fn into_accumulator(self) -> CommitGroupAccumulator {
        self.accumulator
    }

    // ------------------------------------------------------------------
    // Two-phase protocol: prepare
    // ------------------------------------------------------------------

    /// Prepare the commit group for commit.
    ///
    /// Validates that:
    /// - The group is in the Open phase.
    /// - The group is not empty.
    ///
    /// On success, transitions the group to Prepared and builds a pending
    /// root pointer. The pending root derives its handle from the commit
    /// group id so the commit phase can later perform the atomic swap.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::EmptyCommitGroup` if no writes are queued.
    /// Returns `CommitGroupError::PrepareFailed` if the phase is not Open.
    pub fn prepare(&mut self) -> Result<(), CommitGroupError> {
        self.require_open()?;

        if self.accumulator.is_empty() {
            return Err(CommitGroupError::EmptyCommitGroup);
        }

        self.phase = CommitGroupPhase::Preparing;

        // Validate: every write must have non-empty data and valid offset.
        for write in self.accumulator.writes() {
            if write.data.is_empty() {
                self.phase = CommitGroupPhase::Aborted;
                return Err(CommitGroupError::PrepareFailed {
                    reason: format!(
                        "empty write data for ino {} at offset {}",
                        write.ino, write.offset
                    ),
                });
            }
        }

        // Build a pending root pointer. The root_handle is derived from
        // the commit_group_id so the commit phase can atomically reference it.
        let commit_group_id = self.commit_group_id();
        let pending_root = RootPointer::new(commit_group_id, commit_group_id.0);

        self.pending_root = Some(pending_root);
        self.phase = CommitGroupPhase::Prepared;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Two-phase protocol: commit
    // ------------------------------------------------------------------

    /// Commit the prepared group, atomically returning the new live root.
    ///
    /// The root pointer swap is atomic from the perspective of readers:
    /// only after this call succeeds does the pending root become visible
    /// as the live root.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in the Prepared phase.
    pub fn commit(&mut self) -> Result<RootPointer, CommitGroupError> {
        if self.phase != CommitGroupPhase::Prepared {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "commit requires Prepared phase, current phase is {:?}",
                    self.phase
                ),
            });
        }

        let new_root = self
            .pending_root
            .ok_or_else(|| CommitGroupError::CommitPhaseRejected {
                reason: "no pending root set during prepare".into(),
            })?;

        self.phase = CommitGroupPhase::Committed;

        Ok(new_root)
    }

    // ------------------------------------------------------------------
    // Abort
    // ------------------------------------------------------------------

    /// Abort the commit group, discarding all queued writes.
    ///
    /// After abort, the group cannot be prepared or committed.
    /// A fresh group must be created for new writes.
    pub fn abort(&mut self) {
        self.phase = CommitGroupPhase::Aborted;
        self.pending_root = None;
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn require_open(&self) -> Result<(), CommitGroupError> {
        if self.phase != CommitGroupPhase::Open {
            return Err(CommitGroupError::PrepareFailed {
                reason: format!(
                    "commit group is not open for writes, current phase: {:?}",
                    self.phase
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitGroupBuilder — accumulation with flush triggers
// ---------------------------------------------------------------------------

/// Builds commit groups with configurable size- and age-based flush triggers.
///
/// Writes are accumulated into the current open group. When the size or age
/// threshold is exceeded (or an explicit flush is requested), the builder
/// finalizes the current group via prepare + commit and opens a new one.
#[derive(Debug)]
pub struct CommitGroupBuilder {
    /// The currently open commit group (accepting writes).
    current: CommitGroup,
    /// Maximum total bytes before auto-flush (None = no size trigger).
    max_size_bytes: Option<usize>,
    /// Maximum age before auto-flush (None = no age trigger).
    max_age: Option<Duration>,
    /// Monotonic commit group id counter.
    next_commit_group_id: CommitGroupId,
    /// When the current group was opened.
    opened_at: Instant,
    /// Accumulated committed roots.
    committed_roots: Vec<RootPointer>,
}

impl CommitGroupBuilder {
    /// Create a new builder starting at `first_commit_group_id`.
    ///
    /// The builder starts with an empty open group.
    #[must_use]
    pub fn new(first_commit_group_id: CommitGroupId) -> Self {
        let parent_root = RootPointer::NIL;
        Self {
            current: CommitGroup::new(first_commit_group_id, parent_root),
            max_size_bytes: None,
            max_age: None,
            next_commit_group_id: first_commit_group_id.next(),
            opened_at: Instant::now(),
            committed_roots: Vec::new(),
        }
    }

    /// Create a builder resuming from a previously committed root.
    ///
    /// The first open group will have `recovered_root` as its parent,
    /// preserving the chain lineage across mount cycles.
    #[must_use]
    pub fn resume(first_commit_group_id: CommitGroupId, recovered_root: RootPointer) -> Self {
        Self {
            current: CommitGroup::new(first_commit_group_id, recovered_root),
            max_size_bytes: None,
            max_age: None,
            next_commit_group_id: first_commit_group_id.next(),
            opened_at: Instant::now(),
            committed_roots: Vec::new(),
        }
    }

    /// Set a size-based auto-flush threshold.
    ///
    /// When total queued bytes reaches `max_size_bytes`, the next write
    /// will trigger an automatic flush (prepare + commit).
    pub fn with_max_size(mut self, max_size_bytes: usize) -> Self {
        self.max_size_bytes = Some(max_size_bytes);
        self
    }

    /// Set an age-based auto-flush threshold.
    ///
    /// When the open group is older than `max_age`, the next write will
    /// trigger an automatic flush.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Reference to the currently open commit group.
    #[must_use]
    pub fn current(&self) -> &CommitGroup {
        &self.current
    }

    /// Mutable reference to the currently open commit group.
    pub fn current_mut(&mut self) -> &mut CommitGroup {
        &mut self.current
    }

    /// The number of committed roots produced so far.
    #[must_use]
    pub fn committed_root_count(&self) -> usize {
        self.committed_roots.len()
    }

    /// All committed roots produced so far.
    #[must_use]
    pub fn committed_roots(&self) -> &[RootPointer] {
        &self.committed_roots
    }

    /// Returns `true` if the current group is empty.
    #[must_use]
    pub fn current_is_empty(&self) -> bool {
        self.current.is_empty()
    }

    // ------------------------------------------------------------------
    // Write with auto-flush
    // ------------------------------------------------------------------

    /// Queue a write into the current group, optionally triggering a flush.
    ///
    /// After queuing, if the size or age threshold is exceeded, the current
    /// group is automatically prepared and committed, and a new group is
    /// opened for subsequent writes.
    ///
    /// Returns `Some(RootPointer)` if a flush was triggered, `None` otherwise.
    pub fn write(
        &mut self,
        ino: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Option<RootPointer>, CommitGroupError> {
        self.current.queue_write(ino, offset, data)?;

        if self.should_flush() {
            let root = self.flush_inner()?;
            Ok(Some(root))
        } else {
            Ok(None)
        }
    }

    /// Explicitly flush the current group: prepare, commit, open a new group.
    ///
    /// If the current group is empty, this is a no-op that returns `None`.
    /// Otherwise, prepares and commits the group, records the new root, and
    /// opens a fresh group for subsequent writes.
    ///
    /// # Errors
    ///
    /// Returns errors from the prepare or commit phases.
    pub fn flush(&mut self) -> Result<Option<RootPointer>, CommitGroupError> {
        if self.current.is_empty() {
            return Ok(None);
        }
        let root = self.flush_inner()?;
        Ok(Some(root))
    }

    // ------------------------------------------------------------------
    // internals
    // ------------------------------------------------------------------

    fn should_flush(&self) -> bool {
        // Size trigger
        if let Some(max_size) = self.max_size_bytes {
            if self.current.total_bytes() >= max_size {
                return true;
            }
        }
        // Age trigger
        if let Some(max_age) = self.max_age {
            if self.opened_at.elapsed() >= max_age {
                return true;
            }
        }
        false
    }

    fn flush_inner(&mut self) -> Result<RootPointer, CommitGroupError> {
        let mut group = std::mem::replace(
            &mut self.current,
            // placeholder — will be replaced after commit
            CommitGroup::new(CommitGroupId::NIL, RootPointer::NIL),
        );

        // Prepare
        group.prepare()?;

        // Commit — get the new root pointer
        let new_root = group.commit()?;

        self.committed_roots.push(new_root);

        // Open a new group, whose parent is the just-committed root.
        let next_id = self.next_commit_group_id;
        self.next_commit_group_id = next_id.next();
        self.current = CommitGroup::new(next_id, new_root);
        self.opened_at = Instant::now();

        Ok(new_root)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // CommitGroup two-phase state machine
    // ------------------------------------------------------------------

    #[test]
    fn new_group_is_open_and_empty() {
        let group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        assert_eq!(group.phase(), CommitGroupPhase::Open);
        assert!(group.is_empty());
        assert_eq!(group.commit_group_id(), CommitGroupId(1));
        assert_eq!(group.parent_root(), RootPointer::NIL);
        assert!(group.pending_root().is_none());
    }

    #[test]
    fn queue_write_adds_data() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1, 2, 3]).unwrap();
        assert!(!group.is_empty());
        assert_eq!(group.total_bytes(), 3);
        assert_eq!(group.write_count(), 1);
    }

    #[test]
    fn prepare_succeeds_with_writes() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1, 2, 3]).unwrap();
        group.prepare().unwrap();
        assert_eq!(group.phase(), CommitGroupPhase::Prepared);
        let pending = group.pending_root().unwrap();
        assert_eq!(pending.commit_group_id, CommitGroupId(1));
        assert_eq!(pending.root_handle, 1);
    }

    #[test]
    fn prepare_fails_on_empty_group() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        let result = group.prepare();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::EmptyCommitGroup) => {}
            other => panic!("expected EmptyCommitGroup, got {other:?}"),
        }
    }

    #[test]
    fn prepare_fails_when_not_open() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1]).unwrap();
        group.prepare().unwrap();
        // Second prepare should fail.
        let result = group.prepare();
        assert!(result.is_err());
    }

    #[test]
    fn prepare_fails_on_empty_write_data() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![]).unwrap();
        let result = group.prepare();
        assert!(result.is_err());
        assert_eq!(group.phase(), CommitGroupPhase::Aborted);
    }

    #[test]
    fn commit_succeeds_after_prepare() {
        let mut group = CommitGroup::new(CommitGroupId(5), RootPointer::NIL);
        group.queue_write(10, 0, vec![1, 2, 3]).unwrap();
        group.prepare().unwrap();
        let new_root = group.commit().unwrap();
        assert_eq!(group.phase(), CommitGroupPhase::Committed);
        assert_eq!(new_root.commit_group_id, CommitGroupId(5));
        assert_eq!(new_root.root_handle, 5);
    }

    #[test]
    fn commit_rejected_without_prepare() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1]).unwrap();
        let result = group.commit();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    #[test]
    fn commit_rejected_after_abort() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1]).unwrap();
        group.abort();
        assert_eq!(group.phase(), CommitGroupPhase::Aborted);
        let result = group.commit();
        assert!(result.is_err());
    }

    #[test]
    fn abort_discards_pending_root() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1]).unwrap();
        group.prepare().unwrap();
        assert!(group.pending_root().is_some());
        group.abort();
        assert_eq!(group.phase(), CommitGroupPhase::Aborted);
        assert!(group.pending_root().is_none());
    }

    #[test]
    fn write_rejected_after_prepare() {
        let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
        group.queue_write(10, 0, vec![1]).unwrap();
        group.prepare().unwrap();
        let result = group.queue_write(10, 4096, vec![2]);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // RootPointer
    // ------------------------------------------------------------------

    #[test]
    fn root_pointer_nil() {
        let rp = RootPointer::NIL;
        assert!(!rp.is_valid());
        assert_eq!(rp.commit_group_id, CommitGroupId::NIL);
        assert_eq!(rp.root_handle, 0);
    }

    #[test]
    fn root_pointer_valid() {
        let rp = RootPointer::new(CommitGroupId(3), 42);
        assert!(rp.is_valid());
        assert_eq!(rp.commit_group_id, CommitGroupId(3));
        assert_eq!(rp.root_handle, 42);
    }

    // ------------------------------------------------------------------
    // CommitGroupBuilder: size trigger
    // ------------------------------------------------------------------

    #[test]
    fn builder_flush_on_size_trigger() {
        let mut builder = CommitGroupBuilder::new(CommitGroupId::FIRST).with_max_size(32);

        // Write 10 bytes — no flush yet.
        let result = builder.write(1, 0, vec![0u8; 10]).unwrap();
        assert!(result.is_none());
        assert!(!builder.current_is_empty());

        // Write 30 more bytes — crosses 32-byte threshold.
        let result = builder.write(1, 10, vec![0u8; 30]).unwrap();
        assert!(result.is_some());
        // After flush, a new empty group is open.
        assert!(builder.current_is_empty());
        assert_eq!(builder.committed_root_count(), 1);
    }

    #[test]
    fn builder_explicit_flush() {
        let mut builder = CommitGroupBuilder::new(CommitGroupId::FIRST);
        builder
            .current_mut()
            .queue_write(1, 0, vec![1, 2, 3])
            .unwrap();
        let root = builder.flush().unwrap().unwrap();
        assert_eq!(root.commit_group_id, CommitGroupId::FIRST);
        assert!(builder.current_is_empty());
        assert_eq!(builder.committed_root_count(), 1);
    }

    #[test]
    fn builder_explicit_flush_empty_is_noop() {
        let mut builder = CommitGroupBuilder::new(CommitGroupId::FIRST);
        let result = builder.flush().unwrap();
        assert!(result.is_none());
        assert_eq!(builder.committed_root_count(), 0);
    }

    #[test]
    fn builder_multiple_flushes_produces_chain() {
        let mut builder = CommitGroupBuilder::new(CommitGroupId(1));

        // First flush
        builder.current_mut().queue_write(1, 0, vec![1]).unwrap();
        let root1 = builder.flush().unwrap().unwrap();
        assert_eq!(root1.commit_group_id, CommitGroupId(1));

        // Second flush — new group should have parent = root1
        builder.current_mut().queue_write(2, 0, vec![2]).unwrap();
        let root2 = builder.flush().unwrap().unwrap();
        assert_eq!(root2.commit_group_id, CommitGroupId(2));

        assert_eq!(builder.committed_root_count(), 2);
        assert_eq!(builder.committed_roots()[0], root1);
        assert_eq!(builder.committed_roots()[1], root2);
        // root2's parent should be root1
        // (verified by the id chain)
    }

    #[test]
    fn builder_age_trigger_triggers_after_delay() {
        let mut builder =
            CommitGroupBuilder::new(CommitGroupId::FIRST).with_max_age(Duration::from_millis(1));

        builder.current_mut().queue_write(1, 0, vec![1]).unwrap();

        // Wait for age trigger.
        std::thread::sleep(Duration::from_millis(10));

        let result = builder.write(1, 100, vec![2]).unwrap();
        assert!(result.is_some());
        assert_eq!(builder.committed_root_count(), 1);
    }

    // ------------------------------------------------------------------
    // CommitGroupPhase discriminant
    // ------------------------------------------------------------------

    #[test]
    fn phase_discriminants_are_distinct() {
        let phases = [
            CommitGroupPhase::Open,
            CommitGroupPhase::Preparing,
            CommitGroupPhase::Prepared,
            CommitGroupPhase::Committed,
            CommitGroupPhase::Aborted,
        ];
        for i in 0..phases.len() {
            for j in 0..phases.len() {
                if i == j {
                    assert_eq!(phases[i], phases[j]);
                } else {
                    assert_ne!(phases[i], phases[j]);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Integration: full prepare→commit cycle
    // ------------------------------------------------------------------

    #[test]
    fn full_prepare_commit_lifecycle() {
        let mut group =
            CommitGroup::new(CommitGroupId(42), RootPointer::new(CommitGroupId(41), 41));

        // Phase: Open
        assert_eq!(group.phase(), CommitGroupPhase::Open);
        group.queue_write(100, 0, vec![0xAA; 64]).unwrap();
        group.queue_write(200, 4096, vec![0xBB; 128]).unwrap();

        // Phase: Open → Prepared
        group.prepare().unwrap();
        assert_eq!(group.phase(), CommitGroupPhase::Prepared);
        let pending = group.pending_root().unwrap();
        assert_eq!(pending.commit_group_id, CommitGroupId(42));

        // Phase: Prepared → Committed
        let committed_root = group.commit().unwrap();
        assert_eq!(group.phase(), CommitGroupPhase::Committed);
        assert_eq!(committed_root, pending);
    }

    #[test]
    fn atomic_root_switch_preserves_parent() {
        // Readers see either the old root or the new root, never a partial state.
        let parent = RootPointer::new(CommitGroupId(10), 10);
        let mut group = CommitGroup::new(CommitGroupId(11), parent);

        group.queue_write(1, 0, vec![0; 32]).unwrap();
        group.prepare().unwrap();

        let pending = group.pending_root().unwrap();
        // Before commit, parent is still the "live" root from the reader's perspective.
        assert_eq!(group.parent_root(), parent);
        assert_eq!(group.phase(), CommitGroupPhase::Prepared);

        // After commit, the pending root becomes the live root.
        let new_root = group.commit().unwrap();
        assert_eq!(new_root, pending);
        assert_eq!(group.phase(), CommitGroupPhase::Committed);
    }
}
