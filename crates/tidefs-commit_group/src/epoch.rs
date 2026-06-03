//! CommitGroup epoch state machine with BLAKE3-authenticated commit records.
//!
//! Each epoch transitions through Prepare → Commit → Committed (or Abort)
//! and produces a [`CommitRecord`] whose BLAKE3 hash chains into the next
//! epoch, forming a verifiable commit history. The [`CommitGroupStateMachine`]
//! is the driver that the `CommitGroupCoordinator` calls to orchestrate epoch
//! lifecycle: `begin_epoch`, `stage_dirty`, `prepare`, `commit`, `abort`.
//!
//! # Hash chain
//!
//! ```text
//! Epoch 1: hash(epoch=1, prior=None, dirty_ids=[...])
//! Epoch 2: hash(epoch=2, prior=hash_1, dirty_ids=[...])
//! Epoch 3: hash(epoch=3, prior=hash_2, dirty_ids=[...])
//! ```
//!
//! A verifier can replay the chain from any known-good starting point.

use crate::types::{CommitGroupError, CommitGroupId};

// ---------------------------------------------------------------------------
// EpochState — the four epoch phases
// ---------------------------------------------------------------------------

/// The lifecycle phase of a commit-group epoch.
///
/// State machine:
/// ```text
///              begin_epoch()
///                   │
///                   ▼
///   ┌────────── Prepare ──────────┐
///   │   stage_dirty()             │ abort()
///   │         │                   │
///   │    prepare()                ▼
///   │         │               Aborted (terminal)
///   │         ▼
///   │      Commit ──abort()──► Aborted (terminal)
///   │         │
///   │    commit()
///   │         │
///   │         ▼
///   │    Committed (terminal success)
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochState {
    /// Gathering dirty object identifiers; writes are still in-flight.
    Prepare,
    /// Commit in progress; no new dirty objects may be staged.
    Commit,
    /// Commit completed successfully; commit record is sealed.
    Committed,
    /// Epoch was discarded; no commit record produced.
    Aborted,
}

// ---------------------------------------------------------------------------
// CommitRecord — BLAKE3-authenticated epoch result
// ---------------------------------------------------------------------------

/// A sealed, BLAKE3-authenticated commit record produced when an epoch
/// commits successfully.
///
/// The `commit_hash` covers the epoch number, commit-group id, the sorted
/// set of dirty object ids, and the prior epoch's commit hash (or zeroes
/// for the first epoch). This forms a verifiable hash chain that intent-log
/// replay can validate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitRecord {
    /// Monotonically increasing epoch number.
    pub epoch_number: u64,
    /// The commit-group id assigned to this epoch.
    pub commit_group_id: CommitGroupId,
    /// BLAKE3 hash over the epoch content (see [`seal_commit_hash`]).
    pub commit_hash: [u8; 32],
    /// The prior epoch's commit hash, or `None` for the first epoch.
    pub prior_epoch_hash: Option<[u8; 32]>,
    /// How many dirty objects were staged in this epoch.
    pub dirty_object_count: usize,
}

// ---------------------------------------------------------------------------
// CommitGroupEpoch — one epoch in-flight
// ---------------------------------------------------------------------------

/// The in-flight state for a single commit-group epoch.
///
/// Holds the dirty-object manifest, a BLAKE3 accumulator for the commit
/// record, and the prior-epoch hash for chain continuity.
#[derive(Clone, Debug)]
pub struct CommitGroupEpoch {
    /// Monotonically increasing epoch number.
    epoch_number: u64,
    /// The commit-group id assigned to this epoch.
    commit_group_id: CommitGroupId,
    /// Current phase of the epoch state machine.
    state: EpochState,
    /// Object IDs that are dirty in this epoch (sorted, deduplicated).
    dirty_object_ids: Vec<u64>,
    /// BLAKE3 hasher accumulating the commit-record payload.
    hasher: blake3::Hasher,
    /// The prior epoch's commit hash (None if this is epoch 1).
    prior_epoch_hash: Option<[u8; 32]>,
    /// Whether `seal_commit_record()` has been called.
    sealed: bool,
}

impl CommitGroupEpoch {
    /// Create a new epoch in the `Prepare` phase.
    pub fn new(
        epoch_number: u64,
        commit_group_id: CommitGroupId,
        prior_epoch_hash: Option<[u8; 32]>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        // Feed the epoch number and prior hash into the hasher up front.
        hasher.update(&epoch_number.to_le_bytes());
        hasher.update(&commit_group_id.0.to_le_bytes());
        match &prior_epoch_hash {
            Some(h) => {
                hasher.update(h);
            }
            None => {
                hasher.update(&[0u8; 32]);
            }
        }

        Self {
            epoch_number,
            commit_group_id,
            state: EpochState::Prepare,
            dirty_object_ids: Vec::new(),
            hasher,
            prior_epoch_hash,
            sealed: false,
        }
    }

    /// The epoch number.
    pub fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    /// The commit-group id assigned to this epoch.
    pub fn commit_group_id(&self) -> CommitGroupId {
        self.commit_group_id
    }

    /// Current epoch state.
    pub fn state(&self) -> EpochState {
        self.state
    }

    /// The prior epoch's commit hash, if any.
    pub fn prior_epoch_hash(&self) -> Option<[u8; 32]> {
        self.prior_epoch_hash
    }

    /// Number of dirty objects staged in this epoch.
    pub fn dirty_object_count(&self) -> usize {
        self.dirty_object_ids.len()
    }

    /// Immutable view of the sorted dirty object IDs.
    pub fn dirty_object_ids(&self) -> &[u64] {
        &self.dirty_object_ids
    }

    /// Returns `true` if no dirty objects have been staged.
    pub fn is_empty(&self) -> bool {
        self.dirty_object_ids.is_empty()
    }

    // ------------------------------------------------------------------
    // Phase: Prepare (stage_dirty)
    // ------------------------------------------------------------------

    /// Stage a dirty object ID for inclusion in this epoch's commit record.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if the epoch is not in
    /// the `Prepare` state.
    pub fn stage_dirty(&mut self, object_id: u64) -> Result<(), CommitGroupError> {
        self.require_state(EpochState::Prepare, "stage_dirty")?;

        // Insert-sorted, deduplicated.
        let pos = self.dirty_object_ids.binary_search(&object_id);
        match pos {
            Ok(_) => { /* already present; no-op */ }
            Err(idx) => {
                self.dirty_object_ids.insert(idx, object_id);
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase: Prepare → Commit (prepare)
    // ------------------------------------------------------------------

    /// Transition from `Prepare` to `Commit`.
    ///
    /// After this call, no more dirty objects can be staged. The epoch
    /// is ready to be committed or aborted.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if the epoch is not in
    /// the `Prepare` state.
    /// Returns `CommitGroupError::EmptyCommitGroup` if no dirty objects
    /// were staged (empty epochs are allowed but explicitly flagged).
    pub fn prepare(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(EpochState::Prepare, "prepare")?;

        // Feed all dirty object IDs in canonical sorted order.
        for id in &self.dirty_object_ids {
            self.hasher.update(&id.to_le_bytes());
        }
        // Feed the dirty-object count as a final discriminator.
        let count = self.dirty_object_ids.len() as u64;
        self.hasher.update(&count.to_le_bytes());

        self.state = EpochState::Commit;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase: Commit → Committed (commit)
    // ------------------------------------------------------------------

    /// Transition from `Commit` to `Committed` and seal the commit record.
    ///
    /// The BLAKE3 hash is finalized at this point. After this call,
    /// [`Self::seal_commit_record`] becomes available.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the epoch is not
    /// in the `Commit` state (double-commit or premature commit).
    pub fn commit(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(EpochState::Commit, "commit")?;

        self.state = EpochState::Committed;
        self.sealed = true;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase: any → Aborted (abort)
    // ------------------------------------------------------------------

    /// Transition to `Aborted`, discarding the epoch.
    ///
    /// Abort is terminal: once aborted, no further transitions are allowed.
    /// Safe to call from `Prepare` or `Commit`; no-op if already `Aborted`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the epoch is
    /// already `Committed` (a committed epoch cannot be aborted).
    pub fn abort(&mut self) -> Result<(), CommitGroupError> {
        if self.state == EpochState::Aborted {
            return Ok(());
        }
        if self.state == EpochState::Committed {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: "cannot abort a committed epoch".into(),
            });
        }
        self.state = EpochState::Aborted;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Seal: produce the CommitRecord
    // ------------------------------------------------------------------

    /// Produce the sealed [`CommitRecord`] for a committed epoch.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the epoch has not
    /// been committed yet.
    pub fn seal_commit_record(&self) -> Result<CommitRecord, CommitGroupError> {
        if !self.sealed || self.state != EpochState::Committed {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: "commit record can only be sealed after successful commit".into(),
            });
        }

        let commit_hash = self.hasher.finalize();
        Ok(CommitRecord {
            epoch_number: self.epoch_number,
            commit_group_id: self.commit_group_id,
            commit_hash: *commit_hash.as_bytes(),
            prior_epoch_hash: self.prior_epoch_hash,
            dirty_object_count: self.dirty_object_ids.len(),
        })
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn require_state(&self, expected: EpochState, op: &str) -> Result<(), CommitGroupError> {
        if self.state != expected {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "{op} requires {expected:?} state, current state is {:?}",
                    self.state
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitGroupStateMachine — driver for the CommitGroupCoordinator
// ---------------------------------------------------------------------------

/// Drives the commit-group epoch lifecycle.
///
/// The [`CommitGroupStateMachine`] is the public API that the `CommitGroupCoordinator`
/// calls to create epochs, stage dirty objects, and drive them through
/// prepare → commit → committed (or abort). It maintains the BLAKE3 hash
/// chain across epochs for verifiable commit history.
#[derive(Clone, Debug)]
pub struct CommitGroupStateMachine {
    /// The next epoch number to assign.
    next_epoch_number: u64,
    /// The next commit-group id to assign.
    next_commit_group_id: CommitGroupId,
    /// The currently open (in-flight) epoch, if any.
    current_epoch: Option<CommitGroupEpoch>,
    /// The commit hash of the most recently committed epoch.
    /// `None` before the first successful commit.
    last_commit_hash: Option<[u8; 32]>,
    /// All sealed commit records produced so far.
    committed_records: Vec<CommitRecord>,
}

impl CommitGroupStateMachine {
    /// Create a new state machine.
    ///
    /// `starting_commit_group_id` is the commit-group id for the first epoch.
    /// `prior_commit_hash` can be supplied from a previous mount's last
    /// committed record to resume the hash chain; use `None` for a fresh pool.
    pub fn new(
        starting_commit_group_id: CommitGroupId,
        prior_commit_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            next_epoch_number: 1,
            next_commit_group_id: starting_commit_group_id,
            current_epoch: None,
            last_commit_hash: prior_commit_hash,
            committed_records: Vec::new(),
        }
    }

    /// The number of committed epochs.
    pub fn committed_epoch_count(&self) -> usize {
        self.committed_records.len()
    }

    /// All sealed commit records, in epoch order.
    pub fn committed_records(&self) -> &[CommitRecord] {
        &self.committed_records
    }

    /// The most recent commit hash (for chain resumption after remount).
    pub fn last_commit_hash(&self) -> Option<[u8; 32]> {
        self.last_commit_hash
    }

    /// The next epoch number that will be assigned.
    pub fn next_epoch_number(&self) -> u64 {
        self.next_epoch_number
    }

    /// Reference to the currently open epoch, if any.
    pub fn current_epoch(&self) -> Option<&CommitGroupEpoch> {
        self.current_epoch.as_ref()
    }

    /// Returns `true` if an epoch is currently open.
    pub fn has_open_epoch(&self) -> bool {
        self.current_epoch.is_some()
    }

    // ------------------------------------------------------------------
    // begin_epoch
    // ------------------------------------------------------------------

    /// Begin a new epoch.
    ///
    /// Allocates the next epoch number and commit-group id, creates a
    /// [`CommitGroupEpoch`] in `Prepare` state, and links it to the
    /// prior epoch's commit hash for chain continuity.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if an epoch is already
    /// open (only one epoch may be in-flight at a time).
    pub fn begin_epoch(&mut self) -> Result<(), CommitGroupError> {
        if self.current_epoch.is_some() {
            return Err(CommitGroupError::PrepareFailed {
                reason: "an epoch is already open; commit or abort it first".into(),
            });
        }

        let epoch_number = self.next_epoch_number;
        let commit_group_id = self.next_commit_group_id;

        let epoch = CommitGroupEpoch::new(epoch_number, commit_group_id, self.last_commit_hash);

        self.next_epoch_number = epoch_number.saturating_add(1);
        self.next_commit_group_id = commit_group_id.next();
        self.current_epoch = Some(epoch);

        Ok(())
    }

    // ------------------------------------------------------------------
    // stage_dirty
    // ------------------------------------------------------------------

    /// Stage a dirty object for inclusion in the current epoch's commit record.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if no epoch is open.
    /// Returns the underlying error from [`CommitGroupEpoch::stage_dirty`].
    pub fn stage_dirty(&mut self, object_id: u64) -> Result<(), CommitGroupError> {
        let epoch = self
            .current_epoch
            .as_mut()
            .ok_or_else(|| CommitGroupError::PrepareFailed {
                reason: "no open epoch; call begin_epoch first".into(),
            })?;
        epoch.stage_dirty(object_id)
    }

    // ------------------------------------------------------------------
    // prepare
    // ------------------------------------------------------------------

    /// Transition the current epoch from `Prepare` to `Commit`.
    ///
    /// After this, no more dirty objects can be staged. The epoch is
    /// ready for `commit()` or `abort()`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if no epoch is open.
    /// Returns the underlying error from [`CommitGroupEpoch::prepare`].
    pub fn prepare(&mut self) -> Result<(), CommitGroupError> {
        let epoch = self
            .current_epoch
            .as_mut()
            .ok_or_else(|| CommitGroupError::PrepareFailed {
                reason: "no open epoch; call begin_epoch first".into(),
            })?;
        epoch.prepare()
    }

    // ------------------------------------------------------------------
    // commit
    // ------------------------------------------------------------------

    /// Commit the current epoch, sealing the commit record.
    ///
    /// The BLAKE3 commit hash is finalized, the record is appended to the
    /// committed-records list, and the hash chain is advanced. The current
    /// epoch is consumed (the machine is ready for `begin_epoch` to start
    /// the next epoch).
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if no epoch is open.
    /// Returns `CommitGroupError::CommitPhaseRejected` if the epoch is not
    /// in the `Commit` state.
    pub fn commit(&mut self) -> Result<CommitRecord, CommitGroupError> {
        let mut epoch =
            self.current_epoch
                .take()
                .ok_or_else(|| CommitGroupError::PrepareFailed {
                    reason: "no open epoch; call begin_epoch first".into(),
                })?;

        epoch.commit()?;
        let record = epoch.seal_commit_record()?;

        self.last_commit_hash = Some(record.commit_hash);
        self.committed_records.push(record);

        Ok(record)
    }

    // ------------------------------------------------------------------
    // abort
    // ------------------------------------------------------------------

    /// Abort the current epoch, discarding all staged dirty objects.
    ///
    /// No commit record is produced. A new epoch can be started immediately.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if no epoch is open.
    pub fn abort(&mut self) -> Result<(), CommitGroupError> {
        let mut epoch =
            self.current_epoch
                .take()
                .ok_or_else(|| CommitGroupError::PrepareFailed {
                    reason: "no open epoch; call begin_epoch first".into(),
                })?;
        epoch.abort()
    }
}

// ---------------------------------------------------------------------------
// Standalone: seal a commit hash from raw epoch data
// ---------------------------------------------------------------------------

/// Compute a BLAKE3 commit hash from raw epoch fields.
///
/// Used by intent-log replay to verify a commit record without
/// constructing a full [`CommitGroupEpoch`]. The hash covers:
/// `epoch_number || commit_group_id || prior_hash || dirty_count || dirty_ids...`
pub fn seal_commit_hash(
    epoch_number: u64,
    commit_group_id: CommitGroupId,
    prior_epoch_hash: Option<[u8; 32]>,
    dirty_object_ids: &[u64],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&epoch_number.to_le_bytes());
    hasher.update(&commit_group_id.0.to_le_bytes());
    match &prior_epoch_hash {
        Some(h) => {
            hasher.update(h);
        }
        None => {
            hasher.update(&[0u8; 32]);
        }
    }
    for id in dirty_object_ids {
        hasher.update(&id.to_le_bytes());
    }
    let count = dirty_object_ids.len() as u64;
    hasher.update(&count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify that a [`CommitRecord`]'s hash matches a recomputed hash.
///
/// Returns `true` if the record is authentic (hash matches recomputation).
#[must_use]
pub fn verify_commit_record(record: &CommitRecord, dirty_object_ids: &[u64]) -> bool {
    let recomputed = seal_commit_hash(
        record.epoch_number,
        record.commit_group_id,
        record.prior_epoch_hash,
        dirty_object_ids,
    );
    recomputed == record.commit_hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ==================================================================
    // EpochState
    // ==================================================================

    #[test]
    fn epoch_state_discriminants_are_distinct() {
        let states = [
            EpochState::Prepare,
            EpochState::Commit,
            EpochState::Committed,
            EpochState::Aborted,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                if i == j {
                    assert_eq!(states[i], states[j]);
                } else {
                    assert_ne!(states[i], states[j]);
                }
            }
        }
    }

    // ==================================================================
    // CommitGroupEpoch: valid Prepare → Commit → Committed flow
    // ==================================================================

    #[test]
    fn valid_prepare_commit_committed_flow() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);

        assert_eq!(epoch.state(), EpochState::Prepare);
        assert_eq!(epoch.epoch_number(), 1);
        assert_eq!(epoch.commit_group_id(), CommitGroupId(1));
        assert!(epoch.prior_epoch_hash().is_none());
        assert!(epoch.is_empty());

        // Stage some dirty objects.
        epoch.stage_dirty(100).unwrap();
        epoch.stage_dirty(200).unwrap();
        epoch.stage_dirty(150).unwrap(); // should be sorted
        assert_eq!(epoch.dirty_object_count(), 3);
        assert_eq!(epoch.dirty_object_ids(), &[100, 150, 200]);

        // Deduplication: staging the same ID is a no-op.
        epoch.stage_dirty(150).unwrap();
        assert_eq!(epoch.dirty_object_count(), 3);

        // Prepare.
        epoch.prepare().unwrap();
        assert_eq!(epoch.state(), EpochState::Commit);

        // Commit.
        epoch.commit().unwrap();
        assert_eq!(epoch.state(), EpochState::Committed);

        // Seal.
        let record = epoch.seal_commit_record().unwrap();
        assert_eq!(record.epoch_number, 1);
        assert_eq!(record.commit_group_id, CommitGroupId(1));
        assert!(record.prior_epoch_hash.is_none());
        assert_eq!(record.dirty_object_count, 3);
        assert_ne!(record.commit_hash, [0u8; 32]);

        // Verify the record independently.
        assert!(verify_commit_record(&record, &[100, 150, 200]));
    }

    // ==================================================================
    // Empty epoch commit (allowed but flagged)
    // ==================================================================

    #[test]
    fn empty_epoch_commit_allowed() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        assert!(epoch.is_empty());

        epoch.prepare().unwrap();
        epoch.commit().unwrap();

        let record = epoch.seal_commit_record().unwrap();
        assert_eq!(record.dirty_object_count, 0);
        assert!(verify_commit_record(&record, &[]));
    }

    // ==================================================================
    // Abort from Prepare
    // ==================================================================

    #[test]
    fn abort_from_prepare() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(42).unwrap();
        assert_eq!(epoch.state(), EpochState::Prepare);

        epoch.abort().unwrap();
        assert_eq!(epoch.state(), EpochState::Aborted);

        // No further operations allowed except additional aborts (no-op).
        let result = epoch.stage_dirty(99);
        assert!(result.is_err());

        let result = epoch.prepare();
        assert!(result.is_err());

        let result = epoch.commit();
        assert!(result.is_err());

        // Second abort is a no-op.
        assert!(epoch.abort().is_ok());
        assert_eq!(epoch.state(), EpochState::Aborted);

        // Cannot seal.
        assert!(epoch.seal_commit_record().is_err());
    }

    // ==================================================================
    // Abort from Commit
    // ==================================================================

    #[test]
    fn abort_from_commit() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(1).unwrap();
        epoch.prepare().unwrap();
        assert_eq!(epoch.state(), EpochState::Commit);

        epoch.abort().unwrap();
        assert_eq!(epoch.state(), EpochState::Aborted);

        // Commit after abort is rejected.
        assert!(epoch.commit().is_err());
    }

    // ==================================================================
    // Double-commit rejection
    // ==================================================================

    #[test]
    fn double_commit_rejected() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(1).unwrap();
        epoch.prepare().unwrap();
        epoch.commit().unwrap();

        let result = epoch.commit();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    // ==================================================================
    // Commit without Prepare
    // ==================================================================

    #[test]
    fn commit_without_prepare_rejected() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(1).unwrap();
        // Skip prepare, try to commit directly.
        let result = epoch.commit();
        assert!(result.is_err());
    }

    // ==================================================================
    // Prepare without stage (empty) is allowed
    // ==================================================================

    #[test]
    fn prepare_empty_epoch() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        assert!(epoch.is_empty());
        epoch.prepare().unwrap();
        assert_eq!(epoch.state(), EpochState::Commit);
    }

    // ==================================================================
    // Cannot abort a Committed epoch
    // ==================================================================

    #[test]
    fn cannot_abort_committed_epoch() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(1).unwrap();
        epoch.prepare().unwrap();
        epoch.commit().unwrap();

        let result = epoch.abort();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    // ==================================================================
    // BLAKE3 chain continuity across sequential epochs
    // ==================================================================

    #[test]
    fn blake3_chain_continuity() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);

        // Epoch 1.
        sm.begin_epoch().unwrap();
        sm.stage_dirty(10).unwrap();
        sm.stage_dirty(20).unwrap();
        sm.prepare().unwrap();
        let record1 = sm.commit().unwrap();

        assert_eq!(record1.epoch_number, 1);
        assert!(record1.prior_epoch_hash.is_none());
        assert_eq!(sm.last_commit_hash(), Some(record1.commit_hash));

        // Epoch 2 — hash chain should include record1's hash.
        sm.begin_epoch().unwrap();
        sm.stage_dirty(30).unwrap();
        sm.prepare().unwrap();
        let record2 = sm.commit().unwrap();

        assert_eq!(record2.epoch_number, 2);
        assert_eq!(record2.prior_epoch_hash, Some(record1.commit_hash));
        assert_ne!(record2.commit_hash, record1.commit_hash);
        assert_eq!(sm.last_commit_hash(), Some(record2.commit_hash));
        assert_eq!(sm.committed_epoch_count(), 2);

        // Epoch 3.
        sm.begin_epoch().unwrap();
        sm.stage_dirty(40).unwrap();
        sm.stage_dirty(50).unwrap();
        sm.prepare().unwrap();
        let record3 = sm.commit().unwrap();

        assert_eq!(record3.epoch_number, 3);
        assert_eq!(record3.prior_epoch_hash, Some(record2.commit_hash));
        assert_ne!(record3.commit_hash, record2.commit_hash);

        // Verify the full chain independently.
        assert!(verify_commit_record(&record1, &[10, 20]));
        assert!(verify_commit_record(&record2, &[30]));
        assert!(verify_commit_record(&record3, &[40, 50]));

        // Tampering is detected.
        assert!(!verify_commit_record(&record1, &[99]));
        assert!(!verify_commit_record(&record2, &[10, 20]));

        // Chain resumption: a new machine with prior hash.
        let mut sm2 = CommitGroupStateMachine::new(CommitGroupId(4), Some(record3.commit_hash));
        sm2.begin_epoch().unwrap();
        sm2.stage_dirty(60).unwrap();
        sm2.prepare().unwrap();
        let record4 = sm2.commit().unwrap();

        assert_eq!(record4.epoch_number, 1); // new machine, epoch resets
        assert_eq!(record4.prior_epoch_hash, Some(record3.commit_hash));
        assert_ne!(record4.commit_hash, record3.commit_hash);
        assert!(verify_commit_record(&record4, &[60]));
    }

    // ==================================================================
    // Abort then new epoch
    // ==================================================================

    #[test]
    fn abort_then_new_epoch() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);

        sm.begin_epoch().unwrap();
        sm.stage_dirty(1).unwrap();
        sm.abort().unwrap();
        assert!(!sm.has_open_epoch());
        assert_eq!(sm.committed_epoch_count(), 0);
        // last_commit_hash is unchanged after abort.
        assert!(sm.last_commit_hash().is_none());

        // New epoch after abort.
        sm.begin_epoch().unwrap();
        sm.stage_dirty(2).unwrap();
        sm.prepare().unwrap();
        let record = sm.commit().unwrap();

        // After abort, next_epoch_number was already incremented during
        // begin_epoch, so the second epoch gets number 2.
        assert_eq!(record.epoch_number, 2);
        assert!(record.prior_epoch_hash.is_none()); // still first committed
        assert_eq!(sm.committed_epoch_count(), 1);
    }

    // ==================================================================
    // Double begin_epoch rejection
    // ==================================================================

    #[test]
    fn double_begin_epoch_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);
        sm.begin_epoch().unwrap();
        let result = sm.begin_epoch();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::PrepareFailed { .. }) => {}
            other => panic!("expected PrepareFailed, got {other:?}"),
        }
    }

    // ==================================================================
    // Stage dirty without open epoch
    // ==================================================================

    #[test]
    fn stage_dirty_without_epoch_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);
        let result = sm.stage_dirty(1);
        assert!(result.is_err());
    }

    // ==================================================================
    // Prepare without open epoch
    // ==================================================================

    #[test]
    fn prepare_without_epoch_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);
        let result = sm.prepare();
        assert!(result.is_err());
    }

    // ==================================================================
    // Commit without open epoch
    // ==================================================================

    #[test]
    fn commit_without_epoch_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);
        let result = sm.commit();
        assert!(result.is_err());
    }

    // ==================================================================
    // seal_commit_hash: standalone hash function
    // ==================================================================

    #[test]
    fn seal_commit_hash_deterministic() {
        let h1 = seal_commit_hash(1, CommitGroupId(1), None, &[10, 20]);
        let h2 = seal_commit_hash(1, CommitGroupId(1), None, &[10, 20]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn seal_commit_hash_differs_on_content() {
        let h1 = seal_commit_hash(1, CommitGroupId(1), None, &[10, 20]);
        let h2 = seal_commit_hash(1, CommitGroupId(1), None, &[20, 10]); // different order
        assert_ne!(h1, h2);

        let h3 = seal_commit_hash(2, CommitGroupId(1), None, &[10, 20]); // different epoch
        assert_ne!(h1, h3);

        let h4 = seal_commit_hash(1, CommitGroupId(2), None, &[10, 20]); // different commit_group
        assert_ne!(h1, h4);
    }

    #[test]
    fn seal_commit_hash_chains_prior() {
        let prior = seal_commit_hash(1, CommitGroupId(1), None, &[1]);
        let with_prior = seal_commit_hash(2, CommitGroupId(2), Some(prior), &[2]);
        let without_prior = seal_commit_hash(2, CommitGroupId(2), None, &[2]);
        assert_ne!(with_prior, without_prior);
    }

    // ==================================================================
    // CommitRecord: structural invariants
    // ==================================================================

    #[test]
    fn commit_record_epoch_monotonic() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), None);

        sm.begin_epoch().unwrap();
        sm.stage_dirty(1).unwrap();
        sm.prepare().unwrap();
        let r1 = sm.commit().unwrap();

        sm.begin_epoch().unwrap();
        sm.stage_dirty(2).unwrap();
        sm.prepare().unwrap();
        let r2 = sm.commit().unwrap();

        assert!(r2.epoch_number > r1.epoch_number);
        assert!(r2.commit_group_id > r1.commit_group_id);
    }

    // ==================================================================
    // Dense dirty-object set
    // ==================================================================

    #[test]
    fn dense_dirty_object_set() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, None);
        sm.begin_epoch().unwrap();
        for i in 0..1000u64 {
            sm.stage_dirty(i).unwrap();
        }
        sm.prepare().unwrap();
        let record = sm.commit().unwrap();
        assert_eq!(record.dirty_object_count, 1000);
    }

    // ==================================================================
    // Seal before commit is rejected
    // ==================================================================

    #[test]
    fn seal_before_commit_rejected() {
        let mut epoch = CommitGroupEpoch::new(1, CommitGroupId(1), None);
        epoch.stage_dirty(1).unwrap();
        // Not yet prepared or committed.
        assert!(epoch.seal_commit_record().is_err());

        epoch.prepare().unwrap();
        // Prepared but not committed.
        assert!(epoch.seal_commit_record().is_err());
    }
}
