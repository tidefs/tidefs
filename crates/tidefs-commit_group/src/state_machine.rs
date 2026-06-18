// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Commit-group state machine with CommitGroupCoordinator anchoring and
//! BLAKE3 chain-digest verification.
//!
//! The state machine governs the lifecycle of a transaction commit group from
//! open through sealed, committing, committed, and applied (or aborted). It
//! provides the group-level abstraction that CommitGroupCoordinator uses to bracket
//! intent-log records within well-defined commit-group boundaries.
//!
//! Each committed group computes a domain-separated BLAKE3-256 chain digest
//! that cryptographically links to its predecessor, forming a tamper-evident
//! commit history. The digest is computed via `compute_chain_digest` using
//! the same scheme as `CommitGroupCoordinator::chain_digest`.
//!
//! # State transitions
//!
//! ```text
//!                     seal()
//!   Open ─────────────────────────► Sealed
//!    │                                 │
//!    │                                 │ begin_commit()
//!    │ abort()                         │
//!    │                                 ▼
//!    │                            Committing
//!    │                                 │
//!    │                                 │ complete_commit(commit_data)
//!    │                                 │   ─ computes chain digest
//!    │                                 ▼
//!    │                             Committed
//!    │                                 │
//!    │                                 │ apply()
//!    │                                 ▼
//!    │                              Applied (terminal)
//!    ▼
//!  Aborted ◄──── abort() ──── (from Open/Sealed/Committing)
//!    │
//!    │ open()
//!    └──► Open (resets chain digest)
//! ```
//!
//! `Sealing` is defined in the enum for future async-seal support but
//! is not reachable through the primary transition methods in this version.

use crate::types::{CommitGroupError, CommitGroupId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CommitGroupState — lifecycle states
// ---------------------------------------------------------------------------

/// Lifecycle state of a commit group.
///
/// The group flows from `Open` (accepting writes) through `Sealed` (no new
/// writes, ready to commit) and `Committing` (commit in progress) to
/// `Committed` (terminal success). At any point before `Committed`, the
/// group can be `Aborted`, discarding all staged data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CommitGroupState {
    /// Accepting writes and metadata mutations.
    Open,
    /// Seal in progress; no new writes accepted (reserved for async seal).
    Sealing,
    /// Sealed; ready to begin commit.
    Sealed,
    /// Commit in progress; intent-log records are being written.
    Committing,
    /// Commit completed successfully; terminal success state.
    Committed,
    /// Committed group has been applied to the live system state.
    Applied,
    /// Group discarded; terminal failure state.
    Aborted,
}

impl CommitGroupState {
    /// Returns `true` if the state is terminal (no further transitions
    /// except `open()` from `Aborted`).
    /// Returns `true` if the group has been applied to the live system.
    #[must_use]
    pub fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }

    /// Returns `true` if the state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Applied | Self::Aborted)
    }

    /// Returns `true` if writes can still be accepted in this state.
    #[must_use]
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Open)
    }
}

// ---------------------------------------------------------------------------
// CommitGroupStateMachine
// ---------------------------------------------------------------------------

/// Drives a single commit group through its lifecycle.
///
/// Holds the current state and the transaction group identifier. All
/// transitions are guarded: invalid transitions return a clear
/// [`CommitGroupError::CommitPhaseRejected`] describing the mismatch.
///
/// # Example
///
/// ```ignore
/// let mut sm = CommitGroupStateMachine::new(CommitGroupId::FIRST, [0u8; 32]);
/// assert!(sm.is_open());
/// sm.seal().unwrap();
/// sm.begin_commit().unwrap();
/// sm.complete_commit(b"test").unwrap();
/// assert!(sm.is_committed());
/// ```
#[derive(Clone, Debug)]
pub struct CommitGroupStateMachine {
    state: CommitGroupState,
    txg_id: CommitGroupId,
    /// BLAKE3-256 chain digest from the most recent committed group
    /// in the chain; zero for the first group or after abort/re-open.
    chain_digest: [u8; 32],
}

impl CommitGroupStateMachine {
    /// Create a new state machine starting in `Open` state.
    ///
    /// `prior_chain_digest` is the BLAKE3 chain digest of the most recent
    /// committed group. Pass `[0u8; 32]` for the first group in a chain.
    #[must_use]
    pub fn new(txg_id: CommitGroupId, prior_chain_digest: [u8; 32]) -> Self {
        Self {
            state: CommitGroupState::Open,
            txg_id,
            chain_digest: prior_chain_digest,
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> CommitGroupState {
        self.state
    }

    /// The transaction group identifier.
    #[must_use]
    pub fn txg_id(&self) -> CommitGroupId {
        self.txg_id
    }

    /// The BLAKE3-256 chain digest of the most recent committed group
    /// in the chain (the prior digest used to chain this group).
    #[must_use]
    pub fn chain_digest(&self) -> [u8; 32] {
        self.chain_digest
    }

    /// Returns `true` if the group is in `Open` state.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state == CommitGroupState::Open
    }

    /// Returns `true` if the group is in `Sealed` state.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.state == CommitGroupState::Sealed
    }

    /// Returns `true` if the group is in `Committing` state.
    #[must_use]
    pub fn is_committing(&self) -> bool {
        self.state == CommitGroupState::Committing
    }

    /// Returns `true` if the group is in `Committed` state.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.state == CommitGroupState::Committed
    }

    /// Returns `true` if the group is in `Applied` state.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        self.state == CommitGroupState::Applied
    }

    /// Returns `true` if the group is in `Aborted` state.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.state == CommitGroupState::Aborted
    }

    /// Returns `true` if the state is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    // ------------------------------------------------------------------
    // Transition: open
    // ------------------------------------------------------------------

    /// Return the machine to `Open` state.
    ///
    /// Valid from: `Aborted` (re-open after abort) or `Open` (no-op).
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if called from any
    /// other state.
    pub fn open(&mut self) -> Result<(), CommitGroupError> {
        match self.state {
            CommitGroupState::Aborted | CommitGroupState::Open => {
                self.state = CommitGroupState::Open;
                self.chain_digest = [0u8; 32];
                Ok(())
            }
            _ => Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "open requires Open or Aborted state, current: {:?}",
                    self.state
                ),
            }),
        }
    }

    // ------------------------------------------------------------------
    // Transition: seal
    // ------------------------------------------------------------------

    /// Seal the commit group: `Open` → `Sealed`.
    ///
    /// After sealing, no new writes or mutations can be added. The group
    /// is ready for `begin_commit()`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Open` state (double-seal, seal-after-abort, etc.).
    pub fn seal(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(CommitGroupState::Open, "seal")?;
        self.state = CommitGroupState::Sealed;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: begin_commit
    // ------------------------------------------------------------------

    /// Begin the commit phase: `Sealed` → `Committing`.
    ///
    /// Intent-log records should be written during this phase. After this
    /// call, the commit must either be completed or aborted.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Sealed` state.
    pub fn begin_commit(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(CommitGroupState::Sealed, "begin_commit")?;
        self.state = CommitGroupState::Committing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: complete_commit
    // ------------------------------------------------------------------

    /// Complete the commit: `Committing` → `Committed`.
    ///
    /// Computes and stores the BLAKE3 chain digest for this commit group
    /// using domain-separated key derivation. The digest chains this
    /// group to its predecessor, making the commit history tamper-evident.
    ///
    /// `commit_data` is the opaque commit payload (e.g., intent-log record
    /// content or segment footer bytes) that gets hashed into the chain.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Committing` state.
    pub fn complete_commit(&mut self, commit_data: &[u8]) -> Result<(), CommitGroupError> {
        self.require_state(CommitGroupState::Committing, "complete_commit")?;
        self.chain_digest = compute_chain_digest(&self.chain_digest, commit_data);
        self.state = CommitGroupState::Committed;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: apply
    // ------------------------------------------------------------------

    /// Apply the committed group to the live system: `Committed` → `Applied`.
    ///
    /// After this call, the commit group's changes are visible to readers.
    /// This is terminal: once applied, the group cannot be aborted
    /// or re-opened.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Committed` state.
    pub fn apply(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(CommitGroupState::Committed, "apply")?;
        self.state = CommitGroupState::Applied;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: abort
    // ------------------------------------------------------------------

    /// Abort the commit group, discarding all staged data.
    ///
    /// Valid from: `Open`, `Sealing`, `Sealed`, or `Committing`.
    /// No-op if already `Aborted`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is
    /// already `Committed` (a committed group cannot be aborted).
    pub fn abort(&mut self) -> Result<(), CommitGroupError> {
        match self.state {
            CommitGroupState::Committed | CommitGroupState::Applied => {
                Err(CommitGroupError::CommitPhaseRejected {
                    reason: "cannot abort a Committed group".into(),
                })
            }
            CommitGroupState::Aborted => Ok(()),
            _ => {
                self.state = CommitGroupState::Aborted;
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn require_state(&self, expected: CommitGroupState, op: &str) -> Result<(), CommitGroupError> {
        if self.state != expected {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "{op} requires {expected:?} state, current: {:?}",
                    self.state
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TxgHandle — trait for CommitGroupCoordinator anchoring
// ---------------------------------------------------------------------------

/// Abstraction that [`crate::TxgHandle`] implementors use to bracket
/// intent-log records within a commit group.
///
/// The `CommitGroupCoordinator` (#4942) calls these methods to drive commit-group
/// lifecycle: open, accumulate writes, seal, begin_commit (write intent-log
/// records), complete_commit, apply, or abort on failure.
pub trait TxgHandle {
    /// The transaction group identifier.
    fn txg_id(&self) -> CommitGroupId;

    /// Current group lifecycle state.
    fn group_state(&self) -> CommitGroupState;

    /// Returns `true` if the group is accepting writes.
    fn is_open(&self) -> bool;

    /// Seal the group so no more writes are accepted.
    fn seal(&mut self) -> Result<(), CommitGroupError>;

    /// Begin the commit phase (intent-log records written here).
    fn begin_commit(&mut self) -> Result<(), CommitGroupError>;

    /// Complete the commit, computing and storing the BLAKE3 chain digest.
    fn complete_commit(&mut self, commit_data: &[u8]) -> Result<(), CommitGroupError>;

    /// Apply the committed group to the live system state.
    fn apply(&mut self) -> Result<(), CommitGroupError>;

    /// Abort the group, discarding all staged data.
    fn abort(&mut self) -> Result<(), CommitGroupError>;

    /// The BLAKE3-256 chain digest (prior digest used to chain this group).
    fn chain_digest(&self) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// TxgHandle impl for CommitGroupStateMachine
// ---------------------------------------------------------------------------

impl TxgHandle for CommitGroupStateMachine {
    fn txg_id(&self) -> CommitGroupId {
        self.txg_id()
    }

    fn group_state(&self) -> CommitGroupState {
        self.state()
    }

    fn is_open(&self) -> bool {
        self.is_open()
    }

    fn seal(&mut self) -> Result<(), CommitGroupError> {
        self.seal()
    }

    fn begin_commit(&mut self) -> Result<(), CommitGroupError> {
        self.begin_commit()
    }

    fn complete_commit(&mut self, commit_data: &[u8]) -> Result<(), CommitGroupError> {
        self.complete_commit(commit_data)
    }

    fn apply(&mut self) -> Result<(), CommitGroupError> {
        self.apply()
    }

    fn abort(&mut self) -> Result<(), CommitGroupError> {
        self.abort()
    }

    fn chain_digest(&self) -> [u8; 32] {
        self.chain_digest()
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 chain-digest computation
// ---------------------------------------------------------------------------

/// Domain context for commit-group chain digest derivation.
const COMMIT_GROUP_CHAIN_CONTEXT: &str = "TideFS CommitGroup Chain v1";

/// Domain discriminant for commit-group chain digests.
const CHAIN_DOMAIN_DISCRIMINANT: u8 = 0x0B;

/// Compute a domain-separated BLAKE3-256 chain digest.
///
/// The digest chains the new commit to its predecessor:
/// `BLAKE3-keyed(derive_key(context, discriminant), prior_digest || commit_data)`.
///
/// This is the same domain-separation scheme used by [`crate::CommitGroupCoordinator`],
/// ensuring all chain digests across the system share a common verifiable format.
#[must_use]
pub fn compute_chain_digest(prior_digest: &[u8; 32], commit_data: &[u8]) -> [u8; 32] {
    let key = blake3::derive_key(COMMIT_GROUP_CHAIN_CONTEXT, &[CHAIN_DOMAIN_DISCRIMINANT]);
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(prior_digest);
    hasher.update(commit_data);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// GroupCommitState — multi-member group commit lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle state of a multi-member commit group.
///
/// A commit group with multiple storage members flows through:
/// `Open` (accepting writes) -> `Committing` (durability in progress) ->
/// `Committed` (all members durable) -> `Checkpoint` (checkpoint persisted).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GroupCommitState {
    /// Accepting writes from all members.
    Open,
    /// Durability in progress; members are acknowledging their writes.
    Committing,
    /// All members have acknowledged durability; awaiting checkpoint write.
    Committed,
    /// Checkpoint persisted to the intent log; terminal success state.
    Checkpoint,
}

impl GroupCommitState {
    /// Returns `true` if the state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Checkpoint)
    }

    /// Returns `true` if writes can still be accepted.
    #[must_use]
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns `true` if durability acknowledgments are accepted.
    #[must_use]
    pub fn accepts_acks(self) -> bool {
        matches!(self, Self::Committing)
    }
}

// ---------------------------------------------------------------------------
// GroupCommitStateMachine
// ---------------------------------------------------------------------------

/// Drives a multi-member commit group through its lifecycle.
///
/// Tracks member durability acknowledgments and enforces valid state
/// transitions. On recovery, the state machine can be reconstructed from
/// the last known checkpoint to determine which transaction groups need
/// intent-log replay.
///
/// # State transitions
///
/// ```text
///   Open ──close()──► Committing
///                         │
///            acknowledge_durability() per member
///                         │
///                         ▼ (all members acked)
///                     Committed
///                         │
///                   write_checkpoint()
///                         │
///                         ▼
///                    Checkpoint (terminal)
/// ```
#[derive(Clone, Debug)]
pub struct GroupCommitStateMachine {
    txg_id: CommitGroupId,
    state: GroupCommitState,
    /// Ordered set of member identifiers in this commit group.
    member_ids: Vec<u64>,
    /// Members that have acknowledged durability (subset of member_ids).
    durability_acks: Vec<u64>,
}

impl GroupCommitStateMachine {
    /// Create a new state machine starting in `Open` state with the given
    /// member set.
    ///
    /// `member_ids` must be non-empty and sorted in ascending order.
    #[must_use]
    pub fn new(txg_id: CommitGroupId, member_ids: Vec<u64>) -> Self {
        debug_assert!(!member_ids.is_empty(), "member_ids must be non-empty");
        Self {
            txg_id,
            state: GroupCommitState::Open,
            member_ids,
            durability_acks: Vec::new(),
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> GroupCommitState {
        self.state
    }

    /// The transaction group identifier.
    #[must_use]
    pub fn txg_id(&self) -> CommitGroupId {
        self.txg_id
    }

    /// Immutable view of all member identifiers.
    #[must_use]
    pub fn member_ids(&self) -> &[u64] {
        &self.member_ids
    }

    /// Number of members in this commit group.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_ids.len()
    }

    /// Members that have acknowledged durability so far.
    #[must_use]
    pub fn durability_acks(&self) -> &[u64] {
        &self.durability_acks
    }

    /// Number of members that have acknowledged durability.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        self.durability_acks.len()
    }

    /// Members that have not yet acknowledged durability.
    #[must_use]
    pub fn unacked_members(&self) -> Vec<u64> {
        self.member_ids
            .iter()
            .copied()
            .filter(|id| !self.durability_acks.contains(id))
            .collect()
    }

    /// Returns `true` if all members have acknowledged durability.
    #[must_use]
    pub fn all_members_acked(&self) -> bool {
        self.durability_acks.len() == self.member_ids.len()
    }

    /// Returns `true` if a specific member has acknowledged durability.
    #[must_use]
    pub fn has_member_acked(&self, member_id: u64) -> bool {
        self.durability_acks.contains(&member_id)
    }

    // ------------------------------------------------------------------
    // Member management (Open state only)
    // ------------------------------------------------------------------

    /// Add a member to the commit group.
    ///
    /// Valid only in `Open` state. The member must not already be present.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if not in `Open` state.
    pub fn add_member(&mut self, member_id: u64) -> Result<(), CommitGroupError> {
        self.require_state(GroupCommitState::Open, "add_member")?;

        if let Err(idx) = self.member_ids.binary_search(&member_id) {
            self.member_ids.insert(idx, member_id);
        }
        Ok(())
    }

    /// Remove a member from the commit group.
    ///
    /// Valid only in `Open` state. No-op if the member is not present.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if not in `Open` state.
    pub fn remove_member(&mut self, member_id: u64) -> Result<(), CommitGroupError> {
        self.require_state(GroupCommitState::Open, "remove_member")?;
        self.member_ids.retain(|&id| id != member_id);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: close (Open -> Committing)
    // ------------------------------------------------------------------

    /// Close the commit group, transitioning from `Open` to `Committing`.
    ///
    /// Called when the TxgCoordinator signals txg close. After this,
    /// no new members can be added or removed, and writes are no longer
    /// accepted. Members must now acknowledge durability.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Open` state.
    /// Returns `CommitGroupError::EmptyCommitGroup` if there are no members.
    pub fn close(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(GroupCommitState::Open, "close")?;

        if self.member_ids.is_empty() {
            return Err(CommitGroupError::EmptyCommitGroup);
        }

        self.state = GroupCommitState::Committing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: acknowledge_durability (Committing -> Committed)
    // ------------------------------------------------------------------

    /// Register a durability acknowledgment from a member.
    ///
    /// When all members have acknowledged, the state transitions
    /// automatically from `Committing` to `Committed`.
    ///
    /// Duplicate acknowledgments are silently ignored.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Committing` state.
    pub fn acknowledge_durability(&mut self, member_id: u64) -> Result<(), CommitGroupError> {
        self.require_state(GroupCommitState::Committing, "acknowledge_durability")?;

        if !self.member_ids.contains(&member_id) {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "member {member_id} is not in this commit group (txg {})",
                    self.txg_id.0
                ),
            });
        }

        // Deduplicate: ignore if already acked.
        if !self.durability_acks.contains(&member_id) {
            self.durability_acks.push(member_id);
        }

        // Automatic transition when all members have acked.
        if self.all_members_acked() {
            self.state = GroupCommitState::Committed;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Transition: write_checkpoint (Committed -> Checkpoint)
    // ------------------------------------------------------------------

    /// Write the checkpoint, transitioning from `Committed` to `Checkpoint`.
    ///
    /// After this call, the commit group is terminal and its state is
    /// persisted in the intent log. On recovery, groups at or before
    /// this checkpoint are considered durable.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in `Committed` state.
    pub fn write_checkpoint(&mut self) -> Result<(), CommitGroupError> {
        self.require_state(GroupCommitState::Committed, "write_checkpoint")?;
        self.state = GroupCommitState::Checkpoint;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Recovery: reconstruct from last checkpoint
    // ------------------------------------------------------------------

    /// Create a state machine for recovery, positioned based on the last
    /// known checkpoint.
    ///
    /// If `txg_id` is at or before `last_checkpoint_txg`, the group is
    /// already checkpointed and does not need replay. Otherwise, the group
    /// is in `Open` state and needs to be driven through the full lifecycle.
    #[must_use]
    pub fn recover(
        txg_id: CommitGroupId,
        member_ids: Vec<u64>,
        last_checkpoint_txg: Option<CommitGroupId>,
    ) -> Self {
        let state = match last_checkpoint_txg {
            Some(checkpoint) if txg_id.0 <= checkpoint.0 => GroupCommitState::Checkpoint,
            _ => GroupCommitState::Open,
        };
        Self {
            txg_id,
            state,
            member_ids,
            durability_acks: Vec::new(),
        }
    }

    /// Returns `true` if this commit group needs intent-log replay after
    /// recovery. Groups at or before the last checkpoint are already
    /// durable and do not need replay.
    #[must_use]
    pub fn needs_replay(&self, last_checkpoint_txg: Option<CommitGroupId>) -> bool {
        match last_checkpoint_txg {
            Some(checkpoint) => self.txg_id.0 > checkpoint.0,
            None => true, // no checkpoint exists; all txgs need replay
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn require_state(&self, expected: GroupCommitState, op: &str) -> Result<(), CommitGroupError> {
        if self.state != expected {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "{op} requires {expected:?} state, current: {:?}",
                    self.state
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Recovery helpers
// ---------------------------------------------------------------------------

/// Determine which transaction groups need replay after a crash.
///
/// Given a sorted list of known txg ids and the last checkpoint txg,
/// returns only the txg ids that are strictly after the checkpoint.
/// Groups at or before the checkpoint are already durable.
#[must_use]
pub fn determine_replay_txgs(
    known_txg_ids: &[CommitGroupId],
    last_checkpoint_txg: Option<CommitGroupId>,
) -> Vec<CommitGroupId> {
    match last_checkpoint_txg {
        Some(checkpoint) => known_txg_ids
            .iter()
            .copied()
            .filter(|id| id.0 > checkpoint.0)
            .collect(),
        None => known_txg_ids.to_vec(),
    }
}
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ==================================================================
    // CommitGroupState discriminants
    // ==================================================================

    #[test]
    fn state_discriminants_are_distinct() {
        let states = [
            CommitGroupState::Open,
            CommitGroupState::Sealing,
            CommitGroupState::Sealed,
            CommitGroupState::Committing,
            CommitGroupState::Committed,
            CommitGroupState::Applied,
            CommitGroupState::Aborted,
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

    #[test]
    fn terminal_states() {
        assert!(CommitGroupState::Committed.is_terminal());
        assert!(CommitGroupState::Applied.is_terminal());
        assert!(CommitGroupState::Aborted.is_terminal());
        assert!(!CommitGroupState::Open.is_terminal());
        assert!(!CommitGroupState::Sealing.is_terminal());
        assert!(!CommitGroupState::Sealed.is_terminal());
        assert!(!CommitGroupState::Committing.is_terminal());
    }

    #[test]
    fn accepts_writes_only_in_open() {
        assert!(CommitGroupState::Open.accepts_writes());
        assert!(!CommitGroupState::Sealing.accepts_writes());
        assert!(!CommitGroupState::Sealed.accepts_writes());
        assert!(!CommitGroupState::Committing.accepts_writes());
        assert!(!CommitGroupState::Committed.accepts_writes());
        assert!(!CommitGroupState::Applied.accepts_writes());
        assert!(!CommitGroupState::Aborted.accepts_writes());
    }

    // ==================================================================
    // CommitGroupStateMachine: valid transitions
    // ==================================================================

    #[test]
    fn new_machine_is_open() {
        let sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        assert_eq!(sm.state(), CommitGroupState::Open);
        assert_eq!(sm.txg_id(), CommitGroupId(1));
        assert!(sm.is_open());
        assert!(!sm.is_terminal());
    }

    #[test]
    fn valid_open_seal_begin_complete_flow() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(42), [0u8; 32]);

        // Open → Sealed
        sm.seal().unwrap();
        assert_eq!(sm.state(), CommitGroupState::Sealed);
        assert!(sm.is_sealed());

        // Sealed → Committing
        sm.begin_commit().unwrap();
        assert_eq!(sm.state(), CommitGroupState::Committing);
        assert!(sm.is_committing());

        // Committing → Committed
        sm.complete_commit(b"test").unwrap();
        assert_eq!(sm.state(), CommitGroupState::Committed);
        assert!(sm.is_committed());
        assert!(sm.is_terminal());
    }

    #[test]
    fn abort_from_open() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.abort().unwrap();
        assert_eq!(sm.state(), CommitGroupState::Aborted);
        assert!(sm.is_aborted());
        assert!(sm.is_terminal());
    }

    #[test]
    fn abort_from_sealed() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.abort().unwrap();
        assert_eq!(sm.state(), CommitGroupState::Aborted);
    }

    #[test]
    fn abort_from_committing() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.abort().unwrap();
        assert_eq!(sm.state(), CommitGroupState::Aborted);
    }

    #[test]
    fn open_after_abort() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.abort().unwrap();
        assert!(sm.is_aborted());

        // Re-open from Aborted
        sm.open().unwrap();
        assert!(sm.is_open());
        assert_eq!(sm.state(), CommitGroupState::Open);

        // Can proceed through full lifecycle again
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        assert!(sm.is_committed());
    }

    #[test]
    fn open_is_noop_when_already_open() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.open().unwrap();
        assert!(sm.is_open());
    }

    // ==================================================================
    // CommitGroupStateMachine: invalid transitions
    // ==================================================================

    #[test]
    fn double_seal_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        let result = sm.seal();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    #[test]
    fn seal_after_abort_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.abort().unwrap();
        let result = sm.seal();
        assert!(result.is_err());
    }

    #[test]
    fn begin_commit_without_seal_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        // Still Open, not Sealed
        let result = sm.begin_commit();
        assert!(result.is_err());
    }

    #[test]
    fn double_begin_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        let result = sm.begin_commit();
        assert!(result.is_err());
    }

    #[test]
    fn complete_commit_without_begin_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        // Still Open
        let result = sm.complete_commit(b"test");
        assert!(result.is_err());

        // Seal but don't begin_commit
        sm.seal().unwrap();
        let result = sm.complete_commit(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn double_complete_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        let result = sm.complete_commit(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn abort_after_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();

        let result = sm.abort();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    #[test]
    fn double_abort_is_noop() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.abort().unwrap();
        assert!(sm.abort().is_ok());
        assert!(sm.is_aborted());
    }

    #[test]
    fn seal_after_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();

        let result = sm.seal();
        assert!(result.is_err());
    }

    #[test]
    fn open_from_committed_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();

        let result = sm.open();
        assert!(result.is_err());
    }

    #[test]
    fn open_from_sealed_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        let result = sm.open();
        assert!(result.is_err());
    }

    #[test]
    fn open_from_committing_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        let result = sm.open();
        assert!(result.is_err());
    }

    // ==================================================================
    // Error messages are descriptive
    // ==================================================================

    #[test]
    fn error_messages_mention_current_state() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        let err = sm.begin_commit().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("begin_commit"), "msg: {msg}");
        assert!(msg.contains("Open"), "msg: {msg}");
    }

    #[test]
    fn error_messages_mention_expected_state() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        // Try to seal while Committing.
        let err = sm.seal().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("seal"), "msg: {msg}");
        assert!(msg.contains("Open"), "msg: {msg}");
        assert!(msg.contains("Committing"), "msg: {msg}");
    }

    // ==================================================================
    // TxgHandle trait integration
    // ==================================================================

    #[test]
    fn txg_handle_dyn_dispatch() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(99), [0u8; 32]);

        // Use through &mut dyn TxgHandle.
        let handle: &mut dyn TxgHandle = &mut sm;

        assert_eq!(handle.txg_id(), CommitGroupId(99));
        assert!(handle.is_open());
        assert_eq!(handle.group_state(), CommitGroupState::Open);

        handle.seal().unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Sealed);

        handle.begin_commit().unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Committing);

        handle.complete_commit(b"test").unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Committed);
    }

    #[test]
    fn txg_handle_abort_path() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(7), [0u8; 32]);
        let handle: &mut dyn TxgHandle = &mut sm;

        handle.seal().unwrap();
        handle.begin_commit().unwrap();

        // Simulate failure during commit: abort.
        handle.abort().unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Aborted);

        // Double-abort from Aborted is a no-op.
        assert!(handle.abort().is_ok());

        // Cannot abort after Committed — demonstrate with a new group.
        let mut sm2 = CommitGroupStateMachine::new(CommitGroupId(8), [0u8; 32]);
        sm2.seal().unwrap();
        sm2.begin_commit().unwrap();
        sm2.complete_commit(b"test").unwrap();
        assert!(sm2.is_committed());
        let result = sm2.abort();
        assert!(result.is_err());
    }
    // ==================================================================
    // Integration: CommitGroupCoordinator-driven lifecycle
    // ==================================================================

    #[test]
    fn txg_coordinator_simulated_lifecycle() {
        // Simulate a CommitGroupCoordinator driving a commit group through
        // the full lifecycle: open → accumulate → seal → commit → committed.

        let mut sm = CommitGroupStateMachine::new(CommitGroupId(100), [0u8; 32]);

        // Phase 1: Accumulate writes (Open).
        assert!(sm.is_open());
        assert!(sm.state().accepts_writes());

        // Phase 2: Coordinator decides to seal.
        sm.seal().unwrap();
        assert!(sm.is_sealed());
        assert!(!sm.state().accepts_writes());

        // Phase 3: Coordinator begins commit — writes intent-log records.
        sm.begin_commit().unwrap();
        assert!(sm.is_committing());

        // Phase 4: Commit completes successfully.
        sm.complete_commit(b"test").unwrap();
        assert!(sm.is_committed());
    }

    #[test]
    fn txg_coordinator_abort_on_seal_failure() {
        // Simulate the coordinator aborting after some writes.
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(200), [0u8; 32]);

        // Some writes were accumulated (not modeled here, but group is Open).
        assert!(sm.is_open());

        // Coordinator decides to abort (e.g., disk full, conflict).
        sm.abort().unwrap();
        assert!(sm.is_aborted());

        // Coordinator opens a new group for retry.
        sm.open().unwrap();
        assert!(sm.is_open());

        // This new group proceeds normally.
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        assert!(sm.is_committed());
    }

    #[test]
    fn txg_coordinator_abort_during_commit() {
        // Simulate abort during the committing phase (e.g., intent-log
        // write failure).
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(300), [0u8; 32]);

        sm.seal().unwrap();
        sm.begin_commit().unwrap();

        // Intent-log write fails — abort.
        sm.abort().unwrap();
        assert!(sm.is_aborted());

        // Coordinator retries with a new group.
        sm.open().unwrap();
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        assert!(sm.is_committed());
    }

    #[test]
    fn txg_coordinator_multiple_groups_sequential() {
        let mut group1 = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        group1.seal().unwrap();
        group1.begin_commit().unwrap();
        group1.complete_commit(b"test").unwrap();
        assert!(group1.is_committed());
        assert_eq!(group1.txg_id(), CommitGroupId(1));

        let mut group2 = CommitGroupStateMachine::new(CommitGroupId(2), [0u8; 32]);
        group2.seal().unwrap();
        group2.begin_commit().unwrap();
        group2.complete_commit(b"test").unwrap();
        assert!(group2.is_committed());
        assert_eq!(group2.txg_id(), CommitGroupId(2));

        // Group 3 is aborted.
        let mut group3 = CommitGroupStateMachine::new(CommitGroupId(3), [0u8; 32]);
        group3.abort().unwrap();
        assert!(group3.is_aborted());

        // Group 4 succeeds.
        let mut group4 = CommitGroupStateMachine::new(CommitGroupId(4), [0u8; 32]);
        group4.seal().unwrap();
        group4.begin_commit().unwrap();
        group4.complete_commit(b"test").unwrap();
        assert!(group4.is_committed());
    }

    // ==================================================================
    // TxgHandle: is_open check
    // ==================================================================

    #[test]
    fn txg_handle_is_open_changes_with_state() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(5), [0u8; 32]);
        assert!(sm.is_open());

        sm.seal().unwrap();
        assert!(!sm.is_open());

        sm.begin_commit().unwrap();
        assert!(!sm.is_open());

        sm.complete_commit(b"test").unwrap();
        assert!(!sm.is_open());
    }

    // ==================================================================
    // All possible invalid transitions enumerated
    // ==================================================================

    #[test]
    fn all_invalid_seal_transitions() {
        // seal() is only valid from Open.
        let invalid_states = [
            CommitGroupState::Sealing,
            CommitGroupState::Sealed,
            CommitGroupState::Committing,
            CommitGroupState::Committed,
            CommitGroupState::Aborted,
        ];
        for target in &invalid_states {
            let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
            // Force the machine into the target state.
            force_state(&mut sm, *target);
            let result = sm.seal();
            assert!(result.is_err(), "seal from {target:?} should fail");
        }
    }

    #[test]
    fn all_invalid_begin_commit_transitions() {
        // begin_commit() is only valid from Sealed.
        let invalid_states = [
            CommitGroupState::Open,
            CommitGroupState::Sealing,
            CommitGroupState::Committing,
            CommitGroupState::Committed,
            CommitGroupState::Aborted,
        ];
        for target in &invalid_states {
            let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
            force_state(&mut sm, *target);
            let result = sm.begin_commit();
            assert!(result.is_err(), "begin_commit from {target:?} should fail");
        }
    }

    #[test]
    fn all_invalid_complete_commit_transitions() {
        // complete_commit() is only valid from Committing.
        let invalid_states = [
            CommitGroupState::Open,
            CommitGroupState::Sealing,
            CommitGroupState::Sealed,
            CommitGroupState::Committed,
            CommitGroupState::Aborted,
        ];
        for target in &invalid_states {
            let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
            force_state(&mut sm, *target);
            let result = sm.complete_commit(b"test");
            assert!(
                result.is_err(),
                "complete_commit from {target:?} should fail"
            );
        }
    }

    // Helper: force the state machine into a target state for testing
    // invalid transitions.
    fn force_state(sm: &mut CommitGroupStateMachine, target: CommitGroupState) {
        match target {
            CommitGroupState::Open => {
                // Already Open from new().
            }
            CommitGroupState::Sealing => {
                // Sealing is not reachable via public API yet;
                // we set it directly for test coverage.
                sm.state = CommitGroupState::Sealing;
            }
            CommitGroupState::Sealed => {
                sm.seal().unwrap();
            }
            CommitGroupState::Committing => {
                sm.seal().unwrap();
                sm.begin_commit().unwrap();
            }
            CommitGroupState::Committed => {
                sm.seal().unwrap();
                sm.begin_commit().unwrap();
                sm.complete_commit(b"test").unwrap();
            }
            CommitGroupState::Applied => {
                sm.seal().unwrap();
                sm.begin_commit().unwrap();
                sm.complete_commit(b"test").unwrap();
                sm.apply().unwrap();
            }
            CommitGroupState::Aborted => {
                sm.abort().unwrap();
            }
        }
    }

    // ==================================================================
    // Serialization round-trip tests
    // ==================================================================

    #[test]
    fn serde_roundtrip_open() {
        let state = CommitGroupState::Open;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_sealing() {
        let state = CommitGroupState::Sealing;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_sealed() {
        let state = CommitGroupState::Sealed;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_committing() {
        let state = CommitGroupState::Committing;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_committed() {
        let state = CommitGroupState::Committed;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_applied() {
        let state = CommitGroupState::Applied;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_roundtrip_aborted() {
        let state = CommitGroupState::Aborted;
        let json = serde_json::to_string(&state).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn serde_state_machine_preserves_state_after_roundtrip() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(42), [0u8; 32]);
        sm.seal().unwrap();
        let json = serde_json::to_string(&sm.state()).unwrap();
        let back: CommitGroupState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sm.state());
        assert_eq!(back, CommitGroupState::Sealed);
    }

    // ==================================================================
    // Applied state: valid transition
    // ==================================================================

    #[test]
    fn valid_apply_transition() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        assert!(sm.is_committed());

        sm.apply().unwrap();
        assert!(sm.is_applied());
        assert_eq!(sm.state(), CommitGroupState::Applied);
        assert!(sm.is_terminal());
    }

    // ==================================================================
    // Applied state: invalid transitions
    // ==================================================================

    #[test]
    fn apply_without_commit_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        // Open
        let result = sm.apply();
        assert!(result.is_err());

        // Sealed
        sm.seal().unwrap();
        let result = sm.apply();
        assert!(result.is_err());

        // Committing
        sm.begin_commit().unwrap();
        let result = sm.apply();
        assert!(result.is_err());
    }

    #[test]
    fn double_apply_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        sm.apply().unwrap();

        let result = sm.apply();
        assert!(result.is_err());
    }

    #[test]
    fn apply_from_aborted_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.abort().unwrap();
        let result = sm.apply();
        assert!(result.is_err());
    }

    #[test]
    fn all_invalid_apply_transitions() {
        // apply() is only valid from Committed.
        let invalid_states = [
            CommitGroupState::Open,
            CommitGroupState::Sealing,
            CommitGroupState::Sealed,
            CommitGroupState::Committing,
            CommitGroupState::Applied,
            CommitGroupState::Aborted,
        ];
        for target in &invalid_states {
            let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
            force_state(&mut sm, *target);
            let result = sm.apply();
            assert!(result.is_err(), "apply from {target:?} should fail");
        }
    }

    // ==================================================================
    // Applied state: abort-after-apply rejected
    // ==================================================================

    #[test]
    fn abort_after_apply_rejected() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"test").unwrap();
        sm.apply().unwrap();

        let result = sm.abort();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { .. }) => {}
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    // ==================================================================
    // BLAKE3 chain-digest computation
    // ==================================================================

    #[test]
    fn chain_digest_is_deterministic() {
        let prior = [0u8; 32];
        let d1 = compute_chain_digest(&prior, b"commit data");
        let d2 = compute_chain_digest(&prior, b"commit data");
        assert_eq!(d1, d2);
    }

    #[test]
    fn chain_digest_changes_with_data() {
        let prior = [0u8; 32];
        let d1 = compute_chain_digest(&prior, b"commit A");
        let d2 = compute_chain_digest(&prior, b"commit B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn chain_digest_depends_on_prior() {
        let d1 = compute_chain_digest(&[0u8; 32], b"data");
        let d2 = compute_chain_digest(&d1, b"data");
        let d3 = compute_chain_digest(&[0u8; 32], b"data");
        assert_ne!(d2, d3);
    }

    #[test]
    fn complete_commit_stores_chain_digest() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();

        let prior = sm.chain_digest();
        assert_eq!(prior, [0u8; 32]);

        sm.complete_commit(b"commit_group 1 payload").unwrap();
        assert!(sm.is_committed());

        let digest = sm.chain_digest();
        assert_ne!(digest, [0u8; 32]);

        // Verify against manual computation.
        let expected = compute_chain_digest(&[0u8; 32], b"commit_group 1 payload");
        assert_eq!(digest, expected);
    }

    #[test]
    fn chain_digest_chains_across_groups() {
        // Group 1
        let mut g1 = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        g1.seal().unwrap();
        g1.begin_commit().unwrap();
        g1.complete_commit(b"group 1 data").unwrap();
        g1.apply().unwrap();
        let g1_digest = g1.chain_digest();

        // Group 2 chains from group 1
        let mut g2 = CommitGroupStateMachine::new(CommitGroupId(2), g1_digest);
        assert_eq!(g2.chain_digest(), g1_digest);
        g2.seal().unwrap();
        g2.begin_commit().unwrap();
        g2.complete_commit(b"group 2 data").unwrap();

        let g2_digest = g2.chain_digest();
        assert_ne!(g2_digest, g1_digest);
        assert_ne!(g2_digest, [0u8; 32]);

        // Verify chain independently.
        let expected_g2 = compute_chain_digest(&g1_digest, b"group 2 data");
        assert_eq!(g2_digest, expected_g2);

        // Group 3
        let mut g3 = CommitGroupStateMachine::new(CommitGroupId(3), g2_digest);
        g3.seal().unwrap();
        g3.begin_commit().unwrap();
        g3.complete_commit(b"group 3 data").unwrap();
        g3.apply().unwrap();

        let g3_digest = g3.chain_digest();
        let expected_g3 = compute_chain_digest(&g2_digest, b"group 3 data");
        assert_eq!(g3_digest, expected_g3);
    }

    #[test]
    fn open_after_abort_resets_chain_digest() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0xAA; 32]);
        assert_eq!(sm.chain_digest(), [0xAA; 32]);

        sm.abort().unwrap();
        sm.open().unwrap();
        assert_eq!(sm.chain_digest(), [0u8; 32]);
    }

    #[test]
    fn chain_digest_nonzero_after_first_commit() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(1), [0u8; 32]);
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"hello world").unwrap();

        let digest = sm.chain_digest();
        assert_ne!(digest, [0u8; 32]);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn chain_digest_domain_separated_from_raw_blake3() {
        let prior = [0u8; 32];
        let chain_d = compute_chain_digest(&prior, b"test");

        // Raw BLAKE3 without domain separation should differ.
        let mut raw_hasher = blake3::Hasher::new();
        raw_hasher.update(&[0u8; 32]);
        raw_hasher.update(b"test");
        let raw_d: [u8; 32] = *raw_hasher.finalize().as_bytes();

        assert_ne!(chain_d, raw_d);
    }

    // ==================================================================
    // TxgHandle: apply and chain_digest through dyn dispatch
    // ==================================================================

    #[test]
    fn txg_handle_apply_path() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(7), [0u8; 32]);
        let handle: &mut dyn TxgHandle = &mut sm;

        handle.seal().unwrap();
        handle.begin_commit().unwrap();
        handle.complete_commit(b"test").unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Committed);

        handle.apply().unwrap();
        assert_eq!(handle.group_state(), CommitGroupState::Applied);

        // Cannot abort after apply.
        let result = handle.abort();
        assert!(result.is_err());
    }

    #[test]
    fn txg_handle_chain_digest_after_commit() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(99), [0u8; 32]);
        let handle: &mut dyn TxgHandle = &mut sm;

        assert_eq!(handle.chain_digest(), [0u8; 32]);

        handle.seal().unwrap();
        handle.begin_commit().unwrap();
        handle.complete_commit(b"dyn dispatch commit").unwrap();

        let digest = handle.chain_digest();
        assert_ne!(digest, [0u8; 32]);

        let expected = compute_chain_digest(&[0u8; 32], b"dyn dispatch commit");
        assert_eq!(digest, expected);
    }

    // ==================================================================
    // Updated coordinator tests: apply after commit
    // ==================================================================

    #[test]
    fn txg_coordinator_full_lifecycle_with_apply() {
        let mut sm = CommitGroupStateMachine::new(CommitGroupId(100), [0u8; 32]);

        // Open → Sealed → Committing → Committed → Applied
        assert!(sm.is_open());
        sm.seal().unwrap();
        sm.begin_commit().unwrap();
        sm.complete_commit(b"full lifecycle").unwrap();
        assert!(sm.is_committed());
        sm.apply().unwrap();
        assert!(sm.is_applied());
    }

    // ==================================================================
    // Monotonic commit_group across multiple groups (simulates CommitGroupCoordinator)
    // ==================================================================

    #[test]
    fn monotonic_txg_across_multiple_groups() {
        let mut commit_group = CommitGroupId::FIRST;

        let mut g1 = CommitGroupStateMachine::new(commit_group, [0u8; 32]);
        assert_eq!(g1.txg_id(), CommitGroupId(1));
        g1.seal().unwrap();
        g1.begin_commit().unwrap();
        g1.complete_commit(b"g1").unwrap();
        g1.apply().unwrap();
        let d1 = g1.chain_digest();

        commit_group = commit_group.next(); // CommitGroupCoordinator::assign_next() equivalent
        let mut g2 = CommitGroupStateMachine::new(commit_group, d1);
        assert_eq!(g2.txg_id(), CommitGroupId(2));
        g2.seal().unwrap();
        g2.begin_commit().unwrap();
        g2.complete_commit(b"g2").unwrap();
        g2.apply().unwrap();
        let d2 = g2.chain_digest();

        commit_group = commit_group.next();
        let mut g3 = CommitGroupStateMachine::new(commit_group, d2);
        assert_eq!(g3.txg_id(), CommitGroupId(3));
        g3.seal().unwrap();
        g3.begin_commit().unwrap();
        g3.complete_commit(b"g3").unwrap();
        g3.apply().unwrap();
        let d3 = g3.chain_digest();

        // All digests distinct.
        assert_ne!(d1, d2);
        assert_ne!(d2, d3);
        assert_ne!(d1, d3);

        // Verify chain independently.
        assert_eq!(d1, compute_chain_digest(&[0u8; 32], b"g1"));
        assert_eq!(d2, compute_chain_digest(&d1, b"g2"));
        assert_eq!(d3, compute_chain_digest(&d2, b"g3"));
    }

    // ==================================================================
    // GroupCommitState: discriminants and predicates
    // ==================================================================

    #[test]
    fn group_commit_state_discriminants_are_distinct() {
        let states = [
            GroupCommitState::Open,
            GroupCommitState::Committing,
            GroupCommitState::Committed,
            GroupCommitState::Checkpoint,
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

    #[test]
    fn group_commit_state_terminal() {
        assert!(!GroupCommitState::Open.is_terminal());
        assert!(!GroupCommitState::Committing.is_terminal());
        assert!(!GroupCommitState::Committed.is_terminal());
        assert!(GroupCommitState::Checkpoint.is_terminal());
    }

    #[test]
    fn group_commit_state_accepts_writes() {
        assert!(GroupCommitState::Open.accepts_writes());
        assert!(!GroupCommitState::Committing.accepts_writes());
        assert!(!GroupCommitState::Committed.accepts_writes());
        assert!(!GroupCommitState::Checkpoint.accepts_writes());
    }

    #[test]
    fn group_commit_state_accepts_acks() {
        assert!(!GroupCommitState::Open.accepts_acks());
        assert!(GroupCommitState::Committing.accepts_acks());
        assert!(!GroupCommitState::Committed.accepts_acks());
        assert!(!GroupCommitState::Checkpoint.accepts_acks());
    }

    // ==================================================================
    // GroupCommitStateMachine: construction and accessors
    // ==================================================================

    #[test]
    fn new_group_commit_state_machine_is_open() {
        let sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20, 30]);
        assert_eq!(sm.state(), GroupCommitState::Open);
        assert_eq!(sm.txg_id(), CommitGroupId(1));
        assert_eq!(sm.member_ids(), &[10, 20, 30]);
        assert_eq!(sm.member_count(), 3);
        assert_eq!(sm.ack_count(), 0);
        assert!(sm.durability_acks().is_empty());
        assert!(!sm.all_members_acked());
    }

    #[test]
    fn unacked_members_initial() {
        let sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![5, 10, 15]);
        assert_eq!(sm.unacked_members(), vec![5, 10, 15]);
    }

    #[test]
    fn has_member_acked() {
        let sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2]);
        assert!(!sm.has_member_acked(1));
        assert!(!sm.has_member_acked(2));
    }

    // ==================================================================
    // GroupCommitStateMachine: add/remove members (Open state)
    // ==================================================================

    #[test]
    fn add_member_in_open_state() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 30]);
        sm.add_member(20).unwrap();
        assert_eq!(sm.member_ids(), &[10, 20, 30]);
        assert_eq!(sm.member_count(), 3);
    }

    #[test]
    fn add_duplicate_member_is_noop() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20]);
        sm.add_member(10).unwrap();
        assert_eq!(sm.member_ids(), &[10, 20]);
        assert_eq!(sm.member_count(), 2);
    }

    #[test]
    fn remove_member_in_open_state() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20, 30]);
        sm.remove_member(20).unwrap();
        assert_eq!(sm.member_ids(), &[10, 30]);
        assert_eq!(sm.member_count(), 2);
    }

    #[test]
    fn remove_nonexistent_member_is_noop() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20]);
        sm.remove_member(99).unwrap();
        assert_eq!(sm.member_ids(), &[10, 20]);
        assert_eq!(sm.member_count(), 2);
    }

    #[test]
    fn add_member_rejected_after_close() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20]);
        sm.close().unwrap();
        let result = sm.add_member(30);
        assert!(result.is_err());
    }

    #[test]
    fn remove_member_rejected_after_close() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20]);
        sm.close().unwrap();
        let result = sm.remove_member(10);
        assert!(result.is_err());
    }

    // ==================================================================
    // GroupCommitStateMachine: close (Open -> Committing)
    // ==================================================================

    #[test]
    fn close_transitions_to_committing() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(42), vec![1, 2, 3]);
        sm.close().unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committing);
        assert!(!sm.state().accepts_writes());
        assert!(sm.state().accepts_acks());
    }

    #[test]
    fn double_close_rejected() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10]);
        sm.close().unwrap();
        let result = sm.close();
        assert!(result.is_err());
    }

    #[test]
    fn close_with_empty_members_rejected() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1]);
        sm.remove_member(1).unwrap();
        let result = sm.close();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::EmptyCommitGroup) => {}
            other => panic!("expected EmptyCommitGroup, got {other:?}"),
        }
    }

    // ==================================================================
    // GroupCommitStateMachine: acknowledge_durability
    // ==================================================================

    #[test]
    fn ack_triggers_transition_when_all_members_acked() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2, 3]);
        sm.close().unwrap();

        sm.acknowledge_durability(1).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committing);
        assert_eq!(sm.ack_count(), 1);
        assert!(!sm.all_members_acked());

        sm.acknowledge_durability(2).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committing);
        assert_eq!(sm.ack_count(), 2);

        sm.acknowledge_durability(3).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);
        assert_eq!(sm.ack_count(), 3);
        assert!(sm.all_members_acked());
    }

    #[test]
    fn duplicate_ack_is_ignored() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2]);
        sm.close().unwrap();

        sm.acknowledge_durability(1).unwrap();
        sm.acknowledge_durability(1).unwrap(); // duplicate
        assert_eq!(sm.ack_count(), 1);
        assert!(!sm.all_members_acked());

        sm.acknowledge_durability(2).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);
        assert_eq!(sm.ack_count(), 2);
    }

    #[test]
    fn ack_rejected_when_not_committing() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2]);
        // still Open
        let result = sm.acknowledge_durability(1);
        assert!(result.is_err());
    }

    #[test]
    fn ack_rejected_for_unknown_member() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2]);
        sm.close().unwrap();
        let result = sm.acknowledge_durability(99);
        assert!(result.is_err());
    }

    #[test]
    fn ack_rejected_after_committed() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1]);
        sm.close().unwrap();
        sm.acknowledge_durability(1).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);

        let result = sm.acknowledge_durability(1);
        assert!(result.is_err());
    }

    // ==================================================================
    // GroupCommitStateMachine: write_checkpoint (Committed -> Checkpoint)
    // ==================================================================

    #[test]
    fn write_checkpoint_transitions_to_terminal() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1, 2]);
        sm.close().unwrap();
        sm.acknowledge_durability(1).unwrap();
        sm.acknowledge_durability(2).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);

        sm.write_checkpoint().unwrap();
        assert_eq!(sm.state(), GroupCommitState::Checkpoint);
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn write_checkpoint_rejected_before_committed() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1]);
        // Open state
        let result = sm.write_checkpoint();
        assert!(result.is_err());

        sm.close().unwrap();
        let result = sm.write_checkpoint();
        assert!(result.is_err());

        sm.acknowledge_durability(1).unwrap();
        // Committed now
        assert!(sm.write_checkpoint().is_ok());
    }

    #[test]
    fn double_checkpoint_rejected() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![1]);
        sm.close().unwrap();
        sm.acknowledge_durability(1).unwrap();
        sm.write_checkpoint().unwrap();

        let result = sm.write_checkpoint();
        assert!(result.is_err());
    }

    // ==================================================================
    // GroupCommitStateMachine: full lifecycle integration
    // ==================================================================

    #[test]
    fn full_open_to_checkpoint_lifecycle() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(100), vec![10, 20, 30]);
        assert_eq!(sm.state(), GroupCommitState::Open);
        assert_eq!(sm.member_count(), 3);
        assert_eq!(sm.ack_count(), 0);

        // Open -> Committing
        sm.close().unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committing);

        // Ack all members -> Committed
        sm.acknowledge_durability(10).unwrap();
        assert_eq!(sm.ack_count(), 1);
        sm.acknowledge_durability(20).unwrap();
        assert_eq!(sm.ack_count(), 2);
        sm.acknowledge_durability(30).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);
        assert_eq!(sm.ack_count(), 3);
        assert!(sm.all_members_acked());
        assert!(sm.unacked_members().is_empty());

        // Committed -> Checkpoint
        sm.write_checkpoint().unwrap();
        assert_eq!(sm.state(), GroupCommitState::Checkpoint);
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn multi_member_ack_order_independent() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![3, 1, 2]);
        sm.close().unwrap();

        // Ack in reverse order.
        sm.acknowledge_durability(3).unwrap();
        sm.acknowledge_durability(2).unwrap();
        sm.acknowledge_durability(1).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);
        assert!(sm.all_members_acked());
    }

    #[test]
    fn single_member_commit_group() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(77), vec![42]);
        sm.close().unwrap();
        sm.acknowledge_durability(42).unwrap();
        assert_eq!(sm.state(), GroupCommitState::Committed);
        sm.write_checkpoint().unwrap();
        assert_eq!(sm.state(), GroupCommitState::Checkpoint);
    }

    // ==================================================================
    // GroupCommitStateMachine: unacked_members tracking
    // ==================================================================

    #[test]
    fn unacked_members_decreases_with_acks() {
        let mut sm = GroupCommitStateMachine::new(CommitGroupId(1), vec![10, 20, 30, 40]);
        sm.close().unwrap();

        assert_eq!(sm.unacked_members(), vec![10, 20, 30, 40]);
        sm.acknowledge_durability(20).unwrap();
        assert_eq!(sm.unacked_members(), vec![10, 30, 40]);
        sm.acknowledge_durability(40).unwrap();
        assert_eq!(sm.unacked_members(), vec![10, 30]);
        sm.acknowledge_durability(10).unwrap();
        assert_eq!(sm.unacked_members(), vec![30]);
        sm.acknowledge_durability(30).unwrap();
        assert!(sm.unacked_members().is_empty());
        assert!(sm.all_members_acked());
    }

    // ==================================================================
    // GroupCommitStateMachine: recovery and replay
    // ==================================================================

    #[test]
    fn recover_before_checkpoint_is_already_checkpointed() {
        let sm =
            GroupCommitStateMachine::recover(CommitGroupId(5), vec![1, 2], Some(CommitGroupId(10)));
        assert_eq!(sm.state(), GroupCommitState::Checkpoint);
        assert!(!sm.needs_replay(Some(CommitGroupId(10))));
    }

    #[test]
    fn recover_at_checkpoint_is_checkpointed() {
        let sm = GroupCommitStateMachine::recover(
            CommitGroupId(10),
            vec![1, 2],
            Some(CommitGroupId(10)),
        );
        assert_eq!(sm.state(), GroupCommitState::Checkpoint);
        assert!(!sm.needs_replay(Some(CommitGroupId(10))));
    }

    #[test]
    fn recover_after_checkpoint_needs_replay() {
        let sm = GroupCommitStateMachine::recover(
            CommitGroupId(15),
            vec![1, 2],
            Some(CommitGroupId(10)),
        );
        assert_eq!(sm.state(), GroupCommitState::Open);
        assert!(sm.needs_replay(Some(CommitGroupId(10))));
    }

    #[test]
    fn recover_no_checkpoint_all_need_replay() {
        let sm = GroupCommitStateMachine::recover(CommitGroupId(1), vec![1, 2], None);
        assert_eq!(sm.state(), GroupCommitState::Open);
        assert!(sm.needs_replay(None));
    }

    // ==================================================================
    // Recovery: determine_replay_txgs
    // ==================================================================

    #[test]
    fn determine_replay_txgs_with_checkpoint() {
        let known: Vec<CommitGroupId> = (1..=10).map(CommitGroupId).collect();
        let replay = determine_replay_txgs(&known, Some(CommitGroupId(5)));
        assert_eq!(replay, (6..=10).map(CommitGroupId).collect::<Vec<_>>());
    }

    #[test]
    fn determine_replay_txgs_no_checkpoint() {
        let known: Vec<CommitGroupId> = (1..=3).map(CommitGroupId).collect();
        let replay = determine_replay_txgs(&known, None);
        assert_eq!(replay, known);
    }

    #[test]
    fn determine_replay_txgs_checkpoint_beyond_all() {
        let known: Vec<CommitGroupId> = vec![CommitGroupId(1), CommitGroupId(2)];
        let replay = determine_replay_txgs(&known, Some(CommitGroupId(100)));
        assert!(replay.is_empty());
    }

    #[test]
    fn determine_replay_txgs_empty_input() {
        let replay = determine_replay_txgs(&[], Some(CommitGroupId(5)));
        assert!(replay.is_empty());
        let replay = determine_replay_txgs(&[], None);
        assert!(replay.is_empty());
    }

    // ==================================================================
    // GroupCommitState: serialization round-trip
    // ==================================================================

    #[test]
    fn group_commit_state_serde_roundtrip() {
        for state in [
            GroupCommitState::Open,
            GroupCommitState::Committing,
            GroupCommitState::Committed,
            GroupCommitState::Checkpoint,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: GroupCommitState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, state, "serde roundtrip failed for {state:?}");
        }
    }
}
