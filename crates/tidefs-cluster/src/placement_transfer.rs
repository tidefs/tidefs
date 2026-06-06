//! Placement transfer coordinator bridging placement plans to transport
//! data movement.
//!
//! The [`PlacementTransferCoordinator`] drives the lifecycle of a
//! placement-driven data transfer between nodes. It takes a
//! [`TransferPlan`] computed from placement diff analysis, creates a
//! [`TransferSession`] that tracks progress through the transfer state
//! machine, and coordinates message exchange with source and destination
//! nodes via the transport layer.
//!
//! ## Transfer lifecycle
//!
//! ```text
//! Idle --open()--> Planning --initiate()--> Initiating
//!                                                 │
//!                                          ┌───────┘
//!                                          v
//!                                    Transferring --complete()--> Confirm
//!                                         │                          │
//!                                    abort()                   finalize()
//!                                         │                          │
//!                                         v                          v
//!                                      Aborted                   Complete
//! ```
//!
//! Transfers are epoch-bounded: a transfer session is only valid within
//! the epoch it was opened under. Epoch transitions abort in-flight
//! transfers via [`on_epoch_transition`].
//!
//! ## Integration
//!
//! - **Lease state machine**: transfer phases are gated by lease state.
//!   A source node must hold its lease (Held or Renewing) to serve data.
//! - **Transport**: control messages (Initiate, ChunkAck, Chunk, Complete,
//!   Abort) are sent via the transport layer.
//! - **Placement planner**: [`TransferPlan`] consumes placement diffs
//!   produced by the placement planner.

use std::collections::BTreeMap;
use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::PlacementReceiptRef;

use crate::types::{DataPathCarrier, LeaseState};

// ── Transfer plan ───────────────────────────────────────────────────

/// A placement transfer plan identifying which data ranges must move
/// from which source nodes to which destination nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPlan {
    /// The epoch this plan is computed for.
    pub epoch: EpochId,
    /// Plan identifier.
    pub plan_id: u64,
    /// Ordered list of transfers to execute.
    pub transfers: Vec<PlanEntry>,
}

/// A single entry in a [`TransferPlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanEntry {
    /// The node that currently owns the data.
    pub source_node: u64,
    /// The node that will own the data after transfer.
    pub destination_node: u64,
    /// Object IDs and byte ranges to transfer.
    pub object_ranges: Vec<ObjectRange>,
}

/// A byte range within a specific object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRange {
    /// Object identifier.
    pub object_id: u64,
    /// Committed placement receipt that authorizes the source extent.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Start offset in bytes.
    pub start_offset: u64,
    /// Number of bytes.
    pub length_bytes: u64,
}

impl ObjectRange {
    /// Create an object range backed by a committed placement receipt.
    #[must_use]
    pub const fn new(
        object_id: u64,
        placement_receipt_ref: PlacementReceiptRef,
        start_offset: u64,
        length_bytes: u64,
    ) -> Self {
        Self {
            object_id,
            placement_receipt_ref,
            start_offset,
            length_bytes,
        }
    }
}

impl TransferPlan {
    /// Create a new empty transfer plan.
    pub fn new(epoch: EpochId, plan_id: u64) -> Self {
        Self {
            epoch,
            plan_id,
            transfers: Vec::new(),
        }
    }

    /// Add a transfer entry to the plan.
    pub fn add_transfer(&mut self, source: u64, dest: u64, ranges: Vec<ObjectRange>) {
        self.transfers.push(PlanEntry {
            source_node: source,
            destination_node: dest,
            object_ranges: ranges,
        });
    }

    /// Total number of object ranges across all transfers.
    pub fn total_ranges(&self) -> usize {
        self.transfers.iter().map(|t| t.object_ranges.len()).sum()
    }

    /// Total bytes to transfer across all ranges.
    pub fn total_bytes(&self) -> u64 {
        self.transfers
            .iter()
            .flat_map(|t| t.object_ranges.iter())
            .map(|r| r.length_bytes)
            .sum()
    }

    /// True if the plan has no transfers.
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }

    /// Build a plan from a list of (source, dest, ranges) entries.
    /// Useful for construction from placement-runtime transfer tickets.
    pub fn from_entries(
        epoch: EpochId,
        plan_id: u64,
        entries: Vec<(u64, u64, Vec<ObjectRange>)>,
    ) -> Self {
        let mut plan = Self::new(epoch, plan_id);
        for (source, dest, ranges) in entries {
            plan.add_transfer(source, dest, ranges);
        }
        plan
    }

    /// Merge another plan's transfers into this one. The other plan's
    /// epoch must match.
    pub fn merge(&mut self, other: &TransferPlan) -> Result<(), &'static str> {
        if other.epoch != self.epoch {
            return Err("epoch mismatch");
        }
        for entry in &other.transfers {
            self.transfers.push(entry.clone());
        }
        Ok(())
    }
}

// ── Transfer state ──────────────────────────────────────────────────

/// States in the placement transfer lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// No transfer in progress.
    Idle,
    /// Transfer plan is being built.
    Planning,
    /// Initiate message sent to source; awaiting acknowledgement.
    Initiating,
    /// Data chunks are being streamed from source to destination.
    Transferring,
    /// Transfer is complete; final confirmation pending.
    Confirming,
    /// Transfer finished successfully.
    Complete,
    /// Transfer failed and was rolled back.
    Failed,
    /// Transfer was explicitly aborted.
    Aborted,
}

impl TransferState {
    /// True if the state represents an in-progress transfer.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Planning | Self::Initiating | Self::Transferring | Self::Confirming
        )
    }

    /// True if the state is terminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::Aborted)
    }
}

// ── Transfer session ────────────────────────────────────────────────

/// Per-transfer state tracking with progress, retry, and rollback hooks.
#[derive(Clone, Debug)]
pub struct TransferSession {
    /// Unique session identifier.
    pub transfer_id: u64,
    /// The plan this session is executing.
    pub plan: TransferPlan,
    /// Current transfer state.
    pub state: TransferState,
    /// Total chunks expected (computed from plan).
    pub total_chunks: u64,
    /// Chunks received so far.
    pub chunks_received: u64,
    /// Bytes received so far.
    pub bytes_received: u64,
    /// Highest contiguous byte offset received at destination.
    pub highest_contiguous_offset: u64,
    /// Number of retry attempts used.
    pub retry_count: u32,
    /// Maximum retries allowed before failing permanently.
    pub max_retries: u32,
    /// Transport carrier used for this placement transfer.
    pub carrier: DataPathCarrier,
}

impl TransferSession {
    /// Create a new transfer session for the given plan.
    pub fn new(
        transfer_id: u64,
        plan: TransferPlan,
        total_chunks: u64,
        max_retries: u32,
        carrier: DataPathCarrier,
    ) -> Self {
        Self {
            transfer_id,
            plan,
            state: TransferState::Planning,
            total_chunks,
            chunks_received: 0,
            bytes_received: 0,
            highest_contiguous_offset: 0,
            retry_count: 0,
            max_retries,
            carrier,
        }
    }

    /// Advance the session state.
    pub fn advance(&mut self, new_state: TransferState) {
        self.state = new_state;
    }

    /// Record chunk receipt progress.
    pub fn record_ack(&mut self, chunks_received: u64, bytes_received: u64, highest_offset: u64) {
        self.chunks_received = chunks_received;
        self.bytes_received = bytes_received;
        self.highest_contiguous_offset = highest_offset;
    }

    /// True if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.chunks_received >= self.total_chunks
    }

    /// Mark as failed and increment retry count if retries remain.
    /// Returns true if a retry is allowed.
    pub fn retry_or_fail(&mut self) -> bool {
        if self.retry_count < self.max_retries {
            self.retry_count += 1;
            true
        } else {
            self.state = TransferState::Failed;
            false
        }
    }
}

// ── Transfer error ──────────────────────────────────────────────────

/// Errors from placement transfer operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("transfer {0} not found")]
    NotFound(u64),
    #[error("transfer {0} already exists")]
    Duplicate(u64),
    #[error("transfer {0} is not in a state that allows {1}")]
    InvalidState(u64, &'static str),
    #[error(
        "epoch mismatch: transfer epoch {transfer_epoch:?} != current epoch {current_epoch:?}"
    )]
    EpochMismatch {
        transfer_epoch: EpochId,
        current_epoch: EpochId,
    },
    #[error("source node {0} lease is not active (state: {1:?})")]
    SourceLeaseNotActive(u64, LeaseState),
    #[error("max retries ({0}) exceeded for transfer {1}")]
    RetriesExceeded(u32, u64),
    #[error("plan is empty -- nothing to transfer")]
    EmptyPlan,
}

// ── Coordinator ─────────────────────────────────────────────────────

/// Drives the transfer lifecycle (Plan -> Initiate -> Transfer -> Confirm
/// -> Complete) for placement changes.
///
/// Owns a `BTreeMap<u64, TransferSession>` and coordinates message
/// exchange with source and destination nodes.
#[derive(Clone, Debug, Default)]
pub struct PlacementTransferCoordinator {
    /// Active and completed transfer sessions, keyed by transfer_id.
    sessions: BTreeMap<u64, TransferSession>,
    /// Current epoch. Transfers from other epochs are rejected.
    current_epoch: EpochId,
    /// Next transfer ID to assign.
    next_transfer_id: u64,
    /// Default max retries for new sessions.
    default_max_retries: u32,
    /// Transport carrier used for placement transfers.
    carrier: DataPathCarrier,
}

impl PlacementTransferCoordinator {
    /// Create a new coordinator for the given epoch.
    pub fn new(epoch: EpochId) -> Self {
        Self {
            sessions: BTreeMap::new(),
            current_epoch: epoch,
            next_transfer_id: 1,
            default_max_retries: 3,
            carrier: DataPathCarrier::Unknown,
        }
    }

    /// Create a new coordinator with a custom max retry count.
    pub fn with_max_retries(epoch: EpochId, max_retries: u32) -> Self {
        Self {
            sessions: BTreeMap::new(),
            current_epoch: epoch,
            next_transfer_id: 1,
            default_max_retries: max_retries,
            carrier: DataPathCarrier::Unknown,
        }
    }

    /// Set the transport carrier used for placement transfers.
    pub fn set_carrier(&mut self, kind: DataPathCarrier) {
        self.carrier = kind;
    }

    /// Return the transport carrier used for placement transfers.
    #[must_use]
    pub fn carrier(&self) -> DataPathCarrier {
        self.carrier
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Return an iterator over session IDs.
    pub fn session_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.sessions.keys().copied()
    }

    /// Look up a transfer session by ID.
    pub fn session(&self, transfer_id: u64) -> Option<&TransferSession> {
        self.sessions.get(&transfer_id)
    }

    /// Look up a mutable transfer session by ID.
    pub fn session_mut(&mut self, transfer_id: u64) -> Option<&mut TransferSession> {
        self.sessions.get_mut(&transfer_id)
    }

    /// Open a new transfer session from a plan.
    pub fn open_transfer(
        &mut self,
        plan: TransferPlan,
        total_chunks: u64,
    ) -> Result<&TransferSession, TransferError> {
        if plan.is_empty() {
            return Err(TransferError::EmptyPlan);
        }
        if plan.epoch != self.current_epoch {
            return Err(TransferError::EpochMismatch {
                transfer_epoch: plan.epoch,
                current_epoch: self.current_epoch,
            });
        }
        let id = self.next_transfer_id;
        self.next_transfer_id += 1;

        let session = TransferSession::new(
            id,
            plan,
            total_chunks,
            self.default_max_retries,
            self.carrier,
        );
        self.sessions.insert(id, session);
        Ok(&self.sessions[&id])
    }

    /// Transition a session to Initiating.
    pub fn initiate_transfer(
        &mut self,
        transfer_id: u64,
    ) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Planning {
            return Err(TransferError::InvalidState(transfer_id, "initiate"));
        }
        session.state = TransferState::Initiating;
        Ok(&*session)
    }

    /// Transition a session to Transferring.
    pub fn start_transferring(
        &mut self,
        transfer_id: u64,
    ) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Initiating {
            return Err(TransferError::InvalidState(transfer_id, "start transfer"));
        }
        session.state = TransferState::Transferring;
        Ok(&*session)
    }

    /// Record progress via a chunk ACK from the destination.
    pub fn record_chunk_ack(
        &mut self,
        transfer_id: u64,
        chunks_received: u64,
        bytes_received: u64,
        highest_offset: u64,
    ) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Transferring {
            return Err(TransferError::InvalidState(transfer_id, "record ack"));
        }
        session.record_ack(chunks_received, bytes_received, highest_offset);
        Ok(&*session)
    }

    /// Confirm the transfer (transition to Confirming).
    pub fn confirm_transfer(
        &mut self,
        transfer_id: u64,
    ) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Transferring {
            return Err(TransferError::InvalidState(transfer_id, "confirm"));
        }
        session.state = TransferState::Confirming;
        Ok(&*session)
    }

    /// Finalize the transfer (transition to Complete).
    pub fn finalize_transfer(
        &mut self,
        transfer_id: u64,
    ) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Confirming {
            return Err(TransferError::InvalidState(transfer_id, "finalize"));
        }
        session.state = TransferState::Complete;
        Ok(&*session)
    }

    /// Abort a transfer from any non-terminal state.
    pub fn abort_transfer(&mut self, transfer_id: u64) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state.is_terminal() {
            return Err(TransferError::InvalidState(transfer_id, "abort"));
        }
        session.state = TransferState::Aborted;
        Ok(&*session)
    }

    /// Retry a failed transfer. Resets progress and moves back to Initiating.
    pub fn retry_transfer(&mut self, transfer_id: u64) -> Result<&TransferSession, TransferError> {
        let session = self
            .sessions
            .get_mut(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.state != TransferState::Failed {
            return Err(TransferError::InvalidState(transfer_id, "retry"));
        }
        if !session.retry_or_fail() {
            return Err(TransferError::RetriesExceeded(
                session.max_retries,
                transfer_id,
            ));
        }
        session.chunks_received = 0;
        session.bytes_received = 0;
        session.highest_contiguous_offset = 0;
        session.state = TransferState::Initiating;
        Ok(&*session)
    }

    /// Handle an epoch transition. Aborts all in-progress transfers
    /// that belong to the old epoch.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId) -> usize {
        self.current_epoch = new_epoch;
        let mut aborted = 0;
        for session in self.sessions.values_mut() {
            if session.plan.epoch != new_epoch && session.state.is_active() {
                session.state = TransferState::Aborted;
                aborted += 1;
            }
        }
        aborted
    }

    /// Check if a source node can serve data based on lease state.
    pub fn can_source_serve(&self, source_lease_state: LeaseState) -> bool {
        source_lease_state.is_active()
    }

    /// Verify that a transfer epoch matches and the source lease is active.
    pub fn validate_transfer_epoch_and_source(
        &self,
        transfer_id: u64,
        source_lease_state: LeaseState,
    ) -> Result<(), TransferError> {
        let session = self
            .sessions
            .get(&transfer_id)
            .ok_or(TransferError::NotFound(transfer_id))?;
        if session.plan.epoch != self.current_epoch {
            return Err(TransferError::EpochMismatch {
                transfer_epoch: session.plan.epoch,
                current_epoch: self.current_epoch,
            });
        }
        if !self.can_source_serve(source_lease_state) {
            let node = session
                .plan
                .transfers
                .first()
                .map(|t| t.source_node)
                .unwrap_or(0);
            return Err(TransferError::SourceLeaseNotActive(
                node,
                source_lease_state,
            ));
        }
        Ok(())
    }

    /// Count of active transfer sessions.
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state.is_active())
            .count()
    }

    /// Count of completed transfers.
    pub fn completed_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == TransferState::Complete)
            .count()
    }

    /// Remove completed/aborted/failed sessions older than the given epoch.
    pub fn gc_old_sessions(&mut self, before_epoch: EpochId) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| !s.state.is_terminal() || s.plan.epoch >= before_epoch);
        before - self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(v: u64) -> EpochId {
        EpochId(v)
    }

    fn obj_range(id: u64, start: u64, len: u64) -> ObjectRange {
        ObjectRange::new(id, receipt_ref(id, 1), start, len)
    }

    fn receipt_ref(id: u64, generation: u64) -> PlacementReceiptRef {
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&id.to_le_bytes());
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&(id ^ generation).to_le_bytes());
        PlacementReceiptRef::new(
            object_key,
            7,
            generation,
            tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies: 2 },
            digest,
            4096,
        )
    }

    // ── TransferPlan tests ─────────────────────────────────────────

    #[test]
    fn plan_new_is_empty() {
        let plan = TransferPlan::new(eid(1), 100);
        assert!(plan.is_empty());
        assert_eq!(plan.total_ranges(), 0);
        assert_eq!(plan.total_bytes(), 0);
    }

    #[test]
    fn plan_add_transfer_tracks_ranges_and_bytes() {
        let mut plan = TransferPlan::new(eid(2), 200);
        plan.add_transfer(1, 2, vec![obj_range(10, 0, 1000), obj_range(20, 0, 500)]);
        plan.add_transfer(3, 4, vec![obj_range(30, 100, 200)]);
        assert!(!plan.is_empty());
        assert_eq!(plan.total_ranges(), 3);
        assert_eq!(plan.total_bytes(), 1700);
    }

    #[test]
    fn object_ranges_preserve_receipt_generation() {
        let receipt = receipt_ref(10, 42);
        let range = ObjectRange::new(10, receipt, 0, 512);
        assert_eq!(range.placement_receipt_ref, receipt);
        assert_eq!(range.placement_receipt_ref.generation, 42);
    }

    #[test]
    fn plan_total_bytes_empty() {
        let plan = TransferPlan::new(eid(1), 1);
        assert_eq!(plan.total_bytes(), 0);
    }

    #[test]
    fn plan_from_entries_builds_correctly() {
        let plan = TransferPlan::from_entries(
            eid(3),
            42,
            vec![
                (10, 20, vec![obj_range(1, 0, 1000), obj_range(2, 500, 500)]),
                (30, 40, vec![obj_range(3, 0, 300)]),
            ],
        );
        assert_eq!(plan.epoch, eid(3));
        assert_eq!(plan.plan_id, 42);
        assert_eq!(plan.total_ranges(), 3);
        assert_eq!(plan.total_bytes(), 1800);
        assert!(!plan.is_empty());
    }

    #[test]
    fn plan_from_entries_empty() {
        let plan = TransferPlan::from_entries(eid(1), 99, vec![]);
        assert!(plan.is_empty());
        assert_eq!(plan.total_ranges(), 0);
        assert_eq!(plan.total_bytes(), 0);
    }

    #[test]
    fn plan_merge_same_epoch_combines_transfers() {
        let mut plan1 = TransferPlan::new(eid(5), 100);
        plan1.add_transfer(1, 2, vec![obj_range(10, 0, 100)]);
        let mut plan2 = TransferPlan::new(eid(5), 200);
        plan2.add_transfer(3, 4, vec![obj_range(20, 0, 200)]);
        assert!(plan1.merge(&plan2).is_ok());
        assert_eq!(plan1.transfers.len(), 2);
        assert_eq!(plan1.total_bytes(), 300);
    }

    #[test]
    fn plan_merge_epoch_mismatch_fails() {
        let mut plan1 = TransferPlan::new(eid(3), 100);
        let plan2 = TransferPlan::new(eid(7), 200);
        assert!(plan1.merge(&plan2).is_err());
    }

    // ── TransferSession tests ──────────────────────────────────────

    #[test]
    fn session_starts_planning() {
        let plan = TransferPlan::new(eid(1), 1);
        let session = TransferSession::new(42, plan.clone(), 10, 3, DataPathCarrier::Unknown);
        assert_eq!(session.transfer_id, 42);
        assert_eq!(session.state, TransferState::Planning);
        assert_eq!(session.total_chunks, 10);
        assert_eq!(session.max_retries, 3);
    }

    #[test]
    fn session_advance_states() {
        let plan = TransferPlan::new(eid(1), 1);
        let mut session = TransferSession::new(1, plan, 5, 2, DataPathCarrier::Unknown);
        session.advance(TransferState::Initiating);
        assert_eq!(session.state, TransferState::Initiating);
        session.advance(TransferState::Transferring);
        assert_eq!(session.state, TransferState::Transferring);
        session.advance(TransferState::Confirming);
        assert_eq!(session.state, TransferState::Confirming);
        session.advance(TransferState::Complete);
        assert!(session.state.is_terminal());
    }

    #[test]
    fn session_record_ack_updates_progress() {
        let plan = TransferPlan::new(eid(1), 1);
        let mut session = TransferSession::new(1, plan, 100, 3, DataPathCarrier::Unknown);
        session.record_ack(50, 32768, 32768);
        assert_eq!(session.chunks_received, 50);
        assert_eq!(session.bytes_received, 32768);
        assert!(!session.is_complete());
        session.record_ack(100, 65536, 65536);
        assert!(session.is_complete());
    }

    #[test]
    fn session_retry_within_limit() {
        let plan = TransferPlan::new(eid(1), 1);
        let mut session = TransferSession::new(1, plan, 10, 3, DataPathCarrier::Unknown);
        session.state = TransferState::Failed;
        assert!(session.retry_or_fail());
        assert_eq!(session.retry_count, 1);
    }

    #[test]
    fn session_retry_exceeding_limit_fails() {
        let plan = TransferPlan::new(eid(1), 1);
        let mut session = TransferSession::new(1, plan, 10, 2, DataPathCarrier::Unknown);
        session.state = TransferState::Failed;
        session.retry_count = 2;
        assert!(!session.retry_or_fail());
        assert_eq!(session.state, TransferState::Failed);
    }

    // ── Coordinator tests ─────────────────────────────────────────

    #[test]
    fn coordinator_new_sets_epoch() {
        let coord = PlacementTransferCoordinator::new(eid(42));
        assert_eq!(coord.current_epoch(), eid(42));
        assert_eq!(coord.active_count(), 0);
        assert_eq!(coord.completed_count(), 0);
    }

    #[test]
    fn open_transfer_succeeds_with_non_empty_plan() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(10, 20, vec![obj_range(5, 0, 4096)]);
        let result = coord.open_transfer(plan, 1);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.transfer_id, 1);
        assert_eq!(s.state, TransferState::Planning);
    }

    #[test]
    fn open_transfer_fails_on_empty_plan() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let plan = TransferPlan::new(eid(1), 100);
        assert!(matches!(
            coord.open_transfer(plan, 0).unwrap_err(),
            TransferError::EmptyPlan
        ));
    }

    #[test]
    fn open_transfer_fails_on_epoch_mismatch() {
        let mut coord = PlacementTransferCoordinator::new(eid(5));
        let mut plan = TransferPlan::new(eid(3), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        assert!(matches!(
            coord.open_transfer(plan, 1).unwrap_err(),
            TransferError::EpochMismatch { .. }
        ));
    }

    #[test]
    fn full_lifecycle_planning_to_complete() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(10, 20, vec![obj_range(5, 0, 4096)]);
        coord.open_transfer(plan, 5).unwrap();
        assert_eq!(coord.active_count(), 1);

        coord.initiate_transfer(1).unwrap();
        assert_eq!(coord.session(1).unwrap().state, TransferState::Initiating);

        coord.start_transferring(1).unwrap();
        assert_eq!(coord.session(1).unwrap().state, TransferState::Transferring);

        coord.record_chunk_ack(1, 3, 2048, 2048).unwrap();
        assert_eq!(coord.session(1).unwrap().chunks_received, 3);

        coord.confirm_transfer(1).unwrap();
        assert_eq!(coord.session(1).unwrap().state, TransferState::Confirming);

        coord.finalize_transfer(1).unwrap();
        assert_eq!(coord.session(1).unwrap().state, TransferState::Complete);
        assert_eq!(coord.active_count(), 0);
        assert_eq!(coord.completed_count(), 1);
    }

    #[test]
    fn abort_from_transferring() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(10, 0, 512)]);
        coord.open_transfer(plan, 1).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        coord.abort_transfer(1).unwrap();
        assert_eq!(coord.session(1).unwrap().state, TransferState::Aborted);
    }

    #[test]
    fn cannot_abort_completed_transfer() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        coord.open_transfer(plan, 1).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        coord.confirm_transfer(1).unwrap();
        coord.finalize_transfer(1).unwrap();
        assert!(matches!(
            coord.abort_transfer(1).unwrap_err(),
            TransferError::InvalidState(..)
        ));
    }

    #[test]
    fn invalid_state_for_wrong_phase() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        coord.open_transfer(plan, 1).unwrap();
        assert!(matches!(
            coord.confirm_transfer(1).unwrap_err(),
            TransferError::InvalidState(..)
        ));
    }

    #[test]
    fn not_found_transfer() {
        let coord = PlacementTransferCoordinator::new(eid(1));
        assert!(coord.session(999).is_none());
        let mut coord_mut = PlacementTransferCoordinator::new(eid(1));
        assert!(matches!(
            coord_mut.initiate_transfer(999).unwrap_err(),
            TransferError::NotFound(999)
        ));
    }

    #[test]
    fn epoch_transition_aborts_active_transfers() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 512)]);
        coord.open_transfer(plan, 2).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        assert_eq!(coord.active_count(), 1);

        let aborted = coord.on_epoch_transition(eid(2));
        assert_eq!(aborted, 1);
        assert_eq!(coord.session(1).unwrap().state, TransferState::Aborted);
        assert_eq!(coord.current_epoch(), eid(2));
    }

    #[test]
    fn epoch_transition_leaves_completed() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 512)]);
        coord.open_transfer(plan, 1).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        coord.confirm_transfer(1).unwrap();
        coord.finalize_transfer(1).unwrap();

        let aborted = coord.on_epoch_transition(eid(2));
        assert_eq!(aborted, 0);
        assert_eq!(coord.session(1).unwrap().state, TransferState::Complete);
    }

    #[test]
    fn can_source_serve_gates_on_lease() {
        let coord = PlacementTransferCoordinator::new(eid(1));
        assert!(coord.can_source_serve(LeaseState::Held));
        assert!(coord.can_source_serve(LeaseState::Renewing));
        assert!(!coord.can_source_serve(LeaseState::Unleased));
        assert!(!coord.can_source_serve(LeaseState::Acquiring));
        assert!(!coord.can_source_serve(LeaseState::Expiring));
        assert!(!coord.can_source_serve(LeaseState::Released));
    }

    #[test]
    fn validate_epoch_and_source_lease() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(10, 20, vec![obj_range(5, 0, 100)]);
        coord.open_transfer(plan, 1).unwrap();

        assert!(coord
            .validate_transfer_epoch_and_source(1, LeaseState::Held)
            .is_ok());

        let result = coord.validate_transfer_epoch_and_source(1, LeaseState::Expiring);
        assert!(matches!(
            result.unwrap_err(),
            TransferError::SourceLeaseNotActive(..)
        ));
    }

    #[test]
    fn retry_transfer_resets_progress() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan = TransferPlan::new(eid(1), 100);
        plan.add_transfer(1, 2, vec![obj_range(1, 0, 512)]);
        coord.open_transfer(plan, 5).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        coord.record_chunk_ack(1, 3, 2048, 2048).unwrap();
        coord.abort_transfer(1).unwrap();
        coord.session_mut(1).unwrap().state = TransferState::Failed;

        assert!(coord.retry_transfer(1).is_ok());
        let s = coord.session(1).unwrap();
        assert_eq!(s.state, TransferState::Initiating);
        assert_eq!(s.chunks_received, 0);
        assert_eq!(s.bytes_received, 0);
        assert_eq!(s.highest_contiguous_offset, 0);
        assert_eq!(s.retry_count, 1);
    }

    #[test]
    fn gc_removes_terminal_sessions_before_epoch() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan1 = TransferPlan::new(eid(1), 100);
        plan1.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        coord.open_transfer(plan1, 1).unwrap();
        coord.initiate_transfer(1).unwrap();
        coord.start_transferring(1).unwrap();
        coord.confirm_transfer(1).unwrap();
        coord.finalize_transfer(1).unwrap();

        coord.on_epoch_transition(eid(3));
        let mut plan2 = TransferPlan::new(eid(3), 200);
        plan2.add_transfer(3, 4, vec![obj_range(2, 0, 200)]);
        coord.open_transfer(plan2, 1).unwrap();
        coord.initiate_transfer(2).unwrap();
        coord.start_transferring(2).unwrap();

        let removed = coord.gc_old_sessions(eid(3));
        assert_eq!(removed, 1);
        assert!(coord.session(1).is_none());
        assert!(coord.session(2).is_some());
    }

    #[test]
    fn session_ids_iterates_all() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan1 = TransferPlan::new(eid(1), 100);
        plan1.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        coord.open_transfer(plan1, 1).unwrap();
        let mut plan2 = TransferPlan::new(eid(1), 200);
        plan2.add_transfer(3, 4, vec![obj_range(2, 0, 200)]);
        coord.open_transfer(plan2, 1).unwrap();

        let ids: Vec<u64> = coord.session_ids().collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[test]
    fn second_transfer_gets_incrementing_id() {
        let mut coord = PlacementTransferCoordinator::new(eid(1));
        let mut plan1 = TransferPlan::new(eid(1), 100);
        plan1.add_transfer(1, 2, vec![obj_range(1, 0, 100)]);
        coord.open_transfer(plan1, 1).unwrap();
        let mut plan2 = TransferPlan::new(eid(1), 200);
        plan2.add_transfer(3, 4, vec![obj_range(2, 0, 200)]);
        coord.open_transfer(plan2, 1).unwrap();
        assert_eq!(coord.session(1).unwrap().transfer_id, 1);
        assert_eq!(coord.session(2).unwrap().transfer_id, 2);
    }

    #[test]
    fn transfer_state_is_active_terminal() {
        assert!(TransferState::Planning.is_active());
        assert!(TransferState::Initiating.is_active());
        assert!(TransferState::Transferring.is_active());
        assert!(TransferState::Confirming.is_active());
        assert!(TransferState::Complete.is_terminal());
        assert!(TransferState::Failed.is_terminal());
        assert!(TransferState::Aborted.is_terminal());
        assert!(!TransferState::Idle.is_active());
        assert!(!TransferState::Complete.is_active());
    }
}
