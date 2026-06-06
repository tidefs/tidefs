//! Rebuild backfill initiator bridging rebuild-planner outputs to
//! transport state-transfer commands.
//!
//! The [`RebuildBackfillInitiator`] accepts a [`RebuildPlan`] describing
//! which objects must be backfilled to which target nodes, partitions
//! reconstruction tasks by target member, groups source→target data
//! movements into [`BackfillBatch`] entries, and produces state-transfer
//! command batches that the transport layer executes.
//!
//! ## Types
//!
//! - [`ReconstructionTask`]: a single object needing backfill (sources,
//!   targets, priority). Mirrors `tidefs-rebuild-planner::plan` types so
//!   the cluster crate can operate without depending on rebuild-planner.
//! - [`RebuildPlan`]: ordered list of tasks for a backfill operation.
//! - [`BackfillBatch`]: per-target grouping of [`BackfillCommand`]s.
//! - [`BackfillCommand`]: source→target data movement for a set of objects.
//!
//! ## Backfill lifecycle
//!
//! ```text
//! Idle --open()--> Planning --initiate()--> Initiating
//!                                                 │
//!                                          ┌───────┘
//!                                          v
//!                                    Transferring --complete()--> Verifying
//!                                         │                          │
//!                                    abort()                   finalize()
//!                                         │                          │
//!                                         v                          v
//!                                      Aborted                   Complete
//! ```
//!
//! Backfills are epoch-bounded: only valid within the epoch they are
//! opened under. Epoch transitions abort in-flight backfills via
//! [`on_epoch_transition`].
//!
//! ## Integration
//!
//! - **Rebuild planner**: the upstream `tidefs-rebuild-planner` produces
//!   a `RebuildPlan`; the cluster runtime converts it into this crate's
//!   local [`RebuildPlan`] before passing to the initiator.
//! - **Transport**: each [`BackfillCommand`] maps to a
//!   `StateTransferRequest` (source→target with object_ids).
//! - **Lease state machine**: source nodes must hold active leases
//!   (Held or Renewing) to serve backfill data.

use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::PlacementReceiptRef;

use crate::types::{DataPathCarrier, LeaseState};

// ── Reconstruction task ─────────────────────────────────────────────

/// A single object that needs reconstruction (backfill).
///
/// Mirrors `tidefs-rebuild-planner::plan::ReconstructionTask` so the
/// cluster crate can operate without a direct dependency on the
/// rebuild-planner crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconstructionTask {
    /// Object identifier.
    pub object_id: u64,
    /// Placement receipt that currently authorizes viable source copies.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Nodes that currently hold viable copies of this object.
    pub source_nodes: Vec<u64>,
    /// Nodes that need a copy of this object.
    pub target_nodes: Vec<u64>,
    /// Optional byte range within the object (None = full object).
    pub data_range: Option<(u64, u64)>,
    /// Reconstruction priority (lower = more urgent).
    pub priority: u8,
}

impl ReconstructionTask {
    /// Create a task for full-object reconstruction.
    pub fn new_full(
        object_id: u64,
        source_nodes: Vec<u64>,
        target_nodes: Vec<u64>,
        priority: u8,
    ) -> Self {
        Self::new_full_with_receipt(
            object_id,
            PlacementReceiptRef::synthetic_for_subject(
                tidefs_replication_model::ReplicatedSubjectId::new(object_id),
            ),
            source_nodes,
            target_nodes,
            priority,
        )
    }

    /// Create a task for full-object reconstruction with receipt authority.
    pub fn new_full_with_receipt(
        object_id: u64,
        placement_receipt_ref: PlacementReceiptRef,
        source_nodes: Vec<u64>,
        target_nodes: Vec<u64>,
        priority: u8,
    ) -> Self {
        Self {
            object_id,
            placement_receipt_ref,
            source_nodes,
            target_nodes,
            data_range: None,
            priority,
        }
    }

    /// Create a task for partial-range reconstruction.
    pub fn new_range(
        object_id: u64,
        source_nodes: Vec<u64>,
        target_nodes: Vec<u64>,
        start: u64,
        end: u64,
        priority: u8,
    ) -> Self {
        Self::new_range_with_receipt(
            object_id,
            PlacementReceiptRef::synthetic_for_subject(
                tidefs_replication_model::ReplicatedSubjectId::new(object_id),
            ),
            source_nodes,
            target_nodes,
            start,
            end,
            priority,
        )
    }

    /// Create a task for partial-range reconstruction with receipt authority.
    pub fn new_range_with_receipt(
        object_id: u64,
        placement_receipt_ref: PlacementReceiptRef,
        source_nodes: Vec<u64>,
        target_nodes: Vec<u64>,
        start: u64,
        end: u64,
        priority: u8,
    ) -> Self {
        Self {
            object_id,
            placement_receipt_ref,
            source_nodes,
            target_nodes,
            data_range: Some((start, end)),
            priority,
        }
    }

    /// True if there is at least one viable source.
    pub fn has_viable_sources(&self) -> bool {
        !self.source_nodes.is_empty()
    }

    /// Number of target nodes.
    pub fn target_count(&self) -> usize {
        self.target_nodes.len()
    }
}

// ── Rebuild plan ────────────────────────────────────────────────────

/// A rebuild plan: ordered list of reconstruction tasks.
///
/// Mirrors `tidefs-rebuild-planner::plan::RebuildPlan` to avoid the
/// cyclic dependency between cluster and rebuild-planner (via transport).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildPlan {
    /// Plan identifier.
    pub plan_id: u64,
    /// Ordered list of reconstruction tasks.
    pub tasks: Vec<ReconstructionTask>,
    /// Timestamp when the plan was created (ns).
    pub created_at_ns: u64,
}

impl RebuildPlan {
    /// Create a new rebuild plan.
    pub fn new(plan_id: u64, tasks: Vec<ReconstructionTask>, created_at_ns: u64) -> Self {
        Self {
            plan_id,
            tasks,
            created_at_ns,
        }
    }

    /// Number of tasks in the plan.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Total target replicas across all tasks.
    pub fn total_target_replicas(&self) -> usize {
        self.tasks.iter().map(|t| t.target_nodes.len()).sum()
    }

    /// True if the plan has no tasks.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

// ── Backfill command ────────────────────────────────────────────────

/// A single backfill command: source node → target node for a set of objects.
///
/// Maps directly to a transport `StateTransferRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackfillCommand {
    /// Node that holds the data.
    pub source_node: u64,
    /// Node that needs the data (rebuild target).
    pub target_node: u64,
    /// Object IDs to transfer.
    pub object_ids: Vec<u64>,
    /// Placement receipts corresponding one-for-one with `object_ids`.
    pub placement_receipt_refs: Vec<PlacementReceiptRef>,
    /// Maximum chunk size in bytes for this transfer.
    pub max_chunk_bytes: u64,
}

impl BackfillCommand {
    /// Create a new backfill command.
    pub fn new(source: u64, target: u64, object_ids: Vec<u64>, max_chunk_bytes: u64) -> Self {
        let placement_receipt_refs = object_ids
            .iter()
            .copied()
            .map(|object_id| {
                PlacementReceiptRef::synthetic_for_subject(
                    tidefs_replication_model::ReplicatedSubjectId::new(object_id),
                )
            })
            .collect();
        Self::new_with_receipts(
            source,
            target,
            object_ids,
            placement_receipt_refs,
            max_chunk_bytes,
        )
    }

    /// Create a new backfill command from receipt-authoritative object refs.
    pub fn new_with_receipts(
        source: u64,
        target: u64,
        object_ids: Vec<u64>,
        placement_receipt_refs: Vec<PlacementReceiptRef>,
        max_chunk_bytes: u64,
    ) -> Self {
        assert_eq!(
            object_ids.len(),
            placement_receipt_refs.len(),
            "backfill object IDs and placement receipt refs must align"
        );
        Self {
            source_node: source,
            target_node: target,
            object_ids,
            placement_receipt_refs,
            max_chunk_bytes,
        }
    }

    /// Number of objects in this command.
    pub fn object_count(&self) -> usize {
        self.object_ids.len()
    }

    /// True if there are no objects to transfer.
    pub fn is_empty(&self) -> bool {
        self.object_ids.is_empty()
    }
}

// ── Backfill batch ──────────────────────────────────────────────────

/// A batch of backfill commands destined for a single target member.
///
/// All commands in a batch target the same node. The batch can be
/// dispatched as a group, with progress tracked per-command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackfillBatch {
    /// The node receiving the backfill data.
    pub target_node: u64,
    /// Ordered list of commands to execute.
    pub commands: Vec<BackfillCommand>,
    /// The epoch this batch is valid for.
    pub epoch: EpochId,
    /// Transport carrier used for this backfill batch.
    pub carrier: DataPathCarrier,
}

impl BackfillBatch {
    /// Create a new empty batch for the given target.
    pub fn new(target_node: u64, epoch: EpochId, carrier: DataPathCarrier) -> Self {
        Self {
            target_node,
            commands: Vec::new(),
            epoch,
            carrier,
        }
    }

    /// Add a command to the batch.
    pub fn add_command(&mut self, cmd: BackfillCommand) {
        self.commands.push(cmd);
    }

    /// Total number of objects across all commands.
    pub fn total_objects(&self) -> usize {
        self.commands.iter().map(|c| c.object_count()).sum()
    }

    /// Number of commands.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// True if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

// ── Backfill state ──────────────────────────────────────────────────

/// States in the rebuild backfill lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackfillState {
    /// No backfill in progress.
    Idle,
    /// Rebuild plan is being partitioned into batches.
    Planning,
    /// Initiate messages sent to source nodes; awaiting acknowledgement.
    Initiating,
    /// Data chunks are being streamed from sources to targets.
    Transferring,
    /// Transfer complete; integrity verification in progress.
    Verifying,
    /// Backfill finished successfully.
    Complete,
    /// Backfill failed and was rolled back.
    Failed,
    /// Backfill was explicitly aborted.
    Aborted,
}

impl BackfillState {
    /// True if the state represents an in-progress backfill.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Planning | Self::Initiating | Self::Transferring | Self::Verifying
        )
    }

    /// True if the state is terminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::Aborted)
    }
}

// ── Backfill session ────────────────────────────────────────────────

/// Per-backfill progress tracking with retry hooks.
#[derive(Clone, Debug)]
pub struct BackfillSession {
    /// Unique session identifier.
    pub backfill_id: u64,
    /// The rebuild plan this session is executing.
    pub plan: RebuildPlan,
    /// Partitions of the plan by target member.
    pub batches: Vec<BackfillBatch>,
    /// Current backfill state.
    pub state: BackfillState,
    /// Total objects to backfill.
    pub total_objects: u64,
    /// Objects completed so far.
    pub objects_completed: u64,
    /// Total bytes estimated for the backfill.
    pub total_bytes_estimate: u64,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Number of retry attempts used.
    pub retry_count: u32,
    /// Maximum retries allowed before failing permanently.
    pub max_retries: u32,
    /// Transport carrier used for this backfill session.
    pub carrier: DataPathCarrier,
}

impl BackfillSession {
    /// Create a new backfill session from a rebuild plan.
    pub fn new(
        backfill_id: u64,
        plan: RebuildPlan,
        batches: Vec<BackfillBatch>,
        max_retries: u32,
        carrier: DataPathCarrier,
    ) -> Self {
        let total_objects = plan.task_count() as u64;
        Self {
            backfill_id,
            plan,
            batches,
            state: BackfillState::Planning,
            total_objects,
            objects_completed: 0,
            total_bytes_estimate: 0,
            bytes_transferred: 0,
            retry_count: 0,
            max_retries,
            carrier,
        }
    }

    /// Advance the session state.
    pub fn advance(&mut self, new_state: BackfillState) {
        self.state = new_state;
    }

    /// Record completion of objects.
    pub fn record_progress(&mut self, objects_completed: u64, bytes_transferred: u64) {
        self.objects_completed = objects_completed;
        self.bytes_transferred = bytes_transferred;
    }

    /// True if all objects have been backfilled.
    pub fn is_complete(&self) -> bool {
        self.objects_completed >= self.total_objects
    }

    /// Fraction complete (0.0 - 1.0).
    pub fn fraction_complete(&self) -> f64 {
        if self.total_objects == 0 {
            return 1.0;
        }
        self.objects_completed as f64 / self.total_objects as f64
    }

    /// Mark as failed and increment retry count if retries remain.
    /// Returns true if a retry is allowed.
    pub fn retry_or_fail(&mut self) -> bool {
        if self.retry_count < self.max_retries {
            self.retry_count += 1;
            true
        } else {
            self.state = BackfillState::Failed;
            false
        }
    }
}

// ── Backfill error ──────────────────────────────────────────────────

/// Errors from rebuild backfill operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackfillError {
    #[error("backfill {0} not found")]
    NotFound(u64),
    #[error("backfill {0} already exists")]
    Duplicate(u64),
    #[error("backfill {0} is not in a state that allows {1}")]
    InvalidState(u64, &'static str),
    #[error(
        "epoch mismatch: backfill epoch {backfill_epoch:?} != current epoch {current_epoch:?}"
    )]
    EpochMismatch {
        backfill_epoch: EpochId,
        current_epoch: EpochId,
    },
    #[error("source node {0} lease is not active (state: {1:?})")]
    SourceLeaseNotActive(u64, LeaseState),
    #[error("max retries ({0}) exceeded for backfill {1}")]
    RetriesExceeded(u32, u64),
    #[error("plan is empty -- nothing to backfill")]
    EmptyPlan,
    #[error("no viable sources for object {0}")]
    NoViableSource(u64),
}

// ── Initiator ───────────────────────────────────────────────────────

/// Drives the rebuild backfill lifecycle (Plan → Initiate → Transfer →
/// Verify → Complete) for node/device loss recovery.
///
/// Owns a `BTreeMap<u64, BackfillSession>` and partitions rebuild plans
/// into per-target batches for transport execution.
#[derive(Clone, Debug, Default)]
pub struct RebuildBackfillInitiator {
    /// Active and completed backfill sessions, keyed by backfill_id.
    sessions: BTreeMap<u64, BackfillSession>,
    /// Current epoch. Backfills from other epochs are rejected.
    current_epoch: EpochId,
    /// Next backfill ID to assign.
    next_backfill_id: u64,
    /// Default max retries for new sessions.
    default_max_retries: u32,
    /// Default max chunk bytes for generated commands.
    default_max_chunk_bytes: u64,
    /// Transport carrier used for backfill operations.
    carrier: DataPathCarrier,
}

impl RebuildBackfillInitiator {
    /// Create a new initiator for the given epoch.
    pub fn new(epoch: EpochId) -> Self {
        Self {
            sessions: BTreeMap::new(),
            current_epoch: epoch,
            next_backfill_id: 1,
            default_max_retries: 3,
            default_max_chunk_bytes: 1_048_576, // 1 MiB
            carrier: DataPathCarrier::Unknown,
        }
    }

    /// Create with custom retry count and chunk size.
    pub fn with_config(epoch: EpochId, max_retries: u32, max_chunk_bytes: u64) -> Self {
        Self {
            sessions: BTreeMap::new(),
            current_epoch: epoch,
            next_backfill_id: 1,
            default_max_retries: max_retries,
            default_max_chunk_bytes: max_chunk_bytes,
            carrier: DataPathCarrier::Unknown,
        }
    }

    /// Set the transport carrier used for backfill operations.
    pub fn set_carrier(&mut self, kind: DataPathCarrier) {
        self.carrier = kind;
    }

    /// Return the transport carrier used for backfill operations.
    #[must_use]
    pub fn carrier(&self) -> DataPathCarrier {
        self.carrier
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Return an iterator over backfill session IDs.
    pub fn session_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.sessions.keys().copied()
    }

    /// Look up a backfill session by ID.
    pub fn session(&self, backfill_id: u64) -> Option<&BackfillSession> {
        self.sessions.get(&backfill_id)
    }

    /// Look up a mutable backfill session by ID.
    pub fn session_mut(&mut self, backfill_id: u64) -> Option<&mut BackfillSession> {
        self.sessions.get_mut(&backfill_id)
    }

    /// Number of active (non-terminal) backfills.
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state.is_active())
            .count()
    }

    /// Number of completed backfills.
    pub fn completed_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == BackfillState::Complete)
            .count()
    }

    /// Total objects pending across all active backfills.
    pub fn total_pending_objects(&self) -> u64 {
        self.sessions
            .values()
            .filter(|s| s.state.is_active())
            .map(|s| s.total_objects.saturating_sub(s.objects_completed))
            .sum()
    }

    // ── Plan partitioning ───────────────────────────────────────────

    /// Open a new backfill session from a rebuild plan.
    ///
    /// Partitions the plan's reconstruction tasks by target member,
    /// groups tasks by (source, target) into [`BackfillCommand`] entries,
    /// and creates the session in Planning state.
    ///
    /// Returns the assigned backfill_id on success.
    pub fn open_backfill(
        &mut self,
        plan: RebuildPlan,
        epoch: EpochId,
    ) -> Result<u64, BackfillError> {
        if epoch != self.current_epoch {
            return Err(BackfillError::EpochMismatch {
                backfill_epoch: epoch,
                current_epoch: self.current_epoch,
            });
        }
        if plan.is_empty() {
            return Err(BackfillError::EmptyPlan);
        }

        let batches =
            Self::partition_plan(&plan, epoch, self.default_max_chunk_bytes, self.carrier);

        let backfill_id = self.next_backfill_id;
        self.next_backfill_id += 1;

        let session = BackfillSession::new(
            backfill_id,
            plan,
            batches,
            self.default_max_retries,
            self.carrier,
        );

        self.sessions.insert(backfill_id, session);
        Ok(backfill_id)
    }

    /// Partition a rebuild plan into per-target batches.
    ///
    /// For each target node across all reconstruction tasks, groups
    /// tasks by source node and creates one [`BackfillCommand`] per
    /// (source, target) pair carrying the relevant object IDs.
    fn partition_plan(
        plan: &RebuildPlan,
        epoch: EpochId,
        max_chunk_bytes: u64,
        carrier: DataPathCarrier,
    ) -> Vec<BackfillBatch> {
        // Build: target_node -> { (source_node, receipt_ref) -> [object_ids] }
        let mut target_map: BTreeMap<u64, BTreeMap<(u64, PlacementReceiptRef), Vec<u64>>> =
            BTreeMap::new();

        for task in &plan.tasks {
            if task.source_nodes.is_empty() {
                continue; // Skip tasks with no viable sources
            }
            for &target in &task.target_nodes {
                let source_buckets = target_map.entry(target).or_default();
                // Use the first source; multi-source tasks can be serviced
                // by any viable source
                let source = task.source_nodes[0];
                source_buckets
                    .entry((source, task.placement_receipt_ref))
                    .or_default()
                    .push(task.object_id);
            }
        }

        let mut batches: Vec<BackfillBatch> = Vec::new();

        for (target_node, source_buckets) in &target_map {
            let mut batch = BackfillBatch::new(*target_node, epoch, carrier);
            for (&(source_node, receipt_ref), object_ids) in source_buckets {
                batch.add_command(BackfillCommand::new_with_receipts(
                    source_node,
                    *target_node,
                    object_ids.clone(),
                    vec![receipt_ref; object_ids.len()],
                    max_chunk_bytes,
                ));
            }
            batches.push(batch);
        }

        batches
    }

    // ── Lifecycle methods ───────────────────────────────────────────

    /// Initiate a backfill: moves Planning → Initiating.
    ///
    /// Caller should send initiate messages to source nodes after this.
    pub fn initiate_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if session.state != BackfillState::Planning {
            return Err(BackfillError::InvalidState(backfill_id, "initiate"));
        }
        session.advance(BackfillState::Initiating);
        Ok(())
    }

    /// Move to Transferring state.
    pub fn start_transferring(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if session.state != BackfillState::Initiating {
            return Err(BackfillError::InvalidState(
                backfill_id,
                "start_transferring",
            ));
        }
        session.advance(BackfillState::Transferring);
        Ok(())
    }

    /// Record progress on a backfill session.
    pub fn record_progress(
        &mut self,
        backfill_id: u64,
        objects_completed: u64,
        bytes_transferred: u64,
    ) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if !matches!(session.state, BackfillState::Transferring) {
            return Err(BackfillError::InvalidState(backfill_id, "record_progress"));
        }
        session.record_progress(objects_completed, bytes_transferred);
        Ok(())
    }

    /// Mark transfer phase complete: moves Transferring → Verifying.
    pub fn complete_transfer(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if session.state != BackfillState::Transferring {
            return Err(BackfillError::InvalidState(backfill_id, "complete"));
        }
        session.advance(BackfillState::Verifying);
        Ok(())
    }

    /// Finalize a verified backfill: moves Verifying → Complete.
    pub fn finalize_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if session.state != BackfillState::Verifying {
            return Err(BackfillError::InvalidState(backfill_id, "finalize"));
        }
        session.advance(BackfillState::Complete);
        Ok(())
    }

    /// Abort an in-progress backfill from any active state.
    pub fn abort_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if !session.state.is_active() {
            return Err(BackfillError::InvalidState(backfill_id, "abort"));
        }
        session.advance(BackfillState::Aborted);
        Ok(())
    }

    /// Retry a failed backfill, resetting progress.
    pub fn retry_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        let session = self
            .session_mut(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        if !matches!(
            session.state,
            BackfillState::Failed | BackfillState::Aborted
        ) {
            return Err(BackfillError::InvalidState(backfill_id, "retry"));
        }
        if !session.retry_or_fail() {
            return Err(BackfillError::RetriesExceeded(
                session.max_retries,
                backfill_id,
            ));
        }
        session.objects_completed = 0;
        session.bytes_transferred = 0;
        session.state = BackfillState::Planning;
        Ok(())
    }

    // ── Epoch and lease gating ──────────────────────────────────────

    /// Handle an epoch transition.
    ///
    /// Aborts all active backfills and returns the count aborted.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId) -> usize {
        let mut aborted = 0;
        for session in self.sessions.values_mut() {
            if session.state.is_active() {
                session.state = BackfillState::Aborted;
                aborted += 1;
            }
        }
        self.current_epoch = new_epoch;
        aborted
    }

    /// Check whether a source node can serve backfill data based on lease state.
    pub fn can_source_serve(lease_state: LeaseState) -> bool {
        lease_state.is_active()
    }

    /// Validate that a backfill's source nodes hold active leases.
    ///
    /// `source_leases`: map of source_node → LeaseState.
    pub fn validate_epoch_and_sources(
        &self,
        backfill_id: u64,
        source_leases: &BTreeMap<u64, LeaseState>,
    ) -> Result<(), BackfillError> {
        let session = self
            .session(backfill_id)
            .ok_or(BackfillError::NotFound(backfill_id))?;
        let mut sources: BTreeSet<u64> = BTreeSet::new();
        for batch in &session.batches {
            for cmd in &batch.commands {
                sources.insert(cmd.source_node);
            }
        }
        for &source in &sources {
            match source_leases.get(&source) {
                None
                | Some(LeaseState::Unleased)
                | Some(LeaseState::Acquiring)
                | Some(LeaseState::Expiring)
                | Some(LeaseState::Released) => {
                    return Err(BackfillError::SourceLeaseNotActive(
                        source,
                        source_leases
                            .get(&source)
                            .copied()
                            .unwrap_or(LeaseState::Unleased),
                    ));
                }
                Some(LeaseState::Held) | Some(LeaseState::Renewing) => {}
            }
        }
        Ok(())
    }

    // ── Collection helpers ──────────────────────────────────────────

    /// Return all batches for a given backfill.
    pub fn batches_for(&self, backfill_id: u64) -> Option<&[BackfillBatch]> {
        self.session(backfill_id).map(|s| s.batches.as_slice())
    }

    /// Create [`BackfillCommand`]s from a rebuild plan without creating a session.
    ///
    /// Useful for previewing the plan partitioning before opening.
    pub fn preview_batches(
        plan: &RebuildPlan,
        epoch: EpochId,
        max_chunk_bytes: u64,
    ) -> Vec<BackfillBatch> {
        Self::partition_plan(plan, epoch, max_chunk_bytes, DataPathCarrier::Unknown)
    }
}

#[cfg(test)]
mod tests;
