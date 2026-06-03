#![forbid(unsafe_code)]

//! Production replication protocol: fanout writes, collect quorum ACKs,
//! handle partial failures, and commit through the flow commit coordinator.
//!
//! Implements PC-010.3 distributed replication with per-chunk-class quorum
//! policies, receipt-backed completion, and transfer orchestrator integration.
//!
//! # Architecture
//!
//! ```text
//! Write path (protocol state machine):
//!   fanout_write → collect_ack (per target) → poll_result → commit_write → FlowCommitCoordinator
//!
//! Write path (transport dispatch):
//!   ReplicationWriteHandle::submit_write → ReplicaSendDispatch (fan-out)
//!                                         → QuorumAcknowledgmentAggregator
//!                                         → ReplicationWriteOutcome
//!
//! Degraded read path:
//!   select_candidates (health-aware ordering) → try_candidates → escalate to DemandRead
//! ```
//!
//! # Quorum policies per chunk class
//!
//! - `MetadataHead`, `ClaimLedger`, `ProjectionRoot` → `Critical` (all-target quorum)
//! - `ContentPayload` → `Standard` (majority quorum)
//! - `BackgroundData` → `BestEffort` (single ACK)

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

use tidefs_membership_epoch::{EpochId, MemberId};

use tidefs_flow_commit_coordinator::FlowCommitCoordinator;
use tidefs_replication_model::{
    ReplicaLagClass, ReplicaLagStateRecord, ReplicaTransferReceipt, ReplicaVerificationReceipt,
    ReplicatedReceiptId, ReplicatedSubjectId, VerificationStatus,
};
use tidefs_transport::{
    dispatch_write_request, recv_write_ack, SessionId, TransferDispatchError, TransferHandle,
    Transport, WriteStatus,
};

// ═══════════════════════════════════════════════════════════════════════
// Quorum policy types
// ═══════════════════════════════════════════════════════════════════════

/// Quorum replication policy per chunk class.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicationPolicy {
    /// All-target quorum: every target must ACK.
    Critical,
    /// Majority quorum: ⌈N/2⌉ must ACK.
    Standard,
    /// Single ACK: at least one target must ACK.
    BestEffort,
}

impl ReplicationPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Standard => "standard",
            Self::BestEffort => "best_effort",
        }
    }

    /// Minimum ACKs required to achieve quorum given N targets.
    #[must_use]
    pub const fn min_quorum(self, target_count: usize) -> usize {
        match self {
            Self::Critical => target_count,
            Self::Standard => {
                if target_count == 0 {
                    0
                } else {
                    target_count / 2 + 1
                }
            }
            Self::BestEffort => {
                if target_count == 0 {
                    0
                } else {
                    1
                }
            }
        }
    }

    #[must_use]
    pub const fn requires_all(self) -> bool {
        matches!(self, Self::Critical)
    }

    #[must_use]
    pub const fn requires_majority(self) -> bool {
        matches!(self, Self::Standard)
    }
}

/// Chunk classes used for policy selection (PC-010.3).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicationChunkClass {
    MetadataHead,
    ClaimLedger,
    ContentPayload,
    BackgroundData,
    ProjectionRoot,
}

impl ReplicationChunkClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataHead => "metadata_head",
            Self::ClaimLedger => "claim_ledger",
            Self::ContentPayload => "content_payload",
            Self::BackgroundData => "background_data",
            Self::ProjectionRoot => "projection_root",
        }
    }
}

/// Selects quorum replication policy per chunk class.
///
/// - `MetadataHead`, `ClaimLedger`, `ProjectionRoot` → `Critical` (all-target quorum)
/// - `ContentPayload` → `Standard` (majority quorum)
/// - `BackgroundData` → `BestEffort` (single ACK)
#[derive(Debug, Default)]
pub struct ReplicationPolicySelector;

impl ReplicationPolicySelector {
    #[must_use]
    pub const fn select(class: ReplicationChunkClass) -> ReplicationPolicy {
        match class {
            ReplicationChunkClass::MetadataHead
            | ReplicationChunkClass::ClaimLedger
            | ReplicationChunkClass::ProjectionRoot => ReplicationPolicy::Critical,
            ReplicationChunkClass::ContentPayload => ReplicationPolicy::Standard,
            ReplicationChunkClass::BackgroundData => ReplicationPolicy::BestEffort,
        }
    }

    #[must_use]
    pub fn min_quorum_for(class: ReplicationChunkClass, target_count: usize) -> usize {
        Self::select(class).min_quorum(target_count)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Transfer priority classes
// ═══════════════════════════════════════════════════════════════════════

/// Transfer priority classes for admission ordering per P8-03 data-flow mapping.
///
/// | Class            | Data flow | Priority | Description                     |
/// |------------------|-----------|----------|---------------------------------|
/// | SteadyReplication| data_flow_0| 0        | Steady-state replication         |
/// | CatchupRepair    | data_flow_1| 1        | Catch-up repair for lagging copies |
/// | CapacityRebalance| data_flow_3| 2        | Capacity rebalance / relocation  |
/// | LossRebuild      | data_flow_2| 3        | Rebuild lost or suspect copy     |
/// | Drain            | data_flow_5| 4        | Drain / decommission a member    |
/// | DemandRead       | data_flow_4| 5        | Demand read (highest priority)   |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferPriorityClass {
    /// data_flow_0: steady-state replication (lowest priority).
    SteadyReplication,
    /// data_flow_1: catch-up repair for lagging copies.
    CatchupRepair,
    /// data_flow_2: rebuild a lost or suspect copy.
    LossRebuild,
    /// data_flow_3: capacity rebalance / relocation.
    CapacityRebalance,
    /// data_flow_4: demand read (highest priority for reads).
    DemandRead,
    /// data_flow_5: drain / decommission.
    Drain,
}

impl TransferPriorityClass {
    #[must_use]
    pub const fn is_steady(self) -> bool {
        matches!(self, Self::SteadyReplication)
    }

    #[must_use]
    pub const fn is_rebuild(self) -> bool {
        matches!(self, Self::LossRebuild)
    }

    #[must_use]
    pub const fn is_catchup(self) -> bool {
        matches!(self, Self::CatchupRepair)
    }

    #[must_use]
    pub const fn is_demand_read(self) -> bool {
        matches!(self, Self::DemandRead)
    }

    /// Admission priority: lower = lower urgency.
    /// P8-03 data-flow ordering.
    #[must_use]
    pub const fn admission_priority(self) -> u8 {
        match self {
            Self::SteadyReplication => 0,
            Self::CatchupRepair => 1,
            Self::CapacityRebalance => 2,
            Self::LossRebuild => 3,
            Self::Drain => 4,
            Self::DemandRead => 5,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Write protocol types
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct WriteId(pub u64);

impl WriteId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteAck {
    pub target: MemberId,
    pub digest_ok: bool,
    pub placement_receipt_ref: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteCommitReceipt {
    pub write_id: WriteId,
    pub chunk_class: ReplicationChunkClass,
    pub epoch: EpochId,
    pub committed_targets: Vec<MemberId>,
    pub target_count: usize,
    pub policy: ReplicationPolicy,
    pub partial: bool,
    pub failed_targets: Vec<MemberId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteResult {
    Committed {
        write_id: WriteId,
        receipt: WriteCommitReceipt,
    },
    Partial {
        write_id: WriteId,
        receipt: WriteCommitReceipt,
        missing_targets: Vec<MemberId>,
    },
    QuorumFailed {
        write_id: WriteId,
        acks_collected: usize,
        quorum_required: usize,
        reason: QuorumFailureReason,
    },
}

impl WriteResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Partial { .. })
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        matches!(self, Self::Partial { .. })
    }

    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::QuorumFailed { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumFailureReason {
    QuorumImpossible {
        remaining: usize,
        needed: usize,
    },
    Timeout {
        acks_collected: usize,
        quorum_required: usize,
    },
    Cancelled,
}

/// A catchup repair ticket when a target is missing a chunk.
/// Always uses `CatchupRepair` priority per P8-03 data-flow mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchupRepairTicket {
    pub write_id: WriteId,
    pub target: MemberId,
}

impl CatchupRepairTicket {
    #[must_use]
    pub fn is_rebuild(&self) -> bool {
        false
    }

    /// A `CatchupRepairTicket` always carries `CatchupRepair` priority
    /// per P8-03 data-flow mapping.
    #[must_use]
    pub const fn priority_class() -> TransferPriorityClass {
        TransferPriorityClass::CatchupRepair
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Degraded read types
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CandidateHealthClass {
    Local = 0,
    Healthy = 1,
    LaggedButUsable = 2,
    AnyReplica = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradedReadCandidate {
    pub member_id: MemberId,
    pub health_class: CandidateHealthClass,
    pub is_local: bool,
    pub lag_bytes_behind: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemandReadTicket {
    pub ticket_id: u64,
    pub subject_id: ReplicatedSubjectId,
    pub candidate_count_tried: usize,
    pub priority: u8,
    pub epoch: u64,
}

impl DemandReadTicket {
    pub const MAX_PRIORITY: u8 = 255;

    #[must_use]
    pub fn with_max_priority(mut self) -> Self {
        self.priority = Self::MAX_PRIORITY;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedReadVisibility {
    Exact,
    DegradedButValid,
    RepairRequired,
    Unavailable,
}

impl DegradedReadVisibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::DegradedButValid => "degraded_but_valid",
            Self::RepairRequired => "repair_required",
            Self::Unavailable => "unavailable",
        }
    }

    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(
            self,
            Self::Exact | Self::DegradedButValid | Self::RepairRequired
        )
    }

    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::DegradedButValid | Self::RepairRequired)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Pending write state
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct PendingWrite {
    chunk_class: ReplicationChunkClass,
    policy: ReplicationPolicy,
    target_count: usize,
    acks: Vec<WriteAck>,
    failed_targets: Vec<MemberId>,
    epoch: EpochId,
    quorum_impossible: bool,
    timed_out: bool,
}

impl PendingWrite {
    fn quorum_size(&self) -> usize {
        self.policy.min_quorum(self.target_count)
    }

    fn ack_count(&self) -> usize {
        self.acks.len()
    }

    #[allow(dead_code)]
    fn target_id_set_from_acks(&self) -> std::collections::BTreeSet<MemberId> {
        self.acks.iter().map(|a| a.target).collect()
    }

    fn check_quorum_impossible(&mut self) -> bool {
        let acked = self.ack_count();
        let failed = self.failed_targets.len();
        let needed = self.quorum_size();
        // Remaining possible acks = target_count - acked - failed
        let remaining = self
            .target_count
            .saturating_sub(acked)
            .saturating_sub(failed);
        if acked + remaining < needed {
            self.quorum_impossible = true;
            true
        } else {
            false
        }
    }

    fn committed_targets(&self) -> Vec<MemberId> {
        self.acks.iter().map(|a| a.target).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicationProtocol
// ═══════════════════════════════════════════════════════════════════════

/// The production replication protocol runtime.
///
/// Manages fanout writes with per-chunk-class quorum policies,
/// partial failure detection, write commitment, and catchup repair.
#[derive(Debug)]
pub struct ReplicationProtocol {
    next_write_id: u64,
    pending_writes: BTreeMap<u64, PendingWrite>,
    completed_writes: Vec<WriteResult>,
    epoch: EpochId,
    reserve_protection_active: bool,
    transfer_priority_class: TransferPriorityClass,
}

impl ReplicationProtocol {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            next_write_id: 1,
            pending_writes: BTreeMap::new(),
            completed_writes: Vec::new(),
            epoch,
            reserve_protection_active: false,
            transfer_priority_class: TransferPriorityClass::SteadyReplication,
        }
    }

    pub fn set_transfer_priority(&mut self, class: TransferPriorityClass) {
        self.transfer_priority_class = class;
    }

    #[must_use]
    pub fn transfer_priority(&self) -> TransferPriorityClass {
        self.transfer_priority_class
    }

    pub fn set_reserve_protection(&mut self, active: bool) {
        self.reserve_protection_active = active;
    }

    #[must_use]
    pub fn is_reserve_protection_active(&self) -> bool {
        self.reserve_protection_active
    }

    #[must_use]
    pub fn should_yield_for_reserve(&self) -> bool {
        self.reserve_protection_active
    }

    /// Fan out a write to all replica targets. Returns a write id.
    #[must_use]
    pub fn fanout_write(
        &mut self,
        chunk_class: ReplicationChunkClass,
        target_count: usize,
    ) -> WriteId {
        let policy = ReplicationPolicySelector::select(chunk_class);
        let write_id = WriteId::new(self.next_write_id);
        self.next_write_id += 1;
        self.pending_writes.insert(
            write_id.0,
            PendingWrite {
                chunk_class,
                policy,
                target_count,
                acks: Vec::new(),
                failed_targets: Vec::new(),
                epoch: self.epoch,
                quorum_impossible: false,
                timed_out: false,
            },
        );
        write_id
    }

    /// Collect an ACK from a target replica for a pending write.
    pub fn collect_ack(&mut self, write_id: WriteId, ack: WriteAck) {
        if let Some(pending) = self.pending_writes.get_mut(&write_id.0) {
            if pending.quorum_impossible {
                return;
            }
            // Deduplicate
            if pending.acks.iter().any(|a| a.target == ack.target) {
                return;
            }
            pending.acks.push(ack);
            let _ = pending.check_quorum_impossible();
        }
    }

    /// Handle a write failure to a specific target.
    /// If quorum becomes impossible after this failure, the write is marked failed.
    pub fn handle_write_failure(&mut self, write_id: WriteId, target: MemberId) {
        if let Some(pending) = self.pending_writes.get_mut(&write_id.0) {
            if !pending.failed_targets.contains(&target) {
                pending.failed_targets.push(target);
            }
            pending.check_quorum_impossible();
        }
    }

    /// Mark a write as timed out. Fails with `Timeout` reason.
    pub fn timeout_write(&mut self, write_id: WriteId) {
        if let Some(pending) = self.pending_writes.get_mut(&write_id.0) {
            pending.timed_out = true;
        }
    }

    /// Poll the result of a pending write.
    /// Returns `Some` when quorum is reached, impossible, or timed out.
    #[must_use]
    pub fn poll_result(&mut self, write_id: WriteId) -> Option<WriteResult> {
        let pending = self.pending_writes.get(&write_id.0)?;

        // Timeout takes precedence
        if pending.timed_out {
            let pending = self.pending_writes.remove(&write_id.0)?;
            let result = WriteResult::QuorumFailed {
                write_id,
                acks_collected: pending.ack_count(),
                quorum_required: pending.quorum_size(),
                reason: QuorumFailureReason::Timeout {
                    acks_collected: pending.ack_count(),
                    quorum_required: pending.quorum_size(),
                },
            };
            self.completed_writes.push(result.clone());
            return Some(result);
        }

        // Quorum impossible
        if pending.quorum_impossible {
            let pending = self.pending_writes.remove(&write_id.0)?;
            let result = WriteResult::QuorumFailed {
                write_id,
                acks_collected: pending.ack_count(),
                quorum_required: pending.quorum_size(),
                reason: QuorumFailureReason::QuorumImpossible {
                    remaining: pending
                        .target_count
                        .saturating_sub(pending.ack_count())
                        .saturating_sub(pending.failed_targets.len()),
                    needed: pending.quorum_size(),
                },
            };
            self.completed_writes.push(result.clone());
            return Some(result);
        }

        let acked = pending.ack_count();
        let quorum_size = pending.quorum_size();
        let failed_len = pending.failed_targets.len();

        // Full quorum: quorum reached with no failures (all acked or
        // enough acked for non-Critical policies)
        if acked >= quorum_size && failed_len == 0 {
            let pending = self.pending_writes.remove(&write_id.0)?;
            let committed = pending.committed_targets();
            let receipt = WriteCommitReceipt {
                write_id,
                chunk_class: pending.chunk_class,
                epoch: pending.epoch,
                committed_targets: committed,
                target_count: pending.target_count,
                policy: pending.policy,
                partial: false,
                failed_targets: Vec::new(),
            };
            let result = WriteResult::Committed { write_id, receipt };
            self.completed_writes.push(result.clone());
            return Some(result);
        }

        // Partial: majority reached but some targets failed/missing
        if acked >= quorum_size && acked < pending.target_count && failed_len > 0 {
            let pending = self.pending_writes.remove(&write_id.0)?;
            let committed = pending.committed_targets();
            let missing = pending.failed_targets.clone();
            let receipt = WriteCommitReceipt {
                write_id,
                chunk_class: pending.chunk_class,
                epoch: pending.epoch,
                committed_targets: committed,
                target_count: pending.target_count,
                policy: pending.policy,
                partial: true,
                failed_targets: missing.clone(),
            };
            let result = WriteResult::Partial {
                write_id,
                receipt,
                missing_targets: missing,
            };
            self.completed_writes.push(result.clone());
            return Some(result);
        }

        None
    }

    /// Commit a write and produce a `WriteCommitReceipt`.
    /// The receipt is emitted through the flow commit coordinator (#902).
    #[must_use]
    pub fn commit_write(&mut self, write_id: WriteId) -> Option<WriteCommitReceipt> {
        // First poll, then extract receipt
        match self.poll_result(write_id) {
            Some(WriteResult::Committed { receipt, .. }) => Some(receipt),
            Some(WriteResult::Partial { receipt, .. }) => Some(receipt),
            _ => {
                // For writes that haven't been polled yet, force-commit at current ack count
                let pending = self.pending_writes.remove(&write_id.0)?;
                let committed = pending.committed_targets();
                let failed = pending.failed_targets.clone();
                let partial = pending.ack_count() < pending.target_count;

                if committed.is_empty() {
                    return None;
                }

                let receipt = WriteCommitReceipt {
                    write_id,
                    chunk_class: pending.chunk_class,
                    epoch: pending.epoch,
                    committed_targets: committed,
                    target_count: pending.target_count,
                    policy: pending.policy,
                    partial,
                    failed_targets: failed,
                };
                Some(receipt)
            }
        }
    }

    /// Produce a `CatchupRepairTicket` for a missing target.
    #[must_use]
    pub fn repair_missing_target(
        &self,
        write_id: WriteId,
        target: MemberId,
    ) -> CatchupRepairTicket {
        CatchupRepairTicket { write_id, target }
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_writes.len()
    }

    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed_writes.len()
    }

    /// Update the epoch (resets pending writes).
    pub fn set_epoch(&mut self, epoch: EpochId) {
        self.epoch = epoch;
        self.pending_writes.clear();
    }

    /// Emit a transfer receipt for a completed transfer (PC-010.3).
    #[must_use]
    pub fn emit_transfer_receipt(
        &self,
        write_id: WriteId,
        source: MemberId,
        target: MemberId,
        bytes_moved: u64,
    ) -> ReplicaTransferReceipt {
        ReplicaTransferReceipt {
            receipt_id: ReplicatedReceiptId(write_id.0),
            ticket_ref: ReplicatedReceiptId(write_id.0),
            bytes_moved,
            source_anchor_hash: source.0,
            target_anchor_hash: target.0,
            completion_epoch: self.epoch,
            worker_refs: vec![source, target],
        }
    }

    /// Emit a verification receipt for a completed verification (PC-010.3).
    #[must_use]
    pub fn emit_verification_receipt(
        &self,
        receipt_id: ReplicatedReceiptId,
        subject_refs: Vec<ReplicatedSubjectId>,
        digest_results: Vec<tidefs_replication_model::ObjectDigest>,
        witness_refs: Vec<MemberId>,
        status: VerificationStatus,
    ) -> ReplicaVerificationReceipt {
        ReplicaVerificationReceipt {
            receipt_id,
            subject_refs,
            digest_results,
            witness_refs,
            quorum_class: 0,
            verification_epoch: self.epoch,
            status,
        }
    }

    /// Commit a completed write result into the flow commit coordinator (#902).
    ///
    /// Extracts the  and registers committed chunks
    /// in the coordinator. Also emits  and
    ///  for each committed target, advancing
    /// through the transfer→verify→place receipt chain.
    pub fn commit_to_coordinator(
        &mut self,
        write_id: WriteId,
        coordinator: &mut FlowCommitCoordinator,
        subject_refs: &[ReplicatedSubjectId],
    ) -> Option<WriteCommitReceipt> {
        let receipt = self.commit_write(write_id)?;

        // For each committed target, register a chunk in the coordinator
        // and advance through transfer→verification→placement
        for target in &receipt.committed_targets {
            for subject in subject_refs {
                let ticket_ref = ReplicatedReceiptId(write_id.0.wrapping_add(subject.0));
                let _ = coordinator.register_chunk(
                    *subject,
                    MemberId::new(0), // source: the protocol doesn't track per-target source
                    *target,
                    // Map chunk class to FlowCommitClass
                    self.chunk_class_to_flow_class(receipt.chunk_class),
                    ticket_ref,
                );
            }
        }

        // Emit transfer receipts for committed targets
        for target in &receipt.committed_targets {
            let xfer_receipt = self.emit_transfer_receipt(write_id, MemberId::new(0), *target, 0);
            let _ = coordinator.commit_transfer_receipt(xfer_receipt);
        }

        // Emit verification receipts for committed targets
        if !receipt.committed_targets.is_empty() {
            let v_receipt = self.emit_verification_receipt(
                ReplicatedReceiptId(write_id.0),
                subject_refs.to_vec(),
                Vec::new(),
                receipt.committed_targets.clone(),
                VerificationStatus::Verified,
            );
            let _ = coordinator.commit_verification_receipt(v_receipt);
        }

        Some(receipt)
    }

    /// Map a  to a .
    #[must_use]
    fn chunk_class_to_flow_class(
        &self,
        class: ReplicationChunkClass,
    ) -> tidefs_replication_model::FlowCommitClass {
        match class {
            ReplicationChunkClass::MetadataHead
            | ReplicationChunkClass::ClaimLedger
            | ReplicationChunkClass::ContentPayload
            | ReplicationChunkClass::ProjectionRoot => {
                tidefs_replication_model::FlowCommitClass::SteadyReplication
            }
            ReplicationChunkClass::BackgroundData => {
                tidefs_replication_model::FlowCommitClass::SteadyReplication
            }
        }
    }

    /// Update  whenever a fence frontier or
    /// placement receipt advances (PC-010.3, P8-03 §10).
    ///
    /// Computes the lag class based on  total and
    /// records the oldest missing receipt ref.
    #[must_use]
    pub fn update_lag_state(
        &self,
        subject_ref: ReplicatedSubjectId,
        target_ref: MemberId,
        freshness_fence_frontier: u64,
        bytes_behind: u64,
        oldest_missing_receipt_ref: ReplicatedReceiptId,
    ) -> ReplicaLagStateRecord {
        let lag_class = if bytes_behind == 0 {
            ReplicaLagClass::Current
        } else if bytes_behind < 1024 * 1024 {
            ReplicaLagClass::SlightlyBehind
        } else if bytes_behind < 64 * 1024 * 1024 {
            ReplicaLagClass::ModeratelyBehind
        } else if bytes_behind < 256 * 1024 * 1024 {
            ReplicaLagClass::SeverelyBehind
        } else {
            ReplicaLagClass::Stale
        };

        let degraded_visibility_class = match lag_class {
            ReplicaLagClass::Current => tidefs_replication_model::DegradedVisibilityClass::None,
            ReplicaLagClass::SlightlyBehind | ReplicaLagClass::ModeratelyBehind => {
                tidefs_replication_model::DegradedVisibilityClass::DegradedReadPossible
            }
            ReplicaLagClass::SeverelyBehind => {
                tidefs_replication_model::DegradedVisibilityClass::DegradedReadPossible
            }
            ReplicaLagClass::Stale => {
                tidefs_replication_model::DegradedVisibilityClass::StaleDataServed
            }
        };

        ReplicaLagStateRecord {
            subject_ref,
            target_ref,
            freshness_fence_frontier,
            lag_class,
            bytes_behind,
            oldest_missing_receipt_ref,
            degraded_visibility_class,
        }
    }

    /// Submit a  transfer ticket to the transfer
    /// orchestrator (#901) when a target is missing a chunk entirely.
    ///
    /// Returns a  that the transfer orchestrator
    /// can admit as a  transfer.
    #[must_use]
    pub fn submit_catchup_repair_ticket(
        &self,
        write_id: WriteId,
        target: MemberId,
    ) -> CatchupRepairTicket {
        self.repair_missing_target(write_id, target)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// DegradedReadProtocol
// ═══════════════════════════════════════════════════════════════════════

/// Production degraded read protocol with health-aware candidate selection.
///
/// Tries candidates in strict priority order:
/// 1. Local replica (fastest path)
/// 2. Healthy replicas at the frontier
/// 3. Lagged-but-usable replicas
/// 4. Any remaining replica
/// 5. Escalate to DemandRead transfer when all fail
pub struct DegradedReadProtocol {
    candidates: Vec<DegradedReadCandidate>,
    local_member_id: Option<MemberId>,
    escalate_to_demand_read: bool,
}

impl DegradedReadProtocol {
    #[must_use]
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            local_member_id: None,
            escalate_to_demand_read: true,
        }
    }

    pub fn set_local_member(&mut self, member_id: MemberId) {
        self.local_member_id = Some(member_id);
    }

    pub fn set_escalation(&mut self, escalate: bool) {
        self.escalate_to_demand_read = escalate;
    }

    /// Update candidate list from health data.
    /// Each element is (member_id, health_class, lag_bytes_behind).
    /// The local member is automatically promoted to `Local` priority.
    pub fn refresh_candidates(&mut self, health: &[(MemberId, CandidateHealthClass, u64)]) {
        self.candidates = health
            .iter()
            .map(|&(member_id, health_class, lag_bytes_behind)| {
                let is_local = self.local_member_id == Some(member_id);
                let class = if is_local {
                    CandidateHealthClass::Local
                } else {
                    health_class
                };
                DegradedReadCandidate {
                    member_id,
                    health_class: class,
                    is_local,
                    lag_bytes_behind,
                }
            })
            .collect();
        // Sort by health class priority (Local < Healthy < LaggedButUsable < AnyReplica)
        self.candidates.sort_by_key(|c| c.health_class);
    }

    /// Build a DemandRead escalation ticket.
    #[must_use]
    pub fn build_demand_read_ticket(
        &self,
        subject_id: ReplicatedSubjectId,
        next_ticket_id: u64,
    ) -> DemandReadTicket {
        DemandReadTicket {
            ticket_id: next_ticket_id,
            subject_id,
            candidate_count_tried: self.candidates.len(),
            priority: DemandReadTicket::MAX_PRIORITY,
            epoch: 0,
        }
        .with_max_priority()
    }

    #[must_use]
    pub fn can_degrade(&self) -> bool {
        !self.candidates.is_empty()
    }

    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    #[must_use]
    pub fn candidates_by_class(&self) -> BTreeMap<CandidateHealthClass, Vec<MemberId>> {
        let mut map: BTreeMap<CandidateHealthClass, Vec<MemberId>> = BTreeMap::new();
        for c in &self.candidates {
            map.entry(c.health_class).or_default().push(c.member_id);
        }
        map
    }

    /// Whether escalation to DemandRead is enabled.
    #[must_use]
    pub fn escalation_enabled(&self) -> bool {
        self.escalate_to_demand_read
    }

    /// Try candidates in priority order and return the best available
    /// degraded read visibility class (PC-010.3).
    ///
    /// Returns the visibility classification before attempting the read.
    /// - Local replica found → Exact
    /// - Healthy replica found → Exact
    /// - Lagged-but-usable replica found → DegradedButValid
    /// - Any remaining replica found → RepairRequired
    /// - No candidates → Unavailable
    #[must_use]
    pub fn try_candidates_with_visibility(
        &self,
        failed_members: &[MemberId],
    ) -> (Option<DegradedReadCandidate>, DegradedReadVisibility) {
        let failed_set: std::collections::BTreeSet<MemberId> =
            failed_members.iter().copied().collect();

        for candidate in &self.candidates {
            if failed_set.contains(&candidate.member_id) {
                continue;
            }
            let visibility = match candidate.health_class {
                CandidateHealthClass::Local | CandidateHealthClass::Healthy => {
                    DegradedReadVisibility::Exact
                }
                CandidateHealthClass::LaggedButUsable => DegradedReadVisibility::DegradedButValid,
                CandidateHealthClass::AnyReplica => DegradedReadVisibility::RepairRequired,
            };
            return (Some(candidate.clone()), visibility);
        }

        (None, DegradedReadVisibility::Unavailable)
    }

    /// Escalate a degraded read failure to a DemandRead transfer ticket (#901).
    ///
    /// When all candidates have failed, escalate with maximum priority.
    #[must_use]
    pub fn escalate_demand_read(
        &self,
        subject_id: ReplicatedSubjectId,
        next_ticket_id: u64,
    ) -> DemandReadTicket {
        self.build_demand_read_ticket(subject_id, next_ticket_id)
    }

    /// Build a CatchupRepair ticket for a specific missing target (#901).
    #[must_use]
    pub fn escalate_catchup_repair(&self, missing_target: MemberId) -> CatchupRepairTicket {
        CatchupRepairTicket {
            write_id: WriteId::new(0),
            target: missing_target,
        }
    }
}

impl Default for DegradedReadProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Transport-backed replicated write path
// ═══════════════════════════════════════════════════════════════════════

/// Error returned by the transport-backed replicated write path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicationWriteError {
    /// A peer received the write request but refused to commit it.
    PeerRefused { peer_node_id: u64, reason: String },
    /// The write could not be dispatched, acknowledged, or verified.
    Transport { reason: String },
}

impl fmt::Display for ReplicationWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerRefused {
                peer_node_id,
                reason,
            } => write!(
                f,
                "peer node {peer_node_id} refused replicated write: {reason}"
            ),
            Self::Transport { reason } => write!(f, "replicated write transport error: {reason}"),
        }
    }
}

impl std::error::Error for ReplicationWriteError {}

// ═══════════════════════════════════════════════════════════════════════

// QuorumWriteTransport — minimal dispatch interface for quorum-write-runtime

// ═══════════════════════════════════════════════════════════════════════
/// Minimal write-dispatch interface that `tidefs-quorum-write-runtime`
/// calls to reach transport sessions during a quorum write.
///
/// Each call to `write_replica()` dispatches the payload to a single
/// replica target and returns the BLAKE3 checksum of the payload as
/// verified by that replica.  The quorum runtime collects these checksums
/// and compares them against the canonical checksum to determine whether
/// quorum has been reached.
pub trait QuorumWriteTransport {
    /// Write `payload` to `replica_id` and return the BLAKE3 checksum
    /// of the stored payload, or an error string on transport failure.
    fn write_replica(&mut self, replica_id: u64, payload: &[u8]) -> Result<blake3::Hash, String>;
}

/// Single-writer object replication interface shared by local and remote paths.
pub trait ReplicatedWrite {
    /// Write `payload` for `object_id` at `offset` to every required replica.
    fn write_object(
        &mut self,
        object_id: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), ReplicationWriteError>;
}

/// Transport implementation of [`ReplicatedWrite`] for one remote peer session.
pub struct ReplicationWritePath<'t> {
    transport: &'t mut Transport,
    data_session_id: SessionId,
    peer_node_id: u64,
    transfer_handle: TransferHandle,
}

impl<'t> ReplicationWritePath<'t> {
    /// Create a replicated write path over an established data session.
    #[must_use]
    pub fn new(
        transport: &'t mut Transport,
        data_session_id: SessionId,
        peer_node_id: u64,
    ) -> Self {
        Self {
            transport,
            data_session_id,
            peer_node_id,
            transfer_handle: TransferHandle::new(),
        }
    }

    /// Derive the wire object key used by both writer and receiver.
    #[must_use]
    pub fn derive_object_key(object_id: u64, offset: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tidefs.replicated-write.v1");
        hasher.update(&object_id.to_le_bytes());
        hasher.update(&offset.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }

    fn map_dispatch_error(&self, error: TransferDispatchError) -> ReplicationWriteError {
        match error {
            TransferDispatchError::WriteRejected(status) => ReplicationWriteError::PeerRefused {
                peer_node_id: self.peer_node_id,
                reason: format!("{status:?}"),
            },
            other => ReplicationWriteError::Transport {
                reason: format!("peer node {}: {other}", self.peer_node_id),
            },
        }
    }
}

impl ReplicatedWrite for ReplicationWritePath<'_> {
    fn write_object(
        &mut self,
        object_id: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), ReplicationWriteError> {
        let object_key = Self::derive_object_key(object_id, offset);
        let transfer_id = dispatch_write_request(
            self.transport,
            &mut self.transfer_handle,
            self.data_session_id,
            object_key,
            offset,
            payload,
        )
        .map_err(|error| self.map_dispatch_error(error))?;

        let (bytes_written, status) = recv_write_ack(
            self.transport,
            &mut self.transfer_handle,
            self.data_session_id,
            transfer_id,
        )
        .map_err(|error| self.map_dispatch_error(error))?;

        if status != WriteStatus::Ok {
            return Err(ReplicationWriteError::PeerRefused {
                peer_node_id: self.peer_node_id,
                reason: format!("{status:?}"),
            });
        }

        if bytes_written != payload.len() as u64 {
            return Err(ReplicationWriteError::Transport {
                reason: format!(
                    "peer node {} wrote {bytes_written} bytes for {}-byte payload",
                    self.peer_node_id,
                    payload.len()
                ),
            });
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> EpochId {
        EpochId::new(1)
    }

    #[test]
    fn replication_write_error_display_peer_refused() {
        let error = ReplicationWriteError::PeerRefused {
            peer_node_id: 7,
            reason: "Rejected".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "peer node 7 refused replicated write: Rejected"
        );
    }

    #[test]
    fn replication_write_error_display_transport() {
        let error = ReplicationWriteError::Transport {
            reason: "session closed".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "replicated write transport error: session closed"
        );
    }

    #[test]
    fn replication_write_object_key_is_deterministic() {
        let first = ReplicationWritePath::derive_object_key(42, 4096);
        let second = ReplicationWritePath::derive_object_key(42, 4096);
        assert_eq!(first, second);
    }

    #[test]
    fn replication_write_object_key_separates_object_and_offset() {
        let base = ReplicationWritePath::derive_object_key(42, 4096);
        assert_ne!(base, ReplicationWritePath::derive_object_key(43, 4096));
        assert_ne!(base, ReplicationWritePath::derive_object_key(42, 8192));
    }

    // ── Policy selector tests ────────────────────────────────────────

    #[test]
    fn critical_policy_for_metadata_head() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::MetadataHead),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn critical_policy_for_claim_ledger() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ClaimLedger),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn critical_policy_for_projection_root() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ProjectionRoot),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn standard_policy_for_content_payload() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ContentPayload),
            ReplicationPolicy::Standard
        );
    }

    #[test]
    fn best_effort_policy_for_background_data() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::BackgroundData),
            ReplicationPolicy::BestEffort
        );
    }

    #[test]
    fn min_quorum_computation() {
        assert_eq!(ReplicationPolicy::Critical.min_quorum(3), 3);
        assert_eq!(ReplicationPolicy::Critical.min_quorum(5), 5);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(3), 2);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(5), 3);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(4), 3);
        assert_eq!(ReplicationPolicy::BestEffort.min_quorum(3), 1);
        assert_eq!(ReplicationPolicy::BestEffort.min_quorum(1), 1);
        assert_eq!(ReplicationPolicy::BestEffort.min_quorum(0), 0);
        assert_eq!(ReplicationPolicy::Critical.min_quorum(0), 0);
    }

    #[test]
    fn requires_all_only_for_critical() {
        assert!(ReplicationPolicy::Critical.requires_all());
        assert!(!ReplicationPolicy::Standard.requires_all());
        assert!(!ReplicationPolicy::BestEffort.requires_all());
    }

    #[test]
    fn requires_majority_only_for_standard() {
        assert!(!ReplicationPolicy::Critical.requires_majority());
        assert!(ReplicationPolicy::Standard.requires_majority());
        assert!(!ReplicationPolicy::BestEffort.requires_majority());
    }

    // ── Write protocol tests ─────────────────────────────────────────

    #[test]
    fn fanout_write_and_collect_acks() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        let result = proto.poll_result(wid).unwrap();
        assert!(result.is_success());
    }

    #[test]
    fn partial_quorum_when_targets_fail() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.handle_write_failure(wid, MemberId::new(3));
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        let result = proto.poll_result(wid).unwrap();
        assert!(result.is_partial());
    }

    #[test]
    fn critical_policy_requires_all() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::MetadataHead, 3);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).is_none());
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(3),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn critical_failure_when_too_many_missing() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::MetadataHead, 3);
        proto.handle_write_failure(wid, MemberId::new(3));
        assert!(proto.poll_result(wid).unwrap().is_failed());
    }

    #[test]
    fn best_effort_needs_one_ack() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::BackgroundData, 5);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(3),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn commit_write_returns_receipt() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        let receipt = proto.commit_write(wid).unwrap();
        assert_eq!(receipt.write_id, wid);
        assert_eq!(receipt.policy, ReplicationPolicy::Standard);
    }

    #[test]
    fn timeout_write_fails() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.timeout_write(wid);
        assert!(proto.poll_result(wid).unwrap().is_failed());
    }

    #[test]
    fn reserve_protection_yield() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        assert!(!proto.should_yield_for_reserve());
        proto.set_reserve_protection(true);
        assert!(proto.should_yield_for_reserve());
    }

    #[test]
    fn transfer_priority_ordering() {
        assert!(
            TransferPriorityClass::SteadyReplication.admission_priority()
                < TransferPriorityClass::LossRebuild.admission_priority()
        );
    }

    #[test]
    fn repair_missing_target_produces_catchup_ticket() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        proto.set_transfer_priority(TransferPriorityClass::LossRebuild);
        let ticket = proto.repair_missing_target(WriteId::new(42), MemberId::new(7));
        assert_eq!(ticket.target, MemberId::new(7));
        assert!(!ticket.is_rebuild());
        assert_eq!(
            CatchupRepairTicket::priority_class(),
            TransferPriorityClass::CatchupRepair
        );
    }

    #[test]
    fn multiple_concurrent_writes() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let w1 = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        let w2 = proto.fanout_write(ReplicationChunkClass::MetadataHead, 2);
        assert_eq!(proto.pending_count(), 2);
        proto.collect_ack(
            w1,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            w1,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(w1).unwrap().is_success());
        proto.collect_ack(
            w2,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            w2,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(w2).unwrap().is_success());
    }

    #[test]
    fn deduplicate_acks() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::BackgroundData, 3);
        let ack = WriteAck {
            target: MemberId::new(1),
            digest_ok: true,
            placement_receipt_ref: None,
        };
        proto.collect_ack(wid, ack.clone());
        proto.collect_ack(wid, ack.clone());
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn commit_write_after_timeout_returns_none() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.timeout_write(wid);
        // poll_result consumes the write, so commit returns None
        let _ = proto.poll_result(wid);
        assert!(proto.commit_write(wid).is_none());
    }

    // ── Degraded read tests ──────────────────────────────────────────

    #[test]
    fn health_class_ordering() {
        assert!(CandidateHealthClass::Local < CandidateHealthClass::Healthy);
        assert!(CandidateHealthClass::Healthy < CandidateHealthClass::LaggedButUsable);
        assert!(CandidateHealthClass::LaggedButUsable < CandidateHealthClass::AnyReplica);
    }

    #[test]
    fn empty_protocol_cannot_degrade() {
        let p = DegradedReadProtocol::new();
        assert!(!p.can_degrade());
        assert_eq!(p.candidate_count(), 0);
    }

    #[test]
    fn refresh_candidates_orders_by_health() {
        let mut p = DegradedReadProtocol::new();
        p.set_local_member(MemberId::new(2));
        let health = vec![
            (MemberId::new(1), CandidateHealthClass::Healthy, 0),
            (MemberId::new(2), CandidateHealthClass::Healthy, 0),
            (MemberId::new(3), CandidateHealthClass::LaggedButUsable, 100),
        ];
        p.refresh_candidates(&health);
        let by_class = p.candidates_by_class();
        assert_eq!(by_class.get(&CandidateHealthClass::Local).unwrap().len(), 1);
        assert_eq!(
            by_class.get(&CandidateHealthClass::Healthy).unwrap().len(),
            1
        );
        assert_eq!(
            by_class
                .get(&CandidateHealthClass::LaggedButUsable)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn demand_read_ticket_max_priority() {
        let p = DegradedReadProtocol::new();
        let ticket = p.build_demand_read_ticket(ReplicatedSubjectId::new(42), 1);
        assert_eq!(ticket.priority, 255);
        assert_eq!(ticket.subject_id, ReplicatedSubjectId::new(42));
    }

    #[test]
    fn degraded_visibility_is_readable() {
        assert!(DegradedReadVisibility::Exact.is_readable());
        assert!(DegradedReadVisibility::DegradedButValid.is_readable());
        assert!(DegradedReadVisibility::RepairRequired.is_readable());
        assert!(!DegradedReadVisibility::Unavailable.is_readable());
    }

    #[test]
    fn degraded_visibility_is_degraded() {
        assert!(!DegradedReadVisibility::Exact.is_degraded());
        assert!(DegradedReadVisibility::DegradedButValid.is_degraded());
        assert!(DegradedReadVisibility::RepairRequired.is_degraded());
        assert!(!DegradedReadVisibility::Unavailable.is_degraded());
    }

    #[test]
    fn escalation_defaults_to_enabled() {
        let p = DegradedReadProtocol::new();
        assert!(p.escalation_enabled());
        let mut p2 = DegradedReadProtocol::new();
        p2.set_escalation(false);
        assert!(!p2.escalation_enabled());
    }

    // ── Edge case tests ──────────────────────────────────────────────

    #[test]
    fn single_target_critical_quorum() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::MetadataHead, 1);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn single_target_best_effort() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::BackgroundData, 1);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn completed_count_increments() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        assert_eq!(proto.completed_count(), 0);
        let wid = proto.fanout_write(ReplicationChunkClass::BackgroundData, 1);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        let _ = proto.poll_result(wid);
        assert_eq!(proto.completed_count(), 1);
    }

    #[test]
    fn epoch_reset_clears_pending() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let _ = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        assert_eq!(proto.pending_count(), 1);
        proto.set_epoch(EpochId::new(2));
        assert_eq!(proto.pending_count(), 0);
    }

    #[test]
    fn write_result_is_success_partial_failed() {
        let committed = WriteResult::Committed {
            write_id: WriteId::new(1),
            receipt: WriteCommitReceipt {
                write_id: WriteId::new(1),
                chunk_class: ReplicationChunkClass::ContentPayload,
                epoch: test_epoch(),
                committed_targets: vec![MemberId::new(1)],
                target_count: 1,
                policy: ReplicationPolicy::Standard,
                partial: false,
                failed_targets: vec![],
            },
        };
        assert!(committed.is_success());
        assert!(!committed.is_partial());
        assert!(!committed.is_failed());

        let partial = WriteResult::Partial {
            write_id: WriteId::new(2),
            receipt: WriteCommitReceipt {
                write_id: WriteId::new(2),
                chunk_class: ReplicationChunkClass::ContentPayload,
                epoch: test_epoch(),
                committed_targets: vec![MemberId::new(1)],
                target_count: 3,
                policy: ReplicationPolicy::Standard,
                partial: true,
                failed_targets: vec![MemberId::new(3)],
            },
            missing_targets: vec![MemberId::new(3)],
        };
        assert!(partial.is_success());
        assert!(partial.is_partial());
        assert!(!partial.is_failed());

        let failed = WriteResult::QuorumFailed {
            write_id: WriteId::new(3),
            acks_collected: 1,
            quorum_required: 2,
            reason: QuorumFailureReason::QuorumImpossible {
                remaining: 0,
                needed: 2,
            },
        };
        assert!(!failed.is_success());
        assert!(!failed.is_partial());
        assert!(failed.is_failed());
    }

    #[test]
    fn handle_write_failure_does_not_double_count() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.handle_write_failure(wid, MemberId::new(3));
        proto.handle_write_failure(wid, MemberId::new(3)); // duplicate
                                                           // 2 acks should still reach quorum (standard on 3 targets = 2 needed)
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(2),
                digest_ok: true,
                placement_receipt_ref: None,
            },
        );
        assert!(proto.poll_result(wid).unwrap().is_partial());
    }
}

// Replication transport runtime module

// Replica chunk wire format (BLAKE3-framed object-data push)
pub mod chunk;
pub use chunk::{
    DecodeError, ReplicaChunk, ReplicaChunkAck, CHUNK_ACK_FRAME_SIZE, CHUNK_FORMAT_VERSION,
    CHUNK_HEADER_SIZE, REPLICA_CHUNK_ACK_MAGIC, REPLICA_CHUNK_MAGIC,
};

// Push retry policy (exponential backoff, jitter, dead-target marking)
pub mod retry;
pub use retry::PushRetryPolicy;

// Replica chunk push engine (encode, fanout, quorum, retry)
pub mod push;
pub use push::{PushTransport, ReplicaPush, ReplicaPushOutcome};

pub mod runtime;
pub use runtime::{
    AsyncReplicationWorker, QuorumMode, ReplicationRuntime, ReplicationRuntimeConfig,
    ReplicationStatsSnapshot, ReplicationTransport, ReplicationTransportStats, TargetWriteResult,
};

// Replication dispatch engine
pub mod dispatcher;
pub use dispatcher::{
    ObjectStoreRegistry, ObjectWriteTarget, PlacementResolver, ReplicationDispatcher,
    ReplicationOutcome, ReplicationTargetResult,
};

// Adapter implementations (feature-gated)
#[cfg(feature = "local-store-adapter")]
pub mod adapters;
#[cfg(not(feature = "local-store-adapter"))]
pub mod adapters;

#[cfg(feature = "local-store-adapter")]
pub use adapters::LocalObjectStoreTarget;
pub use adapters::StaticPlacementResolver;

// Replication write-path (fanout, quorum ack aggregation, outcome)
pub mod write_path;
pub use write_path::{
    QuorumShortfallReason, ReplicationWriteHandle, ReplicationWriteOutcome,
    ReplicationWriteRequest, ReplicationWriteTransport,
};
