// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P8-03 data_copy_7 flow commit coordinator.
//!
//! The flow commit coordinator is the bridge between the verification pipeline
//! (data_copy_2) and the state machines of rebuild (data_copy_4), relocation
//! (data_copy_5), and replication (steady/catchup) flows. It accepts completed
//! transfer and verification receipts and advances the appropriate flow state
//! machines.
//!
//! # Architecture
//!
//! ```text
//! Transfer receipt → commit_transfer_receipt()  → chunk: Pending→Transferring
//! Verification receipt → commit_verification_receipt() → chunk: Transferring→Verifying
//! Verified placement  → advance_flow_after_receipt_commit() → flow state advance
//! Batch complete       → seal_batch_and_emit_completion()    → batch → parent flow
//! ```
//!
//! # Comparison to ZFS / Ceph
//!
//! - ZFS: ZIL commit is single-node; no distributed receipt coordination,
//!   no multi-flow state bridging
//! - Ceph: PG state machine handles backfill but doesn't bridge verification
//!   receipts to relocation/rebuild/replication flows under a unified
//!   coordinator
//! - TideFS: single coordinator bridges transfer→verification→placement
//!   receipts across all six canonical flow classes with batch sealing
//!   and parent flow notification

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord;
use tidefs_replication_model::{
    FlowCommitClass, FlowCommitResult, FlowState, ObjectDigest, PlacementReceiptRef,
    ReplicaChunkState, ReplicaCopyClass, ReplicaCopyRecord, ReplicaPlacementReceipt,
    ReplicaTransferReceipt, ReplicaVerificationReceipt, ReplicatedReceiptId, ReplicatedSubjectId,
    VerificationStatus,
};

/// Gate constant for P8-03 data_copy_7 flow commit coordinator.
pub const FLOW_COMMIT_COORDINATOR_GATE_P8_03_DATA_COPY_7: &str =
    "P8-03 data_copy_7 flow commit coordinator covers transfer-receipt commit, verification-receipt commit, flow advancement, and batch sealing";

// ── Chunk state tracking ──────────────────────────────────────────────

/// A tracked chunk undergoing transfer/verification/placement.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TrackedChunk {
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub source_ref: MemberId,
    pub target_ref: MemberId,
    pub state: ReplicaChunkState,
    pub transfer_ticket_ref: Option<ReplicatedReceiptId>,
    pub transfer_receipt_ref: Option<ReplicatedReceiptId>,
    pub verification_receipt_ref: Option<ReplicatedReceiptId>,
    pub placement_receipt_ref: Option<ReplicatedReceiptId>,
    pub flow_class: FlowCommitClass,
    pub batch_ref: Option<u64>,
}

impl TrackedChunk {
    #[must_use]
    pub fn new(
        chunk_id: u64,
        subject_ref: ReplicatedSubjectId,
        source_ref: MemberId,
        target_ref: MemberId,
        flow_class: FlowCommitClass,
        ticket_ref: ReplicatedReceiptId,
    ) -> Self {
        Self {
            chunk_id,
            subject_ref,
            source_ref,
            target_ref,
            state: ReplicaChunkState::Pending,
            transfer_ticket_ref: Some(ticket_ref),
            transfer_receipt_ref: None,
            verification_receipt_ref: None,
            placement_receipt_ref: None,
            flow_class,
            batch_ref: None,
        }
    }
}

/// A tracked batch: a group of chunks being processed together.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TrackedBatch {
    pub batch_id: u64,
    pub chunk_refs: Vec<u64>,
    pub flow_class: FlowCommitClass,
    pub rebuild_flow_ref: Option<u64>,
    pub relocation_flow_ref: Option<u64>,
    pub sealed: bool,
}

impl TrackedBatch {
    #[must_use]
    pub fn new(batch_id: u64, chunk_refs: Vec<u64>, flow_class: FlowCommitClass) -> Self {
        Self {
            batch_id,
            chunk_refs,
            flow_class,
            rebuild_flow_ref: None,
            relocation_flow_ref: None,
            sealed: false,
        }
    }
}

// ── Flow commit coordinator ────────────────────────────────────────────

/// The flow commit coordinator bridges the verification pipeline to the
/// rebuild, relocation, and replication flow state machines.
///
/// It tracks chunks through transfer → verification → placement, advances
/// flow states on receipt commit, and seals batches to notify parent flows.
#[derive(Debug)]
pub struct FlowCommitCoordinator {
    /// Tracked chunks, keyed by chunk id.
    pub chunks: BTreeMap<u64, TrackedChunk>,
    /// Tracked batches, keyed by batch id.
    pub batches: BTreeMap<u64, TrackedBatch>,
    /// Accumulated transfer receipts, keyed by receipt id.
    pub transfer_receipts: BTreeMap<u64, ReplicaTransferReceipt>,
    /// Accumulated verification receipts, keyed by receipt id.
    pub verification_receipts: BTreeMap<u64, ReplicaVerificationReceipt>,
    /// Accumulated placement receipts, keyed by receipt id.
    pub placement_receipts: BTreeMap<u64, ReplicaPlacementReceipt>,
    /// Flow commit results for completed flows.
    pub commit_results: Vec<FlowCommitResult>,
    /// Retired copy records (post-placement).
    pub retired_copies: BTreeMap<u64, ReplicaCopyRecord>,
    /// Last recorded flow state per flow class (for transition detection).
    flow_states: BTreeMap<FlowCommitClass, FlowState>,
    /// Monotonic chunk id counter.
    next_chunk_id: u64,
    /// Monotonic batch id counter.
    next_batch_id: u64,
    /// Current epoch for time-binding.
    pub current_epoch: EpochId,
}

impl FlowCommitCoordinator {
    /// Create a new flow commit coordinator at the given epoch.
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            chunks: BTreeMap::new(),
            batches: BTreeMap::new(),
            transfer_receipts: BTreeMap::new(),
            verification_receipts: BTreeMap::new(),
            placement_receipts: BTreeMap::new(),
            commit_results: Vec::new(),
            retired_copies: BTreeMap::new(),
            flow_states: BTreeMap::new(),
            next_chunk_id: 1,
            next_batch_id: 1,
            current_epoch: epoch,
        }
    }

    /// Set the current epoch.
    pub fn set_epoch(&mut self, epoch: EpochId) {
        self.current_epoch = epoch;
    }

    // ── Chunk tracking ────────────────────────────────────────────────

    /// Register a new chunk for tracking.
    #[must_use]
    pub fn register_chunk(
        &mut self,
        subject_ref: ReplicatedSubjectId,
        source_ref: MemberId,
        target_ref: MemberId,
        flow_class: FlowCommitClass,
        ticket_ref: ReplicatedReceiptId,
    ) -> u64 {
        let chunk_id = self.next_chunk_id;
        self.next_chunk_id += 1;

        self.chunks.insert(
            chunk_id,
            TrackedChunk::new(
                chunk_id,
                subject_ref,
                source_ref,
                target_ref,
                flow_class,
                ticket_ref,
            ),
        );
        chunk_id
    }

    /// Register multiple chunks for a batch.
    #[must_use]
    pub fn register_chunk_batch(
        &mut self,
        subject_refs: &[ReplicatedSubjectId],
        source_ref: MemberId,
        target_ref: MemberId,
        flow_class: FlowCommitClass,
        ticket_ref: ReplicatedReceiptId,
    ) -> (u64, Vec<u64>) {
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;

        let mut chunk_ids = Vec::with_capacity(subject_refs.len());
        for subject_ref in subject_refs {
            let cid =
                self.register_chunk(*subject_ref, source_ref, target_ref, flow_class, ticket_ref);
            if let Some(chunk) = self.chunks.get_mut(&cid) {
                chunk.batch_ref = Some(batch_id);
            }
            chunk_ids.push(cid);
        }

        let batch = TrackedBatch::new(batch_id, chunk_ids.clone(), flow_class);
        self.batches.insert(batch_id, batch);
        (batch_id, chunk_ids)
    }

    /// Get a tracked chunk.
    #[must_use]
    pub fn chunk(&self, chunk_id: u64) -> Option<&TrackedChunk> {
        self.chunks.get(&chunk_id)
    }

    /// Get chunks in a specific state.
    #[must_use]
    pub fn chunks_in_state(&self, state: ReplicaChunkState) -> Vec<&TrackedChunk> {
        self.chunks.values().filter(|c| c.state == state).collect()
    }

    // ── Algorithm 1: commit_transfer_receipt ──────────────────────────

    /// Record transfer completion and advance chunk/copy state.
    ///
    /// Accepts a `ReplicaTransferReceipt`, validates the ticket reference,
    /// stores the receipt, and advances all associated chunks from
    /// `Pending` → `Transferring`.
    ///
    /// Returns the list of chunk ids that were advanced.
    pub fn commit_transfer_receipt(
        &mut self,
        receipt: ReplicaTransferReceipt,
    ) -> Result<Vec<u64>, String> {
        let receipt_id = receipt.receipt_id;

        // Find chunks matching this transfer's ticket
        let matched_chunks: Vec<u64> = self
            .chunks
            .iter()
            .filter(|(_, c)| {
                c.transfer_ticket_ref == Some(receipt.ticket_ref)
                    && c.state == ReplicaChunkState::Pending
            })
            .map(|(id, _)| *id)
            .collect();

        if matched_chunks.is_empty() {
            return Err(format!(
                "No pending chunks found for transfer ticket {:?}",
                receipt.ticket_ref
            ));
        }

        // Store receipt
        self.transfer_receipts.insert(receipt_id.0, receipt);

        // Advance each matched chunk
        for chunk_id in &matched_chunks {
            if let Some(chunk) = self.chunks.get_mut(chunk_id) {
                chunk.state = ReplicaChunkState::Transferring;
                chunk.transfer_receipt_ref = Some(receipt_id);
            }
        }

        Ok(matched_chunks)
    }

    // ── Algorithm 2: commit_verification_receipt ──────────────────────

    /// Record verification result and advance chunk state to verified/placed.
    ///
    /// Accepts a `ReplicaVerificationReceipt`, validates the status, stores
    /// the receipt, and advances matching chunks from `Transferring` →
    /// `Verifying`.
    ///
    /// If the verification status is `Verified`, the chunk is further
    /// advanced to `Committed` and a `FlowCommitResult` is produced.
    ///
    /// Returns the list of chunk ids that were advanced.
    pub fn commit_verification_receipt(
        &mut self,
        receipt: ReplicaVerificationReceipt,
    ) -> Result<CommitVerificationOutcome, String> {
        self.commit_verification_receipt_inner(receipt, None)
    }

    /// Record a verified receipt and publish caller-supplied durable target
    /// placement receipt refs into the resulting placement receipts.
    ///
    /// This path fails before mutating coordinator state if the durable refs do
    /// not exactly cover the matched transferring chunk subjects or if any ref
    /// is synthetic, malformed, under-width, duplicated, or subject-mismatched.
    pub fn commit_verification_receipt_with_placement_refs(
        &mut self,
        receipt: ReplicaVerificationReceipt,
        placement_receipt_refs: &[PlacementReceiptRef],
    ) -> Result<CommitVerificationOutcome, String> {
        self.commit_verification_receipt_inner(receipt, Some(placement_receipt_refs))
    }

    fn commit_verification_receipt_inner(
        &mut self,
        receipt: ReplicaVerificationReceipt,
        placement_receipt_refs: Option<&[PlacementReceiptRef]>,
    ) -> Result<CommitVerificationOutcome, String> {
        let receipt_id = receipt.receipt_id;

        // Find chunks whose subject_refs match the receipt's subject_refs
        let receipt_subject_set: BTreeSet<ReplicatedSubjectId> =
            receipt.subject_refs.iter().copied().collect();

        let matched_chunks: Vec<u64> = self
            .chunks
            .iter()
            .filter(|(_, c)| {
                receipt_subject_set.contains(&c.subject_ref)
                    && c.state == ReplicaChunkState::Transferring
            })
            .map(|(id, _)| *id)
            .collect();

        if matched_chunks.is_empty() {
            return Err(format!(
                "No transferring chunks found for verification receipt {receipt_id:?}"
            ));
        }

        let is_verified = receipt.status == VerificationStatus::Verified;
        let durable_refs_by_subject = if is_verified {
            placement_receipt_refs
                .map(|refs| {
                    Self::validate_placement_receipt_refs(
                        &receipt_subject_set,
                        &matched_chunks,
                        &self.chunks,
                        refs,
                    )
                })
                .transpose()?
        } else {
            if let Some(refs) = placement_receipt_refs {
                if !refs.is_empty() {
                    return Err(format!(
                        "placement receipt refs require Verified status for receipt {receipt_id:?}"
                    ));
                }
            }
            None
        };

        self.verification_receipts
            .insert(receipt_id.0, receipt.clone());

        for chunk_id in &matched_chunks {
            if let Some(chunk) = self.chunks.get_mut(chunk_id) {
                chunk.verification_receipt_ref = Some(receipt_id);
                if is_verified {
                    chunk.state = ReplicaChunkState::Committed;
                } else {
                    chunk.state = ReplicaChunkState::Failed;
                }
            }
        }

        if is_verified {
            // Produce placement receipts for verified chunks
            let mut commit_results = Vec::new();
            for chunk_id in &matched_chunks {
                if let Some(chunk) = self.chunks.get(chunk_id) {
                    let placement_receipt_refs = durable_refs_by_subject
                        .as_ref()
                        .and_then(|refs| refs.get(&chunk.subject_ref).copied())
                        .into_iter()
                        .collect();
                    let placement = ReplicaPlacementReceipt {
                        receipt_id: ReplicatedReceiptId(
                            receipt_id.0.wrapping_mul(13).wrapping_add(*chunk_id),
                        ),
                        verification_ref: receipt_id,
                        transfer_ref: chunk
                            .transfer_receipt_ref
                            .unwrap_or(ReplicatedReceiptId::default()),
                        subject_refs: vec![chunk.subject_ref],
                        placed_on: chunk.target_ref,
                        placement_epoch: self.current_epoch,
                        subjects_placed: 1,
                        placement_receipt_refs,
                    };
                    let placement_id = placement.receipt_id;
                    self.placement_receipts
                        .insert(placement_id.0, placement.clone());

                    let result = FlowCommitResult {
                        placement_receipt: placement,
                        updated_copy: ReplicaCopyRecord {
                            subject_ref: chunk.subject_ref,
                            member_ref: chunk.target_ref,
                            domain_ref: tidefs_membership_epoch::DomainId::new(
                                chunk.target_ref.0 * 10 + 1,
                            ),
                            copy_class: ReplicaCopyClass::Verified,
                            payload_digest: receipt
                                .digest_results
                                .first()
                                .copied()
                                .unwrap_or_default(),
                            freshness_frontier: self.current_epoch.0,
                            verification_receipt_ref: receipt_id,
                        },
                        final_flow_state: FlowState::Complete,
                        flow_class: chunk.flow_class,
                        commit_epoch: self.current_epoch,
                    };
                    if let Some(chunk) = self.chunks.get_mut(chunk_id) {
                        chunk.placement_receipt_ref = Some(placement_id);
                    }
                    commit_results.push(result);
                }
            }
            self.commit_results.extend(commit_results);
        }

        Ok(CommitVerificationOutcome {
            advanced_chunks: matched_chunks.clone(),
            is_verified,
            total_commit_results: if is_verified { matched_chunks.len() } else { 0 },
        })
    }

    fn validate_placement_receipt_refs(
        receipt_subject_set: &BTreeSet<ReplicatedSubjectId>,
        matched_chunks: &[u64],
        chunks: &BTreeMap<u64, TrackedChunk>,
        placement_receipt_refs: &[PlacementReceiptRef],
    ) -> Result<BTreeMap<ReplicatedSubjectId, PlacementReceiptRef>, String> {
        let matched_subjects: BTreeSet<ReplicatedSubjectId> = matched_chunks
            .iter()
            .filter_map(|chunk_id| chunks.get(chunk_id).map(|chunk| chunk.subject_ref))
            .collect();
        let mut refs_by_subject = BTreeMap::new();

        for placement_receipt_ref in placement_receipt_refs {
            let subject = ReplicatedSubjectId::new(placement_receipt_ref.object_id);
            if placement_receipt_ref.is_synthetic() {
                return Err(format!(
                    "placement receipt ref for subject {subject:?} is synthetic"
                ));
            }
            if !placement_receipt_ref.redundancy_policy.is_well_formed() {
                return Err(format!(
                    "placement receipt ref for subject {subject:?} has malformed redundancy policy"
                ));
            }
            let required_count = placement_receipt_ref.redundancy_policy.target_width();
            if placement_receipt_ref.target_count < required_count {
                return Err(format!(
                    "placement receipt ref for subject {subject:?} is under-width: target_count {} < required_count {}",
                    placement_receipt_ref.target_count, required_count
                ));
            }
            if !receipt_subject_set.contains(&subject) {
                return Err(format!(
                    "placement receipt ref for subject {subject:?} is not in verification receipt"
                ));
            }
            if !matched_subjects.contains(&subject) {
                return Err(format!(
                    "placement receipt ref for subject {subject:?} has no matched transferring chunk"
                ));
            }
            if refs_by_subject
                .insert(subject, *placement_receipt_ref)
                .is_some()
            {
                return Err(format!(
                    "duplicate placement receipt ref for subject {subject:?}"
                ));
            }
        }

        for subject in &matched_subjects {
            if !refs_by_subject.contains_key(subject) {
                return Err(format!(
                    "missing placement receipt ref for matched subject {subject:?}"
                ));
            }
        }

        Ok(refs_by_subject)
    }

    /// Publish a rebuild-runtime verified receipt completion as flow-commit
    /// repaired-placement evidence.
    ///
    /// This path is for repair execution that already validated source bytes,
    /// target write, and rebuild-runtime completion law. It records the
    /// repaired target placement receipt in the same `ReplicaPlacementReceipt`
    /// / `FlowCommitResult` surface used by the transfer/verification path.
    ///
    /// The coordinator validates all receipt refs and duplicate publication
    /// before mutating state.
    pub fn publish_verified_rebuild_completion(
        &mut self,
        record: VerifiedReceiptCompletionRecord,
    ) -> Result<FlowCommitResult, String> {
        Self::validate_verified_rebuild_completion_record(&record)?;
        if self.has_rebuild_completion_publication(&record) {
            return Err(format!(
                "duplicate verified rebuild completion publication for subject {:?} target {:?}",
                record.subject_ref, record.target_member
            ));
        }

        let verification_ref =
            derive_verified_rebuild_completion_receipt_id(0x7652_4255_494c_4456, &record);
        let transfer_ref =
            derive_verified_rebuild_completion_receipt_id(0x7652_4255_494c_4454, &record);
        let placement_id =
            derive_verified_rebuild_completion_receipt_id(0x7652_4255_494c_4450, &record);
        if self.placement_receipts.contains_key(&placement_id.0) {
            return Err(format!(
                "duplicate verified rebuild completion placement receipt id {:?}",
                placement_id
            ));
        }

        let placement = ReplicaPlacementReceipt {
            receipt_id: placement_id,
            verification_ref,
            transfer_ref,
            subject_refs: vec![record.subject_ref],
            placed_on: record.target_member,
            placement_epoch: self.current_epoch,
            subjects_placed: 1,
            placement_receipt_refs: vec![record.repaired_placement_receipt_ref],
        };
        let result = FlowCommitResult {
            placement_receipt: placement.clone(),
            updated_copy: ReplicaCopyRecord {
                subject_ref: record.subject_ref,
                member_ref: record.target_member,
                domain_ref: tidefs_membership_epoch::DomainId::new(record.target_member.0 * 10 + 1),
                copy_class: ReplicaCopyClass::Verified,
                payload_digest: object_digest_from_receipt_ref(
                    record.repaired_placement_receipt_ref,
                ),
                freshness_frontier: self.current_epoch.0,
                verification_receipt_ref: verification_ref,
            },
            final_flow_state: FlowState::Complete,
            flow_class: FlowCommitClass::Rebuild,
            commit_epoch: self.current_epoch,
        };

        self.placement_receipts.insert(placement_id.0, placement);
        self.commit_results.push(result.clone());
        Ok(result)
    }

    fn validate_verified_rebuild_completion_record(
        record: &VerifiedReceiptCompletionRecord,
    ) -> Result<(), String> {
        Self::validate_completion_receipt_shape(
            "source placement",
            record.subject_ref,
            record.source_placement_receipt_ref,
        )?;
        Self::validate_completion_receipt_shape(
            "repaired placement",
            record.subject_ref,
            record.repaired_placement_receipt_ref,
        )?;

        if record.source_placement_receipt_ref.object_key
            != record.repaired_placement_receipt_ref.object_key
        {
            return Err(format!(
                "source/repaired receipt mismatch for subject {:?}: object key differs",
                record.subject_ref
            ));
        }
        if record.source_placement_receipt_ref.payload_len
            != record.repaired_placement_receipt_ref.payload_len
        {
            return Err(format!(
                "source/repaired receipt mismatch for subject {:?}: payload length differs",
                record.subject_ref
            ));
        }
        if record.source_placement_receipt_ref.payload_digest
            != record.repaired_placement_receipt_ref.payload_digest
        {
            return Err(format!(
                "source/repaired receipt mismatch for subject {:?}: payload digest differs",
                record.subject_ref
            ));
        }

        Ok(())
    }

    fn validate_completion_receipt_shape(
        role: &str,
        subject_ref: ReplicatedSubjectId,
        receipt_ref: PlacementReceiptRef,
    ) -> Result<(), String> {
        let receipt_subject = ReplicatedSubjectId::new(receipt_ref.object_id);
        if receipt_ref.is_synthetic() {
            return Err(format!(
                "{role} receipt ref for subject {receipt_subject:?} is synthetic"
            ));
        }
        if receipt_subject != subject_ref {
            return Err(format!(
                "{role} receipt ref subject mismatch: record subject {subject_ref:?}, receipt subject {receipt_subject:?}"
            ));
        }
        if !receipt_ref.redundancy_policy.is_well_formed() {
            return Err(format!(
                "{role} receipt ref for subject {subject_ref:?} has malformed redundancy policy"
            ));
        }
        let required_count = receipt_ref.redundancy_policy.target_width();
        if receipt_ref.target_count < required_count {
            return Err(format!(
                "{role} receipt ref for subject {subject_ref:?} is under-width: target_count {} < required_count {}",
                receipt_ref.target_count, required_count
            ));
        }
        Ok(())
    }

    fn has_rebuild_completion_publication(&self, record: &VerifiedReceiptCompletionRecord) -> bool {
        self.commit_results.iter().any(|result| {
            result.flow_class == FlowCommitClass::Rebuild
                && result.updated_copy.subject_ref == record.subject_ref
                && result.updated_copy.member_ref == record.target_member
                && result
                    .placement_receipt
                    .placement_receipt_refs
                    .contains(&record.repaired_placement_receipt_ref)
        })
    }

    // ── Algorithm 3: advance_flow_after_receipt_commit ────────────────

    /// Determine the next flow state from current receipts and advance the
    /// rebuild, relocation, or replication flow.
    ///
    /// Inspects the current flow state for a given flow class and scope,
    /// counts committed vs pending chunks, and advances the flow state
    /// machine.
    ///
    /// The previous known state is tracked internally so transitions are
    /// detected even when the chunk-derived state already reflects the
    /// target state (e.g., all chunks Committed → Complete).
    pub fn advance_flow_after_receipt_commit(
        &mut self,
        flow_class: FlowCommitClass,
        _scope: FlowScope,
    ) -> FlowAdvanceReport {
        let relevant_chunks: Vec<&TrackedChunk> = self
            .chunks
            .values()
            .filter(|c| c.flow_class == flow_class)
            .collect();

        if relevant_chunks.is_empty() {
            return FlowAdvanceReport {
                flow_class,
                current_flow_state: FlowState::Planned,
                new_flow_state: FlowState::Planned,
                chunks_total: 0,
                chunks_committed: 0,
                chunks_failed: 0,
                chunks_pending: 0,
                advanced: false,
            };
        }

        let total = relevant_chunks.len() as u64;
        let committed = relevant_chunks
            .iter()
            .filter(|c| c.state == ReplicaChunkState::Committed)
            .count() as u64;
        let failed = relevant_chunks
            .iter()
            .filter(|c| c.state == ReplicaChunkState::Failed)
            .count() as u64;
        let pending = total.saturating_sub(committed).saturating_sub(failed);

        // Derive current flow state from chunk states
        let derived_state = if committed == total {
            FlowState::Complete
        } else if committed > 0 {
            FlowState::Verified
        } else if relevant_chunks
            .iter()
            .any(|c| c.state == ReplicaChunkState::Transferring)
        {
            FlowState::Transferring
        } else {
            FlowState::Planned
        };

        // Look up previously-recorded state to detect transitions
        let previous_state = self
            .flow_states
            .get(&flow_class)
            .copied()
            .unwrap_or(FlowState::Planned);

        // Advance: the effective next state is the derived state;
        // a transition is detected when derived differs from previous.
        let next_state = if failed > 0 && committed == 0 {
            FlowState::Aborted
        } else {
            derived_state
        };

        let advanced = next_state != previous_state;

        // Record the new state
        if advanced {
            self.flow_states.insert(flow_class, next_state);
        }

        FlowAdvanceReport {
            flow_class,
            current_flow_state: previous_state,
            new_flow_state: next_state,
            chunks_total: total,
            chunks_committed: committed,
            chunks_failed: failed,
            chunks_pending: pending,
            advanced,
        }
    }

    // ── Algorithm 4: seal_batch_and_emit_completion ───────────────────

    /// When all chunks in a batch are verified, advance batch state and
    /// notify the parent flow.
    ///
    /// Checks whether all chunks in the batch have reached `Committed`
    /// state. If so, seals the batch and returns a batch completion
    /// record. Otherwise, reports how many chunks remain.
    pub fn seal_batch_and_emit_completion(
        &mut self,
        batch_id: u64,
    ) -> Result<BatchCompletion, String> {
        // Collect needed data from the immutable borrow first.
        let (chunk_refs, flow_class, rebuild_ref, relocation_ref, already_sealed) = {
            let batch = self
                .batches
                .get(&batch_id)
                .ok_or_else(|| format!("Batch {batch_id} not found"))?;
            (
                batch.chunk_refs.clone(),
                batch.flow_class,
                batch.rebuild_flow_ref,
                batch.relocation_flow_ref,
                batch.sealed,
            )
        };

        if already_sealed {
            return Err(format!("Batch {batch_id} is already sealed"));
        }

        let chunk_states: Vec<(u64, ReplicaChunkState)> = chunk_refs
            .iter()
            .filter_map(|cid| self.chunks.get(cid).map(|c| (*cid, c.state)))
            .collect();

        let total = chunk_states.len() as u64;
        let committed = chunk_states
            .iter()
            .filter(|(_, s)| *s == ReplicaChunkState::Committed)
            .count() as u64;
        let failed = chunk_states
            .iter()
            .filter(|(_, s)| *s == ReplicaChunkState::Failed)
            .count() as u64;
        let remaining = total.saturating_sub(committed).saturating_sub(failed);

        if remaining == 0 {
            // All chunks terminal — seal the batch (this is now the only mutable borrow)
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.sealed = true;
            }

            let all_committed = failed == 0;

            Ok(BatchCompletion {
                batch_id,
                flow_class,
                rebuild_flow_ref: rebuild_ref,
                relocation_flow_ref: relocation_ref,
                chunks_total: total,
                chunks_committed: committed,
                chunks_failed: failed,
                all_committed,
                sealed: true,
            })
        } else {
            Ok(BatchCompletion {
                batch_id,
                flow_class,
                rebuild_flow_ref: rebuild_ref,
                relocation_flow_ref: relocation_ref,
                chunks_total: total,
                chunks_committed: committed,
                chunks_failed: failed,
                all_committed: false,
                sealed: false,
            })
        }
    }

    // ── Batch-flow binding ────────────────────────────────────────────

    /// Bind a batch to a rebuild flow.
    pub fn bind_batch_to_rebuild_flow(
        &mut self,
        batch_id: u64,
        flow_id: u64,
    ) -> Result<(), String> {
        match self.batches.get_mut(&batch_id) {
            Some(batch) => {
                batch.rebuild_flow_ref = Some(flow_id);
                Ok(())
            }
            None => Err(format!("Batch {batch_id} not found")),
        }
    }

    /// Bind a batch to a relocation flow.
    pub fn bind_batch_to_relocation_flow(
        &mut self,
        batch_id: u64,
        flow_id: u64,
    ) -> Result<(), String> {
        match self.batches.get_mut(&batch_id) {
            Some(batch) => {
                batch.relocation_flow_ref = Some(flow_id);
                Ok(())
            }
            None => Err(format!("Batch {batch_id} not found")),
        }
    }

    // ── Queries ──────────────────────────────────────────────────────

    /// Count chunks by state.
    #[must_use]
    pub fn chunk_count_by_state(&self, state: ReplicaChunkState) -> usize {
        self.chunks.values().filter(|c| c.state == state).count()
    }

    /// Get all commit results for a flow class.
    #[must_use]
    pub fn commit_results_for_class(&self, flow_class: FlowCommitClass) -> Vec<&FlowCommitResult> {
        self.commit_results
            .iter()
            .filter(|r| r.flow_class == flow_class)
            .collect()
    }

    /// Whether all chunks for a flow class are committed.
    #[must_use]
    pub fn flow_class_complete(&self, flow_class: FlowCommitClass) -> bool {
        let relevant: Vec<_> = self
            .chunks
            .values()
            .filter(|c| c.flow_class == flow_class)
            .collect();
        if relevant.is_empty() {
            return false;
        }
        relevant
            .iter()
            .all(|c| c.state == ReplicaChunkState::Committed)
    }

    /// Total chunks tracked.
    #[must_use]
    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Total sealed batches.
    #[must_use]
    pub fn sealed_batch_count(&self) -> usize {
        self.batches.values().filter(|b| b.sealed).count()
    }
}

fn object_digest_from_receipt_ref(receipt_ref: PlacementReceiptRef) -> ObjectDigest {
    ObjectDigest::new(u64::from_le_bytes(
        receipt_ref.payload_digest[..8]
            .try_into()
            .expect("digest prefix has 8 bytes"),
    ))
}

fn derive_verified_rebuild_completion_receipt_id(
    domain: u64,
    record: &VerifiedReceiptCompletionRecord,
) -> ReplicatedReceiptId {
    let mut state = 0xcbf2_9ce4_8422_2325 ^ domain;
    state = mix_hash_u64(state, record.target_member.0);
    state = mix_hash_u64(state, record.subject_ref.0);
    state = mix_placement_receipt_ref(state, record.source_placement_receipt_ref);
    state = mix_placement_receipt_ref(state, record.repaired_placement_receipt_ref);
    ReplicatedReceiptId(if state == 0 { domain } else { state })
}

fn mix_placement_receipt_ref(mut state: u64, receipt_ref: PlacementReceiptRef) -> u64 {
    state = mix_hash_u64(state, receipt_ref.object_id);
    state = mix_hash_bytes(state, &receipt_ref.object_key);
    state = mix_hash_u64(state, receipt_ref.receipt_epoch.0);
    state = mix_hash_u64(state, receipt_ref.receipt_generation);
    state = match receipt_ref.redundancy_policy {
        tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies } => {
            mix_hash_u64(mix_hash_u64(state, 1), copies as u64)
        }
        tidefs_replication_model::ReceiptRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => mix_hash_u64(
            mix_hash_u64(mix_hash_u64(state, 2), data_shards as u64),
            parity_shards as u64,
        ),
    };
    state = mix_hash_u64(state, receipt_ref.payload_len);
    state = mix_hash_bytes(state, &receipt_ref.payload_digest);
    mix_hash_u64(state, receipt_ref.target_count as u64)
}

fn mix_hash_bytes(mut state: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        state = mix_hash_u64(state, *byte as u64);
    }
    state
}

fn mix_hash_u64(mut state: u64, value: u64) -> u64 {
    state ^= value;
    state = state.wrapping_mul(0x1000_0000_01b3);
    state.rotate_left(13)
}

// ── Outcome types ──────────────────────────────────────────────────────

/// Scope selector for flow advancement routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowScope {
    Rebuild(u64),
    Relocation(u64),
    Replication,
    Cluster,
}

/// Result of committing a verification receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitVerificationOutcome {
    pub advanced_chunks: Vec<u64>,
    pub is_verified: bool,
    pub total_commit_results: usize,
}

/// Report from advancing a flow after receipt commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowAdvanceReport {
    pub flow_class: FlowCommitClass,
    pub current_flow_state: FlowState,
    pub new_flow_state: FlowState,
    pub chunks_total: u64,
    pub chunks_committed: u64,
    pub chunks_failed: u64,
    pub chunks_pending: u64,
    pub advanced: bool,
}

/// Result of sealing a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCompletion {
    pub batch_id: u64,
    pub flow_class: FlowCommitClass,
    pub rebuild_flow_ref: Option<u64>,
    pub relocation_flow_ref: Option<u64>,
    pub chunks_total: u64,
    pub chunks_committed: u64,
    pub chunks_failed: u64,
    pub all_committed: bool,
    pub sealed: bool,
}

// ── Durability Sequence ────────────────────────────────────────────────

/// Errors returned by [`DurabilitySequence`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityError {
    /// Sequence number has already been marked durable.
    AlreadyDurable,
    /// Sequence number is unknown (never submitted).
    UnknownSequence,
    /// A barrier is active; no new durable marks allowed beyond it.
    BarrierActive,
    /// Cannot acknowledge a barrier that is not the active barrier.
    NotActiveBarrier,
    /// Sequence numbers must be submitted in order.
    OutOfOrderSubmission,
}

/// A durability-ordered commit sequence for local fsync/fdatasync paths.
///
/// Ensures that commits are acknowledged in monotonic order: marking
/// commit N durable implies all commits 1..N-1 are also durable.
/// Barriers force all prior commits to be durable before the barrier
/// itself can be acknowledged — no commit after the barrier is marked
/// durable before the barrier completes.
///
/// # Monotonicity invariant
///
/// `durable_high` tracks the highest contiguous durable prefix.
/// When commit N is marked durable and all commits 1..N-1 are also
/// durable, durable_high advances to N. If a gap exists (e.g., commit
/// 3 is durable but 2 is not), durable_high stays at 1 until the gap
/// is filled.
#[derive(Debug, Clone)]
pub struct DurabilitySequence {
    /// Sequence number of the next commit to be submitted.
    next_seq: u64,
    /// Highest contiguous durable sequence number (monotonic prefix).
    durable_high: u64,
    /// Set of commits that have been marked durable (may have gaps).
    durable: BTreeSet<u64>,
    /// Whether a barrier is currently active (blocking new durable marks).
    barrier_active: bool,
    /// The sequence number of the active barrier, if any.
    active_barrier_seq: Option<u64>,
    /// Set of completed (acked) barriers for idempotency checks.
    completed_barriers: BTreeSet<u64>,
}

impl DurabilitySequence {
    /// Create a new empty durability sequence starting at sequence 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            durable_high: 0,
            durable: BTreeSet::new(),
            barrier_active: false,
            active_barrier_seq: None,
            completed_barriers: BTreeSet::new(),
        }
    }

    /// Submit a new commit and return its sequence number.
    ///
    /// Sequence numbers are assigned monotonically. If a barrier is active,
    /// submissions are still allowed — the barrier only blocks durable
    /// acknowledgment, not submission.
    #[must_use]
    pub fn submit(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Submit multiple commits and return their sequence numbers.
    #[must_use]
    pub fn submit_batch(&mut self, count: u64) -> Vec<u64> {
        let start = self.next_seq;
        self.next_seq += count;
        (start..start + count).collect()
    }

    /// Mark a commit as durable.
    ///
    /// # Monotonicity
    ///
    /// When `seq` is marked durable and all prior commits 1..seq-1 are
    /// also durable, `durable_high` advances to `seq`. If gaps exist,
    /// `durable_high` only advances to the highest contiguous prefix.
    ///
    /// # Barrier gating
    ///
    /// If a barrier is active at position B, no commit with seq > B
    /// can be marked durable until the barrier is acknowledged.
    ///
    /// # Errors
    ///
    /// - `AlreadyDurable` if `seq` was already marked durable.
    /// - `UnknownSequence` if `seq` was never submitted.
    /// - `BarrierActive` if an active barrier blocks this seq.
    pub fn mark_durable(&mut self, seq: u64) -> Result<(), DurabilityError> {
        if seq >= self.next_seq {
            return Err(DurabilityError::UnknownSequence);
        }
        if self.durable.contains(&seq) {
            return Err(DurabilityError::AlreadyDurable);
        }
        // Barrier gating: if a barrier is active at position B,
        // no seq > B may be marked durable.
        if let Some(barrier_seq) = self.active_barrier_seq {
            if seq > barrier_seq {
                return Err(DurabilityError::BarrierActive);
            }
        }

        self.durable.insert(seq);

        // Advance durable_high to the highest contiguous prefix.
        self.advance_durable_high();

        Ok(())
    }

    /// Submit a barrier commit.
    ///
    /// A barrier forces all prior commits (seq < barrier_seq) to be
    /// durable before the barrier itself can be acknowledged. No commit
    /// after the barrier (seq > barrier_seq) can be marked durable until
    /// the barrier is acknowledged.
    ///
    /// Returns the barrier's sequence number.
    ///
    /// # Errors
    ///
    /// - `BarrierActive` if a barrier is already active.
    pub fn submit_barrier(&mut self) -> Result<u64, DurabilityError> {
        if self.barrier_active {
            return Err(DurabilityError::BarrierActive);
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.barrier_active = true;
        self.active_barrier_seq = Some(seq);
        // Barriers are also recorded as durable entries.

        Ok(seq)
    }

    /// Acknowledge a barrier, releasing the gate.
    ///
    /// After acknowledgment, commits with seq > barrier_seq can be
    /// marked durable again.
    ///
    /// # Precondition
    ///
    /// All commits with seq < barrier_seq must already be durable
    /// before the barrier can be acknowledged. This is verified by
    /// checking that `durable_high >= barrier_seq`.
    ///
    /// # Errors
    ///
    /// - `NotActiveBarrier` if the seq doesn't match the active barrier.
    /// - `OutOfOrderSubmission` if prior commits are not yet all durable.
    pub fn ack_barrier(&mut self, seq: u64) -> Result<(), DurabilityError> {
        if self.active_barrier_seq != Some(seq) {
            return Err(DurabilityError::NotActiveBarrier);
        }
        // All prior commits must be durable.
        if self.durable_high < seq.saturating_sub(1) {
            return Err(DurabilityError::OutOfOrderSubmission);
        }

        self.barrier_active = false;
        self.active_barrier_seq = None;
        self.completed_barriers.insert(seq);
        self.durable.insert(seq);
        self.advance_durable_high();
        Ok(())
    }

    /// Truncate the sequence from `from_seq` onward (inclusive).
    ///
    /// Used for error recovery: discard all commits at and after
    /// `from_seq`, resetting state as if they were never submitted.
    /// Durable commits < `from_seq` are preserved.
    ///
    /// If truncation removes the active barrier, the barrier state
    /// is cleared.
    pub fn truncate_from(&mut self, from_seq: u64) {
        // Remove all durable marks >= from_seq
        self.durable.retain(|&s| s < from_seq);
        // Reset next_seq if it's past from_seq
        if self.next_seq > from_seq {
            self.next_seq = from_seq;
        }
        // If the active barrier was removed, clear it.
        if let Some(b) = self.active_barrier_seq {
            if b >= from_seq {
                self.barrier_active = false;
                self.active_barrier_seq = None;
            }
        }
        // Remove completed barriers >= from_seq
        self.completed_barriers.retain(|&s| s < from_seq);
        // Recompute durable_high
        self.durable_high = 0;
        self.advance_durable_high();
    }

    /// Return the highest contiguous durable sequence number.
    ///
    /// This is the recovery checkpoint: on restart, all commits
    /// 1..=durable_high() are known to be safely persisted.
    #[must_use]
    pub fn durable_high(&self) -> u64 {
        self.durable_high
    }

    /// Return whether a barrier is currently active.
    #[must_use]
    pub fn barrier_active(&self) -> bool {
        self.barrier_active
    }

    /// Return the active barrier sequence number, if any.
    #[must_use]
    pub fn active_barrier_seq(&self) -> Option<u64> {
        self.active_barrier_seq
    }

    /// Return the next sequence number to be assigned.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Check whether a specific sequence number is durable.
    #[must_use]
    pub fn is_durable(&self, seq: u64) -> bool {
        seq <= self.durable_high
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Advance durable_high to the highest contiguous prefix.
    fn advance_durable_high(&mut self) {
        let mut high = self.durable_high;
        loop {
            let next = high + 1;
            if self.durable.contains(&next) {
                high = next;
            } else {
                break;
            }
        }
        self.durable_high = high;
    }
}

impl Default for DurabilitySequence {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;
    use tidefs_replication_model::{
        ObjectDigest, PlacementReceiptRef, ReceiptRedundancyPolicy, ReplicatedReceiptId,
        ReplicatedSubjectId, VerificationStatus,
    };

    fn make_coordinator() -> FlowCommitCoordinator {
        FlowCommitCoordinator::new(EpochId::new(1))
    }

    fn make_transfer_receipt(id: u64, ticket_ref: u64) -> ReplicaTransferReceipt {
        ReplicaTransferReceipt {
            receipt_id: ReplicatedReceiptId(id),
            ticket_ref: ReplicatedReceiptId(ticket_ref),
            bytes_moved: 4096,
            source_anchor_hash: 0xAAAA,
            target_anchor_hash: 0xBBBB,
            completion_epoch: EpochId::new(1),
            worker_refs: vec![MemberId::new(10)],
        }
    }

    fn make_verification_receipt(
        id: u64,
        subjects: &[ReplicatedSubjectId],
        status: VerificationStatus,
    ) -> ReplicaVerificationReceipt {
        ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(id),
            subject_refs: subjects.to_vec(),
            digest_results: vec![ObjectDigest::new(0xF00D); subjects.len()],
            witness_refs: vec![MemberId::new(60)],
            quorum_class: 2,
            verification_epoch: EpochId::new(1),
            status,
        }
    }

    fn durable_placement_ref(subject: ReplicatedSubjectId, generation: u64) -> PlacementReceiptRef {
        placement_ref_with_policy(
            subject,
            generation,
            ReceiptRedundancyPolicy::Replicated { copies: 1 },
            1,
        )
    }

    fn repaired_ref_for_source(
        source: PlacementReceiptRef,
        generation: u64,
    ) -> PlacementReceiptRef {
        PlacementReceiptRef {
            receipt_generation: generation,
            ..source
        }
    }

    fn verified_rebuild_completion_record(
        subject: ReplicatedSubjectId,
    ) -> VerifiedReceiptCompletionRecord {
        let source = durable_placement_ref(subject, 700);
        let repaired = repaired_ref_for_source(source, 701);
        VerifiedReceiptCompletionRecord {
            target_member: MemberId::new(9),
            subject_ref: subject,
            source_placement_receipt_ref: source,
            repaired_placement_receipt_ref: repaired,
        }
    }

    fn placement_ref_with_policy(
        subject: ReplicatedSubjectId,
        generation: u64,
        redundancy_policy: ReceiptRedundancyPolicy,
        target_count: u16,
    ) -> PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&subject.0.to_le_bytes());
        let mut payload_digest = [0x5A; 32];
        payload_digest[..8].copy_from_slice(&subject.0.to_le_bytes());
        payload_digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::new(
            subject.0,
            object_key,
            EpochId::new(1),
            generation,
            redundancy_policy,
            4096,
            payload_digest,
            target_count,
        )
    }

    fn coordinator_with_transferring_chunk(subject: ReplicatedSubjectId) -> FlowCommitCoordinator {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let _ = coord.register_chunk(
            subject,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        coord
            .commit_transfer_receipt(make_transfer_receipt(500, 1000))
            .unwrap();
        coord
    }

    // ── Chunk registration ──────────────────────────────────────────

    #[test]
    fn register_single_chunk() {
        let mut coord = make_coordinator();
        let cid = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ReplicatedReceiptId(1000),
        );
        assert_eq!(cid, 1);
        assert_eq!(coord.total_chunks(), 1);
        let chunk = coord.chunk(1).unwrap();
        assert_eq!(chunk.state, ReplicaChunkState::Pending);
        assert_eq!(chunk.flow_class, FlowCommitClass::Rebuild);
    }

    #[test]
    fn register_chunk_batch() {
        let mut coord = make_coordinator();
        let subjects: Vec<ReplicatedSubjectId> =
            (0..4).map(|i| ReplicatedSubjectId::new(100 + i)).collect();

        let (batch_id, chunk_ids) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ReplicatedReceiptId(2000),
        );

        assert_eq!(batch_id, 1);
        assert_eq!(chunk_ids.len(), 4);
        assert_eq!(coord.total_chunks(), 4);

        let batch = coord.batches.get(&batch_id).unwrap();
        assert_eq!(batch.chunk_refs, chunk_ids);
        assert!(!batch.sealed);
    }

    // ── Algorithm 1: commit_transfer_receipt ────────────────────────

    #[test]
    fn commit_transfer_receipt_advances_pending_chunks() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::SteadyReplication,
            ticket,
        );
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::SteadyReplication,
            ticket,
        );

        let receipt = make_transfer_receipt(500, 1000);
        let result = coord.commit_transfer_receipt(receipt).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            coord.chunk(1).unwrap().state,
            ReplicaChunkState::Transferring
        );
        assert_eq!(
            coord.chunk(2).unwrap().state,
            ReplicaChunkState::Transferring
        );
        assert_eq!(coord.transfer_receipts.len(), 1);
    }

    #[test]
    fn commit_transfer_receipt_fails_on_no_matching_chunks() {
        let mut coord = make_coordinator();
        let receipt = make_transfer_receipt(500, 9999); // ticket with no chunks
        assert!(coord.commit_transfer_receipt(receipt).is_err());
    }

    #[test]
    fn commit_transfer_receipt_only_advances_pending() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let cid = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        // Manually advance to Transferring
        coord.chunks.get_mut(&cid).unwrap().state = ReplicaChunkState::Transferring;

        // Second commit should find no pending chunks
        let receipt = make_transfer_receipt(501, 1000);
        assert!(coord.commit_transfer_receipt(receipt).is_err());
    }

    // ── Algorithm 2: commit_verification_receipt ────────────────────

    #[test]
    fn commit_verified_receipt_advances_to_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        // First commit transfer
        let t_receipt = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_receipt).unwrap();

        // Then commit verification
        let v_receipt = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        let outcome = coord.commit_verification_receipt(v_receipt).unwrap();

        assert!(outcome.is_verified);
        assert_eq!(outcome.advanced_chunks, vec![1]);
        assert_eq!(outcome.total_commit_results, 1);
        assert_eq!(coord.chunk(1).unwrap().state, ReplicaChunkState::Committed);
        assert_eq!(coord.commit_results.len(), 1);
    }

    #[test]
    fn commit_verified_receipt_with_placement_receipt_refs_publishes_durable_ref() {
        let subj = ReplicatedSubjectId::new(100);
        let mut coord = coordinator_with_transferring_chunk(subj);
        let durable_ref = durable_placement_ref(subj, 700);
        let v_receipt = make_verification_receipt(600, &[subj], VerificationStatus::Verified);

        let outcome = coord
            .commit_verification_receipt_with_placement_refs(v_receipt, &[durable_ref])
            .unwrap();

        assert!(outcome.is_verified);
        assert_eq!(outcome.advanced_chunks, vec![1]);
        assert_eq!(outcome.total_commit_results, 1);
        let chunk = coord.chunk(1).unwrap();
        assert_eq!(chunk.state, ReplicaChunkState::Committed);
        let placement_id = chunk.placement_receipt_ref.expect("placement receipt id");
        let stored = coord
            .placement_receipts
            .get(&placement_id.0)
            .expect("stored placement receipt");
        assert_eq!(stored.placement_receipt_refs, vec![durable_ref]);
        assert_eq!(coord.commit_results.len(), 1);
        assert_eq!(
            coord.commit_results[0]
                .placement_receipt
                .placement_receipt_refs,
            vec![durable_ref]
        );
    }

    #[test]
    fn commit_verified_receipt_with_bad_placement_receipt_refs_fails_without_mutation() {
        let subj = ReplicatedSubjectId::new(100);
        let other = ReplicatedSubjectId::new(999);
        let durable_ref = durable_placement_ref(subj, 701);
        let cases: Vec<(&str, Vec<PlacementReceiptRef>)> = vec![
            ("missing placement receipt ref", vec![]),
            (
                "synthetic",
                vec![PlacementReceiptRef::synthetic_for_subject(subj)],
            ),
            (
                "malformed redundancy policy",
                vec![placement_ref_with_policy(
                    subj,
                    702,
                    ReceiptRedundancyPolicy::Replicated { copies: 0 },
                    0,
                )],
            ),
            (
                "under-width",
                vec![placement_ref_with_policy(
                    subj,
                    703,
                    ReceiptRedundancyPolicy::Replicated { copies: 2 },
                    1,
                )],
            ),
            (
                "not in verification receipt",
                vec![durable_placement_ref(other, 704)],
            ),
            ("duplicate", vec![durable_ref, durable_ref]),
        ];

        for (expected_error, refs) in cases {
            let mut coord = coordinator_with_transferring_chunk(subj);
            let v_receipt = make_verification_receipt(600, &[subj], VerificationStatus::Verified);

            let err = coord
                .commit_verification_receipt_with_placement_refs(v_receipt, &refs)
                .expect_err("invalid placement refs must fail");

            assert!(
                err.contains(expected_error),
                "expected error containing {expected_error:?}, got {err:?}"
            );
            let chunk = coord.chunk(1).unwrap();
            assert_eq!(chunk.state, ReplicaChunkState::Transferring);
            assert_eq!(chunk.verification_receipt_ref, None);
            assert_eq!(chunk.placement_receipt_ref, None);
            assert!(coord.verification_receipts.is_empty());
            assert!(coord.placement_receipts.is_empty());
            assert!(coord.commit_results.is_empty());
        }
    }

    #[test]
    fn publish_verified_rebuild_completion_records_repaired_placement() {
        let subj = ReplicatedSubjectId::new(1400);
        let record = verified_rebuild_completion_record(subj);
        let mut coord = make_coordinator();
        coord.set_epoch(EpochId::new(44));

        let result = coord
            .publish_verified_rebuild_completion(record)
            .expect("verified rebuild completion publishes");

        assert_eq!(result.flow_class, FlowCommitClass::Rebuild);
        assert_eq!(result.final_flow_state, FlowState::Complete);
        assert_eq!(result.commit_epoch, EpochId::new(44));
        assert_eq!(result.updated_copy.subject_ref, subj);
        assert_eq!(result.updated_copy.member_ref, record.target_member);
        assert_eq!(
            result.placement_receipt.placement_receipt_refs,
            vec![record.repaired_placement_receipt_ref]
        );
        assert_eq!(coord.placement_receipts.len(), 1);
        assert_eq!(
            coord
                .placement_receipts
                .get(&result.placement_receipt.receipt_id.0)
                .expect("stored placement receipt"),
            &result.placement_receipt
        );
        assert_eq!(
            coord.commit_results_for_class(FlowCommitClass::Rebuild),
            vec![&result]
        );
        assert_eq!(coord.total_chunks(), 0);
    }

    #[test]
    fn publish_verified_rebuild_completion_refuses_duplicate_without_mutation() {
        let subj = ReplicatedSubjectId::new(1401);
        let record = verified_rebuild_completion_record(subj);
        let mut coord = make_coordinator();
        coord
            .publish_verified_rebuild_completion(record)
            .expect("first publication succeeds");
        let stored_receipt_count = coord.placement_receipts.len();
        let stored_result_count = coord.commit_results.len();

        let err = coord
            .publish_verified_rebuild_completion(record)
            .expect_err("duplicate publication fails");

        assert!(err.contains("duplicate verified rebuild completion publication"));
        assert_eq!(coord.placement_receipts.len(), stored_receipt_count);
        assert_eq!(coord.commit_results.len(), stored_result_count);
    }

    #[test]
    fn publish_verified_rebuild_completion_refuses_invalid_evidence_without_mutation() {
        let subj = ReplicatedSubjectId::new(1402);
        let valid = verified_rebuild_completion_record(subj);
        let other = ReplicatedSubjectId::new(1999);
        let malformed = placement_ref_with_policy(
            subj,
            710,
            ReceiptRedundancyPolicy::Replicated { copies: 0 },
            0,
        );
        let under_width = placement_ref_with_policy(
            subj,
            711,
            ReceiptRedundancyPolicy::Replicated { copies: 2 },
            1,
        );
        let mismatched_subject = durable_placement_ref(other, 712);
        let mut mismatched_repaired = valid.repaired_placement_receipt_ref;
        mismatched_repaired.payload_len += 1;

        let cases = vec![
            (
                "synthetic",
                VerifiedReceiptCompletionRecord {
                    source_placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(subj),
                    ..valid
                },
            ),
            (
                "malformed redundancy policy",
                VerifiedReceiptCompletionRecord {
                    source_placement_receipt_ref: malformed,
                    repaired_placement_receipt_ref: repaired_ref_for_source(malformed, 711),
                    ..valid
                },
            ),
            (
                "under-width",
                VerifiedReceiptCompletionRecord {
                    source_placement_receipt_ref: under_width,
                    repaired_placement_receipt_ref: repaired_ref_for_source(under_width, 712),
                    ..valid
                },
            ),
            (
                "subject mismatch",
                VerifiedReceiptCompletionRecord {
                    source_placement_receipt_ref: mismatched_subject,
                    repaired_placement_receipt_ref: repaired_ref_for_source(
                        mismatched_subject,
                        713,
                    ),
                    ..valid
                },
            ),
            (
                "source/repaired receipt mismatch",
                VerifiedReceiptCompletionRecord {
                    repaired_placement_receipt_ref: mismatched_repaired,
                    ..valid
                },
            ),
        ];

        for (expected_error, record) in cases {
            let mut coord = make_coordinator();

            let err = coord
                .publish_verified_rebuild_completion(record)
                .expect_err("invalid completion evidence fails");

            assert!(
                err.contains(expected_error),
                "expected error containing {expected_error:?}, got {err:?}"
            );
            assert!(coord.placement_receipts.is_empty());
            assert!(coord.commit_results.is_empty());
        }
    }

    #[test]
    fn commit_failed_verification_receipt_marks_chunk_failed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        let t_receipt = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_receipt).unwrap();

        let v_receipt = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
        let outcome = coord.commit_verification_receipt(v_receipt).unwrap();

        assert!(!outcome.is_verified);
        assert_eq!(outcome.total_commit_results, 0);
        assert_eq!(coord.chunk(1).unwrap().state, ReplicaChunkState::Failed);
        assert_eq!(coord.commit_results.len(), 0);
    }

    #[test]
    fn commit_verification_fails_on_non_transferring_chunks() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        // Skip transfer receipt — chunk is still Pending
        let v_receipt = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        assert!(coord.commit_verification_receipt(v_receipt).is_err());
    }

    // ── Algorithm 3: advance_flow_after_receipt_commit ──────────────

    #[test]
    fn advance_flow_reports_complete_when_all_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        for i in 0..3 {
            let subj = ReplicatedSubjectId::new(100 + i);
            let _ = coord.register_chunk(
                subj,
                MemberId::new(1),
                MemberId::new(2),
                FlowCommitClass::CatchupReplication,
                ticket,
            );
        }

        // Complete all chunks
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(
            600,
            &[
                ReplicatedSubjectId::new(100),
                ReplicatedSubjectId::new(101),
                ReplicatedSubjectId::new(102),
            ],
            VerificationStatus::Verified,
        );
        coord.commit_verification_receipt(v).unwrap();

        let report = coord.advance_flow_after_receipt_commit(
            FlowCommitClass::CatchupReplication,
            FlowScope::Cluster,
        );
        assert_eq!(report.chunks_total, 3);
        assert_eq!(report.chunks_committed, 3);
        assert_eq!(report.chunks_failed, 0);
        assert_eq!(report.new_flow_state, FlowState::Complete);
        assert!(report.advanced);
    }

    #[test]
    fn advance_flow_with_failed_chunks_aborts() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        let v = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
        coord.commit_verification_receipt(v).unwrap();

        let report =
            coord.advance_flow_after_receipt_commit(FlowCommitClass::Rebuild, FlowScope::Cluster);
        assert_eq!(report.chunks_failed, 1);
        assert_eq!(report.new_flow_state, FlowState::Aborted);
        assert!(report.advanced);
    }

    #[test]
    fn advance_flow_empty_returns_planned() {
        let mut coord = make_coordinator();
        let report =
            coord.advance_flow_after_receipt_commit(FlowCommitClass::Failover, FlowScope::Cluster);
        assert_eq!(report.chunks_total, 0);
        assert_eq!(report.new_flow_state, FlowState::Planned);
        assert!(!report.advanced);
    }

    // ── Algorithm 4: seal_batch_and_emit_completion ──────────────────

    #[test]
    fn seal_batch_when_all_chunks_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subjects: Vec<ReplicatedSubjectId> =
            (0..3).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ticket,
        );

        // Complete all chunks
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(
            600,
            &[
                ReplicatedSubjectId::new(100),
                ReplicatedSubjectId::new(101),
                ReplicatedSubjectId::new(102),
            ],
            VerificationStatus::Verified,
        );
        coord.commit_verification_receipt(v).unwrap();

        let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
        assert!(completion.sealed);
        assert!(completion.all_committed);
        assert_eq!(completion.chunks_total, 3);
        assert_eq!(completion.chunks_committed, 3);
        assert_eq!(completion.chunks_failed, 0);
    }

    #[test]
    fn seal_batch_reports_remaining_when_not_all_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subjects: Vec<ReplicatedSubjectId> =
            (0..3).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ticket,
        );

        // Only commit transfer (not verification)
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
        assert!(!completion.sealed);
        assert!(!completion.all_committed);
        assert_eq!(completion.chunks_committed, 0); // still in Transferring, not Committed
    }

    #[test]
    fn seal_batch_fails_on_unknown_batch() {
        let mut coord = make_coordinator();
        assert!(coord.seal_batch_and_emit_completion(999).is_err());
    }

    #[test]
    fn seal_batch_fails_on_already_sealed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subjects: Vec<ReplicatedSubjectId> = vec![ReplicatedSubjectId::new(100)];
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::SteadyReplication,
            ticket,
        );

        // Complete and seal
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &subjects, VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();
        coord.seal_batch_and_emit_completion(batch_id).unwrap();

        // Second seal fails
        assert!(coord.seal_batch_and_emit_completion(batch_id).is_err());
    }

    // ── Batch-flow binding ──────────────────────────────────────────

    #[test]
    fn bind_batch_to_rebuild_flow() {
        let mut coord = make_coordinator();
        let subjects: Vec<ReplicatedSubjectId> = vec![ReplicatedSubjectId::new(100)];
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ReplicatedReceiptId(1000),
        );
        coord.bind_batch_to_rebuild_flow(batch_id, 42).unwrap();
        let batch = coord.batches.get(&batch_id).unwrap();
        assert_eq!(batch.rebuild_flow_ref, Some(42));
    }

    #[test]
    fn bind_batch_to_relocation_flow() {
        let mut coord = make_coordinator();
        let subjects: Vec<ReplicatedSubjectId> = vec![ReplicatedSubjectId::new(100)];
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ReplicatedReceiptId(1000),
        );
        coord.bind_batch_to_relocation_flow(batch_id, 7).unwrap();
        let batch = coord.batches.get(&batch_id).unwrap();
        assert_eq!(batch.relocation_flow_ref, Some(7));
    }

    // ── Queries ─────────────────────────────────────────────────────

    #[test]
    fn chunk_count_by_state() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 2);
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 0);
    }

    #[test]
    fn flow_class_complete() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Drain,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();

        assert!(coord.flow_class_complete(FlowCommitClass::Drain));
        assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
    }

    // ── Multi-flow, multi-batch scenarios ───────────────────────────

    #[test]
    fn multiple_independent_flows_progress_independently() {
        let mut coord = make_coordinator();
        let ticket_r = ReplicatedReceiptId(1000);
        let ticket_l = ReplicatedReceiptId(2000);

        // Rebuild flow: 2 chunks
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_r,
        );
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_r,
        );

        // Relocation flow: 1 chunk
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(200),
            MemberId::new(3),
            MemberId::new(4),
            FlowCommitClass::Relocation,
            ticket_l,
        );

        // Complete rebuild flow
        let t_r = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_r).unwrap();
        let v_r = make_verification_receipt(
            600,
            &[ReplicatedSubjectId::new(100), ReplicatedSubjectId::new(101)],
            VerificationStatus::Verified,
        );
        coord.commit_verification_receipt(v_r).unwrap();

        // Rebuild complete, relocation still pending
        assert!(coord.flow_class_complete(FlowCommitClass::Rebuild));
        assert!(!coord.flow_class_complete(FlowCommitClass::Relocation));
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 1);
    }

    #[test]
    fn sealed_batch_count_tracks_progress() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subjects: Vec<ReplicatedSubjectId> = vec![ReplicatedSubjectId::new(100)];
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        assert_eq!(coord.sealed_batch_count(), 0);

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &subjects, VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();
        coord.seal_batch_and_emit_completion(batch_id).unwrap();

        assert_eq!(coord.sealed_batch_count(), 1);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn chunk_in_failed_state_is_not_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
        coord.commit_verification_receipt(v).unwrap();

        assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Failed), 1);
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 0);
    }

    #[test]
    fn partial_batch_completion_reports_correctly() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subjects: Vec<ReplicatedSubjectId> =
            (0..3).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
        let (batch_id, _) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::SteadyReplication,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        // Only verify 1 of 3 subjects
        let v = make_verification_receipt(
            600,
            &[ReplicatedSubjectId::new(100)],
            VerificationStatus::Verified,
        );
        coord.commit_verification_receipt(v).unwrap();

        let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
        assert!(!completion.sealed);
        assert_eq!(completion.chunks_committed, 1);
        assert_eq!(completion.chunks_total, 3);
    }

    // ── Coordinator initial state ──────────────────────────────────

    #[test]
    fn coordinator_initial_state_invariants() {
        let coord = FlowCommitCoordinator::new(EpochId::new(42));
        assert!(coord.chunks.is_empty());
        assert!(coord.batches.is_empty());
        assert!(coord.transfer_receipts.is_empty());
        assert!(coord.verification_receipts.is_empty());
        assert!(coord.placement_receipts.is_empty());
        assert!(coord.commit_results.is_empty());
        assert!(coord.retired_copies.is_empty());
        assert_eq!(coord.current_epoch, EpochId::new(42));
        assert_eq!(coord.total_chunks(), 0);
        assert_eq!(coord.sealed_batch_count(), 0);
    }

    #[test]
    fn set_epoch_updates_current_epoch() {
        let mut coord = FlowCommitCoordinator::new(EpochId::new(1));
        assert_eq!(coord.current_epoch, EpochId::new(1));
        coord.set_epoch(EpochId::new(7));
        assert_eq!(coord.current_epoch, EpochId::new(7));
    }

    // ── Chunk queries ─────────────────────────────────────────────

    #[test]
    fn chunks_in_state_filters_by_state() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let c1 = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let c2 = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        // Before transfer: all pending
        let pending = coord.chunks_in_state(ReplicaChunkState::Pending);
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|c| c.chunk_id == c1));
        assert!(pending.iter().any(|c| c.chunk_id == c2));

        let transferring = coord.chunks_in_state(ReplicaChunkState::Transferring);
        assert!(transferring.is_empty());

        // After transfer receipt
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let pending = coord.chunks_in_state(ReplicaChunkState::Pending);
        assert!(pending.is_empty());
        let transferring = coord.chunks_in_state(ReplicaChunkState::Transferring);
        assert_eq!(transferring.len(), 2);
    }

    #[test]
    fn commit_results_for_class_filters_by_flow_class() {
        let mut coord = make_coordinator();
        let ticket_r = ReplicatedReceiptId(1000);
        let ticket_s = ReplicatedReceiptId(2000);

        // Rebuild chunk
        let subj_r = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj_r,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_r,
        );
        let t_r = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_r).unwrap();
        let v_r = make_verification_receipt(600, &[subj_r], VerificationStatus::Verified);
        coord.commit_verification_receipt(v_r).unwrap();

        // SteadyReplication chunk
        let subj_s = ReplicatedSubjectId::new(200);
        let _ = coord.register_chunk(
            subj_s,
            MemberId::new(3),
            MemberId::new(4),
            FlowCommitClass::SteadyReplication,
            ticket_s,
        );
        let t_s = make_transfer_receipt(700, 2000);
        coord.commit_transfer_receipt(t_s).unwrap();
        let v_s = make_verification_receipt(800, &[subj_s], VerificationStatus::Verified);
        coord.commit_verification_receipt(v_s).unwrap();

        let rebuild_results = coord.commit_results_for_class(FlowCommitClass::Rebuild);
        assert_eq!(rebuild_results.len(), 1);
        assert_eq!(rebuild_results[0].flow_class, FlowCommitClass::Rebuild);

        let steady_results = coord.commit_results_for_class(FlowCommitClass::SteadyReplication);
        assert_eq!(steady_results.len(), 1);
        assert_eq!(
            steady_results[0].flow_class,
            FlowCommitClass::SteadyReplication
        );

        // Empty for unrelated class
        let drain_results = coord.commit_results_for_class(FlowCommitClass::Drain);
        assert!(drain_results.is_empty());
    }

    #[test]
    fn total_chunks_counts_all_registered_chunks() {
        let mut coord = make_coordinator();
        assert_eq!(coord.total_chunks(), 0);

        let ticket = ReplicatedReceiptId(1000);
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        assert_eq!(coord.total_chunks(), 1);

        let subjects: Vec<ReplicatedSubjectId> =
            (0..4).map(|i| ReplicatedSubjectId::new(200 + i)).collect();
        let _ = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ticket,
        );
        assert_eq!(coord.total_chunks(), 5);
    }

    // ── Direct struct construction ─────────────────────────────────

    #[test]
    fn tracked_chunk_new_initializes_pending_with_ticket() {
        let chunk = TrackedChunk::new(
            42,
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ReplicatedReceiptId(999),
        );
        assert_eq!(chunk.chunk_id, 42);
        assert_eq!(chunk.state, ReplicaChunkState::Pending);
        assert_eq!(chunk.transfer_ticket_ref, Some(ReplicatedReceiptId(999)));
        assert_eq!(chunk.transfer_receipt_ref, None);
        assert_eq!(chunk.verification_receipt_ref, None);
        assert_eq!(chunk.placement_receipt_ref, None);
        assert_eq!(chunk.flow_class, FlowCommitClass::Rebuild);
        assert_eq!(chunk.batch_ref, None);
    }

    #[test]
    fn tracked_batch_new_initializes_unsealed() {
        let chunk_refs = vec![1, 2, 3];
        let batch = TrackedBatch::new(10, chunk_refs.clone(), FlowCommitClass::SteadyReplication);
        assert_eq!(batch.batch_id, 10);
        assert_eq!(batch.chunk_refs, chunk_refs);
        assert_eq!(batch.flow_class, FlowCommitClass::SteadyReplication);
        assert_eq!(batch.rebuild_flow_ref, None);
        assert_eq!(batch.relocation_flow_ref, None);
        assert!(!batch.sealed);
    }

    // ── FlowScope construction ─────────────────────────────────────

    #[test]
    fn flow_scope_variants_are_distinct() {
        let r = FlowScope::Rebuild(1);
        let l = FlowScope::Relocation(2);
        let rep = FlowScope::Replication;
        let c = FlowScope::Cluster;
        assert_ne!(r, l);
        assert_ne!(r, rep);
        assert_ne!(r, c);
        assert_ne!(l, rep);
        assert_ne!(l, c);
        assert_ne!(rep, c);
        // Same variant, different payload
        assert_ne!(FlowScope::Rebuild(1), FlowScope::Rebuild(2));
        assert_eq!(FlowScope::Rebuild(42), FlowScope::Rebuild(42));
    }

    // ── Batch binding error paths ──────────────────────────────────

    #[test]
    fn bind_batch_to_rebuild_flow_unknown_batch_errors() {
        let mut coord = make_coordinator();
        let result = coord.bind_batch_to_rebuild_flow(999, 42);
        assert!(result.is_err());
    }

    #[test]
    fn bind_batch_to_relocation_flow_unknown_batch_errors() {
        let mut coord = make_coordinator();
        let result = coord.bind_batch_to_relocation_flow(999, 7);
        assert!(result.is_err());
    }

    // ── Flow advance edge cases ────────────────────────────────────

    #[test]
    fn advance_flow_no_transition_on_second_call() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Drain,
            ticket,
        );
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();

        // First advance: should detect transition
        let r1 =
            coord.advance_flow_after_receipt_commit(FlowCommitClass::Drain, FlowScope::Cluster);
        assert!(r1.advanced);
        assert_eq!(r1.new_flow_state, FlowState::Complete);

        // Second advance: same state, no transition
        let r2 =
            coord.advance_flow_after_receipt_commit(FlowCommitClass::Drain, FlowScope::Cluster);
        assert!(!r2.advanced);
        assert_eq!(r2.new_flow_state, FlowState::Complete);
    }

    #[test]
    fn advance_flow_with_mixed_committed_and_failed_reports_partial() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let subj1 = ReplicatedSubjectId::new(100);
        let subj2 = ReplicatedSubjectId::new(101);
        let _ = coord.register_chunk(
            subj1,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let _ = coord.register_chunk(
            subj2,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        // Transfer both
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        // First chunk verified, second fails
        let v1 = make_verification_receipt(600, &[subj1], VerificationStatus::Verified);
        coord.commit_verification_receipt(v1).unwrap();
        let v2 = make_verification_receipt(601, &[subj2], VerificationStatus::DigestMismatch);
        coord.commit_verification_receipt(v2).unwrap();

        let report =
            coord.advance_flow_after_receipt_commit(FlowCommitClass::Rebuild, FlowScope::Cluster);
        assert_eq!(report.chunks_total, 2);
        assert_eq!(report.chunks_committed, 1);
        assert_eq!(report.chunks_failed, 1);
        assert_eq!(report.chunks_pending, 0);
        // One committed, one failed → not aborted (committed > 0)
        assert_eq!(report.new_flow_state, FlowState::Verified);
    }

    // ── Verification receipt edge cases ────────────────────────────

    #[test]
    fn verification_receipt_matches_chunks_by_subject_not_ticket() {
        // Verification receipt matches chunks by subject_ref, not by ticket.
        // Two chunks with different tickets but same subject: only the
        // one in Transferring state should be found.
        let mut coord = make_coordinator();

        let subj = ReplicatedSubjectId::new(100);
        let ticket_a = ReplicatedReceiptId(1000);
        let ticket_b = ReplicatedReceiptId(2000);

        let c1 = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_a,
        );
        // Chunk c1 should match by subject, not c2
        let _c2 = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_b,
        );

        // Advance c1 to Transferring
        let t_r = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_r).unwrap();

        // Submit verification for subj 100 — should only match c1
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        let outcome = coord.commit_verification_receipt(v).unwrap();
        assert_eq!(outcome.advanced_chunks, vec![c1]);
    }

    #[test]
    fn empty_subject_batch_registration_produces_empty_chunk_list() {
        let mut coord = make_coordinator();
        let subjects: &[ReplicatedSubjectId] = &[];
        let (batch_id, chunk_ids) = coord.register_chunk_batch(
            subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Relocation,
            ReplicatedReceiptId(1000),
        );
        assert_eq!(batch_id, 1);
        assert!(chunk_ids.is_empty());
        assert_eq!(coord.total_chunks(), 0);
        let batch = coord.batches.get(&batch_id).unwrap();
        assert!(batch.chunk_refs.is_empty());
    }

    // ── DurabilitySequence additional edge cases ───────────────────

    #[test]
    fn durability_sequence_truncate_from_one_clears_all() {
        let mut seq = DurabilitySequence::new();
        for _ in 0..5 {
            let _ = seq.submit();
        }
        seq.mark_durable(1).unwrap();
        seq.mark_durable(3).unwrap();
        seq.truncate_from(1);
        assert_eq!(seq.next_seq(), 1);
        assert_eq!(seq.durable_high(), 0);
        assert!(!seq.is_durable(1));
    }

    #[test]
    fn durability_sequence_submit_batch_zero_is_empty() {
        let mut seq = DurabilitySequence::new();
        let ids = seq.submit_batch(0);
        assert!(ids.is_empty());
        assert_eq!(seq.next_seq(), 1); // unchanged
    }

    #[test]
    fn durability_sequence_is_durable_zero_is_true() {
        // durable_high starts at 0; seq 0 <= 0 is true
        let seq = DurabilitySequence::new();
        assert!(seq.is_durable(0));
    }

    #[test]
    fn durability_sequence_double_ack_barrier_is_not_active_barrier() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();
        // Second ack for the same barrier fails — it is no longer the active barrier
        assert_eq!(
            seq.ack_barrier(barrier),
            Err(DurabilityError::NotActiveBarrier)
        );
    }

    #[test]
    fn durability_sequence_truncate_from_removes_completed_barriers_at_cut() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();
        assert!(!seq.barrier_active());

        // Truncate from 2 — the completed barrier at seq 2 should be removed
        seq.truncate_from(2);
        assert_eq!(seq.next_seq(), 2);
        // Barrier seq 2 was truncated, so it should not be durable
        assert!(!seq.is_durable(2));
    }

    #[test]
    fn durability_sequence_mark_durable_after_truncate_reuses_seq() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit(); // 1
        let _ = seq.submit(); // 2
        seq.mark_durable(1).unwrap();
        seq.truncate_from(2);
        // Seq 2 was truncated, submit reuses it
        let new_s = seq.submit();
        assert_eq!(new_s, 2);
        seq.mark_durable(2).unwrap();
        assert_eq!(seq.durable_high(), 2);
    }

    // ── DurabilitySequence tests ─────────────────────────────────────

    #[test]
    fn single_commit_durable() {
        let mut seq = DurabilitySequence::new();
        let s1 = seq.submit();
        assert_eq!(s1, 1);
        assert_eq!(seq.durable_high(), 0);

        seq.mark_durable(1).unwrap();
        assert_eq!(seq.durable_high(), 1);
        assert!(seq.is_durable(1));
    }

    #[test]
    fn ordered_two_commit_durability() {
        let mut seq = DurabilitySequence::new();
        let s1 = seq.submit();
        let s2 = seq.submit();
        assert_eq!((s1, s2), (1, 2));

        // Mark s1 durable first — s2 is not yet durable
        seq.mark_durable(1).unwrap();
        assert_eq!(seq.durable_high(), 1);
        assert!(seq.is_durable(1));
        assert!(!seq.is_durable(2));

        // Mark s2 durable — now both are durable
        seq.mark_durable(2).unwrap();
        assert_eq!(seq.durable_high(), 2);
        assert!(seq.is_durable(2));
    }

    #[test]
    fn out_of_order_mark_fills_gap() {
        let mut seq = DurabilitySequence::new();
        let _s1 = seq.submit(); // 1
        let _s2 = seq.submit(); // 2
        let _s3 = seq.submit(); // 3

        // Mark s2 first — durable_high stays at 0 (gap at s1)
        seq.mark_durable(2).unwrap();
        assert_eq!(seq.durable_high(), 0);

        // Mark s3 — still gap at s1
        seq.mark_durable(3).unwrap();
        assert_eq!(seq.durable_high(), 0);

        // Mark s1 — now the prefix fills to 3
        seq.mark_durable(1).unwrap();
        assert_eq!(seq.durable_high(), 3);
    }

    #[test]
    fn mark_already_durable_is_error() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        seq.mark_durable(1).unwrap();
        assert_eq!(seq.mark_durable(1), Err(DurabilityError::AlreadyDurable));
    }

    #[test]
    fn mark_unknown_sequence_is_error() {
        let mut seq = DurabilitySequence::new();
        assert_eq!(seq.mark_durable(5), Err(DurabilityError::UnknownSequence));
    }

    #[test]
    fn submit_batch_assigns_consecutive_ids() {
        let mut seq = DurabilitySequence::new();
        let ids = seq.submit_batch(5);
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        assert_eq!(seq.next_seq(), 6);
    }

    #[test]
    fn monotonicity_durable_high_never_decreases() {
        let mut seq = DurabilitySequence::new();
        for _ in 0..10 {
            let _ = seq.submit();
        }
        // Mark in order
        for i in 1..=5 {
            seq.mark_durable(i).unwrap();
        }
        assert_eq!(seq.durable_high(), 5);
        // Mark more — never decreases
        seq.mark_durable(6).unwrap();
        seq.mark_durable(7).unwrap();
        assert_eq!(seq.durable_high(), 7);
    }

    // ── Barrier tests ─────────────────────────────────────────────────

    #[test]
    fn barrier_blocks_commits_beyond_it() {
        let mut seq = DurabilitySequence::new();
        let _s1 = seq.submit(); // 1
        let _s2 = seq.submit(); // 2
        let barrier = seq.submit_barrier().unwrap(); // 3
        assert_eq!(barrier, 3);
        assert!(seq.barrier_active());

        // Can mark commits before the barrier
        seq.mark_durable(1).unwrap();
        seq.mark_durable(2).unwrap();

        // Submit after barrier
        let s4 = seq.submit(); // 4

        // Cannot mark seq > barrier while barrier active
        assert_eq!(seq.mark_durable(s4), Err(DurabilityError::BarrierActive));

        // Ack the barrier
        seq.ack_barrier(barrier).unwrap();
        assert!(!seq.barrier_active());

        // Now can mark beyond
        seq.mark_durable(s4).unwrap();
        assert_eq!(seq.durable_high(), 4);
    }

    #[test]
    fn barrier_must_be_acked_before_posting_another() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let b1 = seq.submit_barrier().unwrap();
        // Second barrier while first is active
        assert_eq!(seq.submit_barrier(), Err(DurabilityError::BarrierActive));

        // Ack first, then second works
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(b1).unwrap();
        let b2 = seq.submit_barrier().unwrap();
        assert_eq!(b2, 3);
    }

    #[test]
    fn ack_wrong_barrier_is_error() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let b1 = seq.submit_barrier().unwrap();
        seq.mark_durable(1).unwrap();
        // Try to ack wrong seq
        assert_eq!(seq.ack_barrier(99), Err(DurabilityError::NotActiveBarrier));
        // Correct ack works
        seq.ack_barrier(b1).unwrap();
    }

    #[test]
    fn ack_barrier_with_pending_prior_commits_is_error() {
        let mut seq = DurabilitySequence::new();
        let _s1 = seq.submit(); // 1
        let _s2 = seq.submit(); // 2
        let barrier = seq.submit_barrier().unwrap(); // 3

        // Mark only s1, s2 is still pending
        seq.mark_durable(1).unwrap();

        // Cannot ack because s2 is not durable (durable_high=1 < barrier=3)
        assert_eq!(
            seq.ack_barrier(barrier),
            Err(DurabilityError::OutOfOrderSubmission)
        );

        // Mark s2, then ack works
        seq.mark_durable(2).unwrap();
        seq.ack_barrier(barrier).unwrap();
        assert!(!seq.barrier_active());
    }

    #[test]
    fn barrier_prevents_durable_mark_of_later_submissions() {
        let mut seq = DurabilitySequence::new();
        let _s1 = seq.submit(); // 1
        let barrier = seq.submit_barrier().unwrap(); // 2

        // Submit after barrier
        let s3 = seq.submit(); // 3
        let _s4 = seq.submit(); // 4

        seq.mark_durable(1).unwrap();

        // Barrier blocks s3, s4
        assert_eq!(seq.mark_durable(s3), Err(DurabilityError::BarrierActive));
        assert_eq!(seq.mark_durable(4), Err(DurabilityError::BarrierActive));

        // Ack barrier
        seq.ack_barrier(barrier).unwrap();

        // Now can mark
        seq.mark_durable(s3).unwrap();
        seq.mark_durable(4).unwrap();
        assert_eq!(seq.durable_high(), 4);
    }

    // ── Error recovery tests ───────────────────────────────────────────

    #[test]
    fn truncate_from_removes_uncommitted_work() {
        let mut seq = DurabilitySequence::new();
        for _ in 0..5 {
            let _ = seq.submit(); // 1..5
        }
        // Make 1,2 durable
        seq.mark_durable(1).unwrap();
        seq.mark_durable(2).unwrap();
        assert_eq!(seq.durable_high(), 2);

        // Truncate from 3 — removes 3,4,5
        seq.truncate_from(3);
        assert_eq!(seq.next_seq(), 3);
        assert_eq!(seq.durable_high(), 2);
        // 1 and 2 remain durable
        assert!(seq.is_durable(1));
        assert!(seq.is_durable(2));
    }

    #[test]
    fn truncate_from_clears_active_barrier() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit(); // 1
        let barrier = seq.submit_barrier().unwrap(); // 2
        assert!(seq.barrier_active());

        // Truncate from barrier position removes it
        seq.truncate_from(barrier);
        assert!(!seq.barrier_active());
        assert_eq!(seq.active_barrier_seq(), None);
        assert_eq!(seq.next_seq(), 2);
    }

    #[test]
    fn truncate_from_preserves_barrier_before_cut() {
        let mut seq = DurabilitySequence::new();
        let _s1 = seq.submit(); // 1
        let barrier = seq.submit_barrier().unwrap(); // 2
        let _s3 = seq.submit(); // 3
        let _s4 = seq.submit(); // 4

        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();
        assert!(!seq.barrier_active());

        // Truncate from 3 — removes 3,4 but preserves barrier (2)
        seq.truncate_from(3);
        assert_eq!(seq.next_seq(), 3);
        assert!(!seq.barrier_active());
        // Barrier at 2 is preserved in completed_barriers
        assert!(seq.is_durable(1));
        assert!(seq.is_durable(2));
    }

    #[test]
    fn replay_checkpoint_reports_highest_durable() {
        let mut seq = DurabilitySequence::new();
        for _ in 0..10 {
            let _ = seq.submit();
        }
        // Mark 1,2,3,5 durable — gap at 4
        seq.mark_durable(1).unwrap();
        seq.mark_durable(2).unwrap();
        seq.mark_durable(3).unwrap();
        seq.mark_durable(5).unwrap();

        // durable_high = 3 (contiguous prefix)
        assert_eq!(seq.durable_high(), 3);

        // Fill gap
        seq.mark_durable(4).unwrap();
        assert_eq!(seq.durable_high(), 5);
    }

    #[test]
    fn default_creates_empty_sequence() {
        let seq = DurabilitySequence::default();
        assert_eq!(seq.durable_high(), 0);
        assert_eq!(seq.next_seq(), 1);
        assert!(!seq.barrier_active());
    }

    // ── Concurrent submission simulation tests ─────────────────────────

    #[test]
    fn interleaved_submissions_from_two_sources() {
        // Simulate two concurrent submitters (A and B) whose commits
        // interleave. The durability sequence must produce a
        // linearizable durable order.
        let mut seq = DurabilitySequence::new();

        // A submits 1, 3, 5
        let a1 = seq.submit();
        let _b1 = seq.submit(); // B submits 2
        let a2 = seq.submit(); // A submits 3
        let _b2 = seq.submit(); // B submits 4
        let a3 = seq.submit(); // A submits 5
        assert_eq!((a1, a2, a3), (1, 3, 5));

        // B's commits marked durable out of submission order
        seq.mark_durable(2).unwrap();
        assert_eq!(seq.durable_high(), 0); // gap at 1

        seq.mark_durable(4).unwrap();
        assert_eq!(seq.durable_high(), 0); // still gap at 1

        // A's commits fill the gaps
        seq.mark_durable(1).unwrap();
        seq.mark_durable(3).unwrap();
        seq.mark_durable(5).unwrap();
        assert_eq!(seq.durable_high(), 5);
    }

    #[test]
    fn linearizable_durable_sequence_under_concurrent_barrier() {
        let mut seq = DurabilitySequence::new();

        // Submit 5 commits, then barrier
        for _ in 0..5 {
            let _ = seq.submit();
        }
        let barrier = seq.submit_barrier().unwrap();
        let _s7 = seq.submit(); // after barrier

        // Mark all before barrier in random order
        seq.mark_durable(3).unwrap();
        seq.mark_durable(1).unwrap();
        seq.mark_durable(5).unwrap();
        seq.mark_durable(2).unwrap();
        seq.mark_durable(4).unwrap();
        // Now durable_high should be 5
        assert_eq!(seq.durable_high(), 5);

        // Ack barrier
        seq.ack_barrier(barrier).unwrap();
        // Barrier completed, can mark after-barrier commits
        seq.mark_durable(7).unwrap();
        assert_eq!(seq.durable_high(), 7);
    }

    // ── chunk() direct lookup ─────────────────────────────────────

    #[test]
    fn chunk_get_returns_none_for_unknown_id() {
        let coord = make_coordinator();
        assert!(coord.chunk(999).is_none());
    }

    #[test]
    fn chunk_get_returns_reference_for_valid_id() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let cid = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let found = coord.chunk(cid).unwrap();
        assert_eq!(found.chunk_id, cid);
        assert_eq!(found.subject_ref, ReplicatedSubjectId::new(100));
        assert_eq!(found.state, ReplicaChunkState::Pending);
    }

    // ── chunk_count_by_state coverage ─────────────────────────────

    #[test]
    fn chunk_count_by_state_counts_correctly() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);

        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(101),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 2);
        assert_eq!(
            coord.chunk_count_by_state(ReplicaChunkState::Transferring),
            0
        );
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 0);
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Failed), 0);

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 0);
        assert_eq!(
            coord.chunk_count_by_state(ReplicaChunkState::Transferring),
            2
        );
    }

    // ── sealed_batch_count ────────────────────────────────────────

    #[test]
    fn sealed_batch_count_reflects_only_sealed() {
        let mut coord = make_coordinator();
        let subjects: Vec<ReplicatedSubjectId> =
            (0..3).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
        let ticket = ReplicatedReceiptId(1000);

        let (batch_id, _chunk_ids) = coord.register_chunk_batch(
            &subjects,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        assert_eq!(coord.sealed_batch_count(), 0);

        // Transfer + verify all chunks to seal the batch
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        for subj in &subjects {
            let v = make_verification_receipt(600 + subj.0, &[*subj], VerificationStatus::Verified);
            coord.commit_verification_receipt(v).unwrap();
        }
        let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
        assert!(completion.sealed);

        assert_eq!(coord.sealed_batch_count(), 1);
    }

    // ── active_barrier_seq lifecycle ──────────────────────────────

    #[test]
    fn active_barrier_seq_returns_none_when_no_barrier() {
        let seq = DurabilitySequence::new();
        assert_eq!(seq.active_barrier_seq(), None);
        assert!(!seq.barrier_active());
    }

    #[test]
    fn active_barrier_seq_returns_some_when_barrier_active() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        assert_eq!(seq.active_barrier_seq(), Some(barrier));
        assert!(seq.barrier_active());
    }

    #[test]
    fn active_barrier_seq_returns_none_after_ack() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();
        assert_eq!(seq.active_barrier_seq(), None);
        assert!(!seq.barrier_active());
    }

    #[test]
    fn active_barrier_seq_returns_none_after_truncation() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        assert!(seq.barrier_active());
        seq.truncate_from(barrier);
        assert_eq!(seq.active_barrier_seq(), None);
    }

    // ── flow_class_complete edge cases ────────────────────────────

    #[test]
    fn flow_class_complete_true_when_all_committed() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);

        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();

        assert!(coord.flow_class_complete(FlowCommitClass::Rebuild));
    }

    #[test]
    fn flow_class_complete_false_with_failed_chunks() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);

        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
        coord.commit_verification_receipt(v).unwrap();

        assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
    }

    #[test]
    fn flow_class_complete_false_when_empty() {
        let coord = make_coordinator();
        assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
    }

    #[test]
    fn flow_class_complete_false_when_partial() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let subj1 = ReplicatedSubjectId::new(100);
        let subj2 = ReplicatedSubjectId::new(101);

        let _ = coord.register_chunk(
            subj1,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let _ = coord.register_chunk(
            subj2,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        // Only first chunk verified
        let v = make_verification_receipt(600, &[subj1], VerificationStatus::Verified);
        coord.commit_verification_receipt(v).unwrap();

        assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
    }

    // ── Double-commit rejection ───────────────────────────────────

    #[test]
    fn commit_transfer_receipt_fails_on_already_transferred_chunks() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t.clone()).unwrap();

        // Second attempt with same receipt: chunks are no longer Pending
        let result = coord.commit_transfer_receipt(t);
        assert!(result.is_err());
    }

    #[test]
    fn commit_verification_receipt_fails_on_pending_chunks() {
        let mut coord = make_coordinator();
        let subj = ReplicatedSubjectId::new(100);
        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ReplicatedReceiptId(1000),
        );

        // Try verification before transfer: chunk is still Pending
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        assert!(coord.commit_verification_receipt(v).is_err());
    }

    #[test]
    fn commit_verification_receipt_fails_on_wrong_subject() {
        let mut coord = make_coordinator();
        let ticket = ReplicatedReceiptId(1000);
        let _ = coord.register_chunk(
            ReplicatedSubjectId::new(100),
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );

        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();

        // Verification for a different subject that isn't tracked
        let v = make_verification_receipt(
            600,
            &[ReplicatedSubjectId::new(999)],
            VerificationStatus::Verified,
        );
        assert!(coord.commit_verification_receipt(v).is_err());
    }

    // ── DurabilitySequence: mark past end of buffer ───────────────

    #[test]
    fn durability_sequence_mark_durable_past_next_seq_fails() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit(); // seq 1
                              // seq 10 was never submitted
        assert_eq!(seq.mark_durable(10), Err(DurabilityError::UnknownSequence));
    }

    #[test]
    fn durability_sequence_submit_after_barrier_ack() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit();
        let barrier = seq.submit_barrier().unwrap();
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();

        // Normal submissions resume after barrier
        let s3 = seq.submit();
        assert_eq!(s3, 3);
        seq.mark_durable(3).unwrap();
        assert_eq!(seq.durable_high(), 3);
    }

    #[test]
    fn durability_sequence_barrier_is_durable_entry() {
        // Barriers are also recorded as durable entries (see submit_barrier
        // doc). They can be marked durable directly or via ack_barrier.
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit(); // seq 1
        let barrier = seq.submit_barrier().unwrap(); // seq 2

        // The barrier seq can be marked durable directly (it's < next_seq)
        seq.mark_durable(barrier).unwrap();
        // But it can't be marked twice
        assert_eq!(
            seq.mark_durable(barrier),
            Err(DurabilityError::AlreadyDurable)
        );

        // After marking prior commits durable, the barrier can be acked
        seq.mark_durable(1).unwrap();
        seq.ack_barrier(barrier).unwrap();

        // Barrier is durable after ack
        assert!(seq.is_durable(barrier));
        assert_eq!(seq.durable_high(), 2);
    }

    // ── Coordinator multi-class independence ──────────────────────

    #[test]
    fn coordinator_multiple_flow_classes_independent() {
        let mut coord = make_coordinator();
        let ticket_r = ReplicatedReceiptId(1000);
        let ticket_s = ReplicatedReceiptId(2000);

        let subj_r = ReplicatedSubjectId::new(100);
        let subj_s = ReplicatedSubjectId::new(200);

        let _ = coord.register_chunk(
            subj_r,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket_r,
        );
        let _ = coord.register_chunk(
            subj_s,
            MemberId::new(3),
            MemberId::new(4),
            FlowCommitClass::SteadyReplication,
            ticket_s,
        );

        // Advance only Rebuild
        let t_r = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t_r).unwrap();
        let v_r = make_verification_receipt(600, &[subj_r], VerificationStatus::Verified);
        coord.commit_verification_receipt(v_r).unwrap();

        assert!(coord.flow_class_complete(FlowCommitClass::Rebuild));
        assert!(!coord.flow_class_complete(FlowCommitClass::SteadyReplication));
    }

    // ── Epoch persistence ─────────────────────────────────────────

    #[test]
    fn coordinator_epoch_persists_through_operations() {
        let mut coord = FlowCommitCoordinator::new(EpochId::new(42));
        let ticket = ReplicatedReceiptId(1000);
        let subj = ReplicatedSubjectId::new(100);

        let _ = coord.register_chunk(
            subj,
            MemberId::new(1),
            MemberId::new(2),
            FlowCommitClass::Rebuild,
            ticket,
        );
        let t = make_transfer_receipt(500, 1000);
        coord.commit_transfer_receipt(t).unwrap();
        let v = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
        let outcome = coord.commit_verification_receipt(v).unwrap();
        assert!(outcome.is_verified);

        // Epoch is unchanged by commit operations
        assert_eq!(coord.current_epoch, EpochId::new(42));

        // Placement receipts should carry the current epoch
        let results = coord.commit_results_for_class(FlowCommitClass::Rebuild);
        assert_eq!(
            results[0].placement_receipt.placement_epoch,
            EpochId::new(42)
        );
    }

    #[test]
    fn verify_is_durable_past_end_of_sequence_is_false() {
        let mut seq = DurabilitySequence::new();
        let _ = seq.submit(); // 1
        seq.mark_durable(1).unwrap();
        // Seq 2 was never submitted
        assert!(!seq.is_durable(2));
        // But seq 0 and 1 are durable
        assert!(seq.is_durable(0));
        assert!(seq.is_durable(1));
    }

    // ── DurabilityError Copy trait ────────────────────────────────

    #[test]
    fn durability_error_copy_trait_works() {
        let e = DurabilityError::BarrierActive;
        let e2 = e; // Copy, not move
        assert_eq!(e, e2);
        // Both still usable
        assert_eq!(e, DurabilityError::BarrierActive);
        assert_eq!(e2, DurabilityError::BarrierActive);
    }
}
