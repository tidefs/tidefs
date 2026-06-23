// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Production replication protocol: fanout writes, collect quorum ACKs,
//! handle partial failures, and commit through the flow commit coordinator.
//!
//! Implements distributed replication with per-chunk-class quorum policies,
//! receipt-backed completion, and transfer orchestrator integration.

use std::collections::BTreeMap;

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    CommittedReceiptIdentity, QuorumDurabilityToken, QuorumDurabilityTokenError,
};

use crate::policy::{ReplicationChunkClass, ReplicationPolicy, ReplicationPolicySelector};

/// Unique identifier for a fanout write operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct WriteId(pub u64);

impl WriteId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A receipt proving a write was committed at quorum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteCommitReceipt {
    pub write_id: WriteId,
    pub chunk_class: ReplicationChunkClass,
    pub epoch: EpochId,
    pub committed_targets: Vec<MemberId>,
    pub committed_receipts: Vec<CommittedReceiptIdentity>,
    pub durability_token: QuorumDurabilityToken,
    pub target_count: usize,
    pub policy: ReplicationPolicy,
    pub partial: bool,
    pub failed_targets: Vec<MemberId>,
}

/// Outcome of a fanout write after quorum collection.
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
        committed_receipts: usize,
        quorum_required: usize,
    },
    CommittedReceiptQuorumNotMet {
        acks_collected: usize,
        committed_receipts: usize,
        quorum_required: usize,
    },
    InvalidDurabilityToken(QuorumDurabilityTokenError),
    ReceiptLostAfterAck {
        target: MemberId,
        committed_receipts: usize,
        quorum_required: usize,
    },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteAck {
    pub target: MemberId,
    pub digest_ok: bool,
    pub committed_receipt: Option<CommittedReceiptIdentity>,
}

impl WriteAck {
    #[must_use]
    pub fn committed_receipt_for_epoch(&self, epoch: EpochId) -> Option<CommittedReceiptIdentity> {
        if !self.digest_ok {
            return None;
        }
        let receipt = self.committed_receipt?;
        receipt
            .is_committed_for(self.target, epoch)
            .then_some(receipt)
    }
}

/// Transfer priority class for admission ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferPriorityClass {
    SteadyReplication,
    LossRebuild,
}

impl TransferPriorityClass {
    #[must_use]
    pub const fn is_steady(&self) -> bool {
        matches!(self, Self::SteadyReplication)
    }

    #[must_use]
    pub const fn is_rebuild(&self) -> bool {
        matches!(self, Self::LossRebuild)
    }

    #[must_use]
    pub const fn admission_priority(&self) -> u8 {
        match self {
            Self::SteadyReplication => 0,
            Self::LossRebuild => 1,
        }
    }
}

/// Internal pending write state.
#[derive(Debug, Clone)]
struct PendingWrite {
    chunk_class: ReplicationChunkClass,
    policy: ReplicationPolicy,
    target_count: usize,
    acks: Vec<WriteAck>,
    failed_targets: Vec<MemberId>,
    epoch: EpochId,
    quorum_impossible: bool,
    terminal_result_recorded: bool,
}

/// The production replication protocol runtime.
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

    /// Fan out a write to all replica targets. Non-blocking: returns a `WriteId`.
    #[must_use]
    pub fn fanout_write(
        &mut self,
        chunk_class: ReplicationChunkClass,
        target_count: usize,
    ) -> WriteId {
        let policy = ReplicationPolicySelector::select(chunk_class);
        let write_id = self.next_write_id;
        self.next_write_id += 1;

        self.pending_writes.insert(
            write_id,
            PendingWrite {
                chunk_class,
                policy,
                target_count,
                acks: Vec::new(),
                failed_targets: Vec::new(),
                epoch: self.epoch,
                quorum_impossible: false,
                terminal_result_recorded: false,
            },
        );

        WriteId(write_id)
    }

    /// Collect an acknowledgement for a pending write.
    pub fn collect_ack(&mut self, write_id: WriteId, ack: WriteAck) {
        let Some(pending) = self.pending_writes.get_mut(&write_id.0) else {
            return;
        };

        if pending.quorum_impossible || pending.terminal_result_recorded {
            return;
        }

        let new_is_committed = ack.committed_receipt_for_epoch(pending.epoch).is_some();
        if let Some(existing) = pending
            .acks
            .iter_mut()
            .find(|existing| existing.target == ack.target)
        {
            let existing_is_committed = existing
                .committed_receipt_for_epoch(pending.epoch)
                .is_some();
            if !existing_is_committed && new_is_committed {
                *existing = ack;
            } else {
                return;
            }
        } else {
            pending.acks.push(ack);
        }
        self.check_write_completion(write_id);
    }

    /// Record a target failure. If quorum becomes impossible, fail immediately.
    pub fn handle_write_failure(&mut self, write_id: WriteId, failed_target: MemberId) {
        let Some(pending) = self.pending_writes.get_mut(&write_id.0) else {
            return;
        };

        if pending.quorum_impossible || pending.terminal_result_recorded {
            return;
        }
        if pending.acks.iter().any(|ack| {
            ack.target == failed_target && ack.committed_receipt_for_epoch(pending.epoch).is_some()
        }) {
            return;
        }

        if !pending.failed_targets.contains(&failed_target) {
            pending.failed_targets.push(failed_target);
        }

        let committed_so_far = Self::committed_receipts_for_pending(pending).len();
        let remaining = pending
            .target_count
            .saturating_sub(pending.failed_targets.len())
            .saturating_sub(committed_so_far);
        let needed = pending.policy.min_quorum(pending.target_count);

        if committed_so_far + remaining < needed {
            pending.quorum_impossible = true;
            pending.terminal_result_recorded = true;
            let result = WriteResult::QuorumFailed {
                write_id,
                acks_collected: pending.acks.len(),
                quorum_required: needed,
                reason: QuorumFailureReason::QuorumImpossible {
                    remaining,
                    needed: needed.saturating_sub(committed_so_far),
                },
            };
            self.completed_writes.push(result);
        }
    }

    /// Mark a previously acknowledged committed receipt as lost.
    ///
    /// Receipt loss after ACK invalidates the pending quorum result rather
    /// than allowing the write to fall back to uncommitted acknowledgement
    /// evidence.
    pub fn lose_committed_receipt(&mut self, write_id: WriteId, target: MemberId) {
        self.completed_writes.retain(|result| match result {
            WriteResult::Committed { write_id: wid, .. }
            | WriteResult::Partial { write_id: wid, .. }
            | WriteResult::QuorumFailed { write_id: wid, .. } => *wid != write_id,
        });

        let Some(pending) = self.pending_writes.get_mut(&write_id.0) else {
            return;
        };

        pending.acks.retain(|ack| ack.target != target);
        if !pending.failed_targets.contains(&target) {
            pending.failed_targets.push(target);
        }

        let committed_count = Self::committed_receipts_for_pending(pending).len();
        let needed = pending.policy.min_quorum(pending.target_count);
        pending.quorum_impossible = true;
        pending.terminal_result_recorded = true;
        self.completed_writes.push(WriteResult::QuorumFailed {
            write_id,
            acks_collected: pending.acks.len(),
            quorum_required: needed,
            reason: QuorumFailureReason::ReceiptLostAfterAck {
                target,
                committed_receipts: committed_count,
                quorum_required: needed,
            },
        });
    }

    fn check_write_completion(&mut self, write_id: WriteId) {
        let Some(pending) = self.pending_writes.get_mut(&write_id.0) else {
            return;
        };

        if pending.quorum_impossible || pending.terminal_result_recorded {
            return;
        }

        let policy = pending.policy;
        let min_q = policy.min_quorum(pending.target_count);
        let committed_receipts = Self::committed_receipts_for_pending(pending);
        let committed_count = committed_receipts.len();

        if committed_count >= min_q {
            let durability_token = match QuorumDurabilityToken::new(
                write_id.0,
                pending.epoch,
                pending.target_count,
                min_q,
                committed_receipts,
            ) {
                Ok(token) => token,
                Err(err) => {
                    pending.quorum_impossible = true;
                    pending.terminal_result_recorded = true;
                    self.completed_writes.push(WriteResult::QuorumFailed {
                        write_id,
                        acks_collected: pending.acks.len(),
                        quorum_required: min_q,
                        reason: QuorumFailureReason::InvalidDurabilityToken(err),
                    });
                    return;
                }
            };
            let committed = durability_token.committed_members();
            let failed: Vec<MemberId> = pending.failed_targets.clone();
            let partial = committed_count < pending.target_count || !failed.is_empty();

            let receipt = WriteCommitReceipt {
                write_id,
                chunk_class: pending.chunk_class,
                epoch: pending.epoch,
                committed_targets: committed,
                committed_receipts: durability_token.receipt_identities.clone(),
                durability_token,
                target_count: pending.target_count,
                policy,
                partial,
                failed_targets: failed.clone(),
            };

            pending.terminal_result_recorded = true;
            if partial {
                self.completed_writes.push(WriteResult::Partial {
                    write_id,
                    receipt,
                    missing_targets: failed,
                });
            } else {
                self.completed_writes
                    .push(WriteResult::Committed { write_id, receipt });
            }
        } else if pending.acks.len() + pending.failed_targets.len() >= pending.target_count {
            pending.quorum_impossible = true;
            pending.terminal_result_recorded = true;
            self.completed_writes.push(WriteResult::QuorumFailed {
                write_id,
                acks_collected: pending.acks.len(),
                quorum_required: min_q,
                reason: QuorumFailureReason::CommittedReceiptQuorumNotMet {
                    acks_collected: pending.acks.len(),
                    committed_receipts: committed_count,
                    quorum_required: min_q,
                },
            });
        }
    }

    fn committed_receipts_for_pending(pending: &PendingWrite) -> Vec<CommittedReceiptIdentity> {
        pending
            .acks
            .iter()
            .filter_map(|ack| ack.committed_receipt_for_epoch(pending.epoch))
            .collect()
    }

    /// Commit a write, emitting a `WriteCommitReceipt`.
    #[must_use]
    pub fn commit_write(&mut self, write_id: WriteId) -> Option<WriteCommitReceipt> {
        if let Some(pos) = self.completed_writes.iter().position(|r| match r {
            WriteResult::Committed { write_id: wid, .. }
            | WriteResult::Partial { write_id: wid, .. } => *wid == write_id,
            _ => false,
        }) {
            let result = self.completed_writes.remove(pos);
            self.pending_writes.remove(&write_id.0);
            match result {
                WriteResult::Committed { receipt, .. } | WriteResult::Partial { receipt, .. } => {
                    Some(receipt)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Poll for a completed write result (non-blocking).
    #[must_use]
    pub fn poll_result(&mut self, write_id: WriteId) -> Option<WriteResult> {
        if let Some(pos) = self.completed_writes.iter().position(|r| match r {
            WriteResult::Committed { write_id: wid, .. }
            | WriteResult::Partial { write_id: wid, .. }
            | WriteResult::QuorumFailed { write_id: wid, .. } => *wid == write_id,
        }) {
            let result = self.completed_writes.remove(pos);
            self.pending_writes.remove(&write_id.0);
            Some(result)
        } else {
            None
        }
    }

    /// Submit a `CatchupRepair` transfer ticket when a target is missing a chunk.
    #[must_use]
    pub fn repair_missing_target(
        &mut self,
        _write_id: WriteId,
        _missing_target: MemberId,
    ) -> CatchupRepairTicket {
        CatchupRepairTicket {
            ticket_id: 0,
            target: _missing_target,
            priority_class: self.transfer_priority_class,
            epoch: self.epoch,
        }
    }

    /// Timeout a pending write.
    pub fn timeout_write(&mut self, write_id: WriteId) {
        let Some(pending) = self.pending_writes.get_mut(&write_id.0) else {
            return;
        };
        if pending.quorum_impossible || pending.terminal_result_recorded {
            return;
        }
        let acks = pending.acks.len();
        let committed_receipts = Self::committed_receipts_for_pending(pending).len();
        let needed = pending.policy.min_quorum(pending.target_count);
        pending.terminal_result_recorded = true;
        let result = WriteResult::QuorumFailed {
            write_id,
            acks_collected: acks,
            quorum_required: needed,
            reason: QuorumFailureReason::Timeout {
                acks_collected: acks,
                committed_receipts,
                quorum_required: needed,
            },
        };
        self.completed_writes.push(result);
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_writes.len()
    }

    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed_writes.len()
    }

    pub fn set_epoch(&mut self, epoch: EpochId) {
        self.epoch = epoch;
    }
}

/// A ticket for catchup repair submitted to the transfer orchestrator (#901).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchupRepairTicket {
    pub ticket_id: u64,
    pub target: MemberId,
    pub priority_class: TransferPriorityClass,
    pub epoch: EpochId,
}

impl CatchupRepairTicket {
    #[must_use]
    pub fn is_rebuild(&self) -> bool {
        self.priority_class.is_rebuild()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_replication_model::{PlacementReceiptRef, ReplicatedReceiptId};

    fn test_epoch() -> EpochId {
        EpochId::new(1)
    }

    fn receipt_for(target: u64) -> CommittedReceiptIdentity {
        let member = MemberId::new(target);
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&target.to_le_bytes());
        let mut payload_digest = [0u8; 32];
        payload_digest[0] = target as u8;
        let generation = 100 + target;
        CommittedReceiptIdentity::new(
            member,
            ReplicatedReceiptId::new(generation),
            PlacementReceiptRef::replicated(
                10_000 + target,
                object_key,
                test_epoch(),
                generation,
                1,
                4096,
                payload_digest,
            ),
        )
    }

    fn ack(target: u64) -> WriteAck {
        WriteAck {
            target: MemberId::new(target),
            digest_ok: true,
            committed_receipt: Some(receipt_for(target)),
        }
    }

    fn uncommitted_ack(target: u64) -> WriteAck {
        WriteAck {
            target: MemberId::new(target),
            digest_ok: true,
            committed_receipt: None,
        }
    }

    #[test]
    fn fanout_write_returns_write_id() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        assert!(wid.0 > 0);
        assert_eq!(proto.pending_count(), 1);
    }

    #[test]
    fn standard_policy_quorum_with_2_of_3() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, ack(2));
        let result = proto.poll_result(wid).unwrap();
        match result {
            WriteResult::Partial { receipt, .. } => {
                assert_eq!(receipt.durability_token.committed_count(), 2);
                assert_eq!(
                    receipt.durability_token.receipt_ids(),
                    vec![ReplicatedReceiptId::new(101), ReplicatedReceiptId::new(102)]
                );
            }
            other => panic!("expected partial committed quorum, got {other:?}"),
        }
    }

    #[test]
    fn critical_quorum_rejects_uncommitted_receipt() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::MetadataHead, 3);
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, uncommitted_ack(2));
        proto.collect_ack(wid, ack(3));

        match proto.poll_result(wid).unwrap() {
            WriteResult::QuorumFailed { reason, .. } => match reason {
                QuorumFailureReason::CommittedReceiptQuorumNotMet {
                    acks_collected,
                    committed_receipts,
                    quorum_required,
                } => {
                    assert_eq!(acks_collected, 3);
                    assert_eq!(committed_receipts, 2);
                    assert_eq!(quorum_required, 3);
                }
                other => panic!("unexpected failure reason: {other:?}"),
            },
            other => panic!("expected receipt quorum failure, got {other:?}"),
        }
    }

    #[test]
    fn receipt_loss_after_ack_fails_closed() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, ack(2));
        assert_eq!(proto.completed_count(), 1);

        proto.lose_committed_receipt(wid, MemberId::new(2));

        match proto.poll_result(wid).unwrap() {
            WriteResult::QuorumFailed { reason, .. } => match reason {
                QuorumFailureReason::ReceiptLostAfterAck {
                    target,
                    committed_receipts,
                    quorum_required,
                } => {
                    assert_eq!(target, MemberId::new(2));
                    assert_eq!(committed_receipts, 1);
                    assert_eq!(quorum_required, 2);
                }
                other => panic!("unexpected failure reason: {other:?}"),
            },
            other => panic!("expected fail-closed receipt loss, got {other:?}"),
        }
    }

    #[test]
    fn quorum_accepts_committed_receipt_after_member_restart() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        let restarted_member_receipt = receipt_for(1);
        proto.collect_ack(
            wid,
            WriteAck {
                target: MemberId::new(1),
                digest_ok: true,
                committed_receipt: Some(restarted_member_receipt),
            },
        );
        proto.collect_ack(wid, ack(2));

        match proto.poll_result(wid).unwrap() {
            WriteResult::Partial { receipt, .. } => {
                assert!(receipt
                    .durability_token
                    .receipt_identities
                    .contains(&restarted_member_receipt));
                assert_eq!(receipt.durability_token.committed_count(), 2);
            }
            other => panic!("expected committed quorum after restart, got {other:?}"),
        }
    }

    #[test]
    fn partial_quorum_when_targets_fail() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.handle_write_failure(wid, MemberId::new(3));
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, ack(2));
        let result = proto.poll_result(wid).unwrap();
        assert!(result.is_partial());
    }

    #[test]
    fn critical_policy_requires_all() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::MetadataHead, 3);
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, ack(2));
        assert!(proto.poll_result(wid).is_none());
        proto.collect_ack(wid, ack(3));
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
        proto.collect_ack(wid, ack(3));
        assert!(proto.poll_result(wid).unwrap().is_success());
    }

    #[test]
    fn commit_write_returns_receipt() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(wid, ack(1));
        proto.collect_ack(wid, ack(2));
        let receipt = proto.commit_write(wid).unwrap();
        assert_eq!(receipt.write_id, wid);
        assert_eq!(receipt.policy, ReplicationPolicy::Standard);
    }

    #[test]
    fn timeout_write_fails() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let wid = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        proto.collect_ack(wid, ack(1));
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
        assert!(ticket.is_rebuild());
    }

    #[test]
    fn multiple_concurrent_writes() {
        let mut proto = ReplicationProtocol::new(test_epoch());
        let w1 = proto.fanout_write(ReplicationChunkClass::ContentPayload, 3);
        let w2 = proto.fanout_write(ReplicationChunkClass::MetadataHead, 2);
        assert_eq!(proto.pending_count(), 2);
        proto.collect_ack(w1, ack(1));
        proto.collect_ack(w1, ack(2));
        assert!(proto.poll_result(w1).unwrap().is_success());
        proto.collect_ack(w2, ack(1));
        proto.collect_ack(w2, ack(2));
        assert!(proto.poll_result(w2).unwrap().is_success());
    }
}
