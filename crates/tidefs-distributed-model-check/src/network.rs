// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Deterministic network model with controllable reorder, drop, delay,
//! and duplicate behaviour.

use std::collections::VecDeque;
use super::{LeaseState, NodeState, quorum::{QuorumPhase, QuorumWriteState}};
use super::placement::PlacementReceiptState;

pub type NodeAddress = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryPolicy {
    Normal,
    ReorderFront,
    Drop,
    Delay,
    Duplicate,
    Immediate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedMessage {
    pub from: NodeAddress,
    pub to: NodeAddress,
    pub kind: MessageKind,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
    EpochAdvance { new_epoch: u64 },
    LeaseGrant { lease_id: u64, object_key: String, term_millis: u64 },
    LeaseRevoke { lease_id: u64 },
    QuorumPrepare { write_id: u64, object_key: String },
    QuorumCommitAck { write_id: u64, ack: bool },
    /// A placement receipt delivered to a node.  Carries an object id and
    /// key so the receiver can construct a [`PlacementReceiptRef`] for
    /// identity tracking.
    PlacementReceipt { object_id: u64, object_key_str: String },
}

#[derive(Clone, Debug)]
pub struct NetworkModel {
    queue: VecDeque<DistributedMessage>,
    delayed: VecDeque<DistributedMessage>,
}

impl NetworkModel {
    #[must_use]
    pub fn new(_node_count: usize) -> Self {
        Self { queue: VecDeque::new(), delayed: VecDeque::new() }
    }

    pub fn enqueue(&mut self, msg: DistributedMessage, policy: DeliveryPolicy) {
        match policy {
            DeliveryPolicy::Normal => self.queue.push_back(msg),
            DeliveryPolicy::ReorderFront => self.queue.push_front(msg),
            DeliveryPolicy::Drop => {},
            DeliveryPolicy::Delay => self.delayed.push_back(msg),
            DeliveryPolicy::Duplicate => {
                self.queue.push_back(msg.clone());
                self.queue.push_back(msg);
            }
            DeliveryPolicy::Immediate => self.queue.push_front(msg),
        }
    }

    pub fn deliver_pending(
        &mut self,
        nodes: &mut [NodeState],
        epoch_model: &mut super::MembershipEpochModel,
    ) {
        while let Some(m) = self.delayed.pop_front() {
            self.queue.push_back(m);
        }
        while let Some(msg) = self.queue.pop_front() {
            let idx = msg.to as usize;
            if idx >= nodes.len() { continue; }
            let node = &mut nodes[idx];
            match &msg.kind {
                MessageKind::EpochAdvance { new_epoch } => {
                    if *new_epoch > node.current_epoch {
                        node.current_epoch = *new_epoch;
                        epoch_model.record_advance(msg.to, *new_epoch);
                    }
                }
                MessageKind::LeaseGrant { lease_id, object_key, term_millis: _ } => {
                    if let Some(l) = node.lease_grants.iter_mut().find(|l| l.lease_id == *lease_id) {
                        l.object_key.clone_from(object_key);
                        l.granted = true;
                    } else if node.lease_grants.len() < super::MAX_MODEL_LEASES_PER_NODE {
                        node.lease_grants.push(LeaseState {
                            lease_id: *lease_id, object_key: object_key.clone(),
                            holder: msg.to, epoch: msg.epoch,
                            granted: true, revoked: false,
                        });
                    }
                }
                MessageKind::LeaseRevoke { lease_id } => {
                    if let Some(l) = node.lease_grants.iter_mut().find(|l| l.lease_id == *lease_id) {
                        l.revoked = true;
                        l.granted = false;
                    }
                }
                MessageKind::QuorumPrepare { write_id, object_key } => {
                    node.quorum_writes.push(QuorumWriteState {
                        write_id: *write_id, object_key: object_key.clone(),
                        coordinator: msg.from,
                        participants: vec![msg.to],
                        epoch: msg.epoch, phase: QuorumPhase::Prepared,
                        acks_received: 0, quorum_size: 1, committed: false,
                    });
                }
                MessageKind::QuorumCommitAck { write_id, ack } => {
                    if *ack {
                        if let Some(qw) = node.quorum_writes.iter_mut().find(|w| w.write_id == *write_id) {
                            qw.acks_received += 1;
                            if qw.acks_received >= qw.quorum_size {
                                qw.phase = QuorumPhase::Committed;
                                qw.committed = true;
                            }
                        }
                    }
                }
                MessageKind::PlacementReceipt { object_id, object_key_str } => {
                    let receipt_state = PlacementReceiptState::for_model(
                        *object_id,
                        object_key_str,
                        msg.to,
                        msg.epoch,
                        true, // durable on delivery
                    );
                    node.placement_receipts.push(receipt_state);
                }
            }
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.delayed.is_empty()
    }

    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }
}
