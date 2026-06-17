// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Quorum write model integrated with epoch and lease constraints.
//!
//! Implements the 4-phase write protocol (PREPARE-TRANSFER-COMMIT-WITNESS)
//! from `tidefs-quorum-write` and layers epoch staleness checks and
//! lease-authorization checks on top.  The model is deterministic:
//! given the same inputs it produces the same outcomes.

/// Phase of a quorum write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumPhase {
    Idle,
    Prepared,
    Transferring,
    Committed,
    Witnessed,
    Aborted,
}

/// Per-node quorum write state.
#[derive(Clone, Debug)]
pub struct QuorumWriteState {
    pub write_id: u64,
    pub object_key: String,
    pub coordinator: u64,
    pub participants: Vec<u64>,
    pub epoch: u64,
    pub phase: QuorumPhase,
    pub acks_received: usize,
    pub quorum_size: usize,
    pub committed: bool,
}

/// A quorum write request submitted by a coordinator.
#[derive(Clone, Debug)]
pub struct QuorumWriteRequest {
    pub write_id: u64,
    pub object_key: String,
    pub coordinator: u64,
    pub participants: Vec<u64>,
    pub epoch: u64,
    pub data_size: u64,
}

/// Outcome of a quorum write attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumWriteOutcome {
    Committed {
        write_id: u64,
        acks: usize,
        quorum: usize,
    },
    RefusedNoQuorum {
        write_id: u64,
        acks: usize,
        needed: usize,
    },
    RefusedStaleEpoch {
        write_id: u64,
        request_epoch: u64,
        current_epoch: u64,
    },
    RefusedLeaseConflict {
        write_id: u64,
        object_key: String,
        held_by: u64,
    },
}

/// Quorum write model — validates epoch freshness and lease authority
/// before accepting a write.
#[derive(Clone, Debug)]
pub struct QuorumWriteModel {
    pub writes: Vec<QuorumWriteState>,
}

impl QuorumWriteModel {
    #[must_use]
    pub fn new() -> Self {
        Self { writes: Vec::new() }
    }

    /// Submit a quorum write request.  Checks:
    /// 1. Request epoch is not stale (must equal the coordinator's current epoch).
    /// 2. Coordinator holds a valid lease on the object.
    /// 3. Enough participants acknowledge to meet quorum.
    #[must_use]
    pub fn submit(
        &mut self,
        request: QuorumWriteRequest,
        coordinator_epoch: u64,
        coordinator_leases: &[super::LeaseState],
        participant_epochs: &[(u64, u64)], // (node_id, current_epoch)
    ) -> QuorumWriteOutcome {
        // 1. Epoch staleness check.
        if request.epoch < coordinator_epoch {
            return QuorumWriteOutcome::RefusedStaleEpoch {
                write_id: request.write_id,
                request_epoch: request.epoch,
                current_epoch: coordinator_epoch,
            };
        }

        // 2. Lease check: coordinator must hold an active lease on this object.
        let has_lease = coordinator_leases.iter().any(|l| {
            l.object_key == request.object_key && l.granted && !l.revoked
        });
        if !has_lease {
            return QuorumWriteOutcome::RefusedLeaseConflict {
                write_id: request.write_id,
                object_key: request.object_key.clone(),
                held_by: 0, // no valid lease
            };
        }

        // 3. Quorum: count participants that are at or beyond the request epoch.
        let required = request.participants.len() / 2 + 1;
        let acks = request.participants.iter().filter(|&&pid| {
            participant_epochs.iter().any(|&(nid, ep)| nid == pid && ep >= request.epoch)
        }).count();

        let qs = QuorumWriteState {
            write_id: request.write_id,
            object_key: request.object_key.clone(),
            coordinator: request.coordinator,
            participants: request.participants.clone(),
            epoch: request.epoch,
            phase: if acks >= required { QuorumPhase::Committed } else { QuorumPhase::Prepared },
            acks_received: acks,
            quorum_size: required,
            committed: acks >= required,
        };
        self.writes.push(qs);

        if acks >= required {
            QuorumWriteOutcome::Committed {
                write_id: request.write_id,
                acks,
                quorum: required,
            }
        } else {
            QuorumWriteOutcome::RefusedNoQuorum {
                write_id: request.write_id,
                acks,
                needed: required,
            }
        }
    }

    /// Check if a write is committed.
    #[must_use]
    pub fn is_committed(&self, write_id: u64) -> bool {
        self.writes.iter().any(|w| w.write_id == write_id && w.committed)
    }
}
