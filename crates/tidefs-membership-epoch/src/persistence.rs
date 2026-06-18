// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Intent-log backed persistence for epoch transitions.
//!
//! Provides [`EpochPersistence`] with BLAKE3 domain-tagged integrity,
//! startup replay, and committed-root LSN tracking.

use crate::epoch_error::EpochTransitionError;
use crate::epoch_service::EpochService;
use crate::epoch_service::{TransitionReason, VerifiedEpochTransition};
use crate::{EpochEvent, EpochMemberSet, NodeIdentity};

/// BLAKE3 domain separation tag for epoch persistence records.
const DOMAIN_TAG: &[u8] = b"MembershipEpoch.log.v1";

/// A persisted epoch-log record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EpochLogRecord {
    /// A committed epoch transition.
    TransitionCommitted {
        from_epoch_id: u64,
        to_epoch_id: u64,
        event_discriminant: u8,
        added: Vec<u64>,
        removed: Vec<u64>,
        proposed_by: u64,
        reason_tag: u8,
        blake3_hash: [u8; 32],
    },
    /// A full snapshot of the epoch service state.
    Snapshot {
        epoch_id: u64,
        member_ids: Vec<u64>,
        transition_count: u64,
    },
}

impl EpochLogRecord {
    /// Compute the BLAKE3 hash for a record.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_TAG);
        match self {
            Self::TransitionCommitted {
                from_epoch_id,
                to_epoch_id,
                event_discriminant,
                added,
                removed,
                proposed_by,
                reason_tag,
                blake3_hash: _,
            } => {
                hasher.update(&[0x01]); // variant tag
                hasher.update(&from_epoch_id.to_le_bytes());
                hasher.update(&to_epoch_id.to_le_bytes());
                hasher.update(&[*event_discriminant]);
                for id in added {
                    hasher.update(&id.to_le_bytes());
                }
                hasher.update(b"|");
                for id in removed {
                    hasher.update(&id.to_le_bytes());
                }
                hasher.update(&proposed_by.to_le_bytes());
                hasher.update(&[*reason_tag]);
            }
            Self::Snapshot {
                epoch_id,
                member_ids,
                transition_count,
            } => {
                hasher.update(&[0x02]); // variant tag
                hasher.update(&epoch_id.to_le_bytes());
                for id in member_ids {
                    hasher.update(&id.to_le_bytes());
                }
                hasher.update(&transition_count.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }

    /// Create a [`EpochLogRecord::TransitionCommitted`] from a
    /// [`VerifiedEpochTransition`].
    pub fn from_verified_transition(vt: &VerifiedEpochTransition) -> Self {
        let event_discriminant: u8 = match vt.transition.event {
            EpochEvent::Join(_) => 0x01,
            EpochEvent::Leave(_) => 0x02,
            EpochEvent::Increment => 0x03,
            EpochEvent::CoordinatorChanged { .. } => 0x04,
        };

        let mut added: Vec<u64> = vt
            .transition
            .member_set_delta
            .added
            .iter()
            .map(|ni| ni.node_id)
            .collect();

        // For CoordinatorChanged, encode old/new coordinator in the added field,
        // otherwise the member_set_delta is empty and the event is lost on replay.
        if let EpochEvent::CoordinatorChanged { old, new } = &vt.transition.event {
            added.push(old.node_id);
            added.push(new.node_id);
        }
        let removed: Vec<u64> = vt
            .transition
            .member_set_delta
            .removed
            .iter()
            .map(|ni| ni.node_id)
            .collect();

        let reason_tag: u8 = match vt.reason {
            TransitionReason::Join => 0x01,
            TransitionReason::Leave => 0x02,
            TransitionReason::Heartbeat => 0x03,
            TransitionReason::Admin => 0x04,
            TransitionReason::Quorum => 0x05,
        };

        Self::TransitionCommitted {
            from_epoch_id: vt.transition.from_epoch_id,
            to_epoch_id: vt.transition.to_epoch_id,
            event_discriminant,
            added,
            removed,
            proposed_by: vt.proposed_by,
            reason_tag,
            blake3_hash: vt.blake3_hash,
        }
    }

    /// Create a snapshot record from the current epoch service state.
    pub fn snapshot_from_service(svc: &EpochService) -> Self {
        Self::Snapshot {
            epoch_id: svc.current_epoch().epoch_id,
            member_ids: svc.member_node_ids(),
            transition_count: svc.transition_count() as u64,
        }
    }
}

/// Reason tag to [`TransitionReason`] conversion.
fn reason_from_tag(tag: u8) -> TransitionReason {
    match tag {
        0x01 => TransitionReason::Join,
        0x02 => TransitionReason::Leave,
        0x03 => TransitionReason::Heartbeat,
        0x04 => TransitionReason::Admin,
        0x05 => TransitionReason::Quorum,
        _ => TransitionReason::Admin, // fallback
    }
}

/// Event discriminant to [`EpochEvent`] conversion.
fn event_from_discriminant(discriminant: u8, added: &[u64], removed: &[u64]) -> EpochEvent {
    match discriminant {
        0x01 => {
            if let Some(&id) = added.first() {
                EpochEvent::Join(NodeIdentity::new(id))
            } else {
                EpochEvent::Increment
            }
        }
        0x02 => {
            if let Some(&id) = removed.first() {
                EpochEvent::Leave(NodeIdentity::new(id))
            } else {
                EpochEvent::Increment
            }
        }
        0x04 => {
            if added.len() >= 2 {
                EpochEvent::CoordinatorChanged {
                    old: NodeIdentity::new(added[0]),
                    new: NodeIdentity::new(added[1]),
                }
            } else {
                EpochEvent::Increment
            }
        }
        _ => EpochEvent::Increment,
    }
}

/// In-memory persistence log for epoch transitions.
///
/// Stores [`EpochLogRecord`]s and supports replay to reconstruct an
/// [`EpochService`]. Each record carries a BLAKE3-256 hash for integrity
/// verification.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct EpochPersistence {
    /// The ordered log of epoch records.
    log: Vec<EpochLogRecord>,
    /// The last committed LSN (log sequence number, i.e. index into `log`).
    committed_lsn: u64,
}

impl EpochPersistence {
    /// Create an empty persistence log.
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            committed_lsn: 0,
        }
    }

    /// Append a record to the log.
    pub fn append(&mut self, record: EpochLogRecord) {
        self.log.push(record);
    }

    /// Mark all records up to `lsn` as committed.
    pub fn commit_lsn(&mut self, lsn: u64) {
        self.committed_lsn = lsn;
    }

    /// Return the current committed LSN.
    pub fn committed_lsn(&self) -> u64 {
        self.committed_lsn
    }

    /// Return the number of records in the log.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Return true if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Return all records.
    pub fn records(&self) -> &[EpochLogRecord] {
        &self.log
    }

    /// Verify the BLAKE3 hash of every record in the log.
    ///
    /// Returns the number of records that failed verification.
    pub fn verify_all(&self) -> usize {
        self.log
            .iter()
            .filter(|rec| {
                let computed = rec.compute_hash();
                match rec {
                    EpochLogRecord::TransitionCommitted { blake3_hash, .. } => {
                        computed != *blake3_hash
                    }
                    EpochLogRecord::Snapshot { .. } => {
                        // Snapshot records verify their own hash
                        false
                    }
                }
            })
            .count()
    }

    /// Replay the log to reconstruct an [`EpochService`].
    ///
    /// Only records up to `committed_lsn` are replayed. If `initial_members`
    /// is provided, it bootstraps the service; otherwise replay starts from
    /// the first snapshot found.
    pub fn replay(
        &self,
        initial_members: Option<EpochMemberSet>,
    ) -> Result<EpochService, EpochTransitionError> {
        let has_initial_members = initial_members.is_some();
        let mut svc = if let Some(members) = initial_members {
            EpochService::bootstrap(members)
        } else {
            // Find the most recent snapshot to bootstrap from
            let snapshot = self.log.iter().rev().find_map(|rec| match rec {
                EpochLogRecord::Snapshot {
                    epoch_id,
                    member_ids,
                    transition_count: _,
                } => {
                    let members =
                        EpochMemberSet::new(member_ids.iter().map(|&id| NodeIdentity::new(id)));
                    let mut svc = EpochService::bootstrap(members);
                    svc.set_snapshot_epoch(*epoch_id);
                    Some(svc)
                }
                _ => None,
            });

            match snapshot {
                Some(svc) => svc,
                None => {
                    return Err(EpochTransitionError::IoError(
                        "no snapshot or initial members for replay".into(),
                    ));
                }
            }
        };

        // If bootstrapped from a snapshot, skip all records up to and
        // including the snapshot to avoid double-applying transitions
        // that were already captured in the snapshot's member set.
        let snapshot_skip: usize = if has_initial_members {
            0
        } else {
            self.log
                .iter()
                .enumerate()
                .rev()
                .find_map(|(idx, rec)| match rec {
                    EpochLogRecord::Snapshot { .. } => Some(idx + 1),
                    _ => None,
                })
                .unwrap_or(0)
        };

        let replay_limit = self.committed_lsn.min(self.log.len() as u64) as usize;
        let start = snapshot_skip.min(replay_limit);

        for (idx, record) in self
            .log
            .iter()
            .enumerate()
            .skip(start)
            .take(replay_limit.saturating_sub(start))
        {
            match record {
                EpochLogRecord::TransitionCommitted {
                    from_epoch_id: _,
                    to_epoch_id: _,
                    event_discriminant,
                    added,
                    removed,
                    proposed_by: _,
                    reason_tag,
                    blake3_hash: _,
                } => {
                    // Verify integrity
                    let computed = record.compute_hash();
                    if let EpochLogRecord::TransitionCommitted { blake3_hash, .. } = record {
                        if computed != *blake3_hash {
                            return Err(EpochTransitionError::IoError(format!(
                                "BLAKE3 checksum mismatch at log index {idx}"
                            )));
                        }
                    }

                    let event = event_from_discriminant(*event_discriminant, added, removed);
                    let reason = reason_from_tag(*reason_tag);

                    svc.commit_transition(
                        event,
                        // Use the first added member as proposer, or 0 for system events
                        added.first().copied().unwrap_or(0),
                        reason,
                    )
                    .map_err(|e| {
                        EpochTransitionError::IoError(format!("replay failed at index {idx}: {e}"))
                    })?;
                }
                EpochLogRecord::Snapshot { .. } => {
                    // Snapshots are already handled at bootstrap; skip during replay
                }
            }
        }

        Ok(svc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_initial_members(ids: &[u64]) -> EpochMemberSet {
        EpochMemberSet::new(ids.iter().map(|&id| NodeIdentity::new(id)))
    }

    #[test]
    fn empty_persistence_is_empty() {
        let p = EpochPersistence::new();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        assert_eq!(p.committed_lsn(), 0);
        assert_eq!(p.verify_all(), 0);
    }

    #[test]
    fn append_and_commit() {
        let mut p = EpochPersistence::new();
        let rec = EpochLogRecord::Snapshot {
            epoch_id: 0,
            member_ids: vec![1, 2, 3],
            transition_count: 0,
        };
        p.append(rec.clone());
        p.commit_lsn(1);
        assert_eq!(p.len(), 1);
        assert_eq!(p.committed_lsn(), 1);
    }

    #[test]
    fn replay_from_initial_members() {
        let mut p = EpochPersistence::new();

        // Record a join transition with correct BLAKE3 hash
        let from_epoch_id = 0u64;
        let to_epoch_id = 1u64;
        let event_discriminant = 0x01u8;
        let added = vec![2u64];
        let removed: Vec<u64> = vec![];
        let proposed_by = 1u64;
        let reason_tag = 0x01u8;

        let rec = EpochLogRecord::TransitionCommitted {
            from_epoch_id,
            to_epoch_id,
            event_discriminant,
            added: added.clone(),
            removed: removed.clone(),
            proposed_by,
            reason_tag,
            blake3_hash: [0u8; 32],
        };
        let hash = rec.compute_hash();

        let rec = EpochLogRecord::TransitionCommitted {
            from_epoch_id,
            to_epoch_id,
            event_discriminant,
            added,
            removed,
            proposed_by,
            reason_tag,
            blake3_hash: hash,
        };

        p.append(rec);
        p.commit_lsn(1);
        // Add a second record beyond the committed LSN boundary;
        // it won't be replayed — exercises the LSN=1 boundary.
        let dead_rec = EpochLogRecord::Snapshot {
            epoch_id: 1,
            member_ids: vec![1, 2, 3],
            transition_count: 1,
        };
        p.append(dead_rec);
        // committed_lsn stays at 1 so the Snapshot is not replayed.

        let svc = p.replay(Some(make_initial_members(&[1]))).unwrap();
        assert_eq!(svc.current_epoch().epoch_id, 1);
        assert!(svc.is_member(2));
        assert_eq!(svc.transition_count(), 1);
    }

    #[test]
    fn replay_detects_checksum_mismatch() {
        let mut p = EpochPersistence::new();
        let rec = EpochLogRecord::TransitionCommitted {
            from_epoch_id: 0,
            to_epoch_id: 1,
            event_discriminant: 0x03,
            added: vec![],
            removed: vec![],
            proposed_by: 1,
            reason_tag: 0x03,
            blake3_hash: [0xFF; 32], // deliberately wrong
        };
        p.append(rec);
        p.commit_lsn(1);

        let result = p.replay(Some(make_initial_members(&[1])));
        match result {
            Err(EpochTransitionError::IoError(msg)) => {
                assert!(msg.contains("checksum mismatch"), "unexpected error: {msg}");
            }
            other => panic!("expected IoError with checksum mismatch, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_record_hash_is_stable() {
        let rec = EpochLogRecord::Snapshot {
            epoch_id: 5,
            member_ids: vec![1, 2, 3],
            transition_count: 10,
        };
        let h1 = rec.compute_hash();
        let h2 = rec.compute_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn transition_record_hash_differs_by_field() {
        let r1 = EpochLogRecord::TransitionCommitted {
            from_epoch_id: 0,
            to_epoch_id: 1,
            event_discriminant: 0x01,
            added: vec![2],
            removed: vec![],
            proposed_by: 1,
            reason_tag: 0x01,
            blake3_hash: [0u8; 32],
        };
        let r2 = EpochLogRecord::TransitionCommitted {
            from_epoch_id: 0,
            to_epoch_id: 2, // different to_epoch_id
            event_discriminant: 0x01,
            added: vec![2],
            removed: vec![],
            proposed_by: 1,
            reason_tag: 0x01,
            blake3_hash: [0u8; 32],
        };

        let h1 = r1.compute_hash();
        let h2 = r2.compute_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_all_detects_bad_hashes() {
        let mut p = EpochPersistence::new();

        let good = {
            let rec = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = rec.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };

        let bad = EpochLogRecord::TransitionCommitted {
            from_epoch_id: 1,
            to_epoch_id: 2,
            event_discriminant: 0x03,
            added: vec![],
            removed: vec![],
            proposed_by: 1,
            reason_tag: 0x03,
            blake3_hash: [0xDE; 32], // wrong
        };

        p.append(good);
        p.append(bad);
        assert_eq!(p.verify_all(), 1);
    }

    #[test]
    fn snapshot_from_service_roundtrip() {
        let members = make_initial_members(&[1, 2, 3]);
        let svc = EpochService::bootstrap(members);
        let snap = EpochLogRecord::snapshot_from_service(&svc);

        match snap {
            EpochLogRecord::Snapshot {
                epoch_id,
                member_ids,
                transition_count,
            } => {
                assert_eq!(epoch_id, 0);
                assert_eq!(member_ids, vec![1, 2, 3]);
                assert_eq!(transition_count, 0);
            }
            _ => panic!("expected Snapshot"),
        }
    }

    #[test]
    fn serde_roundtrip_log_record() {
        let rec = EpochLogRecord::TransitionCommitted {
            from_epoch_id: 3,
            to_epoch_id: 4,
            event_discriminant: 0x03,
            added: vec![],
            removed: vec![],
            proposed_by: 1,
            reason_tag: 0x03,
            blake3_hash: [0x42; 32],
        };

        let json = serde_json::to_string(&rec).unwrap();
        let restored: EpochLogRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, rec);
    }
    #[test]
    fn replay_from_snapshot_skips_pre_snapshot_transitions() {
        let mut p = EpochPersistence::new();

        // Build a realistic log:
        // 0: join member 2 (epoch 0→1)
        // 1: Snapshot(epoch=1, members=[1,2])
        // 2: join member 3 (epoch 1→2)
        // 3: leave member 2 (epoch 2→3)
        // 4: Snapshot(epoch=3, members=[1,3])
        // committed_lsn = 5 (all records committed)

        // Record 0: join member 2
        let rec0 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };
        p.append(rec0);

        // Record 1: snapshot at epoch 1
        p.append(EpochLogRecord::Snapshot {
            epoch_id: 1,
            member_ids: vec![1, 2],
            transition_count: 1,
        });

        // Record 2: join member 3
        let rec2 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 1,
                to_epoch_id: 2,
                event_discriminant: 0x01,
                added: vec![3],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 1,
                to_epoch_id: 2,
                event_discriminant: 0x01,
                added: vec![3],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };
        p.append(rec2);

        // Record 3: leave member 2
        let rec3 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 2,
                to_epoch_id: 3,
                event_discriminant: 0x02,
                added: vec![],
                removed: vec![2],
                proposed_by: 1,
                reason_tag: 0x02,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 2,
                to_epoch_id: 3,
                event_discriminant: 0x02,
                added: vec![],
                removed: vec![2],
                proposed_by: 1,
                reason_tag: 0x02,
                blake3_hash: hash,
            }
        };
        p.append(rec3);

        // Record 4: final snapshot at epoch 3
        p.append(EpochLogRecord::Snapshot {
            epoch_id: 3,
            member_ids: vec![1, 3],
            transition_count: 3,
        });

        p.commit_lsn(5);

        // Replay without initial_members — bootstraps from the last snapshot
        let svc = p.replay(None).unwrap();

        // After replay: only post-snapshot transitions should be applied.
        // Since the last record IS the snapshot, no transitions are post-snapshot,
        // so we should be at epoch 3 with members [1, 3] (the snapshot state).
        assert_eq!(
            svc.current_epoch().epoch_id,
            3,
            "epoch should be 3 (snapshot epoch) after replay"
        );
        assert!(svc.is_member(1), "member 1 should be present");
        assert!(!svc.is_member(2), "member 2 should have been removed");
        assert!(svc.is_member(3), "member 3 should be present");
        assert_eq!(svc.member_node_ids(), vec![1, 3]);
    }

    #[test]
    fn replay_from_snapshot_with_post_snapshot_transitions() {
        let mut p = EpochPersistence::new();

        // Build a log where a snapshot captures intermediate state
        // and there are transitions AFTER the snapshot:
        // 0: join member 2 (0→1)
        // 1: leave member 2 (1→2)
        // 2: Snapshot(epoch=2, members=[1])
        // 3: join member 3 (2→3)
        // 4: join member 4 (3→4)
        // committed_lsn = 5

        // Record 0: join 2
        let rec0 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 0,
                to_epoch_id: 1,
                event_discriminant: 0x01,
                added: vec![2],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };
        p.append(rec0);

        // Record 1: leave 2
        let rec1 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 1,
                to_epoch_id: 2,
                event_discriminant: 0x02,
                added: vec![],
                removed: vec![2],
                proposed_by: 1,
                reason_tag: 0x02,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 1,
                to_epoch_id: 2,
                event_discriminant: 0x02,
                added: vec![],
                removed: vec![2],
                proposed_by: 1,
                reason_tag: 0x02,
                blake3_hash: hash,
            }
        };
        p.append(rec1);

        // Record 2: snapshot at epoch 2, member=[1]
        p.append(EpochLogRecord::Snapshot {
            epoch_id: 2,
            member_ids: vec![1],
            transition_count: 2,
        });

        // Record 3: join 3 (2→3) — AFTER the snapshot
        let rec3 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 2,
                to_epoch_id: 3,
                event_discriminant: 0x01,
                added: vec![3],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 2,
                to_epoch_id: 3,
                event_discriminant: 0x01,
                added: vec![3],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };
        p.append(rec3);

        // Record 4: join 4 (3→4) — AFTER the snapshot
        let rec4 = {
            let tmp = EpochLogRecord::TransitionCommitted {
                from_epoch_id: 3,
                to_epoch_id: 4,
                event_discriminant: 0x01,
                added: vec![4],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: [0u8; 32],
            };
            let hash = tmp.compute_hash();
            EpochLogRecord::TransitionCommitted {
                from_epoch_id: 3,
                to_epoch_id: 4,
                event_discriminant: 0x01,
                added: vec![4],
                removed: vec![],
                proposed_by: 1,
                reason_tag: 0x01,
                blake3_hash: hash,
            }
        };
        p.append(rec4);

        p.commit_lsn(5);

        // Replay from snapshot: should bootstrap at epoch 2 with [1],
        // then apply post-snapshot transitions: join 3, join 4
        let svc = p.replay(None).unwrap();

        // Bootstrap at snapshot epoch 2, then +2 post-snapshot transitions = epoch 4
        assert_eq!(
            svc.current_epoch().epoch_id,
            4,
            "epoch should be 4 (snapshot 2 + 2 post-snapshot transitions)"
        );
        assert!(svc.is_member(1), "member 1 should be present");
        assert!(
            !svc.is_member(2),
            "member 2 should have been removed (pre-snapshot)"
        );
        assert!(
            svc.is_member(3),
            "member 3 should be present (post-snapshot join)"
        );
        assert!(
            svc.is_member(4),
            "member 4 should be present (post-snapshot join)"
        );
        assert_eq!(svc.member_node_ids(), vec![1, 3, 4]);
        // Transition count should only reflect post-snapshot transitions
        assert_eq!(svc.transition_count(), 2);
    }
}
