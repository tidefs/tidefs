#![forbid(unsafe_code)]

//! Coordinator local transition journal for crash-recovery replay.
//!
//! Records in-flight join and leave transitions with a prepare-then-commit
//! lifecycle. On coordinator promotion after a crash, the new coordinator
//! replays the journal: committed transitions are re-broadcast for convergence,
//! and prepared-but-uncommitted transitions older than a configurable timeout
//! are aborted.
//!
//! ## Lifecycle
//!
//! ```text
//! record_prepare(transition)
//!   |
//!   +-- validate & execute transition
//!        |
//!        +-- record_commit(id)  on success
//!        +-- record_abort(id)   on failure
//!
//! ... coordinator crash ...
//!
//! replay_pending(timeout_ms)
//!   |
//!   +-- committed  → re-broadcast
//!   +-- prepared, stale → auto-abort
//!   +-- prepared, fresh → yield for caller resolution
//! ```

use crate::{EpochId, LeaveReason, MemberId};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// TransitionId
// ---------------------------------------------------------------------------

/// Monotonically increasing transition identifier.
///
/// Assigned by the journal on `record_prepare`. Zero is reserved as the
/// null/uninitialised sentinel.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct TransitionId(pub u64);

impl TransitionId {
    /// The null transition id (never assigned).
    pub const ZERO: Self = Self(0);

    /// Create a new transition id from a raw counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// TransitionKind
// ---------------------------------------------------------------------------

/// The kind of membership transition being journaled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    /// A peer is joining the cluster.
    Join {
        /// The peer requesting membership.
        peer_id: MemberId,
        /// Epoch at which the join was requested.
        epoch: EpochId,
    },
    /// A peer is leaving the cluster.
    Leave {
        /// The member departing.
        peer_id: MemberId,
        /// Epoch at which the leave was requested.
        epoch: EpochId,
        /// Reason for departure.
        reason: LeaveReason,
    },
}

impl TransitionKind {
    /// Returns the peer id associated with this transition.
    #[must_use]
    pub fn peer_id(&self) -> MemberId {
        match self {
            Self::Join { peer_id, .. } | Self::Leave { peer_id, .. } => *peer_id,
        }
    }

    /// Returns the epoch at which this transition was requested.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        match self {
            Self::Join { epoch, .. } | Self::Leave { epoch, .. } => *epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// TransitionStatus
// ---------------------------------------------------------------------------

/// The current status of a journaled transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionStatus {
    /// Transition intent recorded; validation/execution not yet complete.
    Prepared,
    /// Transition completed and broadcast.
    Committed,
    /// Transition was aborted (validation failure, timeout, etc.).
    Aborted,
}

// ---------------------------------------------------------------------------
// TransitionRecord
// ---------------------------------------------------------------------------

/// A single entry in the transition journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionRecord {
    /// Unique transition identifier.
    pub id: TransitionId,
    /// The transition kind.
    pub kind: TransitionKind,
    /// Current status.
    pub status: TransitionStatus,
    /// Timestamp of `record_prepare` (millis since epoch).
    pub prepared_at_millis: u64,
    /// Timestamp of commit or abort (0 if not yet finalised).
    pub finalised_at_millis: u64,
}

impl TransitionRecord {
    /// Whether this record is still in the Prepared state.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.status, TransitionStatus::Prepared)
    }

    /// Whether this record is in the Committed state.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        matches!(self.status, TransitionStatus::Committed)
    }
}

// ---------------------------------------------------------------------------
// MembershipTransitionJournal
// ---------------------------------------------------------------------------

/// Append-only journal of coordinator membership transitions.
///
/// Records each transition with a monotonically increasing `TransitionId`.
/// Supports prepare-commit-abort lifecycle and replay with timeout-based
/// staleness detection for crash-recovery.
#[derive(Clone, Debug, Default)]
pub struct MembershipTransitionJournal {
    /// Ordered log of transition records.
    log: VecDeque<TransitionRecord>,
    /// Next transition id to assign.
    next_id: u64,
}

impl MembershipTransitionJournal {
    /// Create an empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            log: VecDeque::new(),
            next_id: 1,
        }
    }

    /// Number of records in the journal.
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether the journal is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Record a prepared transition intent.
    ///
    /// Returns the assigned `TransitionId`. The caller must later call
    /// `record_commit` or `record_abort` to finalise.
    #[must_use]
    pub fn record_prepare(&mut self, kind: TransitionKind, now_millis: u64) -> TransitionId {
        let id = self.allocate_id();
        let record = TransitionRecord {
            id,
            kind,
            status: TransitionStatus::Prepared,
            prepared_at_millis: now_millis,
            finalised_at_millis: 0,
        };
        self.log.push_back(record);
        id
    }

    /// Record a prepared transition intent after constraint validation.
    ///
    /// Calls [`crate::roster_constraints::validate_add_peer`] or
    /// [`crate::roster_constraints::validate_remove_peer`] against
    /// `current_roster` and `constraints`, then calls
    /// [`record_prepare`](Self::record_prepare) on success.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintValidationError`] if the transition violates
    /// roster constraints.
    pub fn record_prepare_with_constraints(
        &mut self,
        kind: TransitionKind,
        current_roster: &[crate::MemberId],
        constraints: &crate::roster_constraints::RosterConstraints,
        now_millis: u64,
    ) -> Result<TransitionId, crate::roster_constraints::ConstraintValidationError> {
        use crate::roster_constraints;

        match &kind {
            TransitionKind::Join { peer_id, .. } => {
                roster_constraints::validate_add_peer(current_roster, *peer_id, constraints)?;
            }
            TransitionKind::Leave { peer_id, .. } => {
                roster_constraints::validate_remove_peer(current_roster, *peer_id, constraints)?;
            }
        }

        let resulting = apply_transition_kind(current_roster, &kind);
        roster_constraints::validate_roster_invariants(&resulting, constraints)?;

        Ok(self.record_prepare(kind, now_millis))
    }
    /// Mark a prepared transition as committed.
    ///
    /// Returns `true` if the record was found and was in the Prepared state.
    /// Returns `false` if the id is unknown or the record is already
    /// finalised.
    pub fn record_commit(&mut self, id: TransitionId, now_millis: u64) -> bool {
        self.finalise(id, TransitionStatus::Committed, now_millis)
    }

    /// Mark a prepared transition as aborted.
    ///
    /// Returns `true` if the record was found and was in the Prepared state.
    /// Returns `false` if the id is unknown or the record is already
    /// finalised.
    pub fn record_abort(&mut self, id: TransitionId, now_millis: u64) -> bool {
        self.finalise(id, TransitionStatus::Aborted, now_millis)
    }

    /// Replay pending transitions for crash recovery.
    ///
    /// Returns an iterator over records that need attention after coordinator
    /// promotion:
    ///
    /// - **Committed** records: re-broadcast needed to ensure all members
    ///   received the transition result.
    /// - **Prepared** records fresh enough: yielded for the caller to
    ///   re-evaluate and commit or abort.
    /// - **Prepared** records stale beyond `staleness_timeout_ms`: aborted
    ///   automatically (not yielded). The initiating peer must be notified.
    ///
    /// Staleness is computed against `now_millis`.
    #[must_use]
    pub fn replay_pending(&mut self, now_millis: u64, staleness_timeout_ms: u64) -> ReplayIter<'_> {
        ReplayIter {
            inner: self,
            now_millis,
            staleness_timeout_ms,
            index: 0,
        }
    }

    /// Look up a record by id.
    #[must_use]
    pub fn get(&self, id: TransitionId) -> Option<&TransitionRecord> {
        self.log.iter().find(|r| r.id == id)
    }

    /// Iterator over all records in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &TransitionRecord> {
        self.log.iter()
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.log.clear();
    }

    // ── private helpers ──────────────────────────────────────────────

    fn allocate_id(&mut self) -> TransitionId {
        let id = TransitionId(self.next_id);
        self.next_id += 1;
        id
    }

    fn finalise(&mut self, id: TransitionId, target: TransitionStatus, now_millis: u64) -> bool {
        for record in &mut self.log {
            if record.id == id {
                if record.status != TransitionStatus::Prepared {
                    return false;
                }
                record.status = target;
                record.finalised_at_millis = now_millis;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// ReplayIter
// ---------------------------------------------------------------------------

/// Iterator produced by [`MembershipTransitionJournal::replay_pending`].
///
/// Yields [`ReplayAction`] items: committed records needing re-broadcast,
/// and fresh prepared records needing resolution.
pub struct ReplayIter<'a> {
    inner: &'a mut MembershipTransitionJournal,
    now_millis: u64,
    staleness_timeout_ms: u64,
    index: usize,
}

/// Action the caller must take for a replayed transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayAction {
    /// A committed transition that should be re-broadcast.
    ReBroadcastCommitted { record: TransitionRecord },
    /// A prepared transition that is fresh enough to resolve.
    /// The caller should re-evaluate and either commit or abort.
    ResolvePrepared { record: TransitionRecord },
}

impl Iterator for ReplayIter<'_> {
    type Item = ReplayAction;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = self.inner.log.get(self.index)?;
            self.index += 1;

            match record.status {
                TransitionStatus::Committed => {
                    return Some(ReplayAction::ReBroadcastCommitted {
                        record: record.clone(),
                    });
                }
                TransitionStatus::Prepared => {
                    let age_ms = self.now_millis.saturating_sub(record.prepared_at_millis);
                    if age_ms > self.staleness_timeout_ms {
                        // Auto-abort stale prepared records.
                        // Collect the id so we can mutate after the immutable borrow ends.
                        let stale_id = record.id;
                        // record reference dropped naturally at end of scope
                        // Although we drop the record reference, the immutable borrow
                        // on self.inner (via get) is still active until the next
                        // iteration. We fix this by using a position-based approach:
                        // mutate through a direct index into the VecDeque.
                        let idx = self.index - 1;
                        if let Some(rec) = self.inner.log.get_mut(idx) {
                            if rec.id == stale_id {
                                rec.status = TransitionStatus::Aborted;
                                rec.finalised_at_millis = self.now_millis;
                            }
                        }
                        continue;
                    }
                    return Some(ReplayAction::ResolvePrepared {
                        record: record.clone(),
                    });
                }
                TransitionStatus::Aborted => {
                    continue;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the resulting roster after applying a transition kind.
///
/// For Join, adds the peer. For Leave, removes it. The returned vector
/// is sorted and deduplicated.
#[must_use]
pub fn apply_transition_kind(
    current_roster: &[crate::MemberId],
    kind: &TransitionKind,
) -> Vec<crate::MemberId> {
    use crate::MemberId;
    let mut result: Vec<MemberId> = current_roster.to_vec();
    match kind {
        TransitionKind::Join { peer_id, .. } => {
            result.push(*peer_id);
        }
        TransitionKind::Leave { peer_id, .. } => {
            result.retain(|m| m != peer_id);
        }
    }
    result.sort();
    result.dedup();
    result
}
/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Used as the timestamp source for journal records. Panics if the system
/// clock is set before the Unix epoch.
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn now() -> u64 {
        current_time_millis()
    }

    // ── TransitionId ─────────────────────────────────────────────────

    #[test]
    fn transition_id_zero_is_null() {
        assert_eq!(TransitionId::ZERO, TransitionId::new(0));
    }

    #[test]
    fn transition_id_ordering() {
        assert!(TransitionId::new(1) < TransitionId::new(2));
    }

    // ── TransitionKind ───────────────────────────────────────────────

    #[test]
    fn transition_kind_join_peer_id() {
        let kind = TransitionKind::Join {
            peer_id: member(42),
            epoch: epoch(3),
        };
        assert_eq!(kind.peer_id(), member(42));
        assert_eq!(kind.epoch(), epoch(3));
    }

    #[test]
    fn transition_kind_leave_peer_id() {
        let kind = TransitionKind::Leave {
            peer_id: member(99),
            epoch: epoch(7),
            reason: LeaveReason::Voluntary,
        };
        assert_eq!(kind.peer_id(), member(99));
        assert_eq!(kind.epoch(), epoch(7));
    }

    // ── Journal: basic append ────────────────────────────────────────

    #[test]
    fn journal_starts_empty() {
        let j = MembershipTransitionJournal::new();
        assert!(j.is_empty());
        assert_eq!(j.len(), 0);
    }

    #[test]
    fn record_prepare_returns_monotonic_ids() {
        let mut j = MembershipTransitionJournal::new();
        let t = now();

        let id1 = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(1),
                epoch: epoch(5),
            },
            t,
        );
        let id2 = j.record_prepare(
            TransitionKind::Leave {
                peer_id: member(2),
                epoch: epoch(5),
                reason: LeaveReason::Voluntary,
            },
            t,
        );

        assert_eq!(id1, TransitionId::new(1));
        assert_eq!(id2, TransitionId::new(2));
        assert_eq!(j.len(), 2);
    }

    #[test]
    fn record_prepare_sets_status_and_timestamp() {
        let mut j = MembershipTransitionJournal::new();
        let t = 1000u64;

        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(10),
                epoch: epoch(1),
            },
            t,
        );

        let rec = j.get(id).unwrap();
        assert_eq!(rec.status, TransitionStatus::Prepared);
        assert_eq!(rec.prepared_at_millis, 1000);
        assert_eq!(rec.finalised_at_millis, 0);
    }

    // ── Journal: commit ──────────────────────────────────────────────

    #[test]
    fn record_commit_finalises_prepared() {
        let mut j = MembershipTransitionJournal::new();
        let t = 2000u64;
        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(5),
                epoch: epoch(1),
            },
            t,
        );

        assert!(j.record_commit(id, t + 100));

        let rec = j.get(id).unwrap();
        assert_eq!(rec.status, TransitionStatus::Committed);
        assert_eq!(rec.finalised_at_millis, t + 100);
    }

    #[test]
    fn record_commit_unknown_id_returns_false() {
        let mut j = MembershipTransitionJournal::new();
        assert!(!j.record_commit(TransitionId::new(999), 0));
    }

    #[test]
    fn record_commit_already_committed_returns_false() {
        let mut j = MembershipTransitionJournal::new();
        let t = 3000u64;
        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(3),
                epoch: epoch(2),
            },
            t,
        );
        assert!(j.record_commit(id, t));
        // Second commit on the same id fails.
        assert!(!j.record_commit(id, t + 1));
    }

    // ── Journal: abort ───────────────────────────────────────────────

    #[test]
    fn record_abort_finalises_prepared() {
        let mut j = MembershipTransitionJournal::new();
        let t = 4000u64;
        let id = j.record_prepare(
            TransitionKind::Leave {
                peer_id: member(7),
                epoch: epoch(3),
                reason: LeaveReason::Maintenance,
            },
            t,
        );

        assert!(j.record_abort(id, t + 50));

        let rec = j.get(id).unwrap();
        assert_eq!(rec.status, TransitionStatus::Aborted);
        assert_eq!(rec.finalised_at_millis, t + 50);
    }

    #[test]
    fn record_abort_after_commit_returns_false() {
        let mut j = MembershipTransitionJournal::new();
        let t = 5000u64;
        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(9),
                epoch: epoch(4),
            },
            t,
        );
        assert!(j.record_commit(id, t));
        assert!(!j.record_abort(id, t + 1));
    }

    // ── Journal: replay ──────────────────────────────────────────────

    #[test]
    fn replay_yields_committed_records() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(1),
                epoch: epoch(1),
            },
            t,
        );
        j.record_commit(id, t + 10);

        let actions: Vec<ReplayAction> = j.replay_pending(t + 100, 60_000).collect();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ReplayAction::ReBroadcastCommitted { record } => {
                assert_eq!(record.id, id);
                assert!(record.is_committed());
            }
            _ => panic!("expected ReBroadcastCommitted"),
        }
    }

    #[test]
    fn replay_yields_fresh_prepared_records() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = j.record_prepare(
            TransitionKind::Leave {
                peer_id: member(2),
                epoch: epoch(2),
                reason: LeaveReason::Draining,
            },
            t,
        );

        // Replay at t+100 — age 100ms, timeout 60_000ms → still fresh.
        let actions: Vec<ReplayAction> = j.replay_pending(t + 100, 60_000).collect();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ReplayAction::ResolvePrepared { record } => {
                assert_eq!(record.id, id);
                assert!(record.is_pending());
            }
            _ => panic!("expected ResolvePrepared"),
        }
    }

    #[test]
    fn replay_auto_aborts_stale_prepared() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(3),
                epoch: epoch(3),
            },
            t,
        );

        // Replay at t+100_000 — age 100s, timeout 10_000ms (10s) → stale.
        let actions: Vec<ReplayAction> = j.replay_pending(t + 100_000, 10_000).collect();
        // Should be auto-aborted, not yielded.
        assert!(actions.is_empty());

        let rec = j.get(id).unwrap();
        assert_eq!(rec.status, TransitionStatus::Aborted);
        assert_eq!(rec.finalised_at_millis, t + 100_000);
    }

    #[test]
    fn replay_skips_already_aborted() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(4),
                epoch: epoch(4),
            },
            t,
        );
        j.record_abort(id, t + 5);

        let actions: Vec<ReplayAction> = j.replay_pending(t + 1000, 60_000).collect();
        assert!(actions.is_empty());
    }

    #[test]
    fn replay_mixed_states() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id1 = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(10),
                epoch: epoch(1),
            },
            t,
        );
        j.record_commit(id1, t + 10);

        let _id2 = j.record_prepare(
            TransitionKind::Leave {
                peer_id: member(11),
                epoch: epoch(1),
                reason: LeaveReason::Voluntary,
            },
            t,
        );
        // id2 stays prepared, fresh.

        let id3 = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(12),
                epoch: epoch(1),
            },
            t,
        );
        j.record_abort(id3, t + 10);

        let actions: Vec<ReplayAction> = j.replay_pending(t + 50, 60_000).collect();
        assert_eq!(
            actions.len(),
            2,
            "should yield 1 committed + 1 fresh prepared"
        );

        let committed: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                ReplayAction::ReBroadcastCommitted { record } => Some(record),
                _ => None,
            })
            .collect();
        let prepared: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                ReplayAction::ResolvePrepared { record } => Some(record),
                _ => None,
            })
            .collect();

        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].id, id1);
        assert_eq!(prepared.len(), 1);
    }

    // ── Journal: idempotent operations ───────────────────────────────

    #[test]
    fn replay_is_idempotent() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(50),
                epoch: epoch(10),
            },
            t,
        );
        j.record_commit(id, t + 10);

        // First replay yields committed.
        let actions1: Vec<_> = j.replay_pending(t + 100, 60_000).collect();
        assert_eq!(actions1.len(), 1);

        // Second replay also yields it (committed records are replayed every time).
        let actions2: Vec<_> = j.replay_pending(t + 200, 60_000).collect();
        assert_eq!(actions2.len(), 1);
    }

    // ── Journal: clear ───────────────────────────────────────────────

    #[test]
    fn clear_empties_journal() {
        let mut j = MembershipTransitionJournal::new();
        let _ = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(1),
                epoch: epoch(1),
            },
            now(),
        );
        assert_eq!(j.len(), 1);

        j.clear();
        assert!(j.is_empty());
        assert_eq!(j.len(), 0);
    }

    // ── Journal: get and iter ────────────────────────────────────────

    #[test]
    fn get_returns_correct_record() {
        let mut j = MembershipTransitionJournal::new();
        let t = 5000u64;
        let id = j.record_prepare(
            TransitionKind::Leave {
                peer_id: member(42),
                epoch: epoch(5),
                reason: LeaveReason::Draining,
            },
            t,
        );
        let rec = j.get(id).unwrap();
        assert_eq!(rec.id, id);
        assert_eq!(rec.kind.peer_id(), member(42));
    }

    #[test]
    fn get_unknown_returns_none() {
        let j = MembershipTransitionJournal::new();
        assert!(j.get(TransitionId::new(1)).is_none());
    }

    #[test]
    fn iter_yields_all_in_order() {
        let mut j = MembershipTransitionJournal::new();
        let t = 0u64;

        let _ = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(1),
                epoch: epoch(1),
            },
            t,
        );
        let _ = j.record_prepare(
            TransitionKind::Join {
                peer_id: member(2),
                epoch: epoch(1),
            },
            t,
        );

        let ids: Vec<TransitionId> = j.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![TransitionId::new(1), TransitionId::new(2)]);
    }

    // ── current_time_millis ──────────────────────────────────────────

    #[test]
    fn current_time_millis_is_reasonable() {
        let t = current_time_millis();
        // May 2026 is roughly 1_777_000_000_000 ms since epoch.
        assert!(t > 1_777_000_000_000, "unexpectedly low timestamp: {t}");
    }

    // ── record_prepare_with_constraints tests ────────────────────────

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn def_c() -> crate::roster_constraints::RosterConstraints {
        crate::roster_constraints::RosterConstraints::default()
    }

    #[test]
    fn prepare_with_constraints_join_ok() {
        let mut j = MembershipTransitionJournal::new();
        let roster = [mid(1), mid(2)];
        let kind = TransitionKind::Join {
            peer_id: mid(3),
            epoch: epoch(1),
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &def_c(), 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransitionId::new(1));
    }

    #[test]
    fn prepare_with_constraints_join_already_present_rejected() {
        let mut j = MembershipTransitionJournal::new();
        let roster = [mid(1), mid(2), mid(3)];
        let kind = TransitionKind::Join {
            peer_id: mid(2),
            epoch: epoch(1),
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &def_c(), 1000);
        assert_eq!(
            result,
            Err(crate::roster_constraints::ConstraintValidationError::PeerAlreadyPresent)
        );
    }

    #[test]
    fn prepare_with_constraints_join_too_many_peers_rejected() {
        let mut j = MembershipTransitionJournal::new();
        let constraints = crate::roster_constraints::RosterConstraints::new(2, 1);
        let roster = [mid(1), mid(2)];
        let kind = TransitionKind::Join {
            peer_id: mid(3),
            epoch: epoch(1),
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &constraints, 1000);
        assert_eq!(
            result,
            Err(crate::roster_constraints::ConstraintValidationError::TooManyPeers)
        );
    }

    #[test]
    fn prepare_with_constraints_leave_ok() {
        let mut j = MembershipTransitionJournal::new();
        let roster = [mid(1), mid(2), mid(3), mid(4)];
        let kind = TransitionKind::Leave {
            peer_id: mid(3),
            epoch: epoch(5),
            reason: LeaveReason::Voluntary,
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &def_c(), 2000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransitionId::new(1));
    }

    #[test]
    fn prepare_with_constraints_leave_peer_not_found_rejected() {
        let mut j = MembershipTransitionJournal::new();
        let roster = [mid(1), mid(2)];
        let kind = TransitionKind::Leave {
            peer_id: mid(99),
            epoch: epoch(1),
            reason: LeaveReason::Voluntary,
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &def_c(), 1000);
        assert_eq!(
            result,
            Err(crate::roster_constraints::ConstraintValidationError::PeerNotFound)
        );
    }

    #[test]
    fn prepare_with_constraints_leave_loses_quorum_rejected() {
        let mut j = MembershipTransitionJournal::new();
        let constraints = crate::roster_constraints::RosterConstraints::new(64, 2);
        let roster = [mid(1), mid(2)];
        let kind = TransitionKind::Leave {
            peer_id: mid(1),
            epoch: epoch(1),
            reason: LeaveReason::Voluntary,
        };
        let result = j.record_prepare_with_constraints(kind, &roster, &constraints, 1000);
        assert_eq!(
            result,
            Err(crate::roster_constraints::ConstraintValidationError::QuorumLost)
        );
    }

    #[test]
    fn apply_transition_kind_join() {
        let roster = [mid(1), mid(2)];
        let kind = TransitionKind::Join {
            peer_id: mid(3),
            epoch: epoch(0),
        };
        let result = apply_transition_kind(&roster, &kind);
        assert_eq!(result, vec![mid(1), mid(2), mid(3)]);
    }

    #[test]
    fn apply_transition_kind_leave() {
        let roster = [mid(1), mid(2), mid(3)];
        let kind = TransitionKind::Leave {
            peer_id: mid(2),
            epoch: epoch(0),
            reason: LeaveReason::Voluntary,
        };
        let result = apply_transition_kind(&roster, &kind);
        assert_eq!(result, vec![mid(1), mid(3)]);
    }
}
