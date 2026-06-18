// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Journal sync trigger: pushes batched transition journal entries to
//! newly-connected peers on session establishment.
//!
//! [`JournalSyncTrigger`] takes a snapshot of the transition journal and
//! a sender callback, then packages entries as [`JournalSyncBatch`] messages
//! and dispatches them to peers that have just established a transport
//! session (or are catching up after a partition).
//!
//! ## Integration
//!
//! The trigger is meant to be called after transport session establishment:
//!
//! ```ignore
//! let trigger = JournalSyncTrigger::new(
//!     journal_snapshot,
//!     |peer_id: MemberId, batch: JournalSyncBatch| {
//!         // serialize and send via outbound dispatch
//!     },
//! );
//! trigger.push_to_peer(new_peer_id, base_epoch);
//! ```
//!
//! The sender callback serializes the `JournalSyncBatch` into a
//! `MembershipOutboundMessage::JournalSyncBatch` and enqueues it through
//! the transport send pipeline.

use tidefs_membership_epoch::journal_wire::JournalSyncBatch;
use tidefs_membership_epoch::transition_journal::TransitionRecord;
use tidefs_membership_epoch::MemberId;

/// A function that sends a [`JournalSyncBatch`] to a specific peer.
///
/// Callers provide this callback to decouple the trigger from the
/// transport send pipeline.
pub type JournalSyncSender = Box<dyn Fn(MemberId, JournalSyncBatch) + Send + Sync>;

// ---------------------------------------------------------------------------
// JournalSyncTrigger
// ---------------------------------------------------------------------------

/// Builds and sends batched journal entries to peers on session
/// establishment or catch-up request.
///
/// The trigger holds an immutable snapshot of journal entries taken at
/// construction time. For continuously-updating journals, create a new
/// trigger (or update it) when the journal changes.
///
/// The `sender` callback receives the target `MemberId` and a
/// `JournalSyncBatch`. Callers should serialize the batch into a
/// `MembershipOutboundMessage::JournalSyncBatch` and enqueue it through
/// the transport send pipeline.
pub struct JournalSyncTrigger {
    /// All committed and prepared journal entries to synchronize.
    entries: Vec<TransitionRecord>,
    /// The sender callback: (peer_id, batch) -> ()
    sender: JournalSyncSender,
}

impl JournalSyncTrigger {
    /// Create a new trigger with a snapshot of journal entries.
    ///
    /// `entries` should include all committed entries and optionally
    /// prepared entries that need to be synchronized to new peers.
    pub fn new(entries: Vec<TransitionRecord>, sender: JournalSyncSender) -> Self {
        Self { entries, sender }
    }

    /// Create a trigger that only includes committed entries.
    ///
    /// Prepared entries are excluded because they may still be aborted.
    pub fn new_committed_only(entries: Vec<TransitionRecord>, sender: JournalSyncSender) -> Self {
        let entries: Vec<TransitionRecord> =
            entries.into_iter().filter(|r| r.is_committed()).collect();
        Self::new(entries, sender)
    }

    /// Number of journal entries in this trigger.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Push the full journal snapshot to a specific peer.
    ///
    /// Builds a `JournalSyncBatch` from all entries, encodes it, and
    /// sends via the callback. The base epoch is set to 0 (all entries).
    pub fn push_to_peer(&self, peer_id: MemberId) {
        self.push_to_peer_from(peer_id, 0);
    }

    /// Push journal entries starting from a specific base epoch.
    ///
    /// Only entries with epoch >= `base_epoch` are included. This is
    /// used for catching-up peers that already have state up to a
    /// known epoch.
    pub fn push_to_peer_from(&self, peer_id: MemberId, base_epoch: u64) {
        let filtered: Vec<TransitionRecord> = self
            .entries
            .iter()
            .filter(|r| r.kind.epoch().0 >= base_epoch)
            .cloned()
            .collect();

        if filtered.is_empty() {
            return;
        }

        let batch = JournalSyncBatch::from_records(base_epoch, &filtered);
        (self.sender)(peer_id, batch);
    }

    /// Push journal entries to multiple peers.
    ///
    /// Each peer receives the same batch starting from `base_epoch`.
    /// Empty batch or empty peer list are both no-ops.
    pub fn push_to_peers(&self, peer_ids: &[MemberId], base_epoch: u64) {
        let filtered: Vec<TransitionRecord> = self
            .entries
            .iter()
            .filter(|r| r.kind.epoch().0 >= base_epoch)
            .cloned()
            .collect();

        if filtered.is_empty() || peer_ids.is_empty() {
            return;
        }

        let batch = JournalSyncBatch::from_records(base_epoch, &filtered);
        for &peer_id in peer_ids {
            (self.sender)(peer_id, batch.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tidefs_membership_epoch::transition_journal::{
        TransitionId, TransitionKind, TransitionStatus,
    };
    use tidefs_membership_epoch::{EpochId, LeaveReason};

    fn make_join_record(id: u64, peer: u64, epoch: u64) -> TransitionRecord {
        TransitionRecord {
            id: TransitionId::new(id),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(peer),
                epoch: EpochId::new(epoch),
            },
            status: TransitionStatus::Committed,
            prepared_at_millis: 1000 * id,
            finalised_at_millis: 2000 * id,
        }
    }

    fn make_leave_record(id: u64, peer: u64, epoch: u64) -> TransitionRecord {
        TransitionRecord {
            id: TransitionId::new(id),
            kind: TransitionKind::Leave {
                peer_id: MemberId::new(peer),
                epoch: EpochId::new(epoch),
                reason: LeaveReason::Voluntary,
            },
            status: TransitionStatus::Committed,
            prepared_at_millis: 1000 * id,
            finalised_at_millis: 2000 * id,
        }
    }

    /// A sender that records (peer_id, batch) pairs for test assertions.
    type JournalSyncCalls = Arc<Mutex<Vec<(MemberId, JournalSyncBatch)>>>;

    struct RecordingSender {
        calls: JournalSyncCalls,
    }

    impl RecordingSender {
        fn new() -> (Self, JournalSyncCalls) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let sender = Self {
                calls: calls.clone(),
            };
            (sender, calls)
        }

        fn into_callback(self) -> JournalSyncSender {
            Box::new(move |peer_id, batch| {
                self.calls.lock().unwrap().push((peer_id, batch));
            })
        }
    }

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    // ── Construction and entry count ─────────────────────────────────

    #[test]
    fn new_trigger_stores_entries() {
        let entries = vec![make_join_record(1, 10, 0), make_join_record(2, 20, 1)];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries.clone(), sender.into_callback());
        assert_eq!(trigger.entry_count(), 2);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn new_committed_only_filters_prepared() {
        let entries = vec![
            make_join_record(1, 10, 0),
            TransitionRecord {
                id: TransitionId::new(2),
                kind: TransitionKind::Join {
                    peer_id: MemberId::new(20),
                    epoch: EpochId::new(1),
                },
                status: TransitionStatus::Prepared,
                prepared_at_millis: 1000,
                finalised_at_millis: 0,
            },
            make_leave_record(3, 30, 2),
        ];
        let (sender, _calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new_committed_only(entries, sender.into_callback());
        assert_eq!(
            trigger.entry_count(),
            2,
            "prepared entry should be excluded"
        );
    }

    // ── push_to_peer ────────────────────────────────────────────────

    #[test]
    fn push_to_peer_sends_batch() {
        let entries = vec![make_join_record(1, 10, 0), make_join_record(2, 20, 1)];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries.clone(), sender.into_callback());

        trigger.push_to_peer(mid(42));

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        let (peer_id, batch) = &recorded[0];
        assert_eq!(*peer_id, mid(42));
        assert_eq!(batch.entries.len(), 2);
        assert_eq!(batch.base_epoch, 0);
    }

    #[test]
    fn push_to_peer_empty_entries_is_noop() {
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(vec![], sender.into_callback());
        trigger.push_to_peer(mid(42));
        assert!(calls.lock().unwrap().is_empty());
    }

    // ── push_to_peer_from ───────────────────────────────────────────

    #[test]
    fn push_to_peer_from_filters_by_epoch() {
        let entries = vec![
            make_join_record(1, 10, 0),
            make_join_record(2, 20, 1),
            make_leave_record(3, 10, 2),
            make_join_record(4, 30, 3),
        ];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries, sender.into_callback());

        // Only entries with epoch >= 2
        trigger.push_to_peer_from(mid(42), 2);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        let (_, batch) = &recorded[0];
        assert_eq!(batch.base_epoch, 2);
        assert_eq!(batch.entries.len(), 2); // leave at epoch 2, join at epoch 3
    }

    #[test]
    fn push_to_peer_from_no_matching_entries_is_noop() {
        let entries = vec![make_join_record(1, 10, 0), make_join_record(2, 20, 1)];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries, sender.into_callback());

        trigger.push_to_peer_from(mid(42), 100);
        assert!(calls.lock().unwrap().is_empty());
    }

    // ── push_to_peers ───────────────────────────────────────────────

    #[test]
    fn push_to_peers_sends_to_multiple() {
        let entries = vec![make_join_record(1, 10, 0), make_join_record(2, 20, 1)];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries, sender.into_callback());

        trigger.push_to_peers(&[mid(10), mid(20), mid(30)], 0);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        let peer_ids: Vec<u64> = recorded.iter().map(|(p, _)| p.0).collect();
        assert_eq!(peer_ids, vec![10, 20, 30]);

        // All batches should be identical
        let batch0 = &recorded[0].1;
        for (_, batch) in &recorded[1..] {
            assert_eq!(batch.entries.len(), batch0.entries.len());
            assert_eq!(batch.base_epoch, batch0.base_epoch);
        }
    }

    #[test]
    fn push_to_peers_empty_ids_is_noop() {
        let entries = vec![make_join_record(1, 10, 0)];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries, sender.into_callback());

        trigger.push_to_peers(&[], 0);
        assert!(calls.lock().unwrap().is_empty());
    }

    // ── Batch roundtrip integrity ───────────────────────────────────

    #[test]
    fn batch_roundtrip_through_codec() {
        let entries = vec![
            make_join_record(1, 10, 0),
            make_leave_record(2, 10, 1),
            make_join_record(3, 20, 2),
        ];
        let (sender, calls) = RecordingSender::new();
        let trigger = JournalSyncTrigger::new(entries.clone(), sender.into_callback());

        trigger.push_to_peer(mid(42));

        let recorded = calls.lock().unwrap().clone();
        let batch = &recorded[0].1;

        // Recover records from the batch
        let recovered = batch.to_records().unwrap();
        assert_eq!(recovered, entries);
    }
}
