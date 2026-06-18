// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Catch-up wire message types for epoch range-query protocol.
//!
//! Defines the request/response messages used by a lagging peer to
//! request a range of missed committed epochs from an up-to-date peer
//! over transport. These messages carry no new crypto surface; they
//! rely on the existing transport/session security boundary.
//!
//! ## Wire format
//!
//! - [`EpochCatchUpRequest`]: range query with `from_epoch` (inclusive)
//!   and `to_epoch` (inclusive).
//! - [`EpochCatchUpResponse`]: batched [`CommittedEpochView`] epochs with
//!   a `truncated` flag set when the responder's chain no longer reaches
//!   the requested `from_epoch`.
//!
//! ## Serialization
//!
//! Both types derive `serde::Serialize` and `serde::Deserialize` for
//! bincode wire encoding. The `CommittedEpochView` carries epoch number,
//! sorted member set, and a creation timestamp.

use crate::{EpochId, MemberId};
use serde::{Deserialize, Serialize};

// ── CommittedEpochView ──────────────────────────────────────────────

/// A committed epoch view suitable for wire transmission.
///
/// Carries the monotonic epoch number, the sorted deduplicated member
/// set, and the creation timestamp. This is the wire-compatible form
/// of the membership-live `EpochView` — it derives `Serialize` and
/// `Deserialize` for bincode transport encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedEpochView {
    /// Monotonic epoch number.
    pub epoch_number: EpochId,
    /// Members in this epoch (sorted, deduplicated).
    pub member_set: Vec<MemberId>,
    /// When this view was created (milliseconds since epoch).
    pub created_at_millis: u64,
}

impl CommittedEpochView {
    /// Create a new committed epoch view.
    ///
    /// The member set is sorted and deduplicated.
    #[must_use]
    pub fn new(
        epoch_number: EpochId,
        mut member_set: Vec<MemberId>,
        created_at_millis: u64,
    ) -> Self {
        member_set.sort();
        member_set.dedup();
        Self {
            epoch_number,
            member_set,
            created_at_millis,
        }
    }

    /// Number of members in this view.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_set.len()
    }

    /// Check whether a specific member is in this view.
    #[must_use]
    pub fn contains(&self, member_id: MemberId) -> bool {
        self.member_set.contains(&member_id)
    }

    /// The epoch number as a raw u64 for range comparison.
    #[must_use]
    pub fn epoch_u64(&self) -> u64 {
        self.epoch_number.0
    }
}

// ── EpochCatchUpRequest ─────────────────────────────────────────────

/// A range-query request from a lagging peer asking for missed committed
/// epoch views between `from_epoch` (inclusive) and `to_epoch` (inclusive).
///
/// Sent to the peer with the longest known chain when local committed
/// epoch height trails peer-advertised heights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCatchUpRequest {
    /// First missing epoch (inclusive). Must be > 0.
    pub from_epoch: u64,
    /// Last requested epoch (inclusive). Must be >= from_epoch.
    pub to_epoch: u64,
}

impl EpochCatchUpRequest {
    /// Create a new catch-up request.
    ///
    /// # Panics
    ///
    /// Panics in debug if `from_epoch > to_epoch` or either is 0.
    #[must_use]
    pub fn new(from_epoch: u64, to_epoch: u64) -> Self {
        debug_assert!(from_epoch > 0, "from_epoch must be > 0");
        debug_assert!(to_epoch >= from_epoch, "to_epoch must be >= from_epoch");
        Self {
            from_epoch,
            to_epoch,
        }
    }

    /// Number of epochs requested.
    #[must_use]
    pub fn requested_count(&self) -> u64 {
        self.to_epoch.saturating_sub(self.from_epoch) + 1
    }
}

// ── EpochCatchUpResponse ────────────────────────────────────────────

/// Response to an [`EpochCatchUpRequest`], carrying zero or more
/// [`CommittedEpochView`] entries.
///
/// The `truncated` flag is set when the responder's chain no longer
/// reaches the requested `from_epoch`. The caller should inspect
/// `truncated` and the last received epoch to decide whether to issue
/// a continuation request or accept the partial catch-up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCatchUpResponse {
    /// Batched committed epoch views, in ascending epoch-number order.
    pub epochs: Vec<CommittedEpochView>,
    /// True when the response is truncated and more epochs may exist
    /// before the first entry (responder's chain doesn't reach
    /// `from_epoch`), or when the response was bounded and more epochs
    /// exist after the last entry (responder has more epochs beyond
    /// the requested range).
    pub truncated: bool,
}

impl EpochCatchUpResponse {
    /// Create a new catch-up response.
    #[must_use]
    pub fn new(epochs: Vec<CommittedEpochView>, truncated: bool) -> Self {
        Self { epochs, truncated }
    }

    /// Number of epochs in the response.
    #[must_use]
    pub fn epoch_count(&self) -> usize {
        self.epochs.len()
    }

    /// Whether the response is empty (no epochs returned).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }

    /// The epoch number of the last entry, if any.
    #[must_use]
    pub fn last_epoch_number(&self) -> Option<u64> {
        self.epochs.last().map(|v| v.epoch_u64())
    }

    /// The epoch number of the first entry, if any.
    #[must_use]
    pub fn first_epoch_number(&self) -> Option<u64> {
        self.epochs.first().map(|v| v.epoch_u64())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CommittedEpochView ──────────────────────────────────────────

    #[test]
    fn committed_epoch_view_creation_sorts() {
        let view = CommittedEpochView::new(
            EpochId::new(5),
            vec![MemberId::new(3), MemberId::new(1), MemberId::new(2)],
            1000,
        );
        assert_eq!(view.epoch_u64(), 5);
        assert_eq!(
            view.member_set,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(view.member_count(), 3);
        assert_eq!(view.created_at_millis, 1000);
    }

    #[test]
    fn committed_epoch_view_dedup() {
        let view = CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(10), MemberId::new(10), MemberId::new(20)],
            0,
        );
        assert_eq!(view.member_count(), 2);
        assert_eq!(view.member_set, vec![MemberId::new(10), MemberId::new(20)]);
    }

    #[test]
    fn committed_epoch_view_contains() {
        let view =
            CommittedEpochView::new(EpochId::new(3), vec![MemberId::new(5), MemberId::new(7)], 0);
        assert!(view.contains(MemberId::new(5)));
        assert!(view.contains(MemberId::new(7)));
        assert!(!view.contains(MemberId::new(9)));
    }

    #[test]
    fn committed_epoch_view_empty() {
        let view = CommittedEpochView::new(EpochId::new(0), vec![], 0);
        assert_eq!(view.member_count(), 0);
        assert!(!view.contains(MemberId::new(1)));
    }

    // ── EpochCatchUpRequest ─────────────────────────────────────────

    #[test]
    fn catch_up_request_creation() {
        let req = EpochCatchUpRequest::new(1, 5);
        assert_eq!(req.from_epoch, 1);
        assert_eq!(req.to_epoch, 5);
        assert_eq!(req.requested_count(), 5);
    }

    #[test]
    fn catch_up_request_single_epoch() {
        let req = EpochCatchUpRequest::new(3, 3);
        assert_eq!(req.requested_count(), 1);
    }

    #[test]
    fn catch_up_request_range() {
        // from_epoch=2, to_epoch=2 -> 1 epoch
        let req = EpochCatchUpRequest::new(2, 2);
        assert_eq!(req.requested_count(), 1);

        // from_epoch=10, to_epoch=20 -> 11 epochs
        let req = EpochCatchUpRequest::new(10, 20);
        assert_eq!(req.requested_count(), 11);
    }

    // ── EpochCatchUpResponse ────────────────────────────────────────

    #[test]
    fn catch_up_response_non_truncated() {
        let epochs = vec![
            CommittedEpochView::new(
                EpochId::new(3),
                vec![MemberId::new(1), MemberId::new(2)],
                3000,
            ),
            CommittedEpochView::new(
                EpochId::new(4),
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                4000,
            ),
        ];
        let resp = EpochCatchUpResponse::new(epochs, false);
        assert_eq!(resp.epoch_count(), 2);
        assert!(!resp.is_empty());
        assert!(!resp.truncated);
        assert_eq!(resp.first_epoch_number(), Some(3));
        assert_eq!(resp.last_epoch_number(), Some(4));
    }

    #[test]
    fn catch_up_response_truncated() {
        let resp = EpochCatchUpResponse::new(vec![], true);
        assert!(resp.is_empty());
        assert!(resp.truncated);
        assert_eq!(resp.first_epoch_number(), None);
        assert_eq!(resp.last_epoch_number(), None);
    }

    #[test]
    fn catch_up_response_empty_non_truncated() {
        let resp = EpochCatchUpResponse::new(vec![], false);
        assert!(resp.is_empty());
        assert!(!resp.truncated);
    }

    // ── Round-trip encode/decode (bincode) ──────────────────────────

    #[test]
    fn catch_up_request_bincode_roundtrip() {
        let req = EpochCatchUpRequest::new(5, 10);
        let encoded = bincode::serialize(&req).expect("serialize");
        let decoded: EpochCatchUpRequest = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.from_epoch, 5);
        assert_eq!(decoded.to_epoch, 10);
        assert_eq!(decoded.requested_count(), 6);
    }

    #[test]
    fn catch_up_response_bincode_roundtrip() {
        let epochs = vec![
            CommittedEpochView::new(EpochId::new(7), vec![MemberId::new(1)], 7000),
            CommittedEpochView::new(
                EpochId::new(8),
                vec![MemberId::new(1), MemberId::new(2)],
                8000,
            ),
        ];
        let resp = EpochCatchUpResponse::new(epochs, false);
        let encoded = bincode::serialize(&resp).expect("serialize");
        let decoded: EpochCatchUpResponse = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.epoch_count(), 2);
        assert!(!decoded.truncated);
        assert_eq!(decoded.first_epoch_number(), Some(7));
        assert_eq!(decoded.last_epoch_number(), Some(8));
        assert_eq!(decoded.epochs[0].member_set, vec![MemberId::new(1)]);
        assert_eq!(
            decoded.epochs[1].member_set,
            vec![MemberId::new(1), MemberId::new(2)]
        );
    }

    #[test]
    fn catch_up_response_truncated_bincode_roundtrip() {
        let resp = EpochCatchUpResponse::new(vec![], true);
        let encoded = bincode::serialize(&resp).expect("serialize");
        let decoded: EpochCatchUpResponse = bincode::deserialize(&encoded).expect("deserialize");
        assert!(decoded.is_empty());
        assert!(decoded.truncated);
    }

    #[test]
    fn committed_epoch_view_bincode_roundtrip() {
        let view = CommittedEpochView::new(
            EpochId::new(42),
            vec![MemberId::new(3), MemberId::new(1), MemberId::new(2)],
            999_000,
        );
        let encoded = bincode::serialize(&view).expect("serialize");
        let decoded: CommittedEpochView = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.epoch_u64(), 42);
        // Member set should be sorted after creation
        assert_eq!(
            decoded.member_set,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(decoded.created_at_millis, 999_000);
    }

    // ── Clone / Eq ──────────────────────────────────────────────────

    #[test]
    fn catch_up_request_clone_eq() {
        let req = EpochCatchUpRequest::new(1, 2);
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn catch_up_response_clone_eq() {
        let resp = EpochCatchUpResponse::new(
            vec![CommittedEpochView::new(
                EpochId::new(1),
                vec![MemberId::new(1)],
                100,
            )],
            false,
        );
        let cloned = resp.clone();
        assert_eq!(resp, cloned);
    }

    #[test]
    fn committed_epoch_view_clone_eq() {
        let view = CommittedEpochView::new(EpochId::new(1), vec![MemberId::new(1)], 100);
        let cloned = view.clone();
        assert_eq!(view, cloned);
    }
}
