// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Committed evacuation receipt for drain completion gating.
//!
//! [`EvacuationReceipt`] is a committed record proving that all placement
//! receipts that previously referenced a draining node have been relocated
//! to committed receipts on other cluster members.  Node drain must gate on
//! committed placement receipt evidence that no live extent references the
//! draining node and that all data has been relocated to committed receipts
//! on other members.
//!
//! The receipt is BLAKE3-domain-separated (domain:
//! `tidefs-membership-drain-evacuation-receipt-v1`) so that a verifier can
//! independently confirm the receipt was produced by an honest drain
//! executor and not tampered with.

use serde::{Deserialize, Serialize};
use std::fmt;

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::ReplicatedReceiptId;

// ---------------------------------------------------------------------------
// EvacuationReceipt
// ---------------------------------------------------------------------------

/// A committed evacuation receipt that references the full set of placement
/// receipts that relocated data off the draining node.
///
/// This receipt is the authoritative evidence that no live extent still
/// references the draining node.  Drain phase advancement from data to cache,
/// and decommission itself, both require a committed evacuation receipt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvacuationReceipt {
    /// Unique identifier for this evacuation receipt.
    pub receipt_id: EvacuationReceiptId,
    /// The node that is being drained.
    pub draining_node: MemberId,
    /// The epoch at which this evacuation was initiated.
    pub epoch: EpochId,
    /// The epoch boundary committed after drain completion.
    pub committed_epoch_boundary: Option<EpochId>,
    /// The full set of placement receipt ids that relocated data off the
    /// draining node.  Every extent that was previously on this node must
    /// have a corresponding committed placement receipt on another member
    /// listed here.
    pub placement_receipt_refs: Vec<ReplicatedReceiptId>,
    /// Total number of subjects relocated.
    pub subjects_relocated: u64,
    /// Whether every referenced placement receipt is committed.
    pub all_committed: bool,
    /// Human-readable reason for the drain.
    pub reason: String,
}

/// Opaque receipt identifier.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct EvacuationReceiptId(pub u64);

impl EvacuationReceiptId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl Default for EvacuationReceiptId {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for EvacuationReceiptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evac-receipt-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// EvacuationReceipt construction and verification
// ---------------------------------------------------------------------------

impl EvacuationReceipt {
    /// The BLAKE3 domain separator for evacuation receipt verification.
    pub const DOMAIN: &'static str = "tidefs-membership-drain-evacuation-receipt-v1";

    /// Create an empty evacuation receipt for a draining node.
    #[must_use]
    pub fn new(draining_node: MemberId, epoch: EpochId, reason: String) -> Self {
        Self {
            receipt_id: EvacuationReceiptId::ZERO,
            draining_node,
            epoch,
            committed_epoch_boundary: None,
            placement_receipt_refs: Vec::new(),
            subjects_relocated: 0,
            all_committed: true, // vacuously true when empty
            reason,
        }
    }

    /// Attach a receipt id to this evacuation receipt (used after
    /// persistence).
    #[must_use]
    pub fn with_id(mut self, id: EvacuationReceiptId) -> Self {
        self.receipt_id = id;
        self
    }

    /// Record placement receipt refs that relocated data off the draining
    /// node.
    pub fn record_relocated_receipts(
        &mut self,
        receipt_ids: impl IntoIterator<Item = ReplicatedReceiptId>,
    ) {
        for rid in receipt_ids {
            self.placement_receipt_refs.push(rid);
            self.subjects_relocated += 1;
        }
    }

    /// Mark the epoch boundary committed after drain completion.
    pub fn set_committed_epoch_boundary(&mut self, epoch: EpochId) {
        self.committed_epoch_boundary = Some(epoch);
    }

    /// Returns true if this receipt is empty (no relocated data).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.placement_receipt_refs.is_empty()
    }

    /// Returns true if all referenced placement receipts are considered
    /// committed.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.all_committed
    }

    /// Compute a BLAKE3 domain-separated digest for independent
    /// verification that this receipt was produced honestly.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(Self::DOMAIN);
        hasher.update(&self.draining_node.0.to_le_bytes());
        hasher.update(&self.epoch.0.to_le_bytes());
        for rid in &self.placement_receipt_refs {
            hasher.update(&rid.0.to_le_bytes());
        }
        hasher.update(&self.subjects_relocated.to_le_bytes());
        hasher.update(&[u8::from(self.all_committed)]);
        if let Some(eb) = self.committed_epoch_boundary {
            hasher.update(&eb.0.to_le_bytes());
        }
        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Verify that a stored digest matches a recomputed digest.
    #[must_use]
    pub fn verify_digest(&self, expected: &[u8; 32]) -> bool {
        let computed = self.compute_digest();
        // constant-time comparison
        let mut acc = 0u8;
        for i in 0..32 {
            acc |= computed[i] ^ expected[i];
        }
        acc == 0
    }

    /// Verify that no placement receipt in the evacuation receipt
    /// references the draining node.
    ///
    /// This is the critical safety property: if any receipt still
    /// references the draining node, the evacuation is incomplete.
    #[must_use]
    pub fn verify_no_self_references(
        &self,
        // closure: (receipt_id) -> Option<(placed_on, committed)>
        receipt_lookup: impl Fn(ReplicatedReceiptId) -> Option<(MemberId, bool)>,
    ) -> Result<(), EvacuationReceiptError> {
        for &rid in &self.placement_receipt_refs {
            if let Some((placed_on, committed)) = receipt_lookup(rid) {
                if placed_on == self.draining_node {
                    return Err(EvacuationReceiptError::SelfReferencingReceipt {
                        receipt_id: rid,
                        draining_node: self.draining_node,
                    });
                }
                if !committed {
                    return Err(EvacuationReceiptError::UncommittedReceipt { receipt_id: rid });
                }
            } else {
                return Err(EvacuationReceiptError::UnknownReceipt { receipt_id: rid });
            }
        }
        Ok(())
    }
}

impl fmt::Display for EvacuationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "evacuation receipt for node {} (epoch {}): {} subjects relocated, all_committed={}",
            self.draining_node.0, self.epoch.0, self.subjects_relocated, self.all_committed
        )
    }
}

// ---------------------------------------------------------------------------
// EvacuationReceiptError
// ---------------------------------------------------------------------------

/// Errors during evacuation receipt verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvacuationReceiptError {
    /// A placement receipt in the evacuation set still references the
    /// draining node.
    SelfReferencingReceipt {
        receipt_id: ReplicatedReceiptId,
        draining_node: MemberId,
    },
    /// A placement receipt in the evacuation set is not yet committed.
    UncommittedReceipt { receipt_id: ReplicatedReceiptId },
    /// A placement receipt referenced in the evacuation set is unknown.
    UnknownReceipt { receipt_id: ReplicatedReceiptId },
    /// The evacuation receipt has no placement receipts but drain
    /// expects data relocation.
    EmptyEvacuation { draining_node: MemberId },
    /// The epoch boundary has not been committed.
    EpochBoundaryNotCommitted { draining_node: MemberId },
}

impl fmt::Display for EvacuationReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfReferencingReceipt {
                receipt_id,
                draining_node,
            } => {
                write!(
                    f,
                    "placement receipt {} still references draining node {}",
                    receipt_id.0, draining_node.0,
                )
            }
            Self::UncommittedReceipt { receipt_id } => {
                write!(f, "placement receipt {} is not committed", receipt_id.0)
            }
            Self::UnknownReceipt { receipt_id } => {
                write!(f, "placement receipt {} is unknown", receipt_id.0)
            }
            Self::EmptyEvacuation { draining_node } => {
                write!(
                    f,
                    "evacuation receipt for node {} has no placement receipts",
                    draining_node.0,
                )
            }
            Self::EpochBoundaryNotCommitted { draining_node } => {
                write!(
                    f,
                    "epoch boundary not committed for node {} drain",
                    draining_node.0,
                )
            }
        }
    }
}

impl std::error::Error for EvacuationReceiptError {}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn rid(id: u64) -> ReplicatedReceiptId {
        ReplicatedReceiptId(id)
    }

    fn make_receipt(placed_on: MemberId, committed: bool) -> (MemberId, bool) {
        (placed_on, committed)
    }

    #[test]
    fn empty_evacuation_receipt_is_committed() {
        let receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        assert!(receipt.is_empty());
        assert!(receipt.is_committed());
        assert_eq!(receipt.subjects_relocated, 0);
    }

    #[test]
    fn evacuation_receipt_with_relocated_data() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(10), rid(20), rid(30)]);
        assert!(!receipt.is_empty());
        assert_eq!(receipt.subjects_relocated, 3);
        assert_eq!(receipt.placement_receipt_refs.len(), 3);
    }

    #[test]
    fn verify_no_self_references_ok() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(10), rid(20)]);
        receipt.all_committed = true;

        // All receipts placed on nodes != draining node (1)
        let lookup = |rid: ReplicatedReceiptId| -> Option<(MemberId, bool)> {
            match rid.0 {
                10 => Some(make_receipt(mid(2), true)),
                20 => Some(make_receipt(mid(3), true)),
                _ => None,
            }
        };
        assert!(receipt.verify_no_self_references(lookup).is_ok());
    }

    #[test]
    fn verify_no_self_references_fails_on_self_ref() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(10), rid(20)]);

        // rid(20) is still on draining node 1
        let lookup = |rid: ReplicatedReceiptId| -> Option<(MemberId, bool)> {
            match rid.0 {
                10 => Some(make_receipt(mid(2), true)),
                20 => Some(make_receipt(mid(1), true)), // self-ref!
                _ => None,
            }
        };
        let err = receipt.verify_no_self_references(lookup).unwrap_err();
        assert!(matches!(
            err,
            EvacuationReceiptError::SelfReferencingReceipt { .. }
        ));
    }

    #[test]
    fn verify_no_self_references_fails_on_uncommitted() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(10)]);

        let lookup = |rid: ReplicatedReceiptId| -> Option<(MemberId, bool)> {
            match rid.0 {
                10 => Some(make_receipt(mid(2), false)), // uncommitted!
                _ => None,
            }
        };
        let err = receipt.verify_no_self_references(lookup).unwrap_err();
        assert!(matches!(
            err,
            EvacuationReceiptError::UncommittedReceipt { .. }
        ));
    }

    #[test]
    fn verify_no_self_references_fails_on_unknown() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(99)]);

        let lookup = |_rid: ReplicatedReceiptId| -> Option<(MemberId, bool)> { None };
        let err = receipt.verify_no_self_references(lookup).unwrap_err();
        assert!(matches!(err, EvacuationReceiptError::UnknownReceipt { .. }));
    }

    #[test]
    fn digest_is_deterministic() {
        let mut receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        receipt.record_relocated_receipts(vec![rid(10), rid(20)]);
        receipt.set_committed_epoch_boundary(EpochId::new(6));

        let d1 = receipt.compute_digest();
        let d2 = receipt.compute_digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_differs_on_different_content() {
        let r1 = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        let r2 = EvacuationReceipt::new(mid(2), EpochId::new(5), "test".into());
        assert_ne!(r1.compute_digest(), r2.compute_digest());
    }

    #[test]
    fn verify_digest_roundtrip() {
        let receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into());
        let digest = receipt.compute_digest();
        assert!(receipt.verify_digest(&digest));

        let mut bad = digest;
        bad[0] ^= 0xFF;
        assert!(!receipt.verify_digest(&bad));
    }

    #[test]
    fn with_id_sets_receipt_id() {
        let receipt = EvacuationReceipt::new(mid(1), EpochId::new(5), "test".into())
            .with_id(EvacuationReceiptId::new(42));
        assert_eq!(receipt.receipt_id, EvacuationReceiptId::new(42));
    }

    #[test]
    fn display_includes_key_info() {
        let mut receipt = EvacuationReceipt::new(mid(7), EpochId::new(3), "maintenance".into());
        receipt.record_relocated_receipts(vec![rid(1), rid(2), rid(3)]);
        let s = format!("{receipt}");
        assert!(s.contains("node 7"));
        assert!(s.contains("epoch 3"));
        assert!(s.contains("3 subjects relocated"));
    }

    #[test]
    fn error_display_messages() {
        let err = EvacuationReceiptError::SelfReferencingReceipt {
            receipt_id: rid(42),
            draining_node: mid(7),
        };
        assert!(format!("{err}").contains("42"));
        assert!(format!("{err}").contains("7"));

        let err = EvacuationReceiptError::UncommittedReceipt {
            receipt_id: rid(99),
        };
        assert!(format!("{err}").contains("99"));
        assert!(format!("{err}").contains("not committed"));

        let err = EvacuationReceiptError::EpochBoundaryNotCommitted {
            draining_node: mid(3),
        };
        assert!(format!("{err}").contains("3"));
    }
}
