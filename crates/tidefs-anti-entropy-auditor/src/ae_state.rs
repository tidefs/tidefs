// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Anti-entropy auditor state machine — source-owned data_copy_8.
//!
//! The anti-entropy lifecycle has six states:
//!   idle → enumerating → compare → divergence_found → ticketed → resolved
//!
//! This is the bridge between replica health tracking (which detects
//! lag/degradation) and the rebuild/transfer machinery (which fixes it).
//! Without this state machine, replica health signals have no automated
//! follow-through.

use serde::{Deserialize, Serialize};
use tidefs_checksum_tree::Digest;

/// The six states of the anti-entropy lifecycle.
///
/// Each state carries epoch/timestamp data so the auditor can resume
/// after restart and reason about staleness.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum AntiEntropyState {
    /// Waiting for next scan window or trigger.
    Idle {
        last_scan_completed_ns: u64,
        next_scan_eligible_ns: u64,
    },

    /// Building candidate chunk/object/replica scope for comparison.
    Enumerating {
        started_at_ns: u64,
        /// Number of subjects in the enumeration scope.
        subjects_in_scope: u64,
        /// Frontier high-water mark (subject id last scanned).
        frontier_mark: u64,
    },

    /// Comparing digest, witness, or merkle frontier across replicas.
    Compare {
        started_at_ns: u64,
        /// How many comparisons have been performed so far.
        comparisons_done: u64,
        /// Total comparisons scheduled in this batch.
        comparisons_total: u64,
        /// Number of divergences found so far.
        divergences_found: u64,
    },

    /// Divergence detected — classify as lag, corruption, or missing.
    DivergenceFound {
        detected_at_ns: u64,
        /// Total divergences found in this scan cycle.
        total_divergences: u64,
        /// Classified as lag (behind frontier, not corrupt).
        classified_lag: u64,
        /// Classified as corruption (digest mismatch).
        classified_corruption: u64,
        /// Classified as missing (no replica at expected location).
        classified_missing: u64,
        /// Classified as witness disagreement needing authority selection.
        classified_witness_disagreement: u64,
    },

    /// Repair/replication/rebuild tickets created for divergent chunks.
    Ticketed {
        created_at_ns: u64,
        /// How many tickets were created.
        tickets_created: u64,
        /// Ticket ids emitted (first, last).
        ticket_range_start: u64,
        ticket_range_end: u64,
    },

    /// Tickets consumed, verification receipts emitted, divergence closed.
    Resolved {
        resolved_at_ns: u64,
        /// How many divergences were resolved in this cycle.
        divergences_resolved: u64,
        /// Receipt ids confirming resolution (first, last).
        receipt_range_start: u64,
        receipt_range_end: u64,
    },
}

impl AntiEntropyState {
    /// Whether the auditor is in a terminal/resting state (can start new scan).
    #[must_use]
    pub fn is_resting(&self) -> bool {
        matches!(self, Self::Idle { .. } | Self::Resolved { .. })
    }

    /// Whether the auditor is actively scanning or comparing.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Enumerating { .. } | Self::Compare { .. })
    }

    /// Whether divergences were found and need resolution.
    #[must_use]
    pub fn has_divergences(&self) -> bool {
        matches!(
            self,
            Self::DivergenceFound { total_divergences, .. } if *total_divergences > 0
        ) || matches!(self, Self::Ticketed { tickets_created, .. } if *tickets_created > 0)
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle { .. } => "idle",
            Self::Enumerating { .. } => "enumerating",
            Self::Compare { .. } => "compare",
            Self::DivergenceFound { .. } => "divergence_found",
            Self::Ticketed { .. } => "ticketed",
            Self::Resolved { .. } => "resolved",
        }
    }
}

impl std::fmt::Display for AntiEntropyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Classification of a divergence found during anti-entropy comparison.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceClass {
    /// Replica is behind the primary's frontier (lag, not corruption).
    LagBehind,
    /// Digest mismatch — replica has corrupt or wrong data.
    DigestMismatch,
    /// No replica found at expected placement.
    MissingReplica,
    /// Replica exists but is in a degraded/unreachable state.
    ReplicaUnhealthy,
    /// Witness digest disagrees with both primary and replica.
    WitnessDisagreement,
}

/// A single divergence record produced by the comparator.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DivergenceRecord {
    /// The subject (chunk/object) that diverged.
    pub subject_ref: u64,
    /// The replica node where divergence was detected.
    pub target_node: u64,
    /// Classification of the divergence.
    pub class: DivergenceClass,
    /// Primary's digest at scan time.
    pub expected_digest: u64,
    /// Replica's digest at scan time (0 if missing).
    pub actual_digest: u64,
    /// Full expected digest when the evidence source provides one.
    pub expected_hash: Option<Digest>,
    /// Full actual digest when the evidence source provides one.
    pub actual_hash: Option<Digest>,
    /// Epoch when the divergence was detected.
    pub epoch: u64,
    /// When the divergence was detected.
    pub detected_at_ns: u64,
}

impl DivergenceRecord {
    #[must_use]
    pub fn new(
        subject_ref: u64,
        target_node: u64,
        class: DivergenceClass,
        expected_digest: u64,
        actual_digest: u64,
        epoch: u64,
        detected_at_ns: u64,
    ) -> Self {
        DivergenceRecord {
            subject_ref,
            target_node,
            class,
            expected_digest,
            actual_digest,
            expected_hash: None,
            actual_hash: None,
            epoch,
            detected_at_ns,
        }
    }

    #[must_use]
    pub fn new_with_hashes(
        subject_ref: u64,
        target_node: u64,
        class: DivergenceClass,
        expected_hash: Digest,
        actual_hash: Digest,
        epoch: u64,
        detected_at_ns: u64,
    ) -> Self {
        DivergenceRecord {
            subject_ref,
            target_node,
            class,
            expected_digest: digest_prefix_u64(&expected_hash),
            actual_digest: digest_prefix_u64(&actual_hash),
            expected_hash: Some(expected_hash),
            actual_hash: Some(actual_hash),
            epoch,
            detected_at_ns,
        }
    }

    /// Whether this divergence requires a repair ticket.
    #[must_use]
    pub fn requires_ticket(&self) -> bool {
        matches!(
            self.class,
            DivergenceClass::DigestMismatch
                | DivergenceClass::MissingReplica
                | DivergenceClass::ReplicaUnhealthy
        )
    }

    /// Whether this divergence is just lag (can self-heal if replica catches up).
    #[must_use]
    pub fn is_lag_only(&self) -> bool {
        matches!(self.class, DivergenceClass::LagBehind)
    }

    /// Whether this divergence needs an explicit witness-authority decision.
    #[must_use]
    pub fn is_witness_disagreement(&self) -> bool {
        matches!(self.class, DivergenceClass::WitnessDisagreement)
    }
}

// ── Repair-trigger receipt ───────────────────────────────────────────

/// Durable repair-trigger receipt emitted for ticketable divergences.
///
/// A `RepairTriggerReceipt` is the authority boundary between divergence
/// detection and repair admission. It carries complete evidence so repair
/// scheduling, scrub integration, and later observability can prove why a
/// repair was admitted.  Only ticketable divergence classes produce
/// receipts; lag-only and witness-disagreement records are kept separate
/// from repair admission.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RepairTriggerReceipt {
    /// Subject (chunk/object) id.
    pub subject_ref: u64,
    /// Target node where the divergence was detected.
    pub target_node: u64,
    /// Divergence class — always ticketable (DigestMismatch, MissingReplica,
    /// or ReplicaUnhealthy).
    pub divergence_class: DivergenceClass,
    /// Expected digest prefix.
    pub expected_digest: u64,
    /// Actual (divergent) digest prefix.
    pub actual_digest: u64,
    /// Full expected digest if available.
    pub expected_hash: Option<Digest>,
    /// Full actual digest if available.
    pub actual_hash: Option<Digest>,
    /// Epoch in which the divergence was detected.
    pub epoch: u64,
    /// Monotonic nanosecond timestamp of detection.
    pub detected_at_ns: u64,
    /// Human-readable trigger reason.
    pub trigger_reason: String,
}

impl RepairTriggerReceipt {
    /// Create a receipt from a divergence record.
    ///
    /// Returns `None` for non-ticketable classes (lag-only, witness
    /// disagreement) so callers never accidentally emit repair receipts
    /// for those classes.
    #[must_use]
    pub fn from_divergence(rec: &DivergenceRecord, reason: &str) -> Option<Self> {
        if !rec.requires_ticket() {
            return None;
        }
        Some(RepairTriggerReceipt {
            subject_ref: rec.subject_ref,
            target_node: rec.target_node,
            divergence_class: rec.class,
            expected_digest: rec.expected_digest,
            actual_digest: rec.actual_digest,
            expected_hash: rec.expected_hash,
            actual_hash: rec.actual_hash,
            epoch: rec.epoch,
            detected_at_ns: rec.detected_at_ns,
            trigger_reason: reason.to_string(),
        })
    }

    /// Whether this receipt carries full hash evidence.
    #[must_use]
    pub fn has_full_hashes(&self) -> bool {
        self.expected_hash.is_some() && self.actual_hash.is_some()
    }
}

fn digest_prefix_u64(digest: &Digest) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_labels() {
        assert_eq!(
            AntiEntropyState::Idle {
                last_scan_completed_ns: 0,
                next_scan_eligible_ns: 0
            }
            .label(),
            "idle"
        );
        assert_eq!(
            AntiEntropyState::Enumerating {
                started_at_ns: 1000,
                subjects_in_scope: 100,
                frontier_mark: 0
            }
            .label(),
            "enumerating"
        );
        assert_eq!(
            AntiEntropyState::Compare {
                started_at_ns: 2000,
                comparisons_done: 50,
                comparisons_total: 100,
                divergences_found: 3
            }
            .label(),
            "compare"
        );
    }

    #[test]
    fn resting_states() {
        assert!(AntiEntropyState::Idle {
            last_scan_completed_ns: 0,
            next_scan_eligible_ns: 0
        }
        .is_resting());
        assert!(AntiEntropyState::Resolved {
            resolved_at_ns: 5000,
            divergences_resolved: 10,
            receipt_range_start: 1,
            receipt_range_end: 10
        }
        .is_resting());
        assert!(!AntiEntropyState::Enumerating {
            started_at_ns: 1000,
            subjects_in_scope: 100,
            frontier_mark: 0
        }
        .is_resting());
    }

    #[test]
    fn divergence_classification() {
        let lag = DivergenceRecord::new(1, 2, DivergenceClass::LagBehind, 100, 90, 1, 1000);
        assert!(!lag.requires_ticket());
        assert!(lag.is_lag_only());

        let corrupt =
            DivergenceRecord::new(2, 3, DivergenceClass::DigestMismatch, 200, 199, 1, 1000);
        assert!(corrupt.requires_ticket());
        assert!(!corrupt.is_lag_only());

        let missing = DivergenceRecord::new(3, 4, DivergenceClass::MissingReplica, 300, 0, 1, 1000);
        assert!(missing.requires_ticket());

        let witness =
            DivergenceRecord::new(4, 5, DivergenceClass::WitnessDisagreement, 10, 11, 1, 1000);
        assert!(!witness.requires_ticket());
        assert!(!witness.is_lag_only());
        assert!(witness.is_witness_disagreement());
    }

    #[test]
    fn divergence_records_can_carry_full_hashes() {
        let mut expected = [0u8; 32];
        expected[0] = 9;
        let mut actual = [0u8; 32];
        actual[0] = 7;

        let record = DivergenceRecord::new_with_hashes(
            1,
            2,
            DivergenceClass::DigestMismatch,
            expected,
            actual,
            3,
            4,
        );

        assert_eq!(record.expected_hash, Some(expected));
        assert_eq!(record.actual_hash, Some(actual));
        assert_eq!(record.expected_digest, 9);
        assert_eq!(record.actual_digest, 7);
    }
    // ── RepairTriggerReceipt tests ─────────────────────────────────

    #[test]
    fn receipt_from_ticketable_divergence() {
        let rec = DivergenceRecord::new(
            42,
            3,
            DivergenceClass::DigestMismatch,
            0xAAAA,
            0xBBBB,
            7,
            9_000_000,
        );
        let receipt = RepairTriggerReceipt::from_divergence(&rec, "test");
        assert!(receipt.is_some());
        let r = receipt.unwrap();
        assert_eq!(r.subject_ref, 42);
        assert_eq!(r.target_node, 3);
        assert_eq!(r.divergence_class, DivergenceClass::DigestMismatch);
        assert_eq!(r.expected_digest, 0xAAAA);
        assert_eq!(r.actual_digest, 0xBBBB);
        assert_eq!(r.epoch, 7);
        assert_eq!(r.detected_at_ns, 9_000_000);
        assert_eq!(r.trigger_reason, "test");
    }

    #[test]
    fn receipt_rejected_for_lag_only() {
        let rec = DivergenceRecord::new(1, 2, DivergenceClass::LagBehind, 100, 90, 1, 1000);
        assert!(RepairTriggerReceipt::from_divergence(&rec, "test").is_none());
    }

    #[test]
    fn receipt_rejected_for_witness_disagreement() {
        let rec = DivergenceRecord::new(
            1,
            2,
            DivergenceClass::WitnessDisagreement,
            100,
            200,
            1,
            1000,
        );
        assert!(RepairTriggerReceipt::from_divergence(&rec, "test").is_none());
    }

    #[test]
    fn receipt_from_missing_replica() {
        let rec = DivergenceRecord::new(5, 1, DivergenceClass::MissingReplica, 0xDEAD, 0, 1, 1000);
        assert!(RepairTriggerReceipt::from_divergence(&rec, "missing").is_some());
    }
}
