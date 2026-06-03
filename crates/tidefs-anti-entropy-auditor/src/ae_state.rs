//! Anti-entropy auditor state machine — P8-03 data_copy_8.
//!
//! The anti-entropy lifecycle has six states:
//!   idle → enumerating → compare → divergence_found → ticketed → resolved
//!
//! This is the bridge between replica health tracking (which detects
//! lag/degradation) and the rebuild/transfer machinery (which fixes it).
//! Without this state machine, replica health signals have no automated
//! follow-through.

use serde::{Deserialize, Serialize};

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
    }
}
