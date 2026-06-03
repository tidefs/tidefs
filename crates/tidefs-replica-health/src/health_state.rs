//! Per-chunk replica health state machine — P8-03 data_copy_3.
//!
//! Each chunk on each replica node has a health state. The state
//! transitions through a lifecycle from Absent through Healthy
//! to Retired, with intermediate degraded/suspect/rebuilding states.

use serde::{Deserialize, Serialize};

/// Health state for a single chunk on a single replica node.
///
/// Variants carry epoch/timestamp data so lag and suspicion
/// can be computed from state alone without external lookups.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ReplicaHealthState {
    /// Chunk has never been registered.
    Absent,

    /// Transfer ticket issued, not yet inflight.
    Ticketed { ticket_id: u64, ticketed_at_ns: u64 },

    /// Transfer is in progress.
    Inflight { ticket_id: u64, started_at_ns: u64 },

    /// Payload received but not yet verified.
    Received {
        receipt_id: u64,
        received_at_ns: u64,
    },

    /// Digest/witness/quorum verification passed.
    Verified {
        receipt_id: u64,
        verified_at_ns: u64,
    },

    /// Chunk is placed (initial registration).
    Placed { receipt_id: u64, placed_at_ns: u64 },

    /// All receipts current, fully verified and placed.
    Healthy {
        receipt_id: u64,
        last_verified_ns: u64,
    },

    /// Behind the freshness frontier — lag accumulating.
    Lagged {
        bytes_behind: u64,
        last_receipt_ns: u64,
        detected_at_ns: u64,
    },

    /// Suspicion threshold crossed — may transition to Degraded or back to Healthy.
    Suspect {
        bytes_behind: u64,
        suspect_since_ns: u64,
        consecutive_checks: u32,
    },

    /// Missing or corrupt chunks detected.
    Degraded {
        degraded_since_ns: u64,
        missing_chunks: u64,
        corrupt_chunks: u64,
    },

    /// Rebuild in progress.
    Rebuilding {
        rebuild_started_ns: u64,
        bytes_rebuilt: u64,
        bytes_total: u64,
    },

    /// Rebuild complete, receipt emitted.
    Recovered {
        recovered_at_ns: u64,
        rebuild_receipt_id: u64,
    },

    /// Flap detected — suppressed with exponential backoff.
    FlapSuppressed {
        suppressed_since_ns: u64,
        backoff_until_ns: u64,
    },

    /// Chunk retired from this node (decommission, relocation).
    Retired {
        retired_at_ns: u64,
        reason: RetireReason,
    },
}

/// Why a chunk was retired from tracking.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetireReason {
    /// Operator explicitly decommissioned the node.
    OperatorRetired,
    /// Relocation moved the chunk to a different node.
    Relocated,
    /// Chunk was deleted entirely.
    Deleted,
    /// Node was quarantined.
    Quarantined,
    /// Rebuild replaced this copy with a fresh one.
    Rebuilt,
}

impl ReplicaHealthState {
    /// Whether the chunk is in a healthy state (placed, verified, healthy, recovered).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(
            self,
            Self::Placed { .. }
                | Self::Healthy { .. }
                | Self::Verified { .. }
                | Self::Recovered { .. }
        )
    }

    /// Whether the chunk is degraded or worse.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        matches!(
            self,
            Self::Degraded { .. } | Self::Suspect { .. } | Self::Lagged { .. }
        )
    }

    /// Whether the chunk is currently rebuilding.
    #[must_use]
    pub fn is_rebuilding(&self) -> bool {
        matches!(self, Self::Rebuilding { .. })
    }

    /// Whether the chunk has been retired.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        matches!(self, Self::Retired { .. })
    }

    /// Whether reads can be served from this replica.
    #[must_use]
    pub fn can_serve_reads(&self) -> bool {
        matches!(
            self,
            Self::Placed { .. }
                | Self::Verified { .. }
                | Self::Healthy { .. }
                | Self::Recovered { .. }
                | Self::Lagged { .. }
        )
    }

    /// Whether new writes can be accepted.
    #[must_use]
    pub fn can_accept_writes(&self) -> bool {
        matches!(
            self,
            Self::Healthy { .. } | Self::Verified { .. } | Self::Placed { .. }
        )
    }

    /// Human-readable label for the state.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Ticketed { .. } => "ticketed",
            Self::Inflight { .. } => "inflight",
            Self::Received { .. } => "received",
            Self::Verified { .. } => "verified",
            Self::Placed { .. } => "placed",
            Self::Healthy { .. } => "healthy",
            Self::Lagged { .. } => "lagged",
            Self::Suspect { .. } => "suspect",
            Self::Degraded { .. } => "degraded",
            Self::Rebuilding { .. } => "rebuilding",
            Self::Recovered { .. } => "recovered",
            Self::FlapSuppressed { .. } => "flap_suppressed",
            Self::Retired { .. } => "retired",
        }
    }
}

impl std::fmt::Display for ReplicaHealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Classification of a health state transition.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthTransitionClass {
    Recovery,
    Degradation,
    Flapping,
    Administrative,
}

/// A recorded transition in the health state machine.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct HealthTransitionRecord {
    pub from_state: ReplicaHealthState,
    pub to_state: ReplicaHealthState,
    pub transition_class: HealthTransitionClass,
    pub epoch: u64,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_states() {
        assert!(ReplicaHealthState::Placed {
            receipt_id: 1,
            placed_at_ns: 1000
        }
        .is_healthy());
        assert!(ReplicaHealthState::Healthy {
            receipt_id: 1,
            last_verified_ns: 1000
        }
        .is_healthy());
        assert!(ReplicaHealthState::Verified {
            receipt_id: 1,
            verified_at_ns: 1000
        }
        .is_healthy());
        assert!(!ReplicaHealthState::Absent.is_healthy());
        assert!(!ReplicaHealthState::Lagged {
            bytes_behind: 100,
            last_receipt_ns: 2000,
            detected_at_ns: 2000
        }
        .is_healthy());
    }

    #[test]
    fn degraded_states() {
        assert!(ReplicaHealthState::Degraded {
            degraded_since_ns: 1000,
            missing_chunks: 1,
            corrupt_chunks: 0
        }
        .is_degraded());
        assert!(ReplicaHealthState::Suspect {
            bytes_behind: 5000,
            suspect_since_ns: 1000,
            consecutive_checks: 3
        }
        .is_degraded());
        assert!(!ReplicaHealthState::Healthy {
            receipt_id: 1,
            last_verified_ns: 1000
        }
        .is_degraded());
    }

    #[test]
    fn can_serve_reads() {
        assert!(ReplicaHealthState::Healthy {
            receipt_id: 1,
            last_verified_ns: 1000
        }
        .can_serve_reads());
        assert!(ReplicaHealthState::Lagged {
            bytes_behind: 100,
            last_receipt_ns: 1000,
            detected_at_ns: 1000
        }
        .can_serve_reads());
        assert!(!ReplicaHealthState::Degraded {
            degraded_since_ns: 1000,
            missing_chunks: 1,
            corrupt_chunks: 0
        }
        .can_serve_reads());
        assert!(!ReplicaHealthState::Absent.can_serve_reads());
    }

    #[test]
    fn can_accept_writes() {
        assert!(ReplicaHealthState::Healthy {
            receipt_id: 1,
            last_verified_ns: 1000
        }
        .can_accept_writes());
        assert!(!ReplicaHealthState::Lagged {
            bytes_behind: 100,
            last_receipt_ns: 1000,
            detected_at_ns: 1000
        }
        .can_accept_writes());
        assert!(!ReplicaHealthState::Degraded {
            degraded_since_ns: 1000,
            missing_chunks: 1,
            corrupt_chunks: 0
        }
        .can_accept_writes());
    }

    #[test]
    fn label_roundtrip() {
        assert_eq!(ReplicaHealthState::Absent.label(), "absent");
        assert_eq!(
            ReplicaHealthState::Healthy {
                receipt_id: 1,
                last_verified_ns: 1000
            }
            .label(),
            "healthy"
        );
        assert_eq!(
            ReplicaHealthState::Degraded {
                degraded_since_ns: 1000,
                missing_chunks: 1,
                corrupt_chunks: 0
            }
            .label(),
            "degraded"
        );
        assert_eq!(
            ReplicaHealthState::Retired {
                retired_at_ns: 1000,
                reason: RetireReason::Relocated
            }
            .label(),
            "retired"
        );
    }
}
