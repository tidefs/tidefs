#![forbid(unsafe_code)]

//! QuorumDecision: terminal outcome of a quorum write attempt.
//!
//! Mirrors the three canonical outcomes: quorum satisfied (enough
//! replicas acknowledged with matching checksums), quorum failed
//! (some replicas explicitly refused or checksums mismatched), and
//! quorum timed out (deadline expired before threshold was met).

use tidefs_quorum_write::NodeId;

/// Terminal decision for a quorum write submitted to the runtime.
///
/// Returned by `QuorumWriteRuntime::submit()` after ack collection
/// completes or the total timeout expires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumDecision {
    /// Enough replicas (at least `quorum_threshold`) acknowledged
    /// with matching BLAKE3 checksums.  The write is durable.
    QuorumSatisfied {
        ack_count: usize,
        quorum_threshold: usize,
    },

    /// The write failed because replicas explicitly refused or
    /// checksum mismatches made quorum mathematically impossible.
    QuorumFailed {
        acks: usize,
        required: usize,
        failures: Vec<NodeId>,
    },

    /// The total deadline expired before the quorum threshold was met.
    QuorumTimedOut { acks: usize, required: usize },
}

impl QuorumDecision {
    /// Whether this decision represents a successful durable write.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::QuorumSatisfied { .. })
    }

    /// Whether the write failed (refused or timed out).
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        !self.is_success()
    }

    /// Number of acknowledgements collected, regardless of outcome.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        match self {
            Self::QuorumSatisfied { ack_count, .. }
            | Self::QuorumFailed {
                acks: ack_count, ..
            }
            | Self::QuorumTimedOut {
                acks: ack_count, ..
            } => *ack_count,
        }
    }

    /// Number of acks required for quorum.
    #[must_use]
    pub fn required(&self) -> usize {
        match self {
            Self::QuorumSatisfied {
                quorum_threshold, ..
            } => *quorum_threshold,
            Self::QuorumFailed { required, .. } | Self::QuorumTimedOut { required, .. } => {
                *required
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfied_is_success() {
        let d = QuorumDecision::QuorumSatisfied {
            ack_count: 2,
            quorum_threshold: 2,
        };
        assert!(d.is_success());
        assert!(!d.is_failure());
        assert_eq!(d.ack_count(), 2);
        assert_eq!(d.required(), 2);
    }

    #[test]
    fn failed_is_not_success() {
        let d = QuorumDecision::QuorumFailed {
            acks: 1,
            required: 2,
            failures: vec![NodeId::new(3)],
        };
        assert!(!d.is_success());
        assert!(d.is_failure());
        assert_eq!(d.ack_count(), 1);
        assert_eq!(d.required(), 2);
    }

    #[test]
    fn timed_out_is_not_success() {
        let d = QuorumDecision::QuorumTimedOut {
            acks: 1,
            required: 3,
        };
        assert!(!d.is_success());
        assert!(d.is_failure());
        assert_eq!(d.ack_count(), 1);
        assert_eq!(d.required(), 3);
    }

    #[test]
    fn clone_and_eq() {
        let a = QuorumDecision::QuorumSatisfied {
            ack_count: 3,
            quorum_threshold: 3,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
