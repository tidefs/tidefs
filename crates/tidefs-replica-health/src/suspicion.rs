//! Suspicion escalation levels for failure detection.
//!
//! Unlike Ceph's binary up/down or MongoDB's binary PRIMARY/SECONDARY,
//! TideFS uses five suspicion levels that escalate based on observed
//! behavior. This provides nuanced failure detection that avoids the
//! false-positive cascade of binary failure detectors.
//!
//! Comparison to existing systems:
//! - Ceph: binary up/down based on static timeouts → false positives
//!   during network jitter
//! - etcd: Raft election timeout → false leader elections under load
//! - Cassandra: phi accrual → node-scoped only, no data-health
//!   distinction
//! - TideFS: 5-level escalation with peer consensus and adaptive
//!   timeouts → graceful degradation instead of binary collapse

// HlcValue is not used directly; timestamps are u64 ns counters.

/// Five-level suspicion escalation for failure detection.
///
/// Each level has different operational consequences:
/// - Healthy → normal operation, all reads/writes accepted
/// - Sluggish → still usable, but lag is accumulating
/// - Suspect → gather peer input before trusting
/// - Degraded → don't admit new transfers, prefer healthy replicas
/// - Down → rebuild from remaining replicas
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum SuspicionLevel {
    /// No suspicion — replica is operating normally.
    Healthy = 0,

    /// Replica is slightly behind or showing elevated latency.
    /// Still usable for reads/writes but flagged for monitoring.
    Sluggish = 1,

    /// Suspicion threshold crossed — replica may be compromised.
    /// Peers are queried for consensus before downgrading further.
    Suspect = 2,

    /// Multiple peers confirm the replica is unhealthy.
    /// New transfers are not admitted; existing reads prefer
    /// healthy replicas.
    Degraded = 3,

    /// Replica is unreachable or confirmed dead.
    /// Rebuild is initiated from surviving replicas.
    Down = 4,
}

impl SuspicionLevel {
    /// Whether this level allows new transfers to be admitted.
    pub fn admits_transfers(&self) -> bool {
        matches!(self, SuspicionLevel::Healthy | SuspicionLevel::Sluggish)
    }

    /// Whether reads should prefer this replica.
    pub fn preferred_for_reads(&self) -> bool {
        matches!(self, SuspicionLevel::Healthy)
    }

    /// Whether the replica is considered alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self, SuspicionLevel::Down)
    }

    /// Escalate: move to the next-higher suspicion level.
    /// Does not escalate past Down.
    pub fn escalate(&self) -> SuspicionLevel {
        match self {
            SuspicionLevel::Healthy => SuspicionLevel::Sluggish,
            SuspicionLevel::Sluggish => SuspicionLevel::Suspect,
            SuspicionLevel::Suspect => SuspicionLevel::Degraded,
            SuspicionLevel::Degraded => SuspicionLevel::Down,
            SuspicionLevel::Down => SuspicionLevel::Down,
        }
    }

    /// De-escalate: move to the next-lower suspicion level.
    /// Does not de-escalate below Healthy.
    pub fn de_escalate(&self) -> SuspicionLevel {
        match self {
            SuspicionLevel::Down => SuspicionLevel::Degraded,
            SuspicionLevel::Degraded => SuspicionLevel::Suspect,
            SuspicionLevel::Suspect => SuspicionLevel::Sluggish,
            SuspicionLevel::Sluggish => SuspicionLevel::Healthy,
            SuspicionLevel::Healthy => SuspicionLevel::Healthy,
        }
    }

    /// Whether this level is at least as severe as the given level.
    pub fn is_at_least(&self, level: SuspicionLevel) -> bool {
        *self >= level
    }
}

/// Visibility class for charter adapter consumption.
///
/// Charter adapters (FUSE, block volume) use this to decide how to
/// serve reads: serve directly, serve with stale flag, or refuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VisibilityClass {
    /// Data is current — serve directly.
    Exact,

    /// Data is slightly behind but valid — serve with stale hint.
    BoundedLag,

    /// Data may be valid but replica is significantly behind —
    /// serve degraded, trigger background repair.
    DegradedButValid,

    /// Freshness fence has expired — data cannot be served.
    /// Return ESTALE.
    BlockedByFence,

    /// Replica is missing chunks — repair is required before
    /// this data can be served.
    RepairRequired,
}

/// A single peer observation of a replica's health.
///
/// Used for peer consensus: multiple nodes report their view of a
/// replica, and the health tracker aggregates them to determine the
/// consensus suspicion level.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerHealthObservation {
    /// Which node made this observation.
    pub observer_node: u64,
    /// The observed suspicion level.
    pub suspicion: SuspicionLevel,
    /// When the observation was made.
    pub observed_at_ns: u64,
    /// Optional detail about why this level was assigned.
    pub reason: Option<String>,
}

impl PeerHealthObservation {
    pub fn new(observer_node: u64, suspicion: SuspicionLevel, observed_at_ns: u64) -> Self {
        PeerHealthObservation {
            observer_node,
            suspicion,
            observed_at_ns,
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_chain() {
        let mut level = SuspicionLevel::Healthy;
        level = level.escalate();
        assert_eq!(level, SuspicionLevel::Sluggish);
        level = level.escalate();
        assert_eq!(level, SuspicionLevel::Suspect);
        level = level.escalate();
        assert_eq!(level, SuspicionLevel::Degraded);
        level = level.escalate();
        assert_eq!(level, SuspicionLevel::Down);
        level = level.escalate();
        assert_eq!(level, SuspicionLevel::Down); // stays at Down
    }

    #[test]
    fn de_escalation_chain() {
        let mut level = SuspicionLevel::Down;
        level = level.de_escalate();
        assert_eq!(level, SuspicionLevel::Degraded);
        level = level.de_escalate();
        assert_eq!(level, SuspicionLevel::Suspect);
        level = level.de_escalate();
        assert_eq!(level, SuspicionLevel::Sluggish);
        level = level.de_escalate();
        assert_eq!(level, SuspicionLevel::Healthy);
        level = level.de_escalate();
        assert_eq!(level, SuspicionLevel::Healthy); // stays at Healthy
    }

    #[test]
    fn healthy_admits_transfers() {
        assert!(SuspicionLevel::Healthy.admits_transfers());
        assert!(SuspicionLevel::Sluggish.admits_transfers());
        assert!(!SuspicionLevel::Suspect.admits_transfers());
        assert!(!SuspicionLevel::Degraded.admits_transfers());
        assert!(!SuspicionLevel::Down.admits_transfers());
    }
}
