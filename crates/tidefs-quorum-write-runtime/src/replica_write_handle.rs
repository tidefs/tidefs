#![forbid(unsafe_code)]

//! ReplicaWriteHandle: per-replica write tracking with send timestamp,
//! ack status, BLAKE3 checksum verification, and latency measurement.

use std::time::{Duration, Instant};
use tidefs_quorum_write::NodeId;

/// Per-replica state machine for a single quorum write dispatch.
///
/// Created when the leader fans out a write to a specific replica.
/// Tracks the send timestamp, whether an ack was received, whether
/// the replica's BLAKE3 checksum matched the expected payload hash,
/// and the round-trip latency.
///
/// The handle is consumed by the `QuorumAckCollector` when the
/// replica responds, or left open when the replica is silent.
#[derive(Clone, Debug)]
pub struct ReplicaWriteHandle {
    /// Target replica node id.
    pub replica_id: NodeId,

    /// Wall-clock instant when the write was dispatched to this replica.
    pub send_timestamp: Instant,

    /// Whether the replica has acknowledged the write.
    pub ack_received: bool,

    /// Whether the replica's BLAKE3 checksum matched the expected hash.
    /// Only meaningful when `ack_received` is true.
    pub checksum_match: bool,

    /// Round-trip latency from dispatch to ack receipt.
    /// `None` until an ack is received.
    pub latency: Option<Duration>,
}

impl ReplicaWriteHandle {
    /// Create a new handle for a replica that has just been dispatched.
    #[must_use]
    pub fn new(replica_id: NodeId) -> Self {
        Self {
            replica_id,
            send_timestamp: Instant::now(),
            ack_received: false,
            checksum_match: false,
            latency: None,
        }
    }

    /// Mark this replica as having acknowledged with checksum verification.
    ///
    /// Sets `ack_received = true`, records `checksum_match` from the
    /// caller's BLAKE3 comparison, and captures the latency from
    /// `send_timestamp` to now.
    pub fn record_ack(&mut self, checksum_match: bool) {
        self.ack_received = true;
        self.checksum_match = checksum_match;
        self.latency = Some(self.send_timestamp.elapsed());
    }

    /// Whether the replica has responded (ack or failure).
    #[must_use]
    pub fn has_responded(&self) -> bool {
        self.ack_received
    }

    /// Elapsed time since dispatch, even if no ack yet.
    #[must_use]
    pub fn elapsed_since_send(&self) -> Duration {
        self.send_timestamp.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handle_defaults() {
        let h = ReplicaWriteHandle::new(NodeId::new(1));
        assert_eq!(h.replica_id, NodeId::new(1));
        assert!(!h.ack_received);
        assert!(!h.checksum_match);
        assert!(h.latency.is_none());
        assert!(!h.has_responded());
    }

    #[test]
    fn record_ack_with_matching_checksum() {
        let mut h = ReplicaWriteHandle::new(NodeId::new(2));
        h.record_ack(true);
        assert!(h.ack_received);
        assert!(h.checksum_match);
        assert!(h.latency.is_some());
        assert!(h.has_responded());
    }

    #[test]
    fn record_ack_with_mismatched_checksum() {
        let mut h = ReplicaWriteHandle::new(NodeId::new(3));
        h.record_ack(false);
        assert!(h.ack_received);
        assert!(!h.checksum_match);
        assert!(h.latency.is_some());
    }

    #[test]
    fn elapsed_increases_over_time() {
        let h = ReplicaWriteHandle::new(NodeId::new(4));
        let e1 = h.elapsed_since_send();
        std::thread::sleep(Duration::from_millis(1));
        let e2 = h.elapsed_since_send();
        assert!(e2 >= e1);
    }

    #[test]
    fn clone_preserves_state() {
        let mut h = ReplicaWriteHandle::new(NodeId::new(5));
        h.record_ack(true);
        let h2 = h.clone();
        assert_eq!(h2.replica_id, NodeId::new(5));
        assert!(h2.ack_received);
        assert!(h2.checksum_match);
    }
}
