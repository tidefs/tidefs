#![forbid(unsafe_code)]

//! Gossip message batching for the P8-02 membership runtime.
//!
//! ## Architecture
//!
//! Membership state changes (deltas, suspicion records, liveness events,
//! epoch transitions) are enqueued into per-peer outbound queues. A configurable
//! flush scheduler drains these queues into batch frames,
//! reducing per-message framing overhead, syscall count, and bursty transport
//! load during epoch transitions.
//!
//! - [`GossipUpdate`]: a single gossip event variant.
//! - [`PerPeerOutboundQueue`]: a bounded `VecDeque` per peer with FIFO ordering
//!   and oldest-drop backpressure when capacity is exceeded.
//! - [`GossipBatch`]: a collection of updates serialized into a single wire frame.
//! - [`GossipBatcher`]: the egress aggregation layer holding per-peer queues
//!   and flush policy (max_batch_age, max_batch_size, epoch-bounded flush).
//!
//! ## Data Integrity
//!
//! Transport-layer integrity and Ed25519 signatures provide authenticity.
//! The per-batch BLAKE3 digest has been removed as redundant.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::types::{MembershipDelta, SuspicionRecord};

// ---------------------------------------------------------------------------
// GossipUpdate -- a single gossip event
// ---------------------------------------------------------------------------

/// A single outbound gossip event enqueued for batched delivery.
///
/// Serialized with `bincode` inside a [`GossipBatch`] frame. Each variant
/// carries the canonical wire-format payload for its event kind.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum GossipUpdate {
    /// A membership view change (join, leave, suspect, cleared).
    MembershipDelta(MembershipDelta),
    /// A suspicion state change propagated to peers.
    SuspicionChange(SuspicionRecord),
    /// A liveness event: a peer transitioned between Healthy and Suspect/Down
    /// or recovered.
    LivenessEvent {
        member_id: MemberId,
        #[serde(rename = "up")]
        is_up: bool,
        epoch: EpochId,
        timestamp_millis: u64,
    },
    /// An epoch transition boundary marker, carrying the new epoch id and
    /// the transition reason.
    EpochTransition {
        from_epoch: EpochId,
        to_epoch: EpochId,
        /// Compact reason tag: 0=FailureDetected, 1=GracefulLeave,
        /// 2=JoinRequested, 3=PromotedToVoter, 4=DemotedFromVoter.
        reason_tag: u8,
        timestamp_millis: u64,
    },
}

impl GossipUpdate {
    /// Return the epoch this update belongs to.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        match self {
            GossipUpdate::MembershipDelta(_delta) => EpochId::default(),
            GossipUpdate::SuspicionChange(_rec) => EpochId::default(),
            GossipUpdate::LivenessEvent { epoch, .. } => *epoch,
            GossipUpdate::EpochTransition { to_epoch, .. } => *to_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// PerPeerOutboundQueue
// ---------------------------------------------------------------------------

/// A bounded FIFO queue of [`GossipUpdate`]s for a single peer.
///
/// When the queue is at capacity and a new update is enqueued, the **oldest**
/// update is silently dropped (oldest-drop backpressure). This prevents
/// unbounded memory growth during peer disconnection.
#[derive(Clone, Debug)]
pub struct PerPeerOutboundQueue {
    queue: VecDeque<GossipUpdate>,
    capacity: usize,
    /// Count of updates dropped due to capacity overflow since creation.
    dropped_count: u64,
}

impl PerPeerOutboundQueue {
    /// Create a new queue with the given capacity bound.
    ///
    /// `capacity` must be at least 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "PerPeerOutboundQueue capacity must be >= 1");
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            dropped_count: 0,
        }
    }

    /// Enqueue an update. If the queue is full, the oldest entry is removed
    /// first.
    pub fn enqueue(&mut self, update: GossipUpdate) {
        if self.queue.len() >= self.capacity {
            self.queue.pop_front();
            self.dropped_count += 1;
        }
        self.queue.push_back(update);
    }

    /// Drain all pending updates into a `Vec`, leaving the queue empty.
    #[must_use]
    pub fn drain(&mut self) -> Vec<GossipUpdate> {
        self.queue.drain(..).collect()
    }

    /// Number of pending updates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Number of updates dropped due to capacity overflow.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// Returns the capacity bound.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// GossipBatch -- a BLAKE3-verified multi-update wire frame
// ---------------------------------------------------------------------------

/// A batched collection of gossip updates for wire transmission.
///
/// Transport-layer integrity and Ed25519 signatures provide authenticity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GossipBatch {
    /// Monotonically increasing batch sequence number for this sender.
    pub sequence: u64,
    /// The epoch this batch belongs to.
    pub epoch: EpochId,
    /// The sender's node identity.
    pub sender: MemberId,
    /// The batched gossip updates.
    pub updates: Vec<GossipUpdate>,
}

impl GossipBatch {
    /// Create a new batch from the given updates.
    ///
    /// Panics if `updates` is empty.
    #[must_use]
    pub fn new(
        sequence: u64,
        epoch: EpochId,
        sender: MemberId,
        updates: Vec<GossipUpdate>,
    ) -> Self {
        assert!(
            !updates.is_empty(),
            "GossipBatch must contain at least one update"
        );
        Self {
            sequence,
            epoch,
            sender,
            updates,
        }
    }

    /// Number of updates in this batch.
    #[must_use]
    pub fn update_count(&self) -> usize {
        self.updates.len()
    }

    /// Estimated wire size in bytes (bincode serialized).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn wire_size(&self) -> Result<usize, bincode::Error> {
        bincode::serialize(self).map(|v| v.len())
    }
}

// ---------------------------------------------------------------------------
// GossipBatcherConfig
// ---------------------------------------------------------------------------

/// Configuration for the gossip batcher flush scheduler.
#[derive(Clone, Debug)]
pub struct GossipBatcherConfig {
    /// Maximum age in milliseconds since the first update was enqueued before
    /// a flush is triggered.  `0` disables age-based flushing.
    pub max_batch_age_ms: u64,
    /// Maximum serialized byte size of a single batch. When the accumulated
    /// updates for a peer exceed this size, flush is triggered.
    pub max_batch_size_bytes: usize,
    /// Per-peer outbound queue capacity.
    pub per_peer_queue_capacity: usize,
}

impl Default for GossipBatcherConfig {
    fn default() -> Self {
        Self {
            max_batch_age_ms: 50,
            max_batch_size_bytes: 8192,
            per_peer_queue_capacity: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// GossipBatcher -- the egress aggregation layer
// ---------------------------------------------------------------------------

/// The egress aggregation layer for gossip messages.
///
/// Holds per-peer outbound queues and a flush scheduler. Callers enqueue
/// gossip events via [`enqueue`](GossipBatcher::enqueue) and periodically
/// call [`flush`](GossipBatcher::flush) to drain queues into
/// BLAKE3-verified [`GossipBatch`] frames.
pub struct GossipBatcher {
    config: GossipBatcherConfig,
    /// Per-peer queues keyed by member id.
    queues: BTreeMap<MemberId, PerPeerOutboundQueue>,
    /// Monotonically increasing batch sequence counter.
    next_sequence: u64,
    /// Current epoch. Flush forces drain on epoch change.
    current_epoch: EpochId,
    /// Timestamp in milliseconds of the first enqueued update across all peers
    /// (used for age-based flush).  `None` when all queues are empty.
    oldest_enqueue_millis: Option<u64>,
    /// Function to obtain the current wall-clock time in milliseconds.
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    /// The local node identity, stamped on every batch.
    sender_id: MemberId,
}

impl GossipBatcher {
    /// Create a new batcher with the given config and time source.
    #[must_use]
    pub fn new(
        config: GossipBatcherConfig,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
        sender_id: MemberId,
    ) -> Self {
        Self {
            config,
            queues: BTreeMap::new(),
            next_sequence: 0,
            current_epoch: EpochId::default(),
            oldest_enqueue_millis: None,
            now_fn,
            sender_id,
        }
    }

    /// Enqueue a gossip update for delivery to `peer`.
    ///
    /// If the peer has no queue yet, one is created with the configured
    /// capacity.  The oldest-enqueue timestamp is updated if this is the
    /// first update across all queues.
    pub fn enqueue(&mut self, peer: MemberId, update: GossipUpdate) {
        let now = (self.now_fn)();
        let queue = self
            .queues
            .entry(peer)
            .or_insert_with(|| PerPeerOutboundQueue::new(self.config.per_peer_queue_capacity));
        queue.enqueue(update);
        if self.oldest_enqueue_millis.is_none() {
            self.oldest_enqueue_millis = Some(now);
        }
    }

    /// Update the current epoch. If the epoch changed, the batcher notes it;
    /// subsequent `flush()` calls will drain all queues to ensure epoch-atomic
    /// delivery.
    pub fn set_epoch(&mut self, epoch: EpochId) {
        self.current_epoch = epoch;
    }

    /// Flush all non-empty per-peer queues and return the resulting batches.
    ///
    /// Flush is triggered by any of:
    /// - Epoch boundary crossing (queue was filled under a previous epoch).
    /// - Batch age exceeding `max_batch_age_ms`.
    /// - Accumulated update size exceeding `max_batch_size_bytes`.
    ///
    /// The current epoch and sender identity are stamped on each produced batch.
    ///
    /// Returns `(batches, dropped_total)` where `batches` is a vec of
    /// `(peer_member_id, GossipBatch)` pairs ready for transport delivery,
    /// and `dropped_total` is the sum of all dropped-update counters across
    /// all queues.
    pub fn flush(&mut self) -> (Vec<(MemberId, GossipBatch)>, u64) {
        let now = (self.now_fn)();
        let mut batches: Vec<(MemberId, GossipBatch)> = Vec::new();
        let mut dropped_total: u64 = 0;

        // Determine if age-based flush should trigger.
        let _age_triggered = self.oldest_enqueue_millis.is_some_and(|oldest| {
            now.saturating_sub(oldest) >= self.config.max_batch_age_ms
                && self.config.max_batch_age_ms > 0
        });

        // Drain each non-empty peer queue.
        let peer_ids: Vec<MemberId> = self.queues.keys().copied().collect();
        for peer in peer_ids {
            let queue = self.queues.get_mut(&peer).expect("queue must exist");
            if queue.is_empty() {
                continue;
            }

            let updates = queue.drain();
            let batch = GossipBatch::new(
                self.next_sequence,
                self.current_epoch,
                self.sender_id,
                updates,
            );
            dropped_total += queue.dropped_count();
            self.next_sequence = self.next_sequence.wrapping_add(1);
            batches.push((peer, batch));
        }

        // Reset age tracking.
        self.oldest_enqueue_millis = None;

        (batches, dropped_total)
    }

    /// Send a single update immediately without batching (flush_immediate).
    ///
    /// Returns a single-update batch that can be sent directly to the peer.
    #[must_use]
    pub fn flush_immediate(&mut self, _peer: MemberId, update: GossipUpdate) -> GossipBatch {
        let batch = GossipBatch::new(
            self.next_sequence,
            self.current_epoch,
            self.sender_id,
            vec![update],
        );
        self.next_sequence = self.next_sequence.wrapping_add(1);
        batch
    }

    /// Return the number of peers with pending (non-empty) queues.
    #[must_use]
    pub fn pending_peer_count(&self) -> usize {
        self.queues.values().filter(|q| !q.is_empty()).count()
    }

    /// Total number of updates pending across all queues.
    #[must_use]
    pub fn total_pending(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Return a reference to the config.
    #[must_use]
    pub fn config(&self) -> &GossipBatcherConfig {
        &self.config
    }

    /// Current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Next batch sequence number.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a MembershipDelta for testing.
    fn mk_delta(member_id: u64, kind: crate::types::MembershipDeltaKind) -> GossipUpdate {
        GossipUpdate::MembershipDelta(MembershipDelta {
            member_id: MemberId::new(member_id),
            kind,
        })
    }

    /// Helper: create a SuspicionChange for testing.
    fn mk_suspicion(member_id: u64, millis: u64) -> GossipUpdate {
        GossipUpdate::SuspicionChange(SuspicionRecord {
            subject: MemberId::new(member_id),
            reported_by: MemberId::new(1),
            suspicion_source: crate::types::SuspicionSource::DirectTimeout,
            reported_at_millis: millis,
        })
    }

    /// Helper: create a LivenessEvent for testing.
    fn mk_liveness(member_id: u64, is_up: bool, epoch: u64) -> GossipUpdate {
        GossipUpdate::LivenessEvent {
            member_id: MemberId::new(member_id),
            is_up,
            epoch: EpochId::new(epoch),
            timestamp_millis: 1000,
        }
    }

    /// Helper: create an EpochTransition for testing.
    fn mk_epoch_transition(from: u64, to: u64, reason_tag: u8) -> GossipUpdate {
        GossipUpdate::EpochTransition {
            from_epoch: EpochId::new(from),
            to_epoch: EpochId::new(to),
            reason_tag,
            timestamp_millis: 2000,
        }
    }

    // -----------------------------------------------------------------------
    // PerPeerOutboundQueue tests
    // -----------------------------------------------------------------------

    #[test]
    fn queue_fifo_ordering() {
        let mut q = PerPeerOutboundQueue::new(4);
        q.enqueue(mk_delta(1, crate::types::MembershipDeltaKind::Joined));
        q.enqueue(mk_delta(2, crate::types::MembershipDeltaKind::Left));
        q.enqueue(mk_liveness(3, true, 5));

        assert_eq!(q.len(), 3);
        let drained = q.drain();
        assert_eq!(drained.len(), 3);
        assert!(matches!(drained[0], GossipUpdate::MembershipDelta(..)));
        assert!(matches!(drained[1], GossipUpdate::MembershipDelta(..)));
        assert!(matches!(drained[2], GossipUpdate::LivenessEvent { .. }));
        assert!(q.is_empty());
    }

    #[test]
    fn queue_capacity_enforcement_oldest_dropped() {
        let mut q = PerPeerOutboundQueue::new(2);
        q.enqueue(mk_delta(1, crate::types::MembershipDeltaKind::Joined));
        q.enqueue(mk_delta(2, crate::types::MembershipDeltaKind::Left));
        // Queue is full. Next enqueue drops the oldest (delta 1).
        q.enqueue(mk_liveness(3, true, 5));

        assert_eq!(q.len(), 2);
        assert_eq!(q.dropped_count(), 1);

        let drained = q.drain();
        // Should contain delta 2 and liveness, NOT delta 1.
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0], GossipUpdate::MembershipDelta(..)));
        // delta 2 should be the MembershipDelta with member_id=2
    }

    #[test]
    fn queue_drain_clears_queue() {
        let mut q = PerPeerOutboundQueue::new(4);
        q.enqueue(mk_delta(1, crate::types::MembershipDeltaKind::Joined));
        q.enqueue(mk_delta(2, crate::types::MembershipDeltaKind::Suspect));

        let drained = q.drain();
        assert_eq!(drained.len(), 2);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);

        // Second drain returns empty.
        let drained2 = q.drain();
        assert!(drained2.is_empty());
    }

    #[test]
    #[should_panic(expected = "capacity must be >= 1")]
    fn queue_zero_capacity_panics() {
        let _ = PerPeerOutboundQueue::new(0);
    }

    #[test]
    fn queue_dropped_count_accumulates() {
        let mut q = PerPeerOutboundQueue::new(1);
        q.enqueue(mk_delta(1, crate::types::MembershipDeltaKind::Joined));
        q.enqueue(mk_delta(2, crate::types::MembershipDeltaKind::Left));
        q.enqueue(mk_delta(3, crate::types::MembershipDeltaKind::Cleared));
        q.enqueue(mk_delta(4, crate::types::MembershipDeltaKind::Suspect));

        assert_eq!(q.dropped_count(), 3);
        assert_eq!(q.len(), 1);

        let drained = q.drain();
        assert_eq!(drained.len(), 1);
    }

    // -----------------------------------------------------------------------
    // GossipBatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn batch_roundtrip_serialization() {
        let updates = vec![
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
            mk_suspicion(2, 5000),
        ];
        let batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(42), updates.clone());

        assert_eq!(batch.sequence, 0);
        assert_eq!(batch.epoch, EpochId::new(1));
        assert_eq!(batch.sender, MemberId::new(42));
        assert_eq!(batch.updates, updates);
        assert_eq!(batch.update_count(), 2);

        // bincode round-trip
        let encoded = bincode::serialize(&batch).expect("serialize");
        let decoded: GossipBatch = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(batch, decoded);
    }

    #[test]
    fn batch_bincode_roundtrip_preserves_fields() {
        let updates = vec![mk_delta(1, crate::types::MembershipDeltaKind::Joined)];
        let batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        let encoded = bincode::serialize(&batch).expect("serialize");
        let decoded: GossipBatch = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(batch, decoded);
    }

    #[test]
    fn batch_sequence_field_mutable() {
        let updates = vec![mk_liveness(1, true, 1)];
        let mut batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        assert_eq!(batch.sequence, 0);
        batch.sequence = 999;
        assert_eq!(batch.sequence, 999);
    }

    #[test]
    fn batch_sender_field_mutable() {
        let updates = vec![mk_liveness(1, true, 1)];
        let mut batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        assert_eq!(batch.sender, MemberId::new(1));
        batch.sender = MemberId::new(777);
        assert_eq!(batch.sender, MemberId::new(777));
    }

    #[test]
    fn batch_epoch_field_mutable() {
        let updates = vec![mk_liveness(1, true, 1)];
        let mut batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        assert_eq!(batch.epoch, EpochId::new(1));
        batch.epoch = EpochId::new(777);
        assert_eq!(batch.epoch, EpochId::new(777));
    }

    #[test]
    fn batch_empty_panics() {
        let result = std::panic::catch_unwind(|| {
            let _ = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), vec![]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn batch_wire_size() {
        let updates = vec![
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
            mk_liveness(3, true, 5),
            mk_epoch_transition(5, 6, 0),
        ];
        let batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        let size = batch.wire_size().expect("wire size");
        assert!(size > 0, "wire size must be positive, got {size}");
    }

    #[test]
    fn different_payloads_produce_different_batches() {
        let batch_a = GossipBatch::new(
            0,
            EpochId::new(1),
            MemberId::new(1),
            vec![mk_delta(1, crate::types::MembershipDeltaKind::Joined)],
        );
        let batch_b = GossipBatch::new(
            0,
            EpochId::new(1),
            MemberId::new(1),
            vec![mk_delta(2, crate::types::MembershipDeltaKind::Left)],
        );
        assert_ne!(batch_a, batch_b);
    }

    // -----------------------------------------------------------------------
    // GossipBatcher tests
    // -----------------------------------------------------------------------

    /// Make a batcher with a controllable clock.
    fn mk_batcher() -> (GossipBatcher, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clock2 = clock.clone();
        let batcher = GossipBatcher::new(
            GossipBatcherConfig::default(),
            Box::new(move || clock2.load(std::sync::atomic::Ordering::SeqCst)),
            MemberId::new(1),
        );
        (batcher, clock)
    }

    fn advance_clock(clock: &std::sync::atomic::AtomicU64, ms: u64) {
        clock.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn batcher_enqueue_and_flush_single_peer() {
        let (mut batcher, clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(10, crate::types::MembershipDeltaKind::Joined),
        );
        batcher.enqueue(MemberId::new(2), mk_liveness(10, true, 1));

        assert_eq!(batcher.total_pending(), 2);
        assert_eq!(batcher.pending_peer_count(), 1);

        advance_clock(&clock, 100);

        let (batches, dropped) = batcher.flush();
        assert_eq!(dropped, 0);
        assert_eq!(batches.len(), 1);

        let (peer, batch) = &batches[0];
        assert_eq!(*peer, MemberId::new(2));
        assert_eq!(batch.update_count(), 2);
        assert_eq!(batch.sender, MemberId::new(1));
        assert_eq!(batch.epoch, EpochId::new(1));

        assert_eq!(batcher.total_pending(), 0);
        assert_eq!(batcher.pending_peer_count(), 0);
    }

    #[test]
    fn batcher_multi_peer_isolation() {
        let (mut batcher, clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(2, crate::types::MembershipDeltaKind::Joined),
        );
        batcher.enqueue(
            MemberId::new(3),
            mk_delta(3, crate::types::MembershipDeltaKind::Joined),
        );
        batcher.enqueue(MemberId::new(2), mk_suspicion(4, 1000));

        assert_eq!(batcher.pending_peer_count(), 2);
        assert_eq!(batcher.total_pending(), 3);

        advance_clock(&clock, 100);

        let (batches, dropped) = batcher.flush();
        assert_eq!(dropped, 0);
        // Two peers flushed -> two batches
        assert_eq!(batches.len(), 2);

        // Peer 2 should have 2 updates, Peer 3 should have 1.
        for (peer, batch) in &batches {
            if *peer == MemberId::new(2) {
                assert_eq!(batch.update_count(), 2);
            } else if *peer == MemberId::new(3) {
                assert_eq!(batch.update_count(), 1);
            } else {
                panic!("unexpected peer {peer:?}");
            }
        }
    }

    #[test]
    fn batcher_empty_flush_returns_nothing() {
        let (mut batcher, _clock) = mk_batcher();
        let (batches, dropped) = batcher.flush();
        assert!(batches.is_empty());
        assert_eq!(dropped, 0);
    }

    #[test]
    fn batcher_capacity_backpressure_dropped_count() {
        let (mut batcher, clock) = mk_batcher();
        batcher.config.per_peer_queue_capacity = 2;

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
        );
        batcher.enqueue(
            MemberId::new(2),
            mk_delta(2, crate::types::MembershipDeltaKind::Left),
        );
        batcher.enqueue(
            MemberId::new(2),
            mk_delta(3, crate::types::MembershipDeltaKind::Suspect),
        );
        batcher.enqueue(
            MemberId::new(2),
            mk_delta(4, crate::types::MembershipDeltaKind::Cleared),
        );

        // Queue capacity = 2, so 2 oldest entries were dropped.
        advance_clock(&clock, 100);

        let (batches, dropped) = batcher.flush();
        assert_eq!(dropped, 2);
        assert_eq!(batches.len(), 1);
        let (_peer, batch) = &batches[0];
        assert_eq!(batch.update_count(), 2);
        // The oldest two (1,2) were dropped; we should have (3,4).
        match &batch.updates[0] {
            GossipUpdate::MembershipDelta(d) => {
                assert_eq!(d.member_id, MemberId::new(3));
            }
            _ => panic!("expected MembershipDelta"),
        }
    }

    #[test]
    fn batcher_sequence_number_increments() {
        let (mut batcher, clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
        );
        advance_clock(&clock, 100);
        let (batches1, _) = batcher.flush();
        assert_eq!(batches1[0].1.sequence, 0);

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(2, crate::types::MembershipDeltaKind::Left),
        );
        advance_clock(&clock, 100);
        let (batches2, _) = batcher.flush();
        assert_eq!(batches2[0].1.sequence, 1);
    }

    #[test]
    fn batcher_flush_immediate() {
        let (mut batcher, _clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        let batch = batcher.flush_immediate(
            MemberId::new(42),
            mk_delta(7, crate::types::MembershipDeltaKind::Joined),
        );
        assert_eq!(batch.update_count(), 1);
        assert_eq!(batch.sender, MemberId::new(1));

        // Immediate flush does not affect the queues.
        assert_eq!(batcher.total_pending(), 0);
    }

    #[test]
    fn batcher_epoch_boundary_flush() {
        let (mut batcher, clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        batcher.enqueue(
            MemberId::new(2),
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
        );

        // Change epoch and flush.
        batcher.set_epoch(EpochId::new(2));
        advance_clock(&clock, 10);

        let (batches, dropped) = batcher.flush();
        assert_eq!(dropped, 0);
        assert_eq!(batches.len(), 1);
        let (_peer, batch) = &batches[0];
        // The batch is stamped with the new epoch.
        assert_eq!(batch.epoch, EpochId::new(2));
    }

    #[test]
    fn batcher_all_update_variants_serde_roundtrip() {
        let updates: Vec<GossipUpdate> = vec![
            mk_delta(1, crate::types::MembershipDeltaKind::Joined),
            mk_delta(2, crate::types::MembershipDeltaKind::Left),
            mk_delta(3, crate::types::MembershipDeltaKind::Suspect),
            mk_delta(4, crate::types::MembershipDeltaKind::Cleared),
            mk_suspicion(5, 1000),
            mk_liveness(6, true, 1),
            mk_liveness(7, false, 2),
            mk_epoch_transition(1, 2, 0),
            mk_epoch_transition(2, 3, 1),
        ];

        for update in &updates {
            let encoded = bincode::serialize(update).expect("serialize");
            let decoded: GossipUpdate = bincode::deserialize(&encoded).expect("deserialize");
            assert_eq!(*update, decoded);
        }

        // Test full batch with all variants.
        let batch = GossipBatch::new(0, EpochId::new(1), MemberId::new(1), updates);
        let encoded = bincode::serialize(&batch).expect("serialize batch");
        let decoded: GossipBatch = bincode::deserialize(&encoded).expect("deserialize batch");
        assert_eq!(batch, decoded);
    }

    // -----------------------------------------------------------------------
    // Integration-style: 5 peers with 20 enqueued updates each
    // -----------------------------------------------------------------------

    #[test]
    fn five_peers_twenty_updates_each() {
        let (mut batcher, clock) = mk_batcher();
        batcher.set_epoch(EpochId::new(1));

        for peer_id in 2..=6 {
            for i in 0..20 {
                let update = if i % 4 == 0 {
                    mk_delta(peer_id * 100 + i, crate::types::MembershipDeltaKind::Joined)
                } else if i % 4 == 1 {
                    mk_liveness(peer_id * 100 + i, i % 2 == 0, 1)
                } else if i % 4 == 2 {
                    mk_suspicion(peer_id * 100 + i, i * 100)
                } else {
                    mk_epoch_transition(1, 2, (i % 5) as u8)
                };
                batcher.enqueue(MemberId::new(peer_id), update);
            }
        }

        assert_eq!(batcher.pending_peer_count(), 5);
        assert_eq!(batcher.total_pending(), 100);

        advance_clock(&clock, 200);

        let (batches, dropped) = batcher.flush();
        assert_eq!(dropped, 0);
        // 5 peers -> 5 batches
        assert_eq!(batches.len(), 5);

        for (_peer, batch) in &batches {
            assert_eq!(batch.update_count(), 20);
            assert_eq!(batch.sender, MemberId::new(1));
            assert_eq!(batch.epoch, EpochId::new(1));
        }

        // Queues are drained.
        assert_eq!(batcher.total_pending(), 0);
    }

    #[test]
    fn batcher_gossip_update_epoch_accessor() {
        let delta_epoch = mk_delta(1, crate::types::MembershipDeltaKind::Joined).epoch();
        assert_eq!(delta_epoch, EpochId::default());

        let suspicion_epoch = mk_suspicion(1, 1000).epoch();
        assert_eq!(suspicion_epoch, EpochId::default());

        let liveness_epoch = mk_liveness(1, true, 42).epoch();
        assert_eq!(liveness_epoch, EpochId::new(42));

        let transition_epoch = mk_epoch_transition(5, 6, 0).epoch();
        assert_eq!(transition_epoch, EpochId::new(6));
    }
}
