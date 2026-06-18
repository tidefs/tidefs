// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bounded slot-request queue with priority ordering and backpressure
//! signaling for TDMA transport scheduling.
//!
//! Provides a bounded FIFO queue for [`SlotRequest`] entries. When the
//! queue depth exceeds a configurable backpressure threshold (default
//! 75% of capacity), [`SlotRequestQueue::backpressure`] returns
//! [`BackpressureSignal`] so callers can throttle submission.

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// SlotRequest
// ---------------------------------------------------------------------------

/// A pending request for a TDMA transmit slot.
///
/// Carries the requesting node, an optional object identifier, a priority
/// level (lower = higher urgency), the byte budget requested, and the
/// monotonic insertion timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRequest {
    /// Node requesting the slot.
    pub node_id: u64,
    /// Object or session this request targets (0 if session-level).
    pub object_id: u64,
    /// Priority level: 0 = highest, u32::MAX = lowest.
    pub priority: u32,
    /// Bytes the node wishes to transmit in this slot.
    pub requested_bytes: u64,
    /// Monotonic timestamp when the request was enqueued (milliseconds).
    pub enqueued_at_ms: u64,
}

impl SlotRequest {
    /// Create a new slot request.
    pub fn new(
        node_id: u64,
        object_id: u64,
        priority: u32,
        requested_bytes: u64,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            node_id,
            object_id,
            priority,
            requested_bytes,
            enqueued_at_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// BackpressureSignal
// ---------------------------------------------------------------------------

/// Backpressure status reported by [`SlotRequestQueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureSignal {
    /// Queue has capacity; no throttling needed.
    Clear,
    /// Queue depth has crossed the backpressure threshold; callers
    /// should slow or pause submission.
    Apply,
    /// Queue is at capacity; further enqueues will be rejected.
    Full,
}

impl BackpressureSignal {
    /// True when callers should apply backpressure (Apply or Full).
    pub fn should_throttle(self) -> bool {
        matches!(self, BackpressureSignal::Apply | BackpressureSignal::Full)
    }
}

// ---------------------------------------------------------------------------
// QueueFull error
// ---------------------------------------------------------------------------

/// Error returned when enqueuing into a full [`SlotRequestQueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("slot request queue full: capacity {capacity}, current depth {depth}")]
pub struct QueueFull {
    /// Configured maximum queue depth.
    pub capacity: usize,
    /// Current number of pending requests.
    pub depth: usize,
}

// ---------------------------------------------------------------------------
// SlotRequestQueue
// ---------------------------------------------------------------------------

/// A bounded, priority-ordered FIFO queue of [`SlotRequest`] entries with
/// backpressure signaling.
///
/// Requests are inserted in priority order (lower priority number = higher
/// urgency). Within the same priority level, insertion order (FIFO) is
/// preserved.
///
/// # Backpressure
///
/// When the queue depth exceeds `backpressure_ratio * max_depth`, the queue
/// enters backpressure and callers should throttle submission. At
/// `max_depth`, further enqueues return [`QueueFull`].
#[derive(Debug, Clone)]
pub struct SlotRequestQueue {
    /// Maximum number of pending requests.
    max_depth: usize,
    /// Backpressure threshold in number of requests (derived from ratio).
    backpressure_threshold: usize,
    /// Pending requests ordered by priority then insertion time.
    pending: VecDeque<SlotRequest>,
}

impl SlotRequestQueue {
    /// Create a new bounded queue.
    ///
    /// `max_depth` is the hard capacity. `backpressure_ratio` is the
    /// fraction of capacity at which backpressure activates, clamped to
    /// [0.0, 1.0]. A ratio of 0.75 means backpressure activates at 75%
    /// full. Neither argument may be zero.
    ///
    /// Returns `None` if `max_depth` is zero.
    pub fn new(max_depth: usize, backpressure_ratio: f64) -> Option<Self> {
        if max_depth == 0 {
            return None;
        }
        let ratio = backpressure_ratio.clamp(0.0, 1.0);
        let threshold = ((max_depth as f64) * ratio).ceil() as usize;
        Some(Self {
            max_depth,
            backpressure_threshold: threshold,
            pending: VecDeque::with_capacity(max_depth),
        })
    }

    // ------------------------------------------------------------------
    // Capacity & depth
    // ------------------------------------------------------------------

    /// Maximum number of pending requests.
    pub fn capacity(&self) -> usize {
        self.max_depth
    }

    /// Current number of pending requests.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True when the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// True when the queue is at capacity.
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.max_depth
    }

    /// Number of free slots remaining.
    pub fn remaining(&self) -> usize {
        self.max_depth.saturating_sub(self.pending.len())
    }

    /// The current backlog depth (same as `len`; convenience alias).
    pub fn backlog(&self) -> usize {
        self.pending.len()
    }

    // ------------------------------------------------------------------
    // Backpressure
    // ------------------------------------------------------------------

    /// Current backpressure signal.
    ///
    /// - [`BackpressureSignal::Clear`]: depth < threshold.
    /// - [`BackpressureSignal::Apply`]: depth >= threshold but < capacity.
    /// - [`BackpressureSignal::Full`]: depth == capacity.
    pub fn backpressure(&self) -> BackpressureSignal {
        if self.pending.is_empty() {
            BackpressureSignal::Clear
        } else if self.is_full() {
            BackpressureSignal::Full
        } else if self.pending.len() >= self.backpressure_threshold {
            BackpressureSignal::Apply
        } else {
            BackpressureSignal::Clear
        }
    }

    /// The configured backpressure threshold in requests.
    pub fn backpressure_threshold(&self) -> usize {
        self.backpressure_threshold
    }

    // ------------------------------------------------------------------
    // Enqueue / dequeue
    // ------------------------------------------------------------------

    /// Enqueue a slot request in priority order.
    ///
    /// Returns `Ok(())` on success or `Err(QueueFull)` when the queue is
    /// at capacity.
    ///
    /// Insertion preserves order: higher-priority (lower number) requests
    /// are placed before lower-priority ones. Within the same priority,
    /// FIFO order is maintained (newer requests go after existing ones
    /// of equal priority).
    pub fn enqueue(&mut self, request: SlotRequest) -> Result<(), QueueFull> {
        if self.is_full() {
            return Err(QueueFull {
                capacity: self.max_depth,
                depth: self.pending.len(),
            });
        }

        // Find insertion point: scan for the first entry with strictly
        // greater priority number (lower urgency), insert before it.
        let insert_pos = self
            .pending
            .iter()
            .position(|r| r.priority > request.priority)
            .unwrap_or(self.pending.len());

        // VecDeque doesn't have insert_at; work around it.
        // Split the deque, insert, then rejoin.
        let tail: Vec<SlotRequest> = self.pending.drain(insert_pos..).collect();
        self.pending.push_back(request);
        for r in tail {
            self.pending.push_back(r);
        }

        Ok(())
    }

    /// Dequeue the highest-priority (lowest priority number) request.
    ///
    /// Returns `None` when the queue is empty.
    pub fn dequeue(&mut self) -> Option<SlotRequest> {
        self.pending.pop_front()
    }

    /// Peek at the next request without dequeuing.
    pub fn peek(&self) -> Option<&SlotRequest> {
        self.pending.front()
    }

    /// Drain all requests for a specific node (e.g., on node failure).
    ///
    /// Returns the number of requests removed.
    pub fn drain_node(&mut self, node_id: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|r| r.node_id != node_id);
        before - self.pending.len()
    }

    /// Drain all requests for a specific object.
    ///
    /// Returns the number of requests removed.
    pub fn drain_object(&mut self, object_id: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|r| r.object_id != object_id);
        before - self.pending.len()
    }

    /// Clear all pending requests.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Iterate over pending requests in priority order.
    pub fn iter(&self) -> impl Iterator<Item = &SlotRequest> {
        self.pending.iter()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_queue() -> SlotRequestQueue {
        SlotRequestQueue::new(8, 0.75).unwrap()
    }

    fn req(node: u64, prio: u32) -> SlotRequest {
        SlotRequest::new(node, 0, prio, 1024, 1000)
    }

    // --- Construction ---

    #[test]
    fn rejects_zero_capacity() {
        assert!(SlotRequestQueue::new(0, 0.75).is_none());
    }

    #[test]
    fn capacity_and_backpressure_threshold() {
        let q = SlotRequestQueue::new(100, 0.8).unwrap();
        assert_eq!(q.capacity(), 100);
        assert_eq!(q.backpressure_threshold(), 80);
    }

    #[test]
    fn ratio_clamped_to_one() {
        let q = SlotRequestQueue::new(10, 2.0).unwrap();
        assert_eq!(q.backpressure_threshold(), 10);
    }

    #[test]
    fn ratio_clamped_to_zero() {
        let q = SlotRequestQueue::new(10, -0.5).unwrap();
        assert_eq!(q.backpressure_threshold(), 0);
    }

    // --- Basic enqueue/dequeue ---

    #[test]
    fn enqueue_and_dequeue_single() {
        let mut q = test_queue();
        q.enqueue(req(10, 0)).unwrap();
        assert_eq!(q.len(), 1);
        let r = q.dequeue().unwrap();
        assert_eq!(r.node_id, 10);
        assert!(q.is_empty());
    }

    #[test]
    fn fifo_same_priority() {
        let mut q = test_queue();
        q.enqueue(req(10, 0)).unwrap();
        q.enqueue(req(20, 0)).unwrap();
        q.enqueue(req(30, 0)).unwrap();

        assert_eq!(q.dequeue().unwrap().node_id, 10);
        assert_eq!(q.dequeue().unwrap().node_id, 20);
        assert_eq!(q.dequeue().unwrap().node_id, 30);
    }

    #[test]
    fn priority_ordering() {
        let mut q = test_queue();
        // Insert in reverse priority order
        q.enqueue(req(10, 5)).unwrap(); // low prio
        q.enqueue(req(20, 0)).unwrap(); // high prio
        q.enqueue(req(30, 2)).unwrap(); // medium prio
        q.enqueue(req(40, 1)).unwrap(); // medium-high prio

        // Dequeue should be priority 0, 1, 2, 5
        assert_eq!(q.dequeue().unwrap().node_id, 20); // prio 0
        assert_eq!(q.dequeue().unwrap().node_id, 40); // prio 1
        assert_eq!(q.dequeue().unwrap().node_id, 30); // prio 2
        assert_eq!(q.dequeue().unwrap().node_id, 10); // prio 5
    }

    #[test]
    fn priority_fifo_within_same_priority() {
        let mut q = test_queue();
        q.enqueue(req(10, 1)).unwrap();
        q.enqueue(req(20, 0)).unwrap(); // higher prio, goes first
        q.enqueue(req(30, 1)).unwrap(); // same prio as 10, goes after

        assert_eq!(q.dequeue().unwrap().node_id, 20); // prio 0
        assert_eq!(q.dequeue().unwrap().node_id, 10); // prio 1, first in
        assert_eq!(q.dequeue().unwrap().node_id, 30); // prio 1, second in
    }

    // --- Capacity & backpressure ---

    #[test]
    fn enqueue_full_returns_error() {
        let mut q = SlotRequestQueue::new(3, 0.75).unwrap();
        q.enqueue(req(1, 0)).unwrap();
        q.enqueue(req(2, 0)).unwrap();
        q.enqueue(req(3, 0)).unwrap();

        assert!(q.is_full());
        let err = q.enqueue(req(4, 0)).unwrap_err();
        assert_eq!(err.capacity, 3);
        assert_eq!(err.depth, 3);
    }

    #[test]
    fn backpressure_clear_below_threshold() {
        let mut q = SlotRequestQueue::new(10, 0.75).unwrap(); // threshold at 8
        for i in 0..5 {
            q.enqueue(req(i, 0)).unwrap();
        }
        assert_eq!(q.backpressure(), BackpressureSignal::Clear);
    }

    #[test]
    fn backpressure_apply_above_threshold() {
        let mut q = SlotRequestQueue::new(10, 0.75).unwrap(); // threshold at 8
        for i in 0..8 {
            q.enqueue(req(i, 0)).unwrap();
        }
        assert_eq!(q.backpressure(), BackpressureSignal::Apply);
    }

    #[test]
    fn backpressure_full_at_capacity() {
        let mut q = SlotRequestQueue::new(4, 0.75).unwrap(); // threshold at 3
        for i in 0..4 {
            q.enqueue(req(i, 0)).unwrap();
        }
        assert_eq!(q.backpressure(), BackpressureSignal::Full);
    }

    #[test]
    fn backpressure_should_throttle() {
        assert!(!BackpressureSignal::Clear.should_throttle());
        assert!(BackpressureSignal::Apply.should_throttle());
        assert!(BackpressureSignal::Full.should_throttle());
    }

    // --- Drain node/object ---

    #[test]
    fn drain_node_removes_all_for_node() {
        let mut q = test_queue();
        q.enqueue(req(10, 0)).unwrap();
        q.enqueue(req(20, 0)).unwrap();
        q.enqueue(req(10, 1)).unwrap();
        q.enqueue(req(30, 0)).unwrap();

        let removed = q.drain_node(10);
        assert_eq!(removed, 2);
        assert_eq!(q.len(), 2);

        let r = q.dequeue().unwrap();
        assert!(r.node_id == 20 || r.node_id == 30);
    }

    #[test]
    fn drain_object_removes_all_for_object() {
        let mut q = test_queue();
        q.enqueue(SlotRequest::new(10, 42, 0, 1024, 1000)).unwrap();
        q.enqueue(SlotRequest::new(20, 42, 0, 1024, 1000)).unwrap();
        q.enqueue(SlotRequest::new(10, 99, 0, 1024, 1000)).unwrap();

        let removed = q.drain_object(42);
        assert_eq!(removed, 2);
        assert_eq!(q.len(), 1);
        let r = q.dequeue().unwrap();
        assert_eq!(r.node_id, 10);
        assert_eq!(r.object_id, 99);
        assert!(q.is_empty());
    }

    // --- Clear ---

    #[test]
    fn clear_empties_queue() {
        let mut q = test_queue();
        for i in 0..5 {
            q.enqueue(req(i, 0)).unwrap();
        }
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.backlog(), 0);
        assert_eq!(q.backpressure(), BackpressureSignal::Clear);
    }

    // --- Peek ---

    #[test]
    fn peek_does_not_remove() {
        let mut q = test_queue();
        q.enqueue(req(10, 0)).unwrap();
        assert_eq!(q.peek().unwrap().node_id, 10);
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek().unwrap().node_id, 10);
    }

    #[test]
    fn peek_empty_returns_none() {
        let q = test_queue();
        assert!(q.peek().is_none());
    }

    // --- Remaining ---

    #[test]
    fn remaining_tracks_free_slots() {
        let mut q = SlotRequestQueue::new(5, 0.5).unwrap();
        assert_eq!(q.remaining(), 5);
        q.enqueue(req(1, 0)).unwrap();
        assert_eq!(q.remaining(), 4);
        q.enqueue(req(2, 0)).unwrap();
        assert_eq!(q.remaining(), 3);
    }

    // --- Iter ---

    #[test]
    fn iter_yields_in_priority_order() {
        let mut q = test_queue();
        q.enqueue(req(10, 3)).unwrap();
        q.enqueue(req(20, 0)).unwrap();
        q.enqueue(req(30, 1)).unwrap();

        let ids: Vec<u64> = q.iter().map(|r| r.node_id).collect();
        assert_eq!(ids, vec![20, 30, 10]); // priority 0, 1, 3
    }

    // --- Edge: enqueue into empty after full cycle ---

    #[test]
    fn full_drain_reuse() {
        let mut q = SlotRequestQueue::new(3, 0.75).unwrap();
        q.enqueue(req(1, 0)).unwrap();
        q.enqueue(req(2, 0)).unwrap();
        q.enqueue(req(3, 0)).unwrap();

        assert!(q.is_full());
        q.dequeue().unwrap();
        assert!(!q.is_full());

        // Should be able to enqueue again
        q.enqueue(req(4, 0)).unwrap();
        assert_eq!(q.len(), 3);
        assert!(q.is_full());
    }

    // --- Edge: zero backpressure ratio means immediate Apply ---

    #[test]
    fn zero_backpressure_ratio_immediate_apply() {
        let mut q = SlotRequestQueue::new(4, 0.0).unwrap();
        assert_eq!(q.backpressure(), BackpressureSignal::Clear); // empty

        q.enqueue(req(1, 0)).unwrap();
        // threshold is 0, so any enqueue triggers Apply
        assert_eq!(q.backpressure(), BackpressureSignal::Apply);
    }

    // --- Edge: single slot capacity ---

    #[test]
    fn single_slot_queue() {
        let mut q = SlotRequestQueue::new(1, 0.75).unwrap();
        assert_eq!(q.capacity(), 1);
        assert!(!q.is_full());

        q.enqueue(req(1, 0)).unwrap();
        assert!(q.is_full());
        assert_eq!(q.backpressure(), BackpressureSignal::Full);

        let r = q.dequeue().unwrap();
        assert_eq!(r.node_id, 1);
        assert!(q.is_empty());
    }

    // --- Edge: large priority spread ---

    #[test]
    fn large_priority_spread() {
        let mut q = SlotRequestQueue::new(5, 0.75).unwrap();
        q.enqueue(req(1, u32::MAX)).unwrap();
        q.enqueue(req(2, 0)).unwrap();
        q.enqueue(req(3, u32::MAX - 1)).unwrap();
        q.enqueue(req(4, 1)).unwrap();
        q.enqueue(req(5, u32::MAX)).unwrap();

        // Expected order: prio 0, 1, MAX-1, MAX (first), MAX (second)
        assert_eq!(q.dequeue().unwrap().node_id, 2); // prio 0
        assert_eq!(q.dequeue().unwrap().node_id, 4); // prio 1
        assert_eq!(q.dequeue().unwrap().node_id, 3); // prio MAX-1
        assert_eq!(q.dequeue().unwrap().node_id, 1); // prio MAX, first in
        assert_eq!(q.dequeue().unwrap().node_id, 5); // prio MAX, second in
    }
}
