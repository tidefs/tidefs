// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tidefs_types_transport_session::MessageSequenceNumber;

// ---------------------------------------------------------------------------
// ReorderBuffer -- bounded reorder buffer with gap-timeout eviction
// ---------------------------------------------------------------------------

/// Result of inserting a message into the reorder buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertResult<T> {
    /// In-order delivery: the message was immediately deliverable without
    /// buffering. The caller should process `T` directly.
    Accepted(T),
    /// Out-of-order message buffered for later delivery.
    Buffered,
    /// Duplicate: the sequence number has already been delivered or buffered.
    Duplicate,
    /// The buffer is at capacity (`window_size`); the message was rejected.
    WindowFull,
}

/// A gap event emitted when a timeout fires for an unfilled sequence-number
/// gap. Upper layers use this to request retransmission or take other
/// recovery actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapEvent {
    /// First missing sequence number (inclusive).
    pub missing: MessageSequenceNumber,
    /// Highest buffered sequence number at the time the gap was detected,
    /// giving upper layers a bound on what was seen.
    pub highest_buffered: MessageSequenceNumber,
}

/// Bounded reorder buffer that accepts out-of-order messages keyed by
/// `MessageSequenceNumber`, delivers contiguous runs in order, and evicts
/// gap-timeout entries with `GapEvent`s.
///
/// The buffer is bounded to `window_size` entries. When full, new out-of-order
/// messages are rejected with `InsertResult::WindowFull`. Sequence-number
/// comparison uses wrapping arithmetic so that `u64::MAX -> 0` transitions are
/// correctly ordered.
pub struct ReorderBuffer<T> {
    /// Maximum number of buffered out-of-order entries.
    window_size: usize,
    /// How long to wait for a gap to be filled before evicting.
    gap_timeout: Duration,
    /// Highest consecutive sequence number delivered so far.
    /// Starts at `ZERO` (no messages delivered). After delivering seq N,
    /// this field is set to N. The next in-order message is `last_delivered + 1`
    /// (wrapping).
    last_delivered: MessageSequenceNumber,
    /// Buffered out-of-order entries keyed by sequence number.
    buffered: BTreeMap<MessageSequenceNumber, (Instant, T)>,
    /// Queued gap events for upper-layer consumption.
    gap_events: Vec<GapEvent>,
}

impl<T> ReorderBuffer<T> {
    /// Create a new reorder buffer.
    #[must_use]
    pub fn new(window_size: usize, gap_timeout: Duration) -> Self {
        Self {
            window_size,
            gap_timeout,
            last_delivered: MessageSequenceNumber::ZERO,
            buffered: BTreeMap::new(),
            gap_events: Vec::new(),
        }
    }

    /// Insert a received message with the given sequence number.
    pub fn insert(&mut self, seq: MessageSequenceNumber, msg: T, now: Instant) -> InsertResult<T> {
        // Compute wrapping-aware delta: how far is `seq` past `last_delivered`?
        // delta == 1 means seq == last_delivered + 1 (in-order).
        // delta == 0 means seq == last_delivered (exact duplicate after delivery).
        // negative delta (wrapping sense) means seq <= last_delivered (replayed).
        let delta = seq.0.wrapping_sub(self.last_delivered.0);

        if delta == 1 {
            // In-order: exactly one past the last delivered.
            self.last_delivered = seq;
            return InsertResult::Accepted(msg);
        }

        // delta == 0: exact duplicate of last_delivered.
        // (delta as i64) <= 0 but != 0: replayed old message.
        if delta == 0 || (delta as i64) < 0 {
            return InsertResult::Duplicate;
        }

        // delta > 1: out-of-order (future message). Check for already-buffered
        // duplicate.
        if self.buffered.contains_key(&seq) {
            return InsertResult::Duplicate;
        }

        // Capacity check.
        if self.buffered.len() >= self.window_size {
            return InsertResult::WindowFull;
        }

        self.buffered.insert(seq, (now, msg));
        InsertResult::Buffered
    }

    /// Deliver the longest contiguous in-order prefix of buffered messages.
    ///
    /// Before delivering, any buffered entries whose gap has persisted longer
    /// than `gap_timeout` are evicted: each gap is recorded as a `GapEvent`
    /// and the gap is skipped so that the blocking entry (and any contiguous
    /// followers) can be delivered.
    ///
    /// After this call, `last_delivered` points to the highest consecutive
    /// sequence delivered (accessible via [`next_expected`](Self::next_expected)).
    pub fn deliver_contiguous(&mut self, now: Instant) -> Vec<T> {
        let mut delivered = Vec::new();

        loop {
            // Evict at most one timed-out gap.  If one was evicted,
            // `last_delivered` was advanced to the blocking entry so the drain
            // below will pick it up.
            let jumped = self.evict_one_timeout(now);

            // Drain the contiguous run starting at last_delivered + 1.
            let mut drained_any = false;
            loop {
                let next = MessageSequenceNumber(self.last_delivered.0.wrapping_add(1));
                if let Some((_ts, msg)) = self.buffered.remove(&next) {
                    self.last_delivered = next;
                    delivered.push(msg);
                    drained_any = true;
                } else {
                    break;
                }
            }

            if !jumped && !drained_any {
                break;
            }
        }

        delivered
    }

    /// Drain and return all queued gap events.
    pub fn take_gap_events(&mut self) -> Vec<GapEvent> {
        std::mem::take(&mut self.gap_events)
    }

    /// Return the number of messages currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffered.len()
    }

    /// Return `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffered.is_empty()
    }

    /// Return the window size.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Return the next expected sequence number (one past `last_delivered`).
    #[must_use]
    pub fn next_expected(&self) -> MessageSequenceNumber {
        MessageSequenceNumber(self.last_delivered.0.wrapping_add(1))
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Evict at most one timed-out gap.  Returns `true` if a gap was evicted
    /// (and `last_delivered` was advanced to the blocking entry).
    fn evict_one_timeout(&mut self, now: Instant) -> bool {
        // Find the smallest buffered seq > last_delivered (wrapping-aware).
        let candidate = self.find_smallest_after(self.last_delivered);
        let Some((&seq, &(ts, _))) = candidate else {
            return false;
        };

        let delta = seq.0.wrapping_sub(self.last_delivered.0);
        // Contiguous -- nothing to evict.
        if delta <= 1 {
            return false;
        }

        let age = now.saturating_duration_since(ts);
        if age < self.gap_timeout {
            return false;
        }

        // Gap timed out: record event and skip the gap by advancing
        // last_delivered to just before the blocking entry so that the
        // contiguous-drain loop picks it up as "next".
        let highest = self.highest_buffered();
        self.gap_events.push(GapEvent {
            missing: MessageSequenceNumber(self.last_delivered.0.wrapping_add(1)),
            highest_buffered: highest,
        });
        // Set last_delivered to seq - 1 so that the drain loop finds
        // last_delivered + 1 = seq.
        self.last_delivered = MessageSequenceNumber(seq.0.wrapping_sub(1));
        true
    }

    /// Find the entry with the smallest sequence number strictly greater than
    /// `target` using wrapping-aware comparison.
    fn find_smallest_after(
        &self,
        target: MessageSequenceNumber,
    ) -> Option<(&MessageSequenceNumber, &(Instant, T))> {
        self.buffered
            .iter()
            .filter(|(&seq, _)| {
                let delta = seq.0.wrapping_sub(target.0);
                delta > 0 && delta < (u64::MAX / 2)
            })
            .min_by_key(|(&seq, _)| seq.0.wrapping_sub(target.0))
    }

    /// Return the highest sequence number currently buffered (wrapping-aware).
    fn highest_buffered(&self) -> MessageSequenceNumber {
        self.buffered
            .iter()
            .map(|(&seq, _)| seq)
            .max_by_key(|&seq| seq.0.wrapping_sub(self.last_delivered.0))
            .unwrap_or(self.last_delivered)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> Instant {
        Instant::now()
    }

    fn seq(n: u64) -> MessageSequenceNumber {
        MessageSequenceNumber::new(n)
    }

    // ----------------------------------------------------------------
    // Single in-order delivery
    // ----------------------------------------------------------------

    #[test]
    fn single_in_order_delivery() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let result = buf.insert(seq(1), 100, now());
        assert_eq!(result, InsertResult::Accepted(100));
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.next_expected().0, 2); // last_delivered=1, next_expected=2
    }

    // ----------------------------------------------------------------
    // Single gap buffered, then filled, then delivered
    // ----------------------------------------------------------------

    #[test]
    fn single_gap_buffered_then_filled_and_delivered() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let t0 = now();

        // Accept first in-order.
        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
        assert_eq!(buf.next_expected().0, 2);

        // seq 3 out-of-order (gap at 2).
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);
        assert_eq!(buf.len(), 1);

        // Nothing contiguous (seq 2 missing).
        let delivered = buf.deliver_contiguous(t0);
        assert!(delivered.is_empty());
        assert_eq!(buf.next_expected().0, 2);

        // seq 2 arrives, filling the gap.
        assert_eq!(buf.insert(seq(2), 20, t0), InsertResult::Accepted(20));
        assert_eq!(buf.next_expected().0, 3);

        // Now seq 3 is contiguous and delivered.
        let delivered = buf.deliver_contiguous(t0);
        assert_eq!(delivered, vec![30]);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.next_expected().0, 4); // last_delivered=3, next=4

        assert!(buf.take_gap_events().is_empty());
    }

    // ----------------------------------------------------------------
    // Multiple interleaved gaps
    // ----------------------------------------------------------------

    #[test]
    fn multiple_interleaved_gaps() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let t0 = now();

        // seq 1 in order.
        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));

        // Out-of-order: 3, 5, 2, 4.
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(5), 50, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(2), 20, t0), InsertResult::Accepted(20));

        // After delivering 2 (next_expected=3), 3 is contiguous.
        let delivered = buf.deliver_contiguous(t0);
        assert_eq!(delivered, vec![30]);
        assert_eq!(buf.next_expected().0, 4); // last_delivered=3, next=4
        assert_eq!(buf.len(), 1); // seq 5 remains

        // seq 4 arrives, making 5 contiguous.
        assert_eq!(buf.insert(seq(4), 40, t0), InsertResult::Accepted(40));
        let delivered = buf.deliver_contiguous(t0);
        assert_eq!(delivered, vec![50]);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.next_expected().0, 6); // last_delivered=5, next=6

        assert!(buf.take_gap_events().is_empty());
    }

    // ----------------------------------------------------------------
    // Window-full rejection
    // ----------------------------------------------------------------

    #[test]
    fn window_full_rejection() {
        let mut buf = ReorderBuffer::<u32>::new(2, Duration::from_secs(5));
        let t0 = now();

        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(4), 40, t0), InsertResult::Buffered);
        assert_eq!(buf.len(), 2);

        // Third out-of-order: WindowFull.
        assert_eq!(buf.insert(seq(5), 50, t0), InsertResult::WindowFull);
        assert_eq!(buf.len(), 2);

        // In-order still accepted despite full buffer.
        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
    }

    // ----------------------------------------------------------------
    // Gap timeout fires and frees buffer space
    // ----------------------------------------------------------------

    #[test]
    fn gap_timeout_fires_and_frees_buffer_space() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_millis(100));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));

        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(4), 40, t0), InsertResult::Buffered);

        let t1 = t0 + Duration::from_millis(200);

        // Gap at 2 timed out: evict, deliver 3, 4 contiguously.
        let delivered = buf.deliver_contiguous(t1);
        assert_eq!(delivered, vec![30, 40]);
        assert_eq!(buf.len(), 0);
        // last_delivered=4, next_expected=5
        assert_eq!(buf.next_expected().0, 5);

        let gaps = buf.take_gap_events();
        assert_eq!(gaps.len(), 1);
        // missing is first undelivered seq (last_delivered+1 = 2)
        assert_eq!(gaps[0].missing.0, 2);
        assert_eq!(gaps[0].highest_buffered.0, 4);
    }

    // ----------------------------------------------------------------
    // Duplicate rejection
    // ----------------------------------------------------------------

    #[test]
    fn duplicate_rejection() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let t0 = now();

        // In-order first.
        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));

        // Duplicate of already-delivered (seq 1 == last_delivered).
        assert_eq!(buf.insert(seq(1), 11, t0), InsertResult::Duplicate);

        // Buffer something.
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);

        // Duplicate of already-buffered.
        assert_eq!(buf.insert(seq(3), 31, t0), InsertResult::Duplicate);

        assert_eq!(buf.len(), 1);
    }

    // ----------------------------------------------------------------
    // Empty buffer after full drain
    // ----------------------------------------------------------------

    #[test]
    fn empty_buffer_after_full_drain() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
        assert_eq!(buf.insert(seq(2), 20, t0), InsertResult::Accepted(20));
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Accepted(30));

        let delivered = buf.deliver_contiguous(t0);
        assert!(delivered.is_empty());
        assert!(buf.is_empty());
        assert_eq!(buf.next_expected().0, 4);
    }

    // ----------------------------------------------------------------
    // Sequence wrap-around at u64::MAX -> 0
    // ----------------------------------------------------------------

    #[test]
    fn wrap_around_insertion_order() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_secs(5));
        let t0 = now();

        // Pre-seed last_delivered near the boundary.
        buf.last_delivered = seq(u64::MAX - 2);

        // u64::MAX - 1 in-order (delta = (MAX-1) - (MAX-2) = 1).
        assert_eq!(
            buf.insert(seq(u64::MAX - 1), 50, t0),
            InsertResult::Accepted(50)
        );
        assert_eq!(buf.next_expected().0, u64::MAX);

        // u64::MAX in-order.
        assert_eq!(
            buf.insert(seq(u64::MAX), 100, t0),
            InsertResult::Accepted(100)
        );
        assert_eq!(buf.next_expected().0, 0); // wraps: u64::MAX + 1 = 0

        // 0 in-order.
        assert_eq!(buf.insert(seq(0), 200, t0), InsertResult::Accepted(200));
        assert_eq!(buf.next_expected().0, 1);

        // 1 in-order.
        assert_eq!(buf.insert(seq(1), 300, t0), InsertResult::Accepted(300));
        assert_eq!(buf.next_expected().0, 2);

        // 3 out-of-order (gap at 2).
        assert_eq!(buf.insert(seq(3), 400, t0), InsertResult::Buffered);
        assert_eq!(buf.len(), 1);

        // 2 fills gap.
        assert_eq!(buf.insert(seq(2), 350, t0), InsertResult::Accepted(350));

        let delivered = buf.deliver_contiguous(t0);
        assert_eq!(delivered, vec![400]);
        assert_eq!(buf.next_expected().0, 4);

        assert!(buf.take_gap_events().is_empty());
    }

    // ----------------------------------------------------------------
    // Gap event: correct missing/highest_buffered values
    // ----------------------------------------------------------------

    #[test]
    fn gap_event_missing_and_highest_buffered() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_millis(50));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
        // last_delivered = 1, next_expected = 2.

        // Buffer 5, 7, 9.
        assert_eq!(buf.insert(seq(5), 50, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(7), 70, t0), InsertResult::Buffered);
        assert_eq!(buf.insert(seq(9), 90, t0), InsertResult::Buffered);
        assert_eq!(buf.len(), 3);

        // Advance time past timeout.
        let t1 = t0 + Duration::from_millis(100);

        // In one call: evict gap at 2,3,4 → deliver 5;
        // evict gap at 6 → deliver 7;
        // evict gap at 8 → deliver 9.
        let delivered = buf.deliver_contiguous(t1);
        assert_eq!(delivered, vec![50, 70, 90]);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.next_expected().0, 10); // last_delivered=9, next=10

        let gaps = buf.take_gap_events();
        assert_eq!(gaps.len(), 3);
        assert_eq!(gaps[0].missing.0, 2);
        assert_eq!(gaps[0].highest_buffered.0, 9);
        assert_eq!(gaps[1].missing.0, 6);
        assert_eq!(gaps[1].highest_buffered.0, 9);
        assert_eq!(gaps[2].missing.0, 8);
        assert_eq!(gaps[2].highest_buffered.0, 9);
    }

    // ----------------------------------------------------------------
    // Zero-window edge case
    // ----------------------------------------------------------------

    #[test]
    fn zero_window_buffer_rejects_out_of_order() {
        let mut buf = ReorderBuffer::<u32>::new(0, Duration::from_secs(5));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));

        // Out-of-order immediately WindowFull.
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::WindowFull);
    }

    // ----------------------------------------------------------------
    // take_gap_events drains the queue
    // ----------------------------------------------------------------

    #[test]
    fn take_gap_events_drains_queue() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_millis(10));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Buffered);

        let t1 = t0 + Duration::from_millis(50);
        buf.deliver_contiguous(t1);

        let first = buf.take_gap_events();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].missing.0, 2);

        let second = buf.take_gap_events();
        assert!(second.is_empty());
    }

    // ----------------------------------------------------------------
    // No false timeouts for in-order entries
    // ----------------------------------------------------------------

    #[test]
    fn no_false_timeout_for_in_order_entries() {
        let mut buf = ReorderBuffer::<u32>::new(16, Duration::from_millis(100));
        let t0 = now();

        assert_eq!(buf.insert(seq(1), 10, t0), InsertResult::Accepted(10));
        assert_eq!(buf.insert(seq(2), 20, t0), InsertResult::Accepted(20));
        assert_eq!(buf.insert(seq(3), 30, t0), InsertResult::Accepted(30));

        let t1 = t0 + Duration::from_millis(500);
        let delivered = buf.deliver_contiguous(t1);
        assert!(delivered.is_empty());
        assert!(buf.take_gap_events().is_empty());
    }
}
