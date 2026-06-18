// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TDMA slot allocator: deterministic slot allocation with configurable
//! slot count, slot duration, guard intervals, and round-robin advancement.
//!
//! Produces [`TransmitWindow`] descriptors for per-node bounded-latency
//! transmit scheduling. Slot assignment is deterministic via
//! [`slot_for_node`](TdmaSlotAllocator::slot_for_node).

use std::time::Duration;

// ---------------------------------------------------------------------------
// TdmaSlotAllocator
// ---------------------------------------------------------------------------

/// Deterministic TDMA slot allocator for multi-node transport scheduling.
///
/// Divides time into a repeating frame of `slot_count` transmit windows,
/// each of `slot_duration` followed by a `guard_interval` to absorb clock
/// drift. The allocator provides round-robin advancement, deterministic
/// per-node slot assignment, and slot-boundary arithmetic.
///
/// # Frame layout
///
/// ```text
/// |-- slot 0 active --|-- guard 0 --|-- slot 1 active --|-- guard 1 --|...
/// ```
///
/// The frame repeats indefinitely. Slot and guard boundaries are computed
/// relative to frame start (offset zero).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdmaSlotAllocator {
    /// Number of slots per frame (1..65535).
    slot_count: u16,
    /// Duration of each slot's active transmit window.
    slot_duration: Duration,
    /// Guard interval between adjacent slots.
    guard_interval: Duration,
    /// Current slot index for round-robin advancement.
    current_slot: u16,
}

impl TdmaSlotAllocator {
    /// Create a new allocator.
    ///
    /// Returns `None` if `slot_count` is zero or `slot_duration` is zero
    /// (guard may be zero).
    pub fn new(slot_count: u16, slot_duration: Duration, guard_interval: Duration) -> Option<Self> {
        if slot_count == 0 || slot_duration.is_zero() {
            return None;
        }
        Some(Self {
            slot_count,
            slot_duration,
            guard_interval,
            current_slot: 0,
        })
    }

    /// Number of slots per frame.
    pub fn slot_count(&self) -> u16 {
        self.slot_count
    }

    /// Duration of each slot's active transmit window.
    pub fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    /// Guard interval between adjacent slots.
    pub fn guard_interval(&self) -> Duration {
        self.guard_interval
    }

    /// Total duration of one complete frame cycle.
    pub fn frame_duration(&self) -> Duration {
        let slot_plus_guard = self.slot_duration + self.guard_interval;
        slot_plus_guard * self.slot_count as u32
    }

    // ------------------------------------------------------------------
    // Slot boundary arithmetic
    // ------------------------------------------------------------------

    /// Start time of the active window for `slot_index`, as a [`Duration`]
    /// offset from the frame origin.
    ///
    /// `slot_index` is taken modulo [`slot_count`](Self::slot_count).
    pub fn slot_start(&self, slot_index: u16) -> Duration {
        let idx = slot_index % self.slot_count;
        let slot_plus_guard = self.slot_duration + self.guard_interval;
        slot_plus_guard * idx as u32
    }

    /// End time of the active window for `slot_index` (exclusive).
    pub fn slot_end(&self, slot_index: u16) -> Duration {
        self.slot_start(slot_index) + self.slot_duration
    }

    /// Start of the guard interval following `slot_index`.
    pub fn guard_start(&self, slot_index: u16) -> Duration {
        self.slot_end(slot_index)
    }

    /// End of the guard interval following `slot_index` (start of the
    /// next slot's active window).
    pub fn guard_end(&self, slot_index: u16) -> Duration {
        self.guard_start(slot_index) + self.guard_interval
    }

    /// Return the slot index (0-based) that owns the given `offset`
    /// within one frame. Returns `None` when `offset` falls in a guard
    /// interval or beyond the last slot.
    pub fn slot_at_offset(&self, offset: Duration) -> Option<u16> {
        let slot_plus_guard = self.slot_duration + self.guard_interval;
        if slot_plus_guard.is_zero() {
            return None;
        }
        let total_ns = offset.as_nanos() as u64;
        let spg_ns = slot_plus_guard.as_nanos() as u64;

        let slot_idx = (total_ns / spg_ns) as u16;
        if slot_idx >= self.slot_count {
            return None;
        }
        let offset_in_region = total_ns % spg_ns;
        let slot_ns = self.slot_duration.as_nanos() as u64;
        if offset_in_region >= slot_ns {
            return None;
        }
        Some(slot_idx)
    }

    // ------------------------------------------------------------------
    // Round-robin advancement
    // ------------------------------------------------------------------

    /// Advance the round-robin cursor and return the next slot index.
    ///
    /// Wraps from `slot_count - 1` back to 0.
    pub fn next_slot(&mut self) -> u16 {
        let slot = self.current_slot;
        self.current_slot = self
            .current_slot
            .wrapping_add(1)
            .wrapping_rem(self.slot_count);
        slot
    }

    /// Peek at the slot that `next_slot` would return without advancing.
    pub fn peek_next_slot(&self) -> u16 {
        self.current_slot
    }

    /// Reset the round-robin cursor to a specific slot.
    pub fn set_current_slot(&mut self, slot: u16) {
        self.current_slot = slot % self.slot_count;
    }

    // ------------------------------------------------------------------
    // Deterministic per-node assignment
    // ------------------------------------------------------------------

    /// Deterministically assign a slot index to a node.
    ///
    /// Uses a multiply-rotate-xor mix of `node_id` and `clock_offset` to
    /// produce a stable mapping. Two nodes with identical clock offsets
    /// receive distinct slots (via node_id). A single node with varying
    /// clock offset shifts its assigned slot.
    pub fn slot_for_node(&self, node_id: u64, clock_offset: Duration) -> u16 {
        let offset_ns = clock_offset.as_nanos() as u64;
        let mixed = node_id
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(17)
            .wrapping_add(offset_ns);
        (mixed % self.slot_count as u64) as u16
    }

    // ------------------------------------------------------------------
    // Transmit-window construction
    // ------------------------------------------------------------------

    /// Build the [`TransmitWindow`] descriptor for `slot_index`.
    pub fn transmit_window(&self, slot_index: u16) -> TransmitWindow {
        let idx = slot_index % self.slot_count;
        TransmitWindow {
            slot_index: idx,
            active_start: self.slot_start(idx),
            active_end: self.slot_end(idx),
            guard_start: self.guard_start(idx),
            guard_end: self.guard_end(idx),
        }
    }

    /// Iterator over all transmit windows in order.
    pub fn windows(&self) -> impl Iterator<Item = TransmitWindow> + '_ {
        (0..self.slot_count).map(|i| self.transmit_window(i))
    }
}

// ---------------------------------------------------------------------------
// TransmitWindow
// ---------------------------------------------------------------------------

/// Describes one TDMA transmit window: the active interval when a node
/// may transmit, plus the guard interval that absorbs clock drift before
/// the next slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmitWindow {
    /// Slot index within the frame.
    pub slot_index: u16,
    /// Start of the active transmit window (offset from frame origin).
    pub active_start: Duration,
    /// End of the active transmit window (exclusive).
    pub active_end: Duration,
    /// Start of the guard interval (same as `active_end`).
    pub guard_start: Duration,
    /// End of the guard interval (start of next slot's active window).
    pub guard_end: Duration,
}

impl TransmitWindow {
    /// True when `offset` falls inside the active transmit window.
    pub fn is_active_at(&self, offset: Duration) -> bool {
        offset >= self.active_start && offset < self.active_end
    }

    /// True when `offset` falls inside the guard interval.
    pub fn is_guard_at(&self, offset: Duration) -> bool {
        offset >= self.guard_start && offset < self.guard_end
    }

    /// True when the node assigned to this slot may transmit at `offset`
    /// (i.e. inside the active window, not the guard).
    pub fn can_transmit_at(&self, offset: Duration) -> bool {
        self.is_active_at(offset)
    }

    /// Duration of the active transmit window.
    pub fn active_duration(&self) -> Duration {
        self.active_end - self.active_start
    }

    /// Duration of the guard interval.
    pub fn guard_duration(&self) -> Duration {
        self.guard_end - self.guard_start
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Construction ---

    #[test]
    fn rejects_zero_slot_count() {
        assert!(
            TdmaSlotAllocator::new(0, Duration::from_millis(10), Duration::from_millis(2))
                .is_none()
        );
    }

    #[test]
    fn rejects_zero_slot_duration() {
        assert!(TdmaSlotAllocator::new(8, Duration::ZERO, Duration::from_millis(2)).is_none());
    }

    #[test]
    fn allows_zero_guard() {
        let a = TdmaSlotAllocator::new(4, Duration::from_millis(10), Duration::ZERO).unwrap();
        assert_eq!(a.guard_interval(), Duration::ZERO);
    }

    #[test]
    fn accessors_return_config() {
        let a =
            TdmaSlotAllocator::new(8, Duration::from_millis(10), Duration::from_millis(2)).unwrap();
        assert_eq!(a.slot_count(), 8);
        assert_eq!(a.slot_duration(), Duration::from_millis(10));
        assert_eq!(a.guard_interval(), Duration::from_millis(2));
    }

    // --- Slot boundary arithmetic ---

    fn test_alloc() -> TdmaSlotAllocator {
        TdmaSlotAllocator::new(8, Duration::from_millis(10), Duration::from_millis(2)).unwrap()
    }

    #[test]
    fn frame_duration() {
        let a = test_alloc();
        // 8 slots * (10ms active + 2ms guard) = 96ms
        assert_eq!(a.frame_duration(), Duration::from_millis(96));
    }

    #[test]
    fn slot_start_end() {
        let a = test_alloc();
        assert_eq!(a.slot_start(0), Duration::from_millis(0));
        assert_eq!(a.slot_end(0), Duration::from_millis(10));

        assert_eq!(a.slot_start(1), Duration::from_millis(12));
        assert_eq!(a.slot_end(1), Duration::from_millis(22));

        assert_eq!(a.slot_start(7), Duration::from_millis(84));
        assert_eq!(a.slot_end(7), Duration::from_millis(94));
    }

    #[test]
    fn slot_start_wraps_into_frame() {
        let a = test_alloc();
        // slot_index=8 wraps to slot 0
        assert_eq!(a.slot_start(8), Duration::from_millis(0));
        assert_eq!(a.slot_start(15), Duration::from_millis(84));
    }

    #[test]
    fn guard_start_end() {
        let a = test_alloc();
        assert_eq!(a.guard_start(0), Duration::from_millis(10));
        assert_eq!(a.guard_end(0), Duration::from_millis(12));

        assert_eq!(a.guard_start(1), Duration::from_millis(22));
        assert_eq!(a.guard_end(1), Duration::from_millis(24));
    }

    #[test]
    fn slot_at_offset_active() {
        let a = test_alloc();
        assert_eq!(a.slot_at_offset(Duration::from_millis(0)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_millis(5)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_millis(9)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_millis(12)), Some(1));
        assert_eq!(a.slot_at_offset(Duration::from_millis(84)), Some(7));
        assert_eq!(a.slot_at_offset(Duration::from_millis(93)), Some(7));
    }

    #[test]
    fn slot_at_offset_guard() {
        let a = test_alloc();
        assert_eq!(a.slot_at_offset(Duration::from_millis(10)), None);
        assert_eq!(a.slot_at_offset(Duration::from_millis(11)), None);
        assert_eq!(a.slot_at_offset(Duration::from_millis(22)), None);
        assert_eq!(a.slot_at_offset(Duration::from_millis(23)), None);
    }

    #[test]
    fn slot_at_offset_beyond_last_slot() {
        let a = test_alloc();
        assert_eq!(a.slot_at_offset(Duration::from_millis(94)), None);
        assert_eq!(a.slot_at_offset(Duration::from_millis(95)), None);
        assert_eq!(a.slot_at_offset(Duration::from_millis(96)), None);
    }

    // --- Round-robin advancement ---

    #[test]
    fn next_slot_round_robin() {
        let mut a = test_alloc();
        let order: Vec<u16> = (0..8).map(|_| a.next_slot()).collect();
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn next_slot_wraps_around() {
        let mut a = test_alloc();
        for _ in 0..7 {
            a.next_slot();
        }
        assert_eq!(a.peek_next_slot(), 7);
        assert_eq!(a.next_slot(), 7);
        assert_eq!(a.next_slot(), 0);
        assert_eq!(a.next_slot(), 1);
    }

    #[test]
    fn next_slot_wraps_at_u16_max() {
        let mut a =
            TdmaSlotAllocator::new(u16::MAX, Duration::from_micros(1), Duration::ZERO).unwrap();
        a.set_current_slot(u16::MAX - 1);
        assert_eq!(a.next_slot(), u16::MAX - 1);
        assert_eq!(a.next_slot(), 0);
        assert_eq!(a.next_slot(), 1);
    }

    #[test]
    fn peek_next_slot_without_advancing() {
        let mut a = test_alloc();
        assert_eq!(a.peek_next_slot(), 0);
        assert_eq!(a.peek_next_slot(), 0);
        a.next_slot();
        assert_eq!(a.peek_next_slot(), 1);
    }

    #[test]
    fn set_current_slot_resets_cursor() {
        let mut a = test_alloc();
        a.set_current_slot(5);
        assert_eq!(a.next_slot(), 5);
        assert_eq!(a.next_slot(), 6);
    }

    #[test]
    fn set_current_slot_wraps() {
        let mut a = test_alloc();
        a.set_current_slot(10); // 10 % 8 = 2
        assert_eq!(a.peek_next_slot(), 2);
    }

    // --- Deterministic slot_for_node ---

    #[test]
    fn slot_for_node_is_deterministic() {
        let a = test_alloc();
        let s1 = a.slot_for_node(42, Duration::from_millis(0));
        let s2 = a.slot_for_node(42, Duration::from_millis(0));
        assert_eq!(s1, s2);
    }

    #[test]
    fn slot_for_node_different_nodes_different_slots() {
        let a = TdmaSlotAllocator::new(1024, Duration::from_millis(1), Duration::ZERO).unwrap();
        let s10 = a.slot_for_node(10, Duration::ZERO);
        let s20 = a.slot_for_node(20, Duration::ZERO);
        assert_ne!(s10, s20);
    }

    #[test]
    fn slot_for_node_result_in_range() {
        let a = test_alloc();
        for node_id in 0..100u64 {
            for offset_ms in [0u64, 1, 5, 10, 100] {
                let s = a.slot_for_node(node_id, Duration::from_millis(offset_ms));
                assert!(
                    s < 8,
                    "slot {s} out of range for node={node_id} offset={offset_ms}ms"
                );
            }
        }
    }

    #[test]
    fn slot_for_node_clock_offset_affects_result() {
        let a = TdmaSlotAllocator::new(256, Duration::from_millis(10), Duration::from_millis(2))
            .unwrap();
        let s0 = a.slot_for_node(1, Duration::ZERO);
        let s1 = a.slot_for_node(1, Duration::from_nanos(1_000_000));
        // With 256 slots, the 1ms offset should shift the result
        assert_ne!(s0, s1);
    }

    // --- TransmitWindow ---

    #[test]
    fn transmit_window_boundaries() {
        let a = test_alloc();
        let w = a.transmit_window(0);
        assert_eq!(w.slot_index, 0);
        assert_eq!(w.active_start, Duration::from_millis(0));
        assert_eq!(w.active_end, Duration::from_millis(10));
        assert_eq!(w.guard_start, Duration::from_millis(10));
        assert_eq!(w.guard_end, Duration::from_millis(12));
        assert_eq!(w.active_duration(), Duration::from_millis(10));
        assert_eq!(w.guard_duration(), Duration::from_millis(2));
    }

    #[test]
    fn transmit_window_is_active_at() {
        let a = test_alloc();
        let w = a.transmit_window(0);
        assert!(w.is_active_at(Duration::from_millis(0)));
        assert!(w.is_active_at(Duration::from_millis(5)));
        assert!(w.is_active_at(Duration::from_millis(9)));
        assert!(!w.is_active_at(Duration::from_millis(10)));
        assert!(!w.is_active_at(Duration::from_millis(11)));
        assert!(!w.is_active_at(Duration::from_millis(12)));
    }

    #[test]
    fn transmit_window_is_guard_at() {
        let a = test_alloc();
        let w = a.transmit_window(0);
        assert!(!w.is_guard_at(Duration::from_millis(0)));
        assert!(!w.is_guard_at(Duration::from_millis(9)));
        assert!(w.is_guard_at(Duration::from_millis(10)));
        assert!(w.is_guard_at(Duration::from_millis(11)));
        assert!(!w.is_guard_at(Duration::from_millis(12)));
    }

    #[test]
    fn transmit_window_can_transmit_at() {
        let a = test_alloc();
        let w = a.transmit_window(0);
        assert!(w.can_transmit_at(Duration::from_millis(0)));
        assert!(w.can_transmit_at(Duration::from_millis(5)));
        assert!(!w.can_transmit_at(Duration::from_millis(10)));
        assert!(!w.can_transmit_at(Duration::from_millis(11)));
    }

    #[test]
    fn transmit_window_last_slot() {
        let a = test_alloc();
        let w = a.transmit_window(7);
        assert_eq!(w.active_start, Duration::from_millis(84));
        assert_eq!(w.active_end, Duration::from_millis(94));
        assert_eq!(w.guard_start, Duration::from_millis(94));
        assert_eq!(w.guard_end, Duration::from_millis(96));
    }

    #[test]
    fn windows_iterator_all_slots() {
        let a = test_alloc();
        let windows: Vec<TransmitWindow> = a.windows().collect();
        assert_eq!(windows.len(), 8);
        for (i, w) in windows.iter().enumerate() {
            assert_eq!(w.slot_index, i as u16);
        }
    }

    #[test]
    fn zero_guard_no_gap_between_slots() {
        let a = TdmaSlotAllocator::new(4, Duration::from_millis(10), Duration::ZERO).unwrap();
        let w0 = a.transmit_window(0);
        let w1 = a.transmit_window(1);
        assert_eq!(w0.active_end, w1.active_start);
        assert_eq!(w0.guard_start, w1.active_start);
        assert_eq!(w0.guard_duration(), Duration::ZERO);
    }

    // --- Edge cases ---

    #[test]
    fn single_slot_frame() {
        let a = TdmaSlotAllocator::new(1, Duration::from_millis(100), Duration::from_millis(10))
            .unwrap();
        assert_eq!(a.slot_count(), 1);
        assert_eq!(a.frame_duration(), Duration::from_millis(110));
        assert_eq!(a.slot_start(0), Duration::from_millis(0));
        assert_eq!(a.slot_end(0), Duration::from_millis(100));
        assert_eq!(a.guard_start(0), Duration::from_millis(100));
        assert_eq!(a.guard_end(0), Duration::from_millis(110));
        assert_eq!(a.slot_at_offset(Duration::from_millis(0)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_millis(105)), None);
    }

    #[test]
    fn next_slot_single_item_wraps_to_zero() {
        let mut a = TdmaSlotAllocator::new(1, Duration::from_millis(10), Duration::ZERO).unwrap();
        assert_eq!(a.next_slot(), 0);
        assert_eq!(a.next_slot(), 0);
        assert_eq!(a.next_slot(), 0);
    }

    #[test]
    fn slot_at_offset_sub_millisecond_precision() {
        let a = TdmaSlotAllocator::new(2, Duration::from_nanos(500), Duration::from_nanos(100))
            .unwrap();
        assert_eq!(a.slot_at_offset(Duration::from_nanos(0)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_nanos(499)), Some(0));
        assert_eq!(a.slot_at_offset(Duration::from_nanos(500)), None);
        assert_eq!(a.slot_at_offset(Duration::from_nanos(599)), None);
        assert_eq!(a.slot_at_offset(Duration::from_nanos(600)), Some(1));
    }
}
