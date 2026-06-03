//! Frame-based TDMA scheduler: repeating schedule frame with per-slot
//! node assignment, guard intervals, deterministic arbitration, and
//! fairness tracking across observation windows.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TdmaFrame
// ---------------------------------------------------------------------------

/// A repeating TDMA schedule frame: fixed slot count, per-slot width, and
/// guard interval between adjacent slots.
///
/// Each frame is composed of `slot_count` active windows of `slot_width_us`
/// microseconds, each followed by a guard interval of `guard_interval_us`
/// microseconds. The frame repeats indefinitely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdmaFrame {
    /// Number of slots in one frame.
    pub slot_count: usize,
    /// Width of each slot's active window in microseconds.
    pub slot_width_us: u64,
    /// Guard interval between slots in microseconds.
    pub guard_interval_us: u64,
}

impl TdmaFrame {
    /// Create a new frame. Returns `None` if `slot_count` is zero or
    /// `slot_width_us` is zero (guard may be zero).
    pub fn new(slot_count: usize, slot_width_us: u64, guard_interval_us: u64) -> Option<Self> {
        if slot_count == 0 || slot_width_us == 0 {
            return None;
        }
        Some(Self {
            slot_count,
            slot_width_us,
            guard_interval_us,
        })
    }

    /// Duration of one complete frame cycle in microseconds.
    pub fn frame_duration_us(&self) -> u64 {
        self.slot_count as u64 * (self.slot_width_us + self.guard_interval_us)
    }

    /// Start time of a given slot index within the frame (in microseconds
    /// relative to frame start).
    pub fn slot_start_us(&self, slot_index: usize) -> u64 {
        slot_index as u64 * (self.slot_width_us + self.guard_interval_us)
    }

    /// End time of a given slot's active window (exclusive), relative to
    /// frame start.
    pub fn slot_end_us(&self, slot_index: usize) -> u64 {
        self.slot_start_us(slot_index) + self.slot_width_us
    }

    /// Given a position in microseconds within the frame, return the slot
    /// index that owns that position (in [0, slot_count)). Returns `None`
    /// if the position falls in a guard interval.
    pub fn slot_index_at(&self, position_us: u64) -> Option<usize> {
        let slot = position_us / (self.slot_width_us + self.guard_interval_us);
        let idx = slot as usize;
        if idx >= self.slot_count {
            return None;
        }
        let offset_in_region = position_us % (self.slot_width_us + self.guard_interval_us);
        if offset_in_region >= self.slot_width_us {
            return None;
        }
        Some(idx)
    }
}

// ---------------------------------------------------------------------------
// TdmaSlotAssignment
// ---------------------------------------------------------------------------

/// Maps nodes to contiguous slot ranges within a [`TdmaFrame`].
///
/// Assignments are stored in slot order for deterministic lookup.
#[derive(Debug, Clone)]
pub struct TdmaSlotAssignment {
    assignments: Vec<(u64, usize, usize)>,
}

impl TdmaSlotAssignment {
    /// Create an empty assignment.
    pub fn new() -> Self {
        Self {
            assignments: Vec::new(),
        }
    }

    /// Assign a contiguous range of slots to a node. Replaces any prior
    /// assignment for `node_id`.
    pub fn assign(&mut self, node_id: u64, start_slot: usize, slot_count: usize) {
        self.assignments.retain(|(id, _, _)| *id != node_id);
        self.assignments.push((node_id, start_slot, slot_count));
        self.assignments.sort_by_key(|(_, start, _)| *start);
    }

    /// Remove a node's assignment.
    pub fn remove(&mut self, node_id: u64) {
        self.assignments.retain(|(id, _, _)| *id != node_id);
    }

    /// Find which node owns the given slot index. Returns `None` if the
    /// slot is unassigned.
    pub fn owner_of_slot(&self, slot_index: usize) -> Option<u64> {
        for &(node_id, start, count) in &self.assignments {
            if slot_index >= start && slot_index < start + count {
                return Some(node_id);
            }
        }
        None
    }

    /// Number of nodes with assignments.
    pub fn node_count(&self) -> usize {
        self.assignments.len()
    }

    /// Total number of assigned slots across all nodes.
    pub fn total_assigned_slots(&self) -> usize {
        self.assignments.iter().map(|(_, _, count)| count).sum()
    }

    /// Get the slot count assigned to a specific node.
    pub fn node_slot_count(&self, node_id: u64) -> usize {
        self.assignments
            .iter()
            .find(|(id, _, _)| *id == node_id)
            .map(|(_, _, count)| *count)
            .unwrap_or(0)
    }

    /// Return an iterator over (node_id, start_slot, slot_count) in slot order.
    pub fn iter(&self) -> impl Iterator<Item = &(u64, usize, usize)> {
        self.assignments.iter()
    }
}

impl Default for TdmaSlotAssignment {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FrameScheduler errors
// ---------------------------------------------------------------------------

/// Errors returned by [`FrameScheduler`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameSchedulerError {
    #[error("node {0} is already registered")]
    DuplicateNode(u64),

    #[error("node {0} is not registered")]
    NodeNotRegistered(u64),

    #[error("not enough free slots: requested {requested}, available {available}")]
    InsufficientSlots { requested: usize, available: usize },

    #[error("slot_width_us must be positive (got {0})")]
    SlotWidthZero(u64),

    #[error("slot_count must be positive (got {0})")]
    SlotCountZero(usize),
}

// ---------------------------------------------------------------------------
// FrameScheduler
// ---------------------------------------------------------------------------

/// A deterministic TDMA frame scheduler.
///
/// Registered nodes are assigned contiguous slot ranges within a repeating
/// [`TdmaFrame`]. Callers query slot ownership at a given monotonic
/// microsecond timestamp via [`poll_slot`](Self::poll_slot); the scheduler
/// returns `None` during guard intervals. Registration and unregistration
/// take effect at the next frame boundary.
///
/// Fairness is tracked by counting how many slots each node owns per frame.
/// [`validate_fairness`](Self::validate_fairness) checks that every node's
/// actual slot share matches its proportional allocation within ±1 slot
/// over a configurable observation window.
pub struct FrameScheduler {
    frame: TdmaFrame,
    assignment: TdmaSlotAssignment,
    pending_assignment: Option<TdmaSlotAssignment>,
    registered: HashMap<u64, usize>,
    slot_counters: HashMap<u64, u64>,
    observation_window_frames: u64,
    last_counted_frame: u64,
    frame_counter: u64,
}

impl FrameScheduler {
    /// Create a new frame scheduler.
    ///
    /// `observation_window_frames` determines how many frames of history
    /// [`validate_fairness`](Self::validate_fairness) considers. Must be
    /// at least 1.
    pub fn new(frame: TdmaFrame, observation_window_frames: u64) -> Self {
        let window = if observation_window_frames == 0 {
            1
        } else {
            observation_window_frames
        };
        Self {
            frame,
            assignment: TdmaSlotAssignment::new(),
            pending_assignment: None,
            registered: HashMap::new(),
            slot_counters: HashMap::new(),
            observation_window_frames: window,
            last_counted_frame: u64::MAX,
            frame_counter: 0,
        }
    }

    /// Return a reference to the frame configuration.
    pub fn frame(&self) -> &TdmaFrame {
        &self.frame
    }

    /// Return the number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.registered.len()
    }

    /// Return the number of free (unassigned) slots.
    pub fn free_slots(&self) -> usize {
        self.frame
            .slot_count
            .saturating_sub(self.current_assignment().total_assigned_slots())
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a node and assign it `requested_slots` contiguous slots.
    ///
    /// The assignment takes effect at the next frame boundary. Returns an
    /// error if the node is already registered or if there aren't enough
    /// free slots.
    pub fn register_node(
        &mut self,
        node_id: u64,
        requested_slots: usize,
    ) -> Result<(), FrameSchedulerError> {
        if self.registered.contains_key(&node_id) {
            return Err(FrameSchedulerError::DuplicateNode(node_id));
        }

        let mut pending = self.current_assignment().clone();
        let start = pending.total_assigned_slots();
        let available = self.frame.slot_count.saturating_sub(start);
        if requested_slots > available {
            return Err(FrameSchedulerError::InsufficientSlots {
                requested: requested_slots,
                available,
            });
        }

        pending.assign(node_id, start, requested_slots);
        self.registered.insert(node_id, requested_slots);
        self.pending_assignment = Some(pending);
        Ok(())
    }

    /// Unregister a node. Its slots become free. Takes effect at the next
    /// frame boundary.
    pub fn unregister_node(&mut self, node_id: u64) -> Result<(), FrameSchedulerError> {
        if !self.registered.contains_key(&node_id) {
            return Err(FrameSchedulerError::NodeNotRegistered(node_id));
        }

        let mut pending = self.current_assignment().clone();
        pending.remove(node_id);

        // Compact: rebuild with remaining assignments in order, starting
        // from slot 0.
        let mut compacted = TdmaSlotAssignment::new();
        let mut cursor = 0usize;
        for &(id, _start, count) in pending.iter() {
            compacted.assign(id, cursor, count);
            cursor += count;
        }

        self.registered.remove(&node_id);
        self.slot_counters.remove(&node_id);
        self.pending_assignment = Some(compacted);
        Ok(())
    }

    /// Check whether a node is registered.
    pub fn is_registered(&self, node_id: u64) -> bool {
        self.registered.contains_key(&node_id)
    }

    // ------------------------------------------------------------------
    // Slot arbitration
    // ------------------------------------------------------------------

    /// Determine which node (if any) owns the slot at the given monotonic
    /// microsecond timestamp.
    ///
    /// Returns `Some(node_id)` if a registered node owns the slot, or
    /// `None` during guard intervals or when no node is assigned to that
    /// slot.
    pub fn poll_slot(&mut self, timestamp_us: u64) -> Option<u64> {
        let fd = self.frame.frame_duration_us();
        if fd == 0 {
            return None;
        }

        let frame_num = timestamp_us / fd;
        self.apply_pending_if_new_frame(frame_num);

        let position = timestamp_us % fd;
        let slot_idx = self.frame.slot_index_at(position)?;
        let owner = self.assignment.owner_of_slot(slot_idx);

        // Count slots once per frame.
        if frame_num != self.last_counted_frame {
            self.count_frame_slots();
            self.last_counted_frame = frame_num;
            self.frame_counter = self.frame_counter.saturating_add(1);
        }

        owner
    }

    /// Return the next microsecond timestamp at which the caller should
    /// re-check slot ownership.
    ///
    /// If currently inside a slot, returns the slot's end time. If in a
    /// guard interval, returns the start of the next slot. If past the
    /// last slot, returns the start of the next frame.
    pub fn next_slot_deadline(&self, timestamp_us: u64) -> u64 {
        let fd = self.frame.frame_duration_us();
        if fd == 0 {
            return timestamp_us;
        }

        let position = timestamp_us % fd;
        let frame_base = timestamp_us - position;
        let slot_plus_guard = self.frame.slot_width_us + self.frame.guard_interval_us;

        if slot_plus_guard == 0 {
            return timestamp_us;
        }

        let slot_idx = (position / slot_plus_guard) as usize;

        if slot_idx >= self.frame.slot_count {
            return frame_base + fd;
        }

        let _slot_start = self.frame.slot_start_us(slot_idx);
        let slot_end = self.frame.slot_end_us(slot_idx);

        if position < slot_end {
            frame_base + slot_end
        } else if slot_idx + 1 < self.frame.slot_count {
            frame_base + self.frame.slot_start_us(slot_idx + 1)
        } else {
            frame_base + fd
        }
    }

    // ------------------------------------------------------------------
    // Fairness
    // ------------------------------------------------------------------

    /// Validate that every registered node's slot ownership share over
    /// the observation window matches its proportional allocation within
    /// ±1 slot.
    ///
    /// Returns `true` if all nodes are within the fairness bound.
    pub fn validate_fairness(&self) -> bool {
        let total_slots = self.frame.slot_count as u64;
        if total_slots == 0 {
            return self.registered.is_empty();
        }

        let total_counted: u64 = self.slot_counters.values().sum();
        if total_counted == 0 {
            return true;
        }

        for (&node_id, &requested) in &self.registered {
            let actual = self.slot_counters.get(&node_id).copied().unwrap_or(0);
            let expected = (requested as u64 * total_counted) / total_slots;

            let lower = expected.saturating_sub(1);
            let upper = expected.saturating_add(1);
            if actual < lower || actual > upper {
                return false;
            }
        }
        true
    }

    /// Return the slot counter for a specific node.
    pub fn slot_counter(&self, node_id: u64) -> u64 {
        self.slot_counters.get(&node_id).copied().unwrap_or(0)
    }

    /// Return the total number of completed frames.
    pub fn frame_counter(&self) -> u64 {
        self.frame_counter
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn current_assignment(&self) -> &TdmaSlotAssignment {
        self.pending_assignment.as_ref().unwrap_or(&self.assignment)
    }

    fn apply_pending_if_new_frame(&mut self, frame_num: u64) {
        if self.pending_assignment.is_some()
            && (frame_num != self.last_counted_frame || self.last_counted_frame == u64::MAX)
        {
            let pending = self.pending_assignment.take().unwrap();
            self.assignment = pending;
        }
    }

    fn count_frame_slots(&mut self) {
        for &(node_id, _start, count) in self.assignment.iter() {
            let entry = self.slot_counters.entry(node_id).or_insert(0);
            *entry = entry.saturating_add(count as u64);
        }

        // Prune counters if observation window is exceeded.
        let window_slots = self.observation_window_frames * self.frame.slot_count as u64;
        let total: u64 = self.slot_counters.values().sum();
        if total > window_slots * 2 {
            for v in self.slot_counters.values_mut() {
                *v = v.saturating_sub(window_slots);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic arbitration free function
// ---------------------------------------------------------------------------

/// Given a [`TdmaFrame`], [`TdmaSlotAssignment`], and a monotonic
/// microsecond timestamp, return the node that owns the current slot, or
/// `None` during guard intervals.
///
/// This is a stateless version of [`FrameScheduler::poll_slot`] usable
/// for one-shot queries without maintaining scheduler state.
pub fn arbitrate_slot(
    frame: &TdmaFrame,
    assignment: &TdmaSlotAssignment,
    timestamp_us: u64,
) -> Option<u64> {
    let fd = frame.frame_duration_us();
    if fd == 0 {
        return None;
    }
    let position = timestamp_us % fd;
    let slot_idx = frame.slot_index_at(position)?;
    assignment.owner_of_slot(slot_idx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_frame() -> TdmaFrame {
        TdmaFrame::new(8, 100, 20).unwrap()
    }

    // --- TdmaFrame ---

    #[test]
    fn frame_rejects_zero_slot_count() {
        assert!(TdmaFrame::new(0, 100, 20).is_none());
    }

    #[test]
    fn frame_rejects_zero_slot_width() {
        assert!(TdmaFrame::new(8, 0, 20).is_none());
    }

    #[test]
    fn frame_allows_zero_guard() {
        let f = TdmaFrame::new(4, 50, 0).unwrap();
        assert_eq!(f.frame_duration_us(), 200);
    }

    #[test]
    fn frame_duration() {
        let f = test_frame();
        assert_eq!(f.frame_duration_us(), 960);
    }

    #[test]
    fn slot_start_and_end() {
        let f = test_frame();
        assert_eq!(f.slot_start_us(0), 0);
        assert_eq!(f.slot_end_us(0), 100);
        assert_eq!(f.slot_start_us(1), 120);
        assert_eq!(f.slot_end_us(1), 220);
        assert_eq!(f.slot_start_us(7), 840);
        assert_eq!(f.slot_end_us(7), 940);
    }

    #[test]
    fn slot_index_at_active_window() {
        let f = test_frame();
        assert_eq!(f.slot_index_at(0), Some(0));
        assert_eq!(f.slot_index_at(50), Some(0));
        assert_eq!(f.slot_index_at(99), Some(0));
        assert_eq!(f.slot_index_at(120), Some(1));
        assert_eq!(f.slot_index_at(840), Some(7));
    }

    #[test]
    fn slot_index_at_guard_interval() {
        let f = test_frame();
        assert_eq!(f.slot_index_at(100), None);
        assert_eq!(f.slot_index_at(119), None);
        assert_eq!(f.slot_index_at(220), None);
        assert_eq!(f.slot_index_at(239), None);
        assert_eq!(f.slot_index_at(940), None);
        assert_eq!(f.slot_index_at(959), None);
    }

    // --- TdmaSlotAssignment ---

    #[test]
    fn assignment_owner_lookup() {
        let mut a = TdmaSlotAssignment::new();
        a.assign(10, 0, 3);
        a.assign(20, 3, 2);
        assert_eq!(a.owner_of_slot(0), Some(10));
        assert_eq!(a.owner_of_slot(2), Some(10));
        assert_eq!(a.owner_of_slot(3), Some(20));
        assert_eq!(a.owner_of_slot(4), Some(20));
        assert_eq!(a.owner_of_slot(5), None);
        assert_eq!(a.node_count(), 2);
        assert_eq!(a.total_assigned_slots(), 5);
    }

    #[test]
    fn assignment_remove() {
        let mut a = TdmaSlotAssignment::new();
        a.assign(10, 0, 3);
        a.assign(20, 3, 2);
        a.remove(10);
        assert_eq!(a.owner_of_slot(0), None);
        assert_eq!(a.owner_of_slot(3), Some(20));
        assert_eq!(a.node_count(), 1);
    }

    #[test]
    fn assignment_node_slot_count() {
        let mut a = TdmaSlotAssignment::new();
        a.assign(42, 0, 5);
        assert_eq!(a.node_slot_count(42), 5);
        assert_eq!(a.node_slot_count(99), 0);
    }

    // --- FrameScheduler: single node ---

    #[test]
    fn single_registered_node_owns_every_slot() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 8).unwrap();

        let mids: [u64; 8] = [50, 170, 290, 410, 530, 650, 770, 890];
        for &t in &mids {
            assert_eq!(s.poll_slot(t), Some(1), "at t={t}");
        }

        assert_eq!(s.poll_slot(100), None);
        assert_eq!(s.poll_slot(220), None);
    }

    // --- FrameScheduler: two nodes alternating ---

    #[test]
    fn two_node_alternating_with_frame_wraparound() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(10, 4).unwrap();
        s.register_node(20, 4).unwrap();

        assert_eq!(s.poll_slot(50), Some(10));
        assert_eq!(s.poll_slot(410), Some(10));
        assert_eq!(s.poll_slot(530), Some(20));
        assert_eq!(s.poll_slot(890), Some(20));

        assert_eq!(s.poll_slot(960 + 50), Some(10));
        assert_eq!(s.poll_slot(960 + 530), Some(20));
    }

    // --- FrameScheduler: N-node round-robin (3,5,8) ---

    #[test]
    fn three_node_round_robin() {
        let frame = TdmaFrame::new(9, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(100, 3).unwrap();
        s.register_node(200, 3).unwrap();
        s.register_node(300, 3).unwrap();

        let mid = |slot: usize| -> u64 { slot as u64 * 120 + 50 };
        assert_eq!(s.poll_slot(mid(0)), Some(100));
        assert_eq!(s.poll_slot(mid(3)), Some(200));
        assert_eq!(s.poll_slot(mid(6)), Some(300));
    }

    #[test]
    fn five_node_round_robin() {
        let frame = TdmaFrame::new(10, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        for i in 0..5u64 {
            s.register_node(i * 20 + 10, 2).unwrap();
        }

        let mid = |slot: usize| -> u64 { slot as u64 * 120 + 50 };
        assert_eq!(s.poll_slot(mid(0)), Some(10));
        assert_eq!(s.poll_slot(mid(2)), Some(30));
        assert_eq!(s.poll_slot(mid(4)), Some(50));
        assert_eq!(s.poll_slot(mid(6)), Some(70));
        assert_eq!(s.poll_slot(mid(8)), Some(90));
    }

    #[test]
    fn eight_node_full_frame() {
        let frame = TdmaFrame::new(8, 100, 0).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        for i in 0..8u64 {
            s.register_node(i + 1, 1).unwrap();
        }

        let mid = |slot: usize| -> u64 { slot as u64 * 100 + 50 };
        for i in 0..8 {
            assert_eq!(s.poll_slot(mid(i)), Some(i as u64 + 1));
        }
    }

    // --- FrameScheduler: guard intervals ---

    #[test]
    fn guard_interval_returns_none_between_adjacent_slots() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 8).unwrap();

        assert_eq!(s.poll_slot(99), Some(1));
        assert_eq!(s.poll_slot(100), None);
        assert_eq!(s.poll_slot(110), None);
        assert_eq!(s.poll_slot(119), None);
        assert_eq!(s.poll_slot(120), Some(1));
    }

    // --- FrameScheduler: register/unregister mid-frame ---

    #[test]
    fn register_mid_frame_defers_to_next_boundary() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        // Start frame 0 with a placeholder node so we can test mid-frame registration.
        s.register_node(99, 1).unwrap();
        s.poll_slot(0); // frame 0 now active
                        // Register a second node mid-frame 0.
        s.register_node(1, 4).unwrap();

        // Mid-frame 0: pending not yet applied, assignment is empty.
        // Still in frame 0: pending not yet applied, original assignment still active.
        assert_eq!(s.poll_slot(50), Some(99));

        // Frame 1: pending applied. Slot 0 stays with 99; slot 1 goes to 1.
        assert_eq!(s.poll_slot(960 + 50), Some(99));
        assert_eq!(s.poll_slot(960 + 170), Some(1));
    }

    #[test]
    fn unregister_mid_frame_removes_at_next_boundary() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 8).unwrap();

        // Activate in frame 0.
        s.poll_slot(50);
        assert_eq!(s.poll_slot(890), Some(1));

        // Unregister mid-frame 0.
        s.unregister_node(1).unwrap();

        // Still active for rest of frame 0.
        assert_eq!(s.poll_slot(890), Some(1));

        // Frame 1: node gone.
        assert_eq!(s.poll_slot(960 + 50), None);
    }

    // --- FrameScheduler: slot boundary precision ---

    #[test]
    fn slot_boundary_microsecond_precision() {
        let frame = TdmaFrame::new(4, 1, 1).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(1, 4).unwrap();

        assert_eq!(s.poll_slot(0), Some(1));
        assert_eq!(s.poll_slot(1), None);
        assert_eq!(s.poll_slot(2), Some(1));
        assert_eq!(s.poll_slot(3), None);
        assert_eq!(s.poll_slot(4), Some(1));
        assert_eq!(s.poll_slot(5), None);
        assert_eq!(s.poll_slot(6), Some(1));
        assert_eq!(s.poll_slot(7), None);
        assert_eq!(s.poll_slot(8), Some(1)); // next frame
    }

    // --- FrameScheduler: next_slot_deadline ---

    #[test]
    fn deadline_from_active_slot() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 8).unwrap();
        s.poll_slot(50);
        assert_eq!(s.next_slot_deadline(50), 100);
        assert_eq!(s.next_slot_deadline(99), 100);
    }

    #[test]
    fn deadline_from_guard_interval() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 8).unwrap();
        s.poll_slot(50);

        assert_eq!(s.next_slot_deadline(100), 120);
        assert_eq!(s.next_slot_deadline(110), 120);
        assert_eq!(s.next_slot_deadline(950), 960);
    }

    // --- FrameScheduler: edge cases ---

    #[test]
    fn zero_registered_nodes_all_slots_return_none() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        assert_eq!(s.poll_slot(50), None);
        assert_eq!(s.poll_slot(500), None);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 4).unwrap();
        let err = s.register_node(1, 2).unwrap_err();
        assert!(matches!(err, FrameSchedulerError::DuplicateNode(1)));
    }

    #[test]
    fn max_nodes_frame_saturation_rejected() {
        let frame = TdmaFrame::new(4, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(1, 2).unwrap();
        s.register_node(2, 2).unwrap();
        let err = s.register_node(3, 1).unwrap_err();
        assert!(matches!(
            err,
            FrameSchedulerError::InsufficientSlots {
                requested: 1,
                available: 0
            }
        ));
    }

    #[test]
    fn unregister_nonexistent_rejected() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        let err = s.unregister_node(99).unwrap_err();
        assert!(matches!(err, FrameSchedulerError::NodeNotRegistered(99)));
    }

    #[test]
    fn unregister_frees_slots_for_reuse() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        s.register_node(1, 4).unwrap();
        s.poll_slot(50); // frame 0
        s.unregister_node(1).unwrap();
        s.poll_slot(960 + 50); // frame 1

        s.register_node(2, 8).unwrap();
        s.poll_slot(1920 + 50); // frame 2
        assert_eq!(s.poll_slot(1920 + 50), Some(2));
        assert_eq!(s.poll_slot(1920 + 890), Some(2));
    }

    // --- FrameScheduler: fairness ---

    #[test]
    fn fairness_equal_allocation() {
        let frame = TdmaFrame::new(8, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(10, 4).unwrap();
        s.register_node(20, 4).unwrap();

        for f in 0..5u64 {
            let base = f * 960;
            for slot in 0..8 {
                s.poll_slot(base + slot as u64 * 120 + 50);
            }
        }

        assert!(s.validate_fairness());
        assert_eq!(s.slot_counter(10), 20);
        assert_eq!(s.slot_counter(20), 20);
    }

    #[test]
    fn fairness_unequal_allocation() {
        let frame = TdmaFrame::new(8, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(10, 6).unwrap();
        s.register_node(20, 2).unwrap();

        for f in 0..10u64 {
            let base = f * 960;
            for slot in 0..8 {
                s.poll_slot(base + slot as u64 * 120 + 50);
            }
        }

        assert!(s.validate_fairness());
        assert_eq!(s.slot_counter(10), 60);
        assert_eq!(s.slot_counter(20), 20);
    }

    #[test]
    fn fairness_within_one_slot_tolerance() {
        let frame = TdmaFrame::new(3, 100, 20).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(10, 2).unwrap();
        s.register_node(20, 1).unwrap();

        for f in 0..3u64 {
            let base = f * 360;
            for slot in 0..3 {
                s.poll_slot(base + slot as u64 * 120 + 50);
            }
        }

        assert!(s.validate_fairness());
    }

    // --- Free function: arbitrate_slot ---

    #[test]
    fn arbitrate_slot_stateless() {
        let frame = test_frame();
        let mut assignment = TdmaSlotAssignment::new();
        assignment.assign(42, 0, 4);
        assignment.assign(99, 4, 4);

        assert_eq!(arbitrate_slot(&frame, &assignment, 50), Some(42));
        assert_eq!(arbitrate_slot(&frame, &assignment, 530), Some(99));
        assert_eq!(arbitrate_slot(&frame, &assignment, 100), None);
    }

    #[test]
    fn arbitrate_slot_empty_assignment() {
        let frame = test_frame();
        let assignment = TdmaSlotAssignment::new();
        assert_eq!(arbitrate_slot(&frame, &assignment, 50), None);
    }

    // --- is_registered ---

    #[test]
    fn is_registered_reflects_state() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        assert!(!s.is_registered(1));
        s.register_node(1, 4).unwrap();
        assert!(s.is_registered(1));
        s.unregister_node(1).unwrap();
        assert!(!s.is_registered(1));
    }

    // --- node_count and free_slots ---

    #[test]
    fn node_count_and_free_slots() {
        let mut s = FrameScheduler::new(test_frame(), 10);
        assert_eq!(s.node_count(), 0);
        assert_eq!(s.free_slots(), 8);

        s.register_node(1, 3).unwrap();
        assert_eq!(s.node_count(), 1);
        assert_eq!(s.free_slots(), 5);
    }

    // --- FrameScheduler: zero guard interval ---

    #[test]
    fn zero_guard_no_none_between_slots() {
        let frame = TdmaFrame::new(4, 100, 0).unwrap();
        let mut s = FrameScheduler::new(frame, 10);
        s.register_node(1, 4).unwrap();

        for t in 0..400 {
            assert_eq!(s.poll_slot(t), Some(1), "at t={t}");
        }
    }

    // --- deadline edge: empty scheduler ---

    #[test]
    fn deadline_with_no_registered_nodes() {
        let s = FrameScheduler::new(TdmaFrame::new(1, 100, 0).unwrap(), 10);
        assert_eq!(s.next_slot_deadline(50), 100);
    }
}
