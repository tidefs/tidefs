// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TDMA clock synchronization: per-node clock offset tracking with bounded
//! drift compensation for guard-interval collision avoidance.

use std::collections::HashMap;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TdmaClockSync
// ---------------------------------------------------------------------------

/// Per-node clock-offset tracker for TDMA slot scheduling.
///
/// Each node reports its observed clock offset relative to a shared
/// reference (typically the cluster monotonic clock). The sync tracker
/// enforces a maximum allowed drift (`max_drift`) and provides
/// compensated slot lookups so a node transmitting slightly early or
/// late still fits within its assigned guard interval.
#[derive(Debug, Clone)]
pub struct TdmaClockSync {
    /// Maximum allowed absolute clock offset before a node is considered
    /// out of bounds and its transmissions are blocked.
    max_drift: Duration,
    /// Per-node clock offset (node `monotonic_now - reference_now`).
    offsets: HashMap<u64, Duration>,
}

impl TdmaClockSync {
    /// Create a new clock-sync tracker with the given maximum drift bound.
    pub fn new(max_drift: Duration) -> Self {
        Self {
            max_drift,
            offsets: HashMap::new(),
        }
    }

    /// Maximum allowed drift bound.
    pub fn max_drift(&self) -> Duration {
        self.max_drift
    }

    /// Number of tracked nodes.
    pub fn node_count(&self) -> usize {
        self.offsets.len()
    }

    // ------------------------------------------------------------------
    // Offset management
    // ------------------------------------------------------------------

    /// Record or update a node's clock offset.
    ///
    /// `offset` is `node_monotonic_now - reference_monotonic_now`:
    /// positive means the node's clock is ahead of the reference.
    pub fn set_offset(&mut self, node_id: u64, offset: Duration) {
        self.offsets.insert(node_id, offset);
    }

    /// Get the last recorded clock offset for `node_id`.
    pub fn offset(&self, node_id: u64) -> Option<Duration> {
        self.offsets.get(&node_id).copied()
    }

    /// Remove a node's offset tracking.
    pub fn remove_node(&mut self, node_id: u64) {
        self.offsets.remove(&node_id);
    }

    // ------------------------------------------------------------------
    // Drift boundedness
    // ------------------------------------------------------------------

    /// Check whether a node's clock offset is within the allowed drift
    /// bound. Returns `false` for unknown nodes.
    pub fn is_within_bounds(&self, node_id: u64) -> bool {
        self.offsets
            .get(&node_id)
            .map(|&offset| offset <= self.max_drift)
            .unwrap_or(false)
    }

    /// Return the absolute drift magnitude for a node.
    ///
    /// Returns `None` for unknown nodes.
    pub fn drift_magnitude(&self, node_id: u64) -> Option<Duration> {
        self.offsets.get(&node_id).copied()
    }

    /// Check whether any tracked node exceeds the drift bound.
    pub fn any_out_of_bounds(&self) -> bool {
        self.offsets.values().any(|&offset| offset > self.max_drift)
    }

    /// List all nodes currently out of bounds.
    pub fn out_of_bounds_nodes(&self) -> Vec<u64> {
        self.offsets
            .iter()
            .filter(|(_, &offset)| offset > self.max_drift)
            .map(|(&id, _)| id)
            .collect()
    }

    // ------------------------------------------------------------------
    // Compensated slot assignment
    // ------------------------------------------------------------------

    /// Return the clock-compensated slot index for a node given a raw
    /// slot allocator result.
    ///
    /// `raw_slot` is the slot assigned by [`TdmaSlotAllocator::slot_for_node`]
    /// without clock compensation. This method shifts the slot forward or
    /// backward by one position to keep the node within its guard interval.
    ///
    /// Returns `None` when the node is unknown or out of bounds.
    pub fn compensated_slot(&self, node_id: u64, raw_slot: u16, slot_count: u16) -> Option<u16> {
        let &offset = self.offsets.get(&node_id)?;

        if offset > self.max_drift {
            return None;
        }

        if slot_count == 0 {
            return None;
        }

        // If the node is ahead of reference, shift its slot earlier to
        // compensate (so it transmits in the guard band of the previous
        // slot, avoiding collision with the next slot holder).
        //
        // Compensation is +1 slot shift when drift exceeds half the
        // guard interval. This is a coarse adjustment; a production
        // implementation would use microsecond-precise compensation.
        let half_drift = self.max_drift / 2;
        let compensated = if offset > half_drift {
            raw_slot.wrapping_add(1) % slot_count
        } else {
            raw_slot
        };

        Some(compensated)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sync() -> TdmaClockSync {
        TdmaClockSync::new(Duration::from_millis(10))
    }

    #[test]
    fn new_has_zero_nodes() {
        let sync = test_sync();
        assert_eq!(sync.node_count(), 0);
        assert_eq!(sync.max_drift(), Duration::from_millis(10));
    }

    #[test]
    fn set_and_get_offset() {
        let mut sync = test_sync();
        sync.set_offset(1, Duration::from_millis(3));
        assert_eq!(sync.offset(1), Some(Duration::from_millis(3)));
        assert_eq!(sync.offset(99), None);
        assert_eq!(sync.node_count(), 1);
    }

    #[test]
    fn set_offset_overwrites() {
        let mut sync = test_sync();
        sync.set_offset(1, Duration::from_millis(3));
        sync.set_offset(1, Duration::from_millis(7));
        assert_eq!(sync.offset(1), Some(Duration::from_millis(7)));
        assert_eq!(sync.node_count(), 1);
    }

    #[test]
    fn remove_node_clears_tracking() {
        let mut sync = test_sync();
        sync.set_offset(1, Duration::from_millis(3));
        sync.remove_node(1);
        assert_eq!(sync.offset(1), None);
        assert_eq!(sync.node_count(), 0);
    }

    #[test]
    fn is_within_bounds_checks_max_drift() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(5));
        sync.set_offset(1, Duration::from_millis(3));
        assert!(sync.is_within_bounds(1));
        sync.set_offset(1, Duration::from_millis(5));
        assert!(sync.is_within_bounds(1));
        sync.set_offset(1, Duration::from_millis(6));
        assert!(!sync.is_within_bounds(1));
    }

    #[test]
    fn is_within_bounds_unknown_node() {
        let sync = test_sync();
        assert!(!sync.is_within_bounds(99));
    }

    #[test]
    fn any_out_of_bounds_detects_exceeding_nodes() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(5));
        assert!(!sync.any_out_of_bounds());

        sync.set_offset(1, Duration::from_millis(3));
        sync.set_offset(2, Duration::from_millis(7));
        assert!(sync.any_out_of_bounds());
    }

    #[test]
    fn out_of_bounds_nodes_lists_exceeding() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(5));
        sync.set_offset(1, Duration::from_millis(3));
        sync.set_offset(2, Duration::from_millis(7));
        sync.set_offset(3, Duration::from_millis(8));
        let mut bad = sync.out_of_bounds_nodes();
        bad.sort();
        assert_eq!(bad, vec![2, 3]);
    }

    #[test]
    fn compensated_slot_unknown_node_returns_none() {
        let sync = test_sync();
        assert_eq!(sync.compensated_slot(99, 5, 16), None);
    }

    #[test]
    fn compensated_slot_out_of_bounds_returns_none() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(5));
        sync.set_offset(1, Duration::from_millis(7));
        assert_eq!(sync.compensated_slot(1, 5, 16), None);
    }

    #[test]
    fn compensated_slot_within_half_drift_no_shift() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(10));
        // offset 4ms <= 5ms (half of max_drift 10ms) -> no shift
        sync.set_offset(1, Duration::from_millis(4));
        assert_eq!(sync.compensated_slot(1, 3, 8), Some(3));
    }

    #[test]
    fn compensated_slot_exceeds_half_drift_shifts_forward() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(10));
        // offset 6ms > 5ms (half of max_drift 10ms) -> shift +1
        sync.set_offset(1, Duration::from_millis(6));
        assert_eq!(sync.compensated_slot(1, 3, 8), Some(4));
    }

    #[test]
    fn compensated_slot_wraps_at_boundary() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(10));
        sync.set_offset(1, Duration::from_millis(8));
        // slot 7 + 1 = 8 -> 8 % 8 = 0
        assert_eq!(sync.compensated_slot(1, 7, 8), Some(0));
    }

    #[test]
    fn compensated_slot_zero_slot_count_returns_none() {
        let mut sync = test_sync();
        sync.set_offset(1, Duration::from_millis(1));
        assert_eq!(sync.compensated_slot(1, 0, 0), None);
    }

    #[test]
    fn multiple_nodes_independent_tracking() {
        let mut sync = TdmaClockSync::new(Duration::from_millis(10));
        sync.set_offset(10, Duration::from_millis(2));
        sync.set_offset(20, Duration::from_millis(8));
        sync.set_offset(30, Duration::from_millis(12));

        assert!(sync.is_within_bounds(10));
        assert!(sync.is_within_bounds(20));
        assert!(!sync.is_within_bounds(30));

        assert_eq!(sync.node_count(), 3);
        sync.remove_node(20);
        assert_eq!(sync.node_count(), 2);
        assert_eq!(sync.offset(20), None);
    }

    #[test]
    fn drift_magnitude_returns_offset() {
        let mut sync = test_sync();
        sync.set_offset(1, Duration::from_millis(4));
        assert_eq!(sync.drift_magnitude(1), Some(Duration::from_millis(4)));
        assert_eq!(sync.drift_magnitude(99), None);
    }

    #[test]
    fn zero_drift_bound_allows_only_exact_match() {
        let mut sync = TdmaClockSync::new(Duration::ZERO);
        sync.set_offset(1, Duration::ZERO);
        assert!(sync.is_within_bounds(1));
        sync.set_offset(1, Duration::from_nanos(1));
        assert!(!sync.is_within_bounds(1));
    }
}
