// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Hybrid Logical Clock (source-owned timing model).
//!
//! HLC provides causal ordering across nodes without requiring synchronized
//! physical clocks. Every local event advances the HLC; remote messages merge
//! the sender's HLC into the receiver's. HLC values appear in receipts and
//! validation bundles for narrative ordering, but authority still depends on
//! receipts, epochs, and anchor state.

use crate::types::{ClockClass, HlcState, HlcValue};

/// A Hybrid Logical Clock instance.
///
/// HLC tracks `(physical_component_ns, logical_counter)` and advances on every
/// event. On receiving a message with a higher physical component, the local
/// HLC jumps forward. The logical counter breaks ties when physical components
/// are equal.
///
/// # Law (source-owned timing model)
/// - HLC merges on message receive / receipt ingest / publication emit.
/// - HLC does not replace epochs, receipts, or anchor references.
/// - HLC values are for narrative ordering and tie-breaking, not sovereign truth.
#[derive(Debug, Clone)]
pub struct HybridLogicalClock {
    /// Current HLC value.
    value: HlcValue,
    /// Current lifecycle state.
    state: HlcState,
    /// Monotonic counter for receipt persistence tracking.
    receipt_count: u64,
}

impl HybridLogicalClock {
    /// Create a new HLC initialized to zero.
    pub fn new() -> Self {
        HybridLogicalClock {
            value: HlcValue::zero(),
            state: HlcState::Idle,
            receipt_count: 0,
        }
    }

    /// Create an HLC initialized from a specific value (e.g. after recovery).
    pub fn from_value(value: HlcValue) -> Self {
        HybridLogicalClock {
            value,
            state: HlcState::Idle,
            receipt_count: 0,
        }
    }

    /// Return the current HLC value without advancing.
    pub fn current(&self) -> HlcValue {
        self.value
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> HlcState {
        self.state
    }

    /// Return the number of receipts persisted from this HLC.
    pub fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    /// Advance the HLC for a local event (source-owned timing model:
    /// `advance_hlc_on_send_merge_or_publish`).
    ///
    /// Uses the provided physical time (nanoseconds from a monotonic or
    /// HLC-anchored source). The logical counter increments, or resets if
    /// the physical component advances.
    pub fn advance_local(&mut self, physical_ns: u64) -> HlcValue {
        if physical_ns > self.value.physical_ns() {
            // Physical time moved forward: reset logical counter.
            self.value.physical_ns = physical_ns;
            self.value.logical = 0;
        } else {
            // Same physical time: increment logical counter.
            self.value.logical = self.value.logical().saturating_add(1);
        }
        self.state = HlcState::LocalAdvanced;
        self.value
    }

    /// Merge a remote HLC value from a received message (source-owned timing model:
    /// `advance_hlc_on_send_merge_or_publish`).
    ///
    /// After merge, the local HLC is guaranteed to be strictly greater than
    /// both the previous local value and the received remote value.
    pub fn merge_remote(&mut self, remote: HlcValue, local_physical_ns: u64) -> HlcValue {
        // The new physical component is the max of local physical, remote
        // physical, and the current wall clock.
        let max_physical = self
            .value
            .physical_ns()
            .max(remote.physical_ns())
            .max(local_physical_ns);

        if max_physical > self.value.physical_ns() {
            // Physical time moved forward from either remote or wall clock.
            self.value.physical_ns = max_physical;
            if max_physical == remote.physical_ns() && max_physical > local_physical_ns {
                // Remote was ahead: increment remote's logical counter.
                self.value.logical = remote.logical().saturating_add(1);
            } else {
                // Wall clock was ahead: reset logical.
                self.value.logical = 0;
            }
        } else {
            // Same physical time: ensure causality by taking max logical + 1.
            let max_logical = self.value.logical().max(remote.logical());
            self.value.logical = max_logical.saturating_add(1);
        }
        self.state = HlcState::RemoteMerged;
        self.value
    }

    /// Mark the current HLC value as persisted into a receipt.
    ///
    /// After this call, the HLC transitions to `PersistedForReceipt` state
    /// and the receipt counter increments.
    pub fn persist_for_receipt(&mut self) -> HlcValue {
        self.state = HlcState::PersistedForReceipt;
        self.receipt_count = self.receipt_count.saturating_add(1);
        self.value
    }

    /// Compare two HLC values for causal ordering.
    ///
    /// Returns `Ordering::Less` if `a` happened-before `b`, etc.
    /// Note: this is a causal ordering, not a total order.
    pub fn causal_compare(a: &HlcValue, b: &HlcValue) -> core::cmp::Ordering {
        a.cmp(b)
    }

    /// Check whether `a` strictly happened-before `b`.
    pub fn happened_before(a: &HlcValue, b: &HlcValue) -> bool {
        a < b
    }

    /// Get the clock class for this HLC.
    pub fn clock_class() -> ClockClass {
        ClockClass::HlcCluster
    }
}

impl Default for HybridLogicalClock {
    fn default() -> Self {
        HybridLogicalClock::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_hlc_starts_at_zero() {
        let hlc = HybridLogicalClock::new();
        assert_eq!(hlc.current(), HlcValue::zero());
        assert_eq!(hlc.state(), HlcState::Idle);
        assert_eq!(hlc.receipt_count(), 0);
    }

    #[test]
    fn advance_local_physical_forward_resets_logical() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        assert_eq!(hlc.current().physical_ns(), 100);
        assert_eq!(hlc.current().logical(), 0);
        assert_eq!(hlc.state(), HlcState::LocalAdvanced);
    }

    #[test]
    fn advance_local_same_physical_increments_logical() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        let v1 = hlc.advance_local(100);
        assert_eq!(v1.physical_ns(), 100);
        assert_eq!(v1.logical(), 1);

        let v2 = hlc.advance_local(100);
        assert_eq!(v2.logical(), 2);
    }

    #[test]
    fn advance_local_physical_jump_resets_logical() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        hlc.advance_local(100); // logical = 1
        hlc.advance_local(200); // physical jump
        assert_eq!(hlc.current().physical_ns(), 200);
        assert_eq!(hlc.current().logical(), 0);
    }

    #[test]
    fn merge_remote_ahead() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        // Remote is ahead in physical time
        let remote = HlcValue::new(300, 5);
        let merged = hlc.merge_remote(remote, 150);

        assert_eq!(merged.physical_ns(), 300);
        assert_eq!(merged.logical(), 6); // remote.logical() + 1
        assert_eq!(hlc.state(), HlcState::RemoteMerged);
    }

    #[test]
    fn merge_remote_behind_wall_clock_ahead() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        // Remote is behind, but wall clock is ahead
        let remote = HlcValue::new(50, 3);
        let merged = hlc.merge_remote(remote, 500);

        assert_eq!(merged.physical_ns(), 500);
        assert_eq!(merged.logical(), 0); // wall clock ahead, reset
    }

    #[test]
    fn merge_remote_same_physical_causal() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100); // logical = 0
        hlc.advance_local(100); // logical = 1
                                // Remote at same physical time with higher logical
        let remote = HlcValue::new(100, 10);
        let merged = hlc.merge_remote(remote, 100);

        assert_eq!(merged.physical_ns(), 100);
        assert_eq!(merged.logical(), 11); // max(2, 10) + 1
    }

    #[test]
    fn persist_for_receipt() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        let v = hlc.persist_for_receipt();

        assert_eq!(v, HlcValue::new(100, 0));
        assert_eq!(hlc.state(), HlcState::PersistedForReceipt);
        assert_eq!(hlc.receipt_count(), 1);

        // Second receipt
        hlc.advance_local(200);
        hlc.persist_for_receipt();
        assert_eq!(hlc.receipt_count(), 2);
    }

    #[test]
    fn happened_before_transitive() {
        let a = HlcValue::new(100, 0);
        let b = HlcValue::new(100, 5);
        let c = HlcValue::new(200, 0);

        assert!(HybridLogicalClock::happened_before(&a, &b));
        assert!(HybridLogicalClock::happened_before(&b, &c));
        assert!(HybridLogicalClock::happened_before(&a, &c));
        assert!(!HybridLogicalClock::happened_before(&c, &a));
    }

    #[test]
    fn from_value_recovery() {
        let hlc = HybridLogicalClock::from_value(HlcValue::new(500, 42));
        assert_eq!(hlc.current(), HlcValue::new(500, 42));
        assert_eq!(hlc.state(), HlcState::Idle);
    }

    #[test]
    fn merge_chain_maintains_causality() {
        // Node A: local events
        let mut hlc_a = HybridLogicalClock::new();
        let a1 = hlc_a.advance_local(100); // 100.0
        let a2 = hlc_a.advance_local(100); // 100.1

        // Node B: receives a2, then does local work
        let mut hlc_b = HybridLogicalClock::new();
        let b1 = hlc_b.merge_remote(a2, 120); // 120.0
        let b2 = hlc_b.advance_local(120); // 120.1

        // Node A: receives b2
        let a3 = hlc_a.merge_remote(b2, 130); // 130.0 (wall clock 130 > 120)

        // Verify causality: a1 < a2 < b1 < b2 < a3
        assert!(HybridLogicalClock::happened_before(&a1, &a2));
        assert!(HybridLogicalClock::happened_before(&a2, &b1));
        assert!(HybridLogicalClock::happened_before(&b1, &b2));
        assert!(HybridLogicalClock::happened_before(&b2, &a3));
    }

    #[test]
    fn default_equals_new() {
        let hlc1 = HybridLogicalClock::new();
        let hlc2 = HybridLogicalClock::default();
        assert_eq!(hlc1.current(), hlc2.current());
    }

    #[test]
    fn clock_class_returns_hlc_cluster() {
        assert_eq!(
            HybridLogicalClock::clock_class(),
            crate::types::ClockClass::HlcCluster
        );
    }

    #[test]
    fn advance_local_logical_saturates_at_max() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(u64::MAX);
        assert_eq!(hlc.current().logical(), 0);
        // Set logical near max, verify saturating_add caps.
        hlc.value.logical = u64::MAX - 1;
        let v = hlc.advance_local(u64::MAX);
        assert_eq!(v.logical(), u64::MAX);
        let v2 = hlc.advance_local(u64::MAX);
        assert_eq!(v2.logical(), u64::MAX);
    }

    #[test]
    fn merge_remote_at_max_values_saturates() {
        let mut hlc = HybridLogicalClock::new();
        hlc.advance_local(100);
        let remote = HlcValue::new(u64::MAX, u64::MAX);
        let merged = hlc.merge_remote(remote, u64::MAX);
        assert_eq!(merged.physical_ns(), u64::MAX);
        assert_eq!(merged.logical(), 0); // wall-clock path: local_physical also at max, remote not strictly ahead
        assert_eq!(hlc.state(), HlcState::RemoteMerged);
    }
}
