// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Device health state machine with sliding-window error tracking.
//!
//! Provides ONLINE → DEGRADED → FAULTED transitions driven by I/O error
//! counters with configurable thresholds and a timestamped sliding window.
//! This is prerequisite infrastructure for mirror read-error retry,
//! online device replacement, and self-healing repair.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::pool_lifecycle_evidence::{
    PoolLifecycleAction, PoolLifecycleContext, PoolLifecycleEvidence,
};

// ---------------------------------------------------------------------------
// DeviceHealth — the three health states
// ---------------------------------------------------------------------------

/// Health state of a virtual device.
///
/// This is the health state-machine view. It is narrower than
/// [`crate::device::DeviceState`], which additionally models administrative
/// states (Offline, Removed).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceHealth {
    /// Fully operational, error count below degraded threshold.
    #[default]
    Online,
    /// Error count crossed degraded threshold; device still serves I/O but
    /// is a candidate for evacuation or repair.
    Degraded,
    /// Error count crossed faulted threshold or a non-redundant write
    /// failed. Terminal — no automatic recovery.
    Faulted,
}

impl DeviceHealth {
    /// Whether `self` can legally transition to `target`.
    ///
    /// All self-transitions are valid. FAULTED is terminal and cannot
    /// transition to any other state. DEGRADED can recover to ONLINE
    /// when the error window expires. ONLINE can jump directly to
    /// FAULTED on a catastrophic write error.
    #[must_use]
    pub fn can_transition_to(self, target: DeviceHealth) -> bool {
        matches!(
            (self, target),
            (DeviceHealth::Online, DeviceHealth::Online)
                | (DeviceHealth::Online, DeviceHealth::Degraded)
                | (DeviceHealth::Online, DeviceHealth::Faulted)
                | (DeviceHealth::Degraded, DeviceHealth::Online)
                | (DeviceHealth::Degraded, DeviceHealth::Degraded)
                | (DeviceHealth::Degraded, DeviceHealth::Faulted)
                | (DeviceHealth::Faulted, DeviceHealth::Faulted)
        )
    }
}

impl fmt::Display for DeviceHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceHealth::Online => write!(f, "ONLINE"),
            DeviceHealth::Degraded => write!(f, "DEGRADED"),
            DeviceHealth::Faulted => write!(f, "FAULTED"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceErrorKind
// ---------------------------------------------------------------------------

/// Kind of I/O error for health tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceErrorKind {
    /// A read operation failed.
    Read,
    /// A write operation failed.
    Write,
    /// A checksum verification failed on read.
    Checksum,
}

// ---------------------------------------------------------------------------
// DeviceHealthState
// ---------------------------------------------------------------------------

/// Per-device health state tracker with sliding-window error counters.
///
/// Each call to [`record_error`](Self::record_error) increments the
/// appropriate counter, slides the timestamp window, and evaluates
/// whether a health transition should fire.
///
/// # Transition rules
///
/// - ONLINE → DEGRADED when `window_errors() > degraded_threshold`
/// - ONLINE → FAULTED when `window_errors() > faulted_threshold`
/// - ONLINE → FAULTED immediately on any write error when `non_redundant`
/// - DEGRADED → FAULTED when `window_errors() > faulted_threshold`
/// - DEGRADED → FAULTED immediately on any write error when `non_redundant`
/// - DEGRADED → ONLINE when window slides and
///   `window_errors() <= degraded_threshold`
/// - FAULTED is terminal (no further transitions)
#[derive(Clone, Debug)]
pub struct DeviceHealthState {
    /// Current health.
    pub health: DeviceHealth,

    // Per-kind sliding-window timestamps. Counters are derived from vector
    // lengths after each slide_window call.
    read_error_times: Vec<Instant>,
    write_error_times: Vec<Instant>,
    checksum_error_times: Vec<Instant>,

    /// Total error counts (all-time, across all windows).
    pub total_read_errors: u64,
    pub total_write_errors: u64,
    pub total_checksum_errors: u64,

    /// Sliding window duration.
    window: Duration,

    /// Error count threshold for ONLINE → DEGRADED.
    degraded_threshold: u64,

    /// Error count threshold for DEGRADED → FAULTED.
    faulted_threshold: u64,

    /// When true, any single write error immediately faults the device.
    /// Set for non-redundant leaf devices (no mirror, no parity).
    non_redundant: bool,

    /// Ring buffer of recent health transitions for diagnostics.
    /// Fixed capacity (64 entries); oldest entry is evicted when full.
    transition_history: VecDeque<DeviceHealthTransitionEntry>,
}

impl DeviceHealthState {
    /// Create a new health state tracker.
    ///
    /// `window` is the sliding time window. Errors older than
    /// `now - window` are pruned on each `record_error` call.
    ///
    /// `degraded_threshold` is the error count at which the device
    /// transitions from ONLINE to DEGRADED.
    ///
    /// `faulted_threshold` is the error count at which the device
    /// transitions from DEGRADED (or ONLINE) to FAULTED.
    ///
    /// `non_redundant` should be `true` for single-disk devices with
    /// no mirror or parity redundancy.
    #[must_use]
    pub fn new(
        window: Duration,
        degraded_threshold: u64,
        faulted_threshold: u64,
        non_redundant: bool,
    ) -> Self {
        Self {
            health: DeviceHealth::Online,
            read_error_times: Vec::new(),
            write_error_times: Vec::new(),
            checksum_error_times: Vec::new(),
            total_read_errors: 0,
            total_write_errors: 0,
            total_checksum_errors: 0,
            window,
            degraded_threshold,
            faulted_threshold,
            non_redundant,
            transition_history: VecDeque::new(),
        }
    }

    /// Record an I/O error and return the new health if a transition
    /// fired.
    ///
    /// Returns `None` when the health state did not change; returns
    /// `Some(new_health)` when a transition occurred.
    pub fn record_error(&mut self, kind: DeviceErrorKind) -> Option<DeviceHealth> {
        let now = Instant::now();

        // Slide the window first so new error is evaluated against
        // current window.
        self.slide_window(now);

        // Record the error timestamp and increment counters.
        match kind {
            DeviceErrorKind::Read => {
                self.read_error_times.push(now);
                self.total_read_errors = self.total_read_errors.saturating_add(1);
            }
            DeviceErrorKind::Write => {
                self.write_error_times.push(now);
                self.total_write_errors = self.total_write_errors.saturating_add(1);
            }
            DeviceErrorKind::Checksum => {
                self.checksum_error_times.push(now);
                self.total_checksum_errors = self.total_checksum_errors.saturating_add(1);
            }
        }

        self.evaluate_transition(kind)
    }

    /// Evaluate whether the current error counts trigger a health
    /// transition.
    fn evaluate_transition(&mut self, kind: DeviceErrorKind) -> Option<DeviceHealth> {
        let total = self.window_errors();
        let from = self.health;

        let result = match self.health {
            DeviceHealth::Online => {
                // Direct fault: any write error on a non-redundant leaf.
                if (self.non_redundant && matches!(kind, DeviceErrorKind::Write))
                    || total > self.faulted_threshold
                {
                    self.health = DeviceHealth::Faulted;
                    Some(DeviceHealth::Faulted)
                } else if total > self.degraded_threshold {
                    self.health = DeviceHealth::Degraded;
                    Some(DeviceHealth::Degraded)
                } else {
                    None
                }
            }
            DeviceHealth::Degraded => {
                if (self.non_redundant && matches!(kind, DeviceErrorKind::Write))
                    || total > self.faulted_threshold
                {
                    self.health = DeviceHealth::Faulted;
                    Some(DeviceHealth::Faulted)
                } else if total <= self.degraded_threshold {
                    // Recovery: errors aged out, back below threshold.
                    self.health = DeviceHealth::Online;
                    Some(DeviceHealth::Online)
                } else {
                    None
                }
            }
            DeviceHealth::Faulted => {
                // Terminal — no transitions.
                None
            }
        };

        // Record the transition in the ring buffer.
        if let Some(to) = result {
            if self.transition_history.len() >= 64 {
                self.transition_history.pop_front();
            }
            self.transition_history
                .push_back(DeviceHealthTransitionEntry::new(from, to, kind, total));
        }

        result
    }

    /// Slide all error timestamp windows, removing entries older than
    /// `now - self.window`.
    fn slide_window(&mut self, now: Instant) {
        let cutoff = now - self.window;
        self.read_error_times.retain(|ts| *ts >= cutoff);
        self.write_error_times.retain(|ts| *ts >= cutoff);
        self.checksum_error_times.retain(|ts| *ts >= cutoff);
    }

    /// Total errors across all time.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.total_read_errors
            .saturating_add(self.total_write_errors)
            .saturating_add(self.total_checksum_errors)
    }

    /// Errors in the current sliding window.
    #[must_use]
    pub fn window_errors(&self) -> u64 {
        (self.read_error_times.len() as u64)
            .saturating_add(self.write_error_times.len() as u64)
            .saturating_add(self.checksum_error_times.len() as u64)
    }

    /// Read errors in the current sliding window.
    #[must_use]
    pub fn window_read_errors(&self) -> u64 {
        self.read_error_times.len() as u64
    }

    /// Write errors in the current sliding window.
    #[must_use]
    pub fn window_write_errors(&self) -> u64 {
        self.write_error_times.len() as u64
    }

    /// Checksum errors in the current sliding window.
    #[must_use]
    pub fn window_checksum_errors(&self) -> u64 {
        self.checksum_error_times.len() as u64
    }

    /// Reset the sliding window (e.g., after a successful resilver or
    /// device replacement that cleared the underlying problem).
    pub fn reset_window(&mut self) {
        self.read_error_times.clear();
        self.write_error_times.clear();
        self.checksum_error_times.clear();
    }

    /// Return a snapshot of recent health transitions.
    ///
    /// The ring buffer holds at most 64 entries; oldest entries are
    /// evicted when the buffer is full.
    #[must_use]
    pub fn recent_transitions(&self) -> Vec<DeviceHealthTransitionEntry> {
        self.transition_history.iter().cloned().collect()
    }

    /// Number of transitions recorded since creation or last clear.
    #[must_use]
    pub fn transition_count(&self) -> usize {
        self.transition_history.len()
    }

    /// Clear the transition history ring buffer.
    pub fn clear_transition_history(&mut self) {
        self.transition_history.clear();
    }

    /// Drain all pending transitions from the ring buffer.
    ///
    /// Returns all entries in insertion order and clears the buffer.
    /// Callers (typically the pool) consume these to emit
    /// [`DeviceHealthTransition`] events.
    pub fn drain_transitions(&mut self) -> Vec<DeviceHealthTransitionEntry> {
        self.transition_history.drain(..).collect()
    }

    /// Force the health state to a specific value (e.g., during import
    /// from persisted state or administrative override).
    ///
    /// Records the forced transition in the ring buffer.
    pub fn set_health(&mut self, health: DeviceHealth) {
        let from = self.health;
        self.health = health;
        if self.transition_history.len() >= 64 {
            self.transition_history.pop_front();
        }
        self.transition_history
            .push_back(DeviceHealthTransitionEntry::new(
                from,
                health,
                // No specific I/O error triggered this; use Checksum as a
                // sentinel for administrative overrides.
                DeviceErrorKind::Checksum,
                self.window_errors(),
            ));
    }

    /// Force-inject errors for testing purposes. This bypasses the sliding
    /// window and directly simulates N errors of the given kind, triggering
    /// health transitions if the accumulated count crosses thresholds.
    ///
    /// Returns the new health state if a transition fired.
    #[cfg(test)]
    pub fn force_error_for_test(
        &mut self,
        kind: DeviceErrorKind,
        count: u64,
    ) -> Option<DeviceHealth> {
        let mut result = None;
        for _ in 0..count {
            if let Some(h) = self.record_error(kind) {
                result = Some(h);
            }
        }
        result
    }
}

impl Default for DeviceHealthState {
    /// Conservative defaults: 10-minute window, degrade at 10 errors,
    /// fault at 50 errors, non-redundant.
    fn default() -> Self {
        Self::new(Duration::from_secs(600), 10, 50, true)
    }
}

// ---------------------------------------------------------------------------
// DeviceHealthTransitionEntry — lightweight history record
// ---------------------------------------------------------------------------

/// A single health state transition recorded in the ring buffer.
///
/// Lighter than [`DeviceHealthTransition`]; stored per-device in a
/// fixed-capacity ring buffer for diagnostics and observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceHealthTransitionEntry {
    /// Previous health state.
    pub from: DeviceHealth,
    /// New health state.
    pub to: DeviceHealth,
    /// Monotonic instant when the transition fired.
    pub when: Instant,
    /// Error kind that triggered the transition.
    pub trigger: DeviceErrorKind,
    /// Window error count at transition time.
    pub window_errors: u64,
}

impl DeviceHealthTransitionEntry {
    #[must_use]
    pub fn new(
        from: DeviceHealth,
        to: DeviceHealth,
        trigger: DeviceErrorKind,
        window_errors: u64,
    ) -> Self {
        Self {
            from,
            to,
            when: Instant::now(),
            trigger,
            window_errors,
        }
    }

    /// Build fail-closed lifecycle evidence for health transitions to FAULTED.
    #[must_use]
    pub fn fail_closed_lifecycle_evidence(
        &self,
        pool_guid: [u8; 16],
        pool_name: impl Into<String>,
    ) -> Option<PoolLifecycleEvidence> {
        if self.to != DeviceHealth::Faulted {
            return None;
        }

        let context = PoolLifecycleContext {
            pool_guid: Some(pool_guid),
            pool_name: Some(pool_name.into()),
            device_count: 1,
            expected_device_count: 1,
            capacity_bytes: 0,
            topology_generation: 0,
            commit_group: 0,
        };

        Some(PoolLifecycleEvidence::refused(
            PoolLifecycleAction::FailClosed,
            context,
            format!(
                "device health transitioned from {} to {} after {} {:?} error(s)",
                self.from, self.to, self.window_errors, self.trigger
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// DeviceHealthTransition — event emitted on state change
// ---------------------------------------------------------------------------

/// Event emitted when a device's health state changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceHealthTransition {
    /// Per-device GUID.
    pub device_guid: u64,
    /// Owning pool UUID.
    pub pool_uuid: u64,
    /// Previous health state.
    pub from: DeviceHealth,
    /// New health state.
    pub to: DeviceHealth,
    /// Human-readable reason for the transition.
    pub reason: String,
}

impl DeviceHealthTransition {
    /// Create a new transition event.
    #[must_use]
    pub fn new(
        device_guid: u64,
        pool_uuid: u64,
        from: DeviceHealth,
        to: DeviceHealth,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            device_guid,
            pool_uuid,
            from,
            to,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for DeviceHealthTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "device {:#x} pool {:#x}: {} → {} ({})",
            self.device_guid, self.pool_uuid, self.from, self.to, self.reason
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_lifecycle_evidence::PoolLifecycleOutcome;

    // Default thresholds for tests: degrade at 5, fault at 20, 60s window.
    fn test_state(non_redundant: bool) -> DeviceHealthState {
        DeviceHealthState::new(Duration::from_secs(60), 5, 20, non_redundant)
    }

    // --------------------------------------------------------------
    // can_transition_to: all 9 state pairs (3×3)
    // --------------------------------------------------------------

    #[test]
    fn can_transition_online_to_online() {
        assert!(DeviceHealth::Online.can_transition_to(DeviceHealth::Online));
    }

    #[test]
    fn can_transition_online_to_degraded() {
        assert!(DeviceHealth::Online.can_transition_to(DeviceHealth::Degraded));
    }

    #[test]
    fn can_transition_online_to_faulted() {
        assert!(DeviceHealth::Online.can_transition_to(DeviceHealth::Faulted));
    }

    #[test]
    fn can_transition_degraded_to_online() {
        assert!(DeviceHealth::Degraded.can_transition_to(DeviceHealth::Online));
    }

    #[test]
    fn can_transition_degraded_to_degraded() {
        assert!(DeviceHealth::Degraded.can_transition_to(DeviceHealth::Degraded));
    }

    #[test]
    fn can_transition_degraded_to_faulted() {
        assert!(DeviceHealth::Degraded.can_transition_to(DeviceHealth::Faulted));
    }

    #[test]
    fn can_transition_faulted_to_online() {
        assert!(!DeviceHealth::Faulted.can_transition_to(DeviceHealth::Online));
    }

    #[test]
    fn can_transition_faulted_to_degraded() {
        assert!(!DeviceHealth::Faulted.can_transition_to(DeviceHealth::Degraded));
    }

    #[test]
    fn can_transition_faulted_to_faulted() {
        assert!(DeviceHealth::Faulted.can_transition_to(DeviceHealth::Faulted));
    }

    // --------------------------------------------------------------
    // State machine: ONLINE stays ONLINE below threshold
    // --------------------------------------------------------------

    #[test]
    fn online_stays_online_below_degraded_threshold() {
        let mut state = test_state(false);
        for _ in 0..5 {
            assert_eq!(state.record_error(DeviceErrorKind::Read), None);
        }
        assert_eq!(state.health, DeviceHealth::Online);
    }

    // --------------------------------------------------------------
    // State machine: ONLINE → DEGRADED at threshold
    // --------------------------------------------------------------

    #[test]
    fn online_to_degraded_when_above_degraded_threshold() {
        let mut state = test_state(false);
        // degraded_threshold=5, so 5 errors: still Online
        for _ in 0..5 {
            assert_eq!(state.record_error(DeviceErrorKind::Read), None);
        }
        assert_eq!(state.health, DeviceHealth::Online);
        // 6th error crosses threshold
        let result = state.record_error(DeviceErrorKind::Read);
        assert_eq!(result, Some(DeviceHealth::Degraded));
        assert_eq!(state.health, DeviceHealth::Degraded);
    }

    // --------------------------------------------------------------
    // State machine: DEGRADED stays DEGRADED below faulted threshold
    // --------------------------------------------------------------

    #[test]
    fn degraded_stays_degraded_below_faulted_threshold() {
        let mut state = test_state(false);
        // Push into DEGRADED first
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);

        // More errors but below faulted threshold (20)
        for _ in 0..12 {
            let result = state.record_error(DeviceErrorKind::Read);
            assert!(result.is_none(), "unexpected transition");
        }
        assert_eq!(state.health, DeviceHealth::Degraded);
    }

    // --------------------------------------------------------------
    // State machine: DEGRADED → FAULTED at faulted threshold
    // --------------------------------------------------------------

    #[test]
    fn degraded_to_faulted_when_above_faulted_threshold() {
        let mut state = test_state(false);
        // Push into DEGRADED first (6 errors)
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);

        // Push to 20 errors (at threshold)
        for _ in 0..14 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);

        // 21st error crosses faulted threshold
        let result = state.record_error(DeviceErrorKind::Read);
        assert_eq!(result, Some(DeviceHealth::Faulted));
        assert_eq!(state.health, DeviceHealth::Faulted);
    }

    // --------------------------------------------------------------
    // State machine: non-redundant write → immediate FAULTED
    // --------------------------------------------------------------

    #[test]
    fn non_redundant_write_error_faults_immediately_from_online() {
        let mut state = test_state(true); // non_redundant=true
        let result = state.record_error(DeviceErrorKind::Write);
        assert_eq!(result, Some(DeviceHealth::Faulted));
        assert_eq!(state.health, DeviceHealth::Faulted);
    }

    #[test]
    fn non_redundant_write_error_faults_immediately_from_degraded() {
        let mut state = test_state(true);
        // Get into DEGRADED first via read errors
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);

        // A write error immediately faults
        let result = state.record_error(DeviceErrorKind::Write);
        assert_eq!(result, Some(DeviceHealth::Faulted));
        assert_eq!(state.health, DeviceHealth::Faulted);
    }

    #[test]
    fn redundant_device_write_error_does_not_fault_immediately() {
        let mut state = test_state(false); // non_redundant=false
        let result = state.record_error(DeviceErrorKind::Write);
        assert_eq!(result, None);
        assert_eq!(state.health, DeviceHealth::Online);
    }

    // --------------------------------------------------------------
    // State machine: FAULTED is terminal
    // --------------------------------------------------------------

    #[test]
    fn faulted_does_not_transition_on_more_errors() {
        let mut state = test_state(true);
        // Fault immediately
        state.record_error(DeviceErrorKind::Write);
        assert_eq!(state.health, DeviceHealth::Faulted);

        // More errors should not change state
        for _ in 0..100 {
            let result = state.record_error(DeviceErrorKind::Read);
            assert_eq!(result, None);
        }
        assert_eq!(state.health, DeviceHealth::Faulted);
    }

    // --------------------------------------------------------------
    // Sliding window: old errors expire
    // --------------------------------------------------------------

    #[test]
    fn old_errors_expire_from_window() {
        let mut state = DeviceHealthState::new(Duration::from_millis(10), 5, 20, false);

        // Record 6 errors to get into DEGRADED
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(20));

        // Next error slides window: old errors expire, count resets,
        // then this single error is below degraded threshold.
        let result = state.record_error(DeviceErrorKind::Read);
        assert_eq!(result, Some(DeviceHealth::Online));
        assert_eq!(state.health, DeviceHealth::Online);
    }

    #[test]
    fn error_window_expiration_resets_counters() {
        let mut state = DeviceHealthState::new(Duration::from_millis(10), 5, 20, false);

        // Record 3 errors
        for _ in 0..3 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.window_errors(), 3);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(20));

        // Record one more error — old ones should be gone
        state.record_error(DeviceErrorKind::Checksum);
        assert_eq!(state.window_errors(), 1);
        assert_eq!(state.health, DeviceHealth::Online);
    }

    // --------------------------------------------------------------
    // Counter accuracy
    // --------------------------------------------------------------

    #[test]
    fn per_kind_counters_are_accurate() {
        let mut state = test_state(false);

        state.record_error(DeviceErrorKind::Read);
        state.record_error(DeviceErrorKind::Read);
        state.record_error(DeviceErrorKind::Write);
        state.record_error(DeviceErrorKind::Checksum);

        assert_eq!(state.window_read_errors(), 2);
        assert_eq!(state.window_write_errors(), 1);
        assert_eq!(state.window_checksum_errors(), 1);
        assert_eq!(state.window_errors(), 4);
        assert_eq!(state.total_read_errors, 2);
        assert_eq!(state.total_write_errors, 1);
        assert_eq!(state.total_checksum_errors, 1);
        assert_eq!(state.total_errors(), 4);
    }

    // --------------------------------------------------------------
    // reset_window
    // --------------------------------------------------------------

    #[test]
    fn reset_window_clears_counters() {
        let mut state = test_state(false);

        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);
        assert!(state.window_errors() > 0);

        state.reset_window();
        assert_eq!(state.window_errors(), 0);
        assert_eq!(state.window_read_errors(), 0);
        // Total counters are not reset by reset_window (only window)
        assert_eq!(state.total_errors(), 6);
    }

    // --------------------------------------------------------------
    // Display
    // --------------------------------------------------------------

    #[test]
    fn device_health_display() {
        assert_eq!(DeviceHealth::Online.to_string(), "ONLINE");
        assert_eq!(DeviceHealth::Degraded.to_string(), "DEGRADED");
        assert_eq!(DeviceHealth::Faulted.to_string(), "FAULTED");
    }

    #[test]
    fn device_health_transition_display() {
        let t = DeviceHealthTransition::new(
            0x1234,
            0xABCD,
            DeviceHealth::Online,
            DeviceHealth::Degraded,
            "6 read errors in window",
        );
        let s = t.to_string();
        assert!(s.contains("0x1234"));
        assert!(s.contains("0xabcd"));
        assert!(s.contains("ONLINE"));
        assert!(s.contains("DEGRADED"));
        assert!(s.contains("6 read errors"));
    }

    // --------------------------------------------------------------
    // Transition history ring buffer
    // --------------------------------------------------------------

    #[test]
    fn transition_history_records_online_to_degraded() {
        let mut state = DeviceHealthState::new(Duration::from_secs(60), 3, 20, false);
        // Push 4 read errors to trigger degrade at 3
        for _ in 0..4 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);
        let history = state.recent_transitions();
        assert_eq!(history.len(), 1, "exactly one transition recorded");
        let t = &history[0];
        assert_eq!(t.from, DeviceHealth::Online);
        assert_eq!(t.to, DeviceHealth::Degraded);
        assert_eq!(t.trigger, DeviceErrorKind::Read);
    }

    #[test]
    fn transition_history_records_degraded_to_faulted() {
        let mut state = DeviceHealthState::new(Duration::from_secs(600), 5, 10, false);
        // Online -> Degraded (6 errors)
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Write);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);
        // Degraded -> Faulted (5 more = 11 > faulted_threshold 10)
        for _ in 0..5 {
            state.record_error(DeviceErrorKind::Write);
        }
        assert_eq!(state.health, DeviceHealth::Faulted);
        let history = state.recent_transitions();
        assert_eq!(
            history.len(),
            2,
            "two transitions: Online->Degraded->Faulted"
        );
        assert_eq!(history[0].from, DeviceHealth::Online);
        assert_eq!(history[0].to, DeviceHealth::Degraded);
        assert_eq!(history[1].from, DeviceHealth::Degraded);
        assert_eq!(history[1].to, DeviceHealth::Faulted);
    }

    #[test]
    fn transition_history_records_non_redundant_write_fault() {
        let mut state = DeviceHealthState::new(Duration::from_secs(60), 5, 20, true);
        state.record_error(DeviceErrorKind::Write);
        assert_eq!(state.health, DeviceHealth::Faulted);
        let history = state.recent_transitions();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].from, DeviceHealth::Online);
        assert_eq!(history[0].to, DeviceHealth::Faulted);
        assert_eq!(history[0].trigger, DeviceErrorKind::Write);
    }

    #[test]
    fn transition_history_records_recovery_degraded_to_online() {
        let mut state = DeviceHealthState::new(Duration::from_millis(10), 5, 20, false);
        // Push into Degraded
        for _ in 0..6 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert_eq!(state.health, DeviceHealth::Degraded);
        assert_eq!(state.recent_transitions().len(), 1);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(20));

        // Next error slides window, errors expire, recover to Online
        state.record_error(DeviceErrorKind::Read);
        assert_eq!(state.health, DeviceHealth::Online);
        let history = state.recent_transitions();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].from, DeviceHealth::Degraded);
        assert_eq!(history[1].to, DeviceHealth::Online);
    }

    #[test]
    fn transition_history_ring_buffer_evicts_oldest() {
        let mut state = DeviceHealthState::new(Duration::from_secs(60), 5, 20, false);
        // Force many transitions by toggling thresholds artificially.
        // Use force_error_for_test to generate many transitions.
        // 64 transitions fill the buffer; the 65th evicts the oldest.
        for i in 0..65 {
            // Reset and force errors to create transitions
            let _ = state.force_error_for_test(DeviceErrorKind::Read, 6);
            if state.health == DeviceHealth::Degraded {
                state.reset_window();
                state.set_health(DeviceHealth::Online);
            }
            let _ = i;
        }
        let history = state.recent_transitions();
        assert_eq!(history.len(), 64, "buffer capped at 64");
    }

    #[test]
    fn clear_transition_history_empties_buffer() {
        let mut state = DeviceHealthState::new(Duration::from_secs(60), 3, 20, false);
        // Generate a transition
        for _ in 0..4 {
            state.record_error(DeviceErrorKind::Read);
        }
        assert!(state.transition_count() > 0);
        state.clear_transition_history();
        assert_eq!(state.transition_count(), 0);
        assert!(state.recent_transitions().is_empty());
    }

    #[test]
    fn set_health_records_forced_transition() {
        let mut state = DeviceHealthState::new(Duration::from_secs(60), 5, 20, false);
        assert_eq!(state.transition_count(), 0);
        state.set_health(DeviceHealth::Faulted);
        assert_eq!(state.transition_count(), 1);
        let t = &state.recent_transitions()[0];
        assert_eq!(t.from, DeviceHealth::Online);
        assert_eq!(t.to, DeviceHealth::Faulted);
    }

    #[test]
    fn transition_history_default_new_is_empty() {
        let state = DeviceHealthState::new(Duration::from_secs(60), 5, 20, false);
        assert_eq!(state.transition_count(), 0);
        assert!(state.recent_transitions().is_empty());
    }

    #[test]
    fn transition_entry_has_window_errors() {
        let mut state = DeviceHealthState::new(Duration::from_secs(600), 3, 20, false);
        // 4 read errors cross degraded_threshold=3
        for _ in 0..4 {
            state.record_error(DeviceErrorKind::Read);
        }
        let t = &state.recent_transitions()[0];
        assert!(
            t.window_errors >= 4,
            "transition entry should capture window error count at transition time"
        );
    }

    #[test]
    fn faulted_transition_emits_fail_closed_lifecycle_evidence() {
        let transition = DeviceHealthTransitionEntry::new(
            DeviceHealth::Degraded,
            DeviceHealth::Faulted,
            DeviceErrorKind::Write,
            21,
        );

        let evidence = transition
            .fail_closed_lifecycle_evidence([0x17; 16], "pool-a")
            .expect("faulted transition should emit fail-closed evidence");

        assert_eq!(evidence.action, PoolLifecycleAction::FailClosed);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.pool_guid, Some([0x17; 16]));
        assert_eq!(evidence.pool_name.as_deref(), Some("pool-a"));
        assert!(evidence.reason.contains("DEGRADED to FAULTED"));
        assert!(evidence.reason.contains("21 Write"));
    }

    #[test]
    fn non_faulted_transition_does_not_emit_fail_closed_lifecycle_evidence() {
        let transition = DeviceHealthTransitionEntry::new(
            DeviceHealth::Online,
            DeviceHealth::Degraded,
            DeviceErrorKind::Read,
            6,
        );

        assert!(transition
            .fail_closed_lifecycle_evidence([0x17; 16], "pool-a")
            .is_none());
    }
}
