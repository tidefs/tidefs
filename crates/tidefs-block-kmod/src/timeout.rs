//! Block request timeout detection and reset recovery.
//!
//! This module provides inflight-request deadline tracking and a timeout
//! detection path so that stalled backend I/O produces precise timeouts
//! and the device recovers without corrupting committed roots.
//!
//! # Architecture
//!
//! ```text
//! queue_rq / submit_bio
//!   -> InflightTracker::record_request(deadline)
//!   -> backend I/O
//!   -> InflightTracker::complete_request(id)
//!
//! timeout path (kernel timeout callback or watchdog):
//!   -> InflightTracker::check_timeouts(now)
//!   -> for each timed-out request:
//!       -> complete_request_with_error(id, BLK_STS_TIMEOUT)
//!       -> device.reset_stalled_backend()
//!   -> committed-root integrity is preserved (no partial writes)
//! ```
//!
//! # Committed-root safety
//!
//! When a timeout fires during a write, the inflight write is abandoned.
//! The committed root is NOT advanced for that write, so crash recovery
//! will replay the intent log and the write either completes on replay
//! or the filesystem sees the pre-write state. Either outcome is
//! consistent -- no torn writes reach the committed root.
//!
//! # Reset recovery
//!
//! After a timeout, the device fences new I/O, drains inflight requests,
//! resets the stalled backend connection, and un-fences. This prevents
//! a single stalled operation from permanently wedging the device.

use core::fmt;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::kernel_types::KmodVec as Vec;

// -- RequestDeadline -------------------------------------------------------

/// A deadline for a single block I/O request.
///
/// Deadlines are expressed in milliseconds from an arbitrary epoch
/// (typically a monotonic counter or jiffies value). The deadline
/// is inclusive: a request with `deadline_ms <= now` has timed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestDeadline {
    /// Deadline timestamp in milliseconds.
    deadline_ms: u64,
}

impl RequestDeadline {
    /// Create a new deadline `timeout_ms` milliseconds from `now_ms`.
    #[must_use]
    pub fn from_now(now_ms: u64, timeout_ms: u32) -> Self {
        Self {
            deadline_ms: now_ms.saturating_add(u64::from(timeout_ms)),
        }
    }

    /// Whether this deadline has expired at `now_ms`.
    #[must_use]
    pub fn has_expired(&self, now_ms: u64) -> bool {
        self.deadline_ms <= now_ms
    }

    /// Milliseconds remaining until expiry (0 if expired).
    #[must_use]
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms)
    }

    /// The raw deadline timestamp.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
}

impl fmt::Display for RequestDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "deadline={}ms", self.deadline_ms)
    }
}

// -- InflightRequest -------------------------------------------------------

/// Operation type for an inflight block request (for timeout diagnosis).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightOp {
    /// REQ_OP_READ -- reading sectors from the device.
    Read,
    /// REQ_OP_WRITE -- writing sectors to the device.
    Write,
    /// REQ_OP_FLUSH -- flushing volatile caches.
    Flush,
    /// REQ_OP_DISCARD -- discarding sector range.
    Discard,
    /// REQ_OP_WRITE_ZEROES -- writing zeroes.
    WriteZeroes,
}

impl fmt::Display for InflightOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Flush => write!(f, "flush"),
            Self::Discard => write!(f, "discard"),
            Self::WriteZeroes => write!(f, "write_zeroes"),
        }
    }
}

/// A tracked inflight block I/O request.
#[derive(Debug, Clone)]
pub struct InflightRequest {
    /// Opaque request identifier (e.g., pointer or tag).
    pub request_id: u64,
    /// Deadline for this request.
    pub deadline: RequestDeadline,
    /// Operation type for diagnosis.
    pub op: InflightOp,
    /// Starting sector (for diagnosis).
    pub start_sector: u64,
    /// Number of sectors.
    pub sector_count: u32,
}

impl InflightRequest {
    /// Create a new inflight request record.
    #[must_use]
    pub fn new(
        request_id: u64,
        deadline: RequestDeadline,
        op: InflightOp,
        start_sector: u64,
        sector_count: u32,
    ) -> Self {
        Self {
            request_id,
            deadline,
            op,
            start_sector,
            sector_count,
        }
    }

    /// Whether this request has timed out at `now_ms`.
    #[must_use]
    pub fn has_timed_out(&self, now_ms: u64) -> bool {
        self.deadline.has_expired(now_ms)
    }
}

impl fmt::Display for InflightRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "req={} op={} sector={} count={} {}",
            self.request_id, self.op, self.start_sector, self.sector_count, self.deadline
        )
    }
}

// -- TimeoutConfig ---------------------------------------------------------

/// Configuration for the block request timeout and reset recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// Default per-request timeout in milliseconds.
    pub request_timeout_ms: u32,
    /// Maximum number of inflight requests before backpressure.
    pub max_inflight: u32,
    /// Whether to auto-reset after a timeout (true) or require operator
    /// intervention (false).
    pub auto_reset: bool,
    /// Maximum number of consecutive timeouts before the device is fenced
    /// permanently (0 = no limit).
    pub max_consecutive_timeouts: u32,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 30_000,
            max_inflight: 64,
            auto_reset: true,
            max_consecutive_timeouts: 3,
        }
    }
}

impl TimeoutConfig {
    /// Create a config with a custom per-request timeout.
    #[must_use]
    pub fn with_timeout(request_timeout_ms: u32) -> Self {
        Self {
            request_timeout_ms,
            ..Self::default()
        }
    }
}

// -- TimeoutOutcome --------------------------------------------------------

/// Outcome of a timeout check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// No requests have timed out.
    NoTimeout,
    /// One or more requests timed out; contains the timed-out request IDs.
    TimedOut {
        /// IDs of timed-out requests.
        request_ids: Vec<u64>,
        /// Number of consecutive timeouts so far (including this one).
        consecutive_count: u32,
    },
    /// The device has been fenced due to excessive consecutive timeouts.
    Fenced {
        /// Number of consecutive timeouts that triggered the fence.
        consecutive_count: u32,
    },
}

// -- InflightTracker -------------------------------------------------------

/// Tracks inflight block I/O requests with deadline-based timeout detection.
///
/// The tracker records each inflight request with a deadline. When
/// `check_timeouts` is called, any request whose deadline has expired
/// is reported as timed out. The tracker maintains a consecutive-timeout
/// counter for permanent fence decisions.
///
/// # Capacity
///
/// The tracker uses a fixed-capacity linear scan. For the expected
/// blk-mq tag depth (64-128), this is efficient. For larger depths,
/// a binary heap or timer wheel would be more appropriate.
pub struct InflightTracker {
    /// Currently inflight requests.
    inflight: Vec<InflightRequest>,
    /// Maximum inflight capacity.
    max_inflight: u32,
    /// Per-request timeout in milliseconds.
    request_timeout_ms: u32,
    /// Whether auto-reset is enabled.
    #[allow(dead_code)]
    auto_reset: bool,
    /// Maximum consecutive timeouts before permanent fence.
    max_consecutive_timeouts: u32,
    /// Counter for consecutive timeouts.
    consecutive_timeouts: u32,
    /// Whether the device is fenced (permanently rejecting I/O).
    fenced: bool,
    /// Total number of timeouts since tracker creation.
    total_timeouts: u64,
    /// Total number of completed requests.
    total_completed: u64,
}

impl InflightTracker {
    /// Create a new inflight tracker with the given configuration.
    #[must_use]
    pub fn new(config: TimeoutConfig) -> Self {
        Self {
            inflight: Vec::new(),
            max_inflight: config.max_inflight,
            request_timeout_ms: config.request_timeout_ms,
            auto_reset: config.auto_reset,
            max_consecutive_timeouts: config.max_consecutive_timeouts,
            consecutive_timeouts: 0,
            fenced: false,
            total_timeouts: 0,
            total_completed: 0,
        }
    }

    /// Create a tracker with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(TimeoutConfig::default())
    }

    // -- Accessors ---------------------------------------------------------

    /// Number of currently inflight requests.
    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Whether the tracker is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.inflight.len() >= self.max_inflight as usize
    }

    /// Whether the device is fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }

    /// Total timeouts since creation.
    #[must_use]
    pub fn total_timeouts(&self) -> u64 {
        self.total_timeouts
    }

    /// Total completed requests.
    #[must_use]
    pub fn total_completed(&self) -> u64 {
        self.total_completed
    }

    /// Whether auto-reset is enabled.
    #[must_use]
    pub fn auto_reset_enabled(&self) -> bool {
        self.auto_reset
    }

    /// Consecutive timeout count.
    #[must_use]
    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }

    // -- Request tracking --------------------------------------------------

    /// Record a new inflight request with a deadline computed from `now_ms`.
    ///
    /// Returns `None` if the tracker is at capacity or fenced.
    #[must_use]
    pub fn record_request(
        &mut self,
        request_id: u64,
        now_ms: u64,
        op: InflightOp,
        start_sector: u64,
        sector_count: u32,
    ) -> Option<&InflightRequest> {
        if self.is_full() || self.fenced {
            return None;
        }
        let deadline = RequestDeadline::from_now(now_ms, self.request_timeout_ms);
        let req = InflightRequest::new(request_id, deadline, op, start_sector, sector_count);
        self.inflight.push(req);
        self.inflight.last()
    }

    /// Complete (remove) a request by ID.
    ///
    /// Returns `true` if the request was found and removed.
    pub fn complete_request(&mut self, request_id: u64) -> bool {
        let len_before = self.inflight.len();
        self.inflight.retain(|r| r.request_id != request_id);
        let removed = self.inflight.len() < len_before;
        if removed {
            self.total_completed += 1;
            self.consecutive_timeouts = 0;
        }
        removed
    }

    // -- Timeout detection -------------------------------------------------

    /// Check all inflight requests for timeouts at `now_ms`.
    ///
    /// Returns `TimeoutOutcome::TimedOut` with the list of timed-out
    /// request IDs, or `TimeoutOutcome::NoTimeout` if all requests
    /// are within their deadlines. If the consecutive timeout count
    /// exceeds the configured maximum, returns `TimeoutOutcome::Fenced`
    /// and permanently fences the device.
    pub fn check_timeouts(&mut self, now_ms: u64) -> TimeoutOutcome {
        if self.fenced {
            return TimeoutOutcome::Fenced {
                consecutive_count: self.consecutive_timeouts,
            };
        }

        let mut timed_out: Vec<u64> = Vec::new();
        for r in &self.inflight {
            if r.has_timed_out(now_ms) {
                timed_out.push(r.request_id);
            }
        }

        if timed_out.is_empty() {
            return TimeoutOutcome::NoTimeout;
        }

        self.consecutive_timeouts += 1;
        self.total_timeouts += timed_out.len() as u64;

        for &id in &timed_out {
            self.inflight.retain(|r| r.request_id != id);
        }

        if self.max_consecutive_timeouts > 0
            && self.consecutive_timeouts >= self.max_consecutive_timeouts
        {
            self.fenced = true;
            return TimeoutOutcome::Fenced {
                consecutive_count: self.consecutive_timeouts,
            };
        }

        TimeoutOutcome::TimedOut {
            request_ids: timed_out,
            consecutive_count: self.consecutive_timeouts,
        }
    }

    // -- Recovery ----------------------------------------------------------

    /// Reset the consecutive timeout counter (e.g., after a successful
    /// backend reset).
    pub fn reset_consecutive_timeouts(&mut self) {
        self.consecutive_timeouts = 0;
    }

    /// Unfence the device (operator action after diagnosis).
    pub fn unfence(&mut self) {
        self.fenced = false;
        self.consecutive_timeouts = 0;
    }

    /// Drain all inflight requests without completing them (used during
    /// device teardown or emergency reset).
    pub fn drain(&mut self) -> Vec<InflightRequest> {
        let mut drained = Vec::new();
        core::mem::swap(&mut self.inflight, &mut drained);
        self.consecutive_timeouts = 0;
        drained
    }

    /// Return a snapshot of currently inflight requests (for diagnosis).
    #[must_use]
    pub fn inflight_snapshot(&self) -> &[InflightRequest] {
        &self.inflight
    }
}

impl fmt::Display for InflightTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InflightTracker(inflight={} max={} timeout_ms={} fenced={} consecutive={} total_timeouts={})",
            self.inflight.len(),
            self.max_inflight,
            self.request_timeout_ms,
            self.fenced,
            self.consecutive_timeouts,
            self.total_timeouts
        )
    }
}

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- RequestDeadline tests ---------------------------------------------

    #[test]
    fn deadline_from_now() {
        let d = RequestDeadline::from_now(1000, 500);
        assert_eq!(d.deadline_ms(), 1500);
    }

    #[test]
    fn deadline_not_expired() {
        let d = RequestDeadline::from_now(1000, 500);
        assert!(!d.has_expired(1400));
        assert_eq!(d.remaining_ms(1400), 100);
    }

    #[test]
    fn deadline_expired_exact() {
        let d = RequestDeadline::from_now(1000, 500);
        assert!(d.has_expired(1500));
    }

    #[test]
    fn deadline_expired_past() {
        let d = RequestDeadline::from_now(1000, 500);
        assert!(d.has_expired(2000));
        assert_eq!(d.remaining_ms(2000), 0);
    }

    #[test]
    fn deadline_saturating_add() {
        let d = RequestDeadline::from_now(u64::MAX - 100, 500);
        assert_eq!(d.deadline_ms(), u64::MAX);
    }

    #[test]
    fn deadline_display() {
        let d = RequestDeadline::from_now(0, 30000);
        let s = alloc::format!("{d}");
        assert!(s.contains("deadline=30000ms"));
    }

    // -- InflightTracker basic tests ---------------------------------------

    #[test]
    fn tracker_starts_empty() {
        let t = InflightTracker::default_config();
        assert_eq!(t.inflight_count(), 0);
        assert!(!t.is_full());
        assert!(!t.is_fenced());
    }

    #[test]
    fn record_and_complete_request() {
        let mut t = InflightTracker::default_config();
        assert!(t.record_request(1, 0, InflightOp::Read, 0, 8).is_some());
        assert_eq!(t.inflight_count(), 1);
        assert!(t.complete_request(1));
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.total_completed(), 1);
    }

    #[test]
    fn complete_nonexistent_request() {
        let mut t = InflightTracker::default_config();
        assert!(!t.complete_request(999));
    }

    #[test]
    fn record_at_capacity() {
        let mut t = InflightTracker::new(TimeoutConfig {
            max_inflight: 2,
            ..TimeoutConfig::default()
        });
        assert!(t.record_request(1, 0, InflightOp::Read, 0, 1).is_some());
        assert!(t.record_request(2, 0, InflightOp::Write, 1, 1).is_some());
        assert!(t.is_full());
        assert!(t.record_request(3, 0, InflightOp::Read, 2, 1).is_none());
    }

    #[test]
    fn record_when_fenced() {
        let mut t = InflightTracker::default_config();
        t.fenced = true;
        assert!(t.record_request(1, 0, InflightOp::Read, 0, 1).is_none());
    }

    // -- Timeout detection tests -------------------------------------------

    #[test]
    fn no_timeout_when_within_deadline() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(5000));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let outcome = t.check_timeouts(4000);
        assert_eq!(outcome, TimeoutOutcome::NoTimeout);
        assert_eq!(t.inflight_count(), 1);
    }

    #[test]
    fn single_timeout() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Write, 0, 8);
        let outcome = t.check_timeouts(200);
        assert!(
            matches!(&outcome, TimeoutOutcome::TimedOut { request_ids, consecutive_count }
                if request_ids == &alloc::vec![1] && *consecutive_count == 1)
        );
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.total_timeouts(), 1);
    }

    #[test]
    fn multiple_timeouts() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.record_request(2, 50, InflightOp::Write, 1, 1);
        let outcome = t.check_timeouts(200);
        assert!(
            matches!(&outcome, TimeoutOutcome::TimedOut { request_ids, .. }
                if request_ids.len() == 2)
        );
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.total_timeouts(), 2);
    }

    #[test]
    fn mixed_timeout_and_active() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.record_request(2, 150, InflightOp::Write, 1, 1);
        let outcome = t.check_timeouts(200);
        assert!(
            matches!(&outcome, TimeoutOutcome::TimedOut { request_ids, .. }
                if request_ids == &alloc::vec![1])
        );
        assert_eq!(t.inflight_count(), 1);
    }

    #[test]
    fn timeout_counter_resets_on_completion() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.check_timeouts(200);
        assert_eq!(t.consecutive_timeouts(), 1);

        let _ = t.record_request(2, 200, InflightOp::Read, 1, 1);
        t.complete_request(2);
        assert_eq!(t.consecutive_timeouts(), 0);
    }

    // -- Fence tests -------------------------------------------------------

    #[test]
    fn fence_after_max_consecutive_timeouts() {
        let mut t = InflightTracker::new(TimeoutConfig {
            request_timeout_ms: 100,
            max_consecutive_timeouts: 2,
            ..TimeoutConfig::default()
        });

        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let outcome = t.check_timeouts(200);
        assert!(matches!(
            outcome,
            TimeoutOutcome::TimedOut {
                consecutive_count: 1,
                ..
            }
        ));
        assert!(!t.is_fenced());

        let _ = t.record_request(2, 200, InflightOp::Write, 1, 1);
        let outcome = t.check_timeouts(400);
        assert!(matches!(
            outcome,
            TimeoutOutcome::Fenced {
                consecutive_count: 2
            }
        ));
        assert!(t.is_fenced());
    }

    #[test]
    fn no_fence_when_max_is_zero() {
        let mut t = InflightTracker::new(TimeoutConfig {
            request_timeout_ms: 100,
            max_consecutive_timeouts: 0,
            ..TimeoutConfig::default()
        });

        for i in 0..10 {
            let _ = t.record_request(i, i * 200, InflightOp::Read, i, 1);
            let outcome = t.check_timeouts(i * 200 + 200);
            assert!(!matches!(outcome, TimeoutOutcome::Fenced { .. }));
        }
        assert!(!t.is_fenced());
    }

    #[test]
    fn unfence_after_fence() {
        let mut t = InflightTracker::new(TimeoutConfig {
            request_timeout_ms: 100,
            max_consecutive_timeouts: 1,
            ..TimeoutConfig::default()
        });
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.check_timeouts(200);
        assert!(t.is_fenced());

        t.unfence();
        assert!(!t.is_fenced());
        assert_eq!(t.consecutive_timeouts(), 0);
    }

    // -- Drain tests -------------------------------------------------------

    #[test]
    fn drain_empties_tracker() {
        let mut t = InflightTracker::default_config();
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.record_request(2, 0, InflightOp::Write, 1, 1);
        let drained = t.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(t.inflight_count(), 0);
    }

    #[test]
    fn drain_resets_consecutive_counter() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.check_timeouts(200);
        assert_eq!(t.consecutive_timeouts(), 1);
        let _ = t.drain();
        assert_eq!(t.consecutive_timeouts(), 0);
    }

    // -- Display tests -----------------------------------------------------

    #[test]
    fn inflight_request_display() {
        let req = InflightRequest::new(
            42,
            RequestDeadline::from_now(0, 5000),
            InflightOp::Write,
            100,
            8,
        );
        let s = alloc::format!("{req}");
        assert!(s.contains("req=42"));
        assert!(s.contains("write"));
        assert!(s.contains("sector=100"));
    }

    #[test]
    fn tracker_display() {
        let t = InflightTracker::default_config();
        let s = alloc::format!("{t}");
        assert!(s.contains("InflightTracker"));
        assert!(s.contains("inflight=0"));
    }

    // -- InflightOp tests --------------------------------------------------

    #[test]
    fn inflight_op_display_all_variants() {
        assert!(alloc::format!("{}", InflightOp::Read).contains("read"));
        assert!(alloc::format!("{}", InflightOp::Write).contains("write"));
        assert!(alloc::format!("{}", InflightOp::Flush).contains("flush"));
        assert!(alloc::format!("{}", InflightOp::Discard).contains("discard"));
        assert!(alloc::format!("{}", InflightOp::WriteZeroes).contains("write_zeroes"));
    }

    // -- TimeoutConfig tests -----------------------------------------------

    #[test]
    fn timeout_config_defaults() {
        let cfg = TimeoutConfig::default();
        assert_eq!(cfg.request_timeout_ms, 30_000);
        assert_eq!(cfg.max_inflight, 64);
        assert!(cfg.auto_reset);
        assert_eq!(cfg.max_consecutive_timeouts, 3);
    }

    #[test]
    fn timeout_config_with_timeout() {
        let cfg = TimeoutConfig::with_timeout(5000);
        assert_eq!(cfg.request_timeout_ms, 5000);
        assert_eq!(cfg.max_inflight, 64);
        assert!(cfg.auto_reset);
    }

    #[test]
    fn reset_consecutive_timeouts_works() {
        let mut t = InflightTracker::new(TimeoutConfig::with_timeout(100));
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.check_timeouts(200);
        assert_eq!(t.consecutive_timeouts(), 1);
        t.reset_consecutive_timeouts();
        assert_eq!(t.consecutive_timeouts(), 0);
    }

    #[test]
    fn inflight_snapshot_reflects_current_state() {
        let mut t = InflightTracker::default_config();
        let _ = t.record_request(1, 0, InflightOp::Read, 0, 1);
        let _ = t.record_request(2, 0, InflightOp::Write, 1, 1);
        let snap = t.inflight_snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].request_id, 1);
        assert_eq!(snap[1].request_id, 2);
    }
}
