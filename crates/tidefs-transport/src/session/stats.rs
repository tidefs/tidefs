//! Per-session operational statistics with atomic counters.
//!
//! Tracks bytes sent/received, message counts by priority, error tallies,
//! and queue-depth snapshots for observability without adding protocol or
//! crypto layers.
//!
//! ## Counter semantics
//!
//! - Monotonic counters (`bytes_sent`, `messages_sent`, `send_errors`, etc.)
//!   only increase over the session lifetime. They are reset to zero by
//!   [`SessionStats::reset`].
//! - Queue-depth fields in [`SessionStatsSnapshot`] reflect the current depth
//!   at snapshot time; they are not monotonic.
//! - Snapshots are point-in-time consistent: all counters are loaded under
//!   the session lock so no counter can advance between reads.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::message_priority::MessagePriority;
use crate::types::{HlcTimestamp, SessionId};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// SessionStats
// ---------------------------------------------------------------------------

/// Per-session operational statistics backed by atomic counters.
///
/// All counter fields are [`AtomicU64`] so they can be read without
/// blocking writers. Queue-depth fields are not stored here -- they are
/// captured at snapshot time from the live queues.
pub struct SessionStats {
    /// Total bytes sent over this session's write path.
    pub bytes_sent: AtomicU64,
    /// Total bytes received over this session's read path.
    pub bytes_received: AtomicU64,
    /// Number of messages sent since session establishment.
    pub messages_sent: AtomicU64,
    /// Number of messages received since session establishment.
    pub messages_received: AtomicU64,
    /// Messages sent with Control priority.
    pub messages_sent_control: AtomicU64,
    /// Messages sent with Data priority.
    pub messages_sent_data: AtomicU64,
    /// Messages received classified as Control (best-effort).
    pub messages_received_control: AtomicU64,
    /// Messages received classified as Data (best-effort).
    pub messages_received_data: AtomicU64,
    /// Number of send-side errors encountered.
    pub send_errors: AtomicU64,
    /// Number of receive-side errors encountered.
    pub receive_errors: AtomicU64,
    /// Count of reconnection attempts for this session.
    pub reconnections: AtomicU64,
    /// Number of chunks shipped (sent) through this session.
    pub chunks_shipped: AtomicU64,
    /// Number of chunks received through this session.
    pub chunks_received: AtomicU64,
    /// HLC timestamp of the last I/O activity on this session.
    /// Not atomic -- protected by the session lock.
    pub last_activity: Option<HlcTimestamp>,
    /// HLC timestamp when the session first reached Established state.
    /// Not atomic -- protected by the session lock.
    pub established_at: Option<HlcTimestamp>,
}

impl SessionStats {
    /// Create a new zeroed stats instance.
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            messages_sent_control: AtomicU64::new(0),
            messages_sent_data: AtomicU64::new(0),
            messages_received_control: AtomicU64::new(0),
            messages_received_data: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
            reconnections: AtomicU64::new(0),
            chunks_shipped: AtomicU64::new(0),
            chunks_received: AtomicU64::new(0),
            last_activity: None,
            established_at: None,
        }
    }

    /// Record a successful send of `byte_count` bytes with the given priority.
    pub fn record_send(&self, byte_count: u64, priority: MessagePriority) {
        self.bytes_sent.fetch_add(byte_count, Ordering::Relaxed);
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        match priority {
            MessagePriority::Control => {
                self.messages_sent_control.fetch_add(1, Ordering::Relaxed);
            }
            MessagePriority::Data => {
                self.messages_sent_data.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a successful receive of `byte_count` bytes with an optional
    /// priority classification. When priority is unknown (common on the
    /// receive path), only the total message counter is incremented.
    pub fn record_recv(&self, byte_count: u64, priority: Option<MessagePriority>) {
        self.bytes_received.fetch_add(byte_count, Ordering::Relaxed);
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        match priority {
            Some(MessagePriority::Control) => {
                self.messages_received_control
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(MessagePriority::Data) => {
                self.messages_received_data.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                // Unknown priority -- counted in total only.
            }
        }
    }

    /// Increment the send-error counter.
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the receive-error counter.
    pub fn record_recv_error(&self) {
        self.receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the reconnection counter.
    pub fn record_reconnect(&self) {
        self.reconnections.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment chunks shipped counter.
    pub fn record_chunk_shipped(&self) {
        self.chunks_shipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment chunks received counter.
    pub fn record_chunk_received(&self) {
        self.chunks_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Reset all counters to zero. Timestamp fields are cleared.
    pub fn reset(&mut self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.messages_sent_control.store(0, Ordering::Relaxed);
        self.messages_sent_data.store(0, Ordering::Relaxed);
        self.messages_received_control.store(0, Ordering::Relaxed);
        self.messages_received_data.store(0, Ordering::Relaxed);
        self.send_errors.store(0, Ordering::Relaxed);
        self.receive_errors.store(0, Ordering::Relaxed);
        self.reconnections.store(0, Ordering::Relaxed);
        self.chunks_shipped.store(0, Ordering::Relaxed);
        self.chunks_received.store(0, Ordering::Relaxed);
        self.last_activity = None;
        self.established_at = None;
    }

    /// Produce a point-in-time snapshot of all counters.
    ///
    /// Queue-depth fields are set to 0 here; callers should use
    /// the session-level `stats()` method to populate queue depths.
    pub fn snapshot(&self) -> SessionStatsSnapshot {
        SessionStatsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            messages_sent_control: self.messages_sent_control.load(Ordering::Relaxed),
            messages_sent_data: self.messages_sent_data.load(Ordering::Relaxed),
            messages_received_control: self.messages_received_control.load(Ordering::Relaxed),
            messages_received_data: self.messages_received_data.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            receive_errors: self.receive_errors.load(Ordering::Relaxed),
            reconnections: self.reconnections.load(Ordering::Relaxed),
            chunks_shipped: self.chunks_shipped.load(Ordering::Relaxed),
            chunks_received: self.chunks_received.load(Ordering::Relaxed),
            send_queue_depth: 0,
            priority_queue_control_depth: 0,
            priority_queue_data_depth: 0,
            last_activity: self.last_activity,
            established_at: self.established_at,
        }
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("SessionStats")
            .field("bytes_sent", &snap.bytes_sent)
            .field("bytes_received", &snap.bytes_received)
            .field("messages_sent", &snap.messages_sent)
            .field("messages_received", &snap.messages_received)
            .field("send_errors", &snap.send_errors)
            .field("receive_errors", &snap.receive_errors)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SessionStatsSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of per-session operational statistics.
///
/// All counter values are plain `u64` read atomically from [`SessionStats`].
/// Queue-depth fields reflect the live queue state at snapshot time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionStatsSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_sent_control: u64,
    pub messages_sent_data: u64,
    pub messages_received_control: u64,
    pub messages_received_data: u64,
    pub send_errors: u64,
    pub receive_errors: u64,
    pub reconnections: u64,
    pub chunks_shipped: u64,
    pub chunks_received: u64,
    /// Current depth of the send buffer (PeerSendBuffer).
    pub send_queue_depth: u64,
    /// Current depth of the priority queue Control sub-queue.
    pub priority_queue_control_depth: u64,
    /// Current depth of the priority queue Data sub-queue.
    pub priority_queue_data_depth: u64,
    pub last_activity: Option<HlcTimestamp>,
    pub established_at: Option<HlcTimestamp>,
}

// ---------------------------------------------------------------------------
// TransportStats
// ---------------------------------------------------------------------------

/// Aggregate statistics across all sessions known to a [`Transport`].
///
/// Session snapshots are keyed by [`SessionId`] for per-session drill-down.
#[derive(Clone, Debug, Default)]
pub struct TransportStats {
    /// Per-session statistics snapshots keyed by session id.
    pub sessions: BTreeMap<SessionId, SessionStatsSnapshot>,
}

impl TransportStats {
    /// Create an empty aggregate.
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    /// Total bytes sent summed across all sessions.
    pub fn total_bytes_sent(&self) -> u64 {
        self.sessions.values().map(|s| s.bytes_sent).sum()
    }

    /// Total bytes received summed across all sessions.
    pub fn total_bytes_received(&self) -> u64 {
        self.sessions.values().map(|s| s.bytes_received).sum()
    }

    /// Total messages sent summed across all sessions.
    pub fn total_messages_sent(&self) -> u64 {
        self.sessions.values().map(|s| s.messages_sent).sum()
    }

    /// Total send errors summed across all sessions.
    pub fn total_send_errors(&self) -> u64 {
        self.sessions.values().map(|s| s.send_errors).sum()
    }

    /// Total receive errors summed across all sessions.
    pub fn total_receive_errors(&self) -> u64 {
        self.sessions.values().map(|s| s.receive_errors).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SessionStats construction and defaults --

    #[test]
    fn new_stats_all_zero() {
        let stats = SessionStats::new();
        let snap = stats.snapshot();
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.bytes_received, 0);
        assert_eq!(snap.messages_sent, 0);
        assert_eq!(snap.messages_received, 0);
        assert_eq!(snap.messages_sent_control, 0);
        assert_eq!(snap.messages_sent_data, 0);
        assert_eq!(snap.send_errors, 0);
        assert_eq!(snap.receive_errors, 0);
        assert_eq!(snap.reconnections, 0);
    }

    #[test]
    fn default_stats_all_zero() {
        let stats = SessionStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.messages_sent, 0);
    }

    // -- record_send increments counters --

    #[test]
    fn record_send_increments_bytes_and_messages() {
        let stats = SessionStats::new();
        stats.record_send(100, MessagePriority::Data);
        stats.record_send(50, MessagePriority::Control);

        let snap = stats.snapshot();
        assert_eq!(snap.bytes_sent, 150);
        assert_eq!(snap.messages_sent, 2);
    }

    #[test]
    fn record_send_tracks_per_priority() {
        let stats = SessionStats::new();
        stats.record_send(10, MessagePriority::Control);
        stats.record_send(20, MessagePriority::Data);
        stats.record_send(30, MessagePriority::Data);
        stats.record_send(40, MessagePriority::Control);

        let snap = stats.snapshot();
        assert_eq!(snap.messages_sent_control, 2);
        assert_eq!(snap.messages_sent_data, 2);
        assert_eq!(snap.messages_sent, 4);
        assert_eq!(snap.bytes_sent, 100);
    }

    // -- record_recv --

    #[test]
    fn record_recv_increments_bytes_and_messages() {
        let stats = SessionStats::new();
        stats.record_recv(200, Some(MessagePriority::Data));
        stats.record_recv(300, None);

        let snap = stats.snapshot();
        assert_eq!(snap.bytes_received, 500);
        assert_eq!(snap.messages_received, 2);
        assert_eq!(snap.messages_received_data, 1);
        assert_eq!(snap.messages_received_control, 0);
    }

    #[test]
    fn record_recv_with_control_priority() {
        let stats = SessionStats::new();
        stats.record_recv(10, Some(MessagePriority::Control));
        stats.record_recv(20, Some(MessagePriority::Control));

        let snap = stats.snapshot();
        assert_eq!(snap.messages_received_control, 2);
        assert_eq!(snap.messages_received, 2);
    }

    // -- Error counters --

    #[test]
    fn record_send_error_increments() {
        let stats = SessionStats::new();
        stats.record_send_error();
        stats.record_send_error();
        let snap = stats.snapshot();
        assert_eq!(snap.send_errors, 2);
    }

    #[test]
    fn record_recv_error_increments() {
        let stats = SessionStats::new();
        stats.record_recv_error();
        let snap = stats.snapshot();
        assert_eq!(snap.receive_errors, 1);
    }

    // -- reset zeros all counters --

    #[test]
    fn reset_zeros_all_counters() {
        let mut stats = SessionStats::new();
        stats.record_send(100, MessagePriority::Data);
        stats.record_send_error();
        stats.record_recv(50, None);

        stats.reset();
        let snap = stats.snapshot();
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.messages_sent, 0);
        assert_eq!(snap.bytes_received, 0);
        assert_eq!(snap.messages_received, 0);
        assert_eq!(snap.send_errors, 0);
        assert_eq!(snap.messages_sent_control, 0);
        assert_eq!(snap.messages_sent_data, 0);
    }

    // -- Snapshot isolation --

    #[test]
    fn snapshot_is_point_in_time() {
        let stats = SessionStats::new();
        stats.record_send(42, MessagePriority::Data);
        let snap = stats.snapshot();
        assert_eq!(snap.bytes_sent, 42);
        // Record more after snapshot; snapshot should not change.
        stats.record_send(100, MessagePriority::Control);
        assert_eq!(snap.bytes_sent, 42);
        // New snapshot reflects updated values.
        let snap2 = stats.snapshot();
        assert_eq!(snap2.bytes_sent, 142);
    }

    // -- Debug output --

    #[test]
    fn debug_output_contains_key_fields() {
        let stats = SessionStats::new();
        stats.record_send(64, MessagePriority::Data);
        let s = format!("{stats:?}");
        assert!(s.contains("SessionStats"));
        assert!(s.contains("bytes_sent"));
    }

    // -- TransportStats aggregate sums across sessions --

    #[test]
    fn transport_stats_sums_across_sessions() {
        let mut agg = TransportStats::new();
        let stats_a = SessionStats::new();
        stats_a.record_send(100, MessagePriority::Data);
        stats_a.record_send(50, MessagePriority::Control);
        stats_a.record_send_error();

        let stats_b = SessionStats::new();
        stats_b.record_send(200, MessagePriority::Data);
        stats_b.record_recv(300, None);

        agg.sessions.insert(SessionId::new(1), stats_a.snapshot());
        agg.sessions.insert(SessionId::new(2), stats_b.snapshot());

        assert_eq!(agg.total_bytes_sent(), 350);
        assert_eq!(agg.total_messages_sent(), 3);
        assert_eq!(agg.total_send_errors(), 1);
        assert_eq!(agg.total_bytes_received(), 300);
    }

    #[test]
    fn transport_stats_empty_is_zero() {
        let agg = TransportStats::new();
        assert_eq!(agg.total_bytes_sent(), 0);
        assert_eq!(agg.total_bytes_received(), 0);
        assert_eq!(agg.total_messages_sent(), 0);
        assert_eq!(agg.total_send_errors(), 0);
        assert_eq!(agg.total_receive_errors(), 0);
    }

    // -- Chunk counters --

    #[test]
    fn chunk_counters_increment() {
        let stats = SessionStats::new();
        stats.record_chunk_shipped();
        stats.record_chunk_shipped();
        stats.record_chunk_received();
        let snap = stats.snapshot();
        assert_eq!(snap.chunks_shipped, 2);
        assert_eq!(snap.chunks_received, 1);
    }

    // -- Reconnection counter --

    #[test]
    fn reconnection_counter_increments() {
        let stats = SessionStats::new();
        stats.record_reconnect();
        stats.record_reconnect();
        stats.record_reconnect();
        let snap = stats.snapshot();
        assert_eq!(snap.reconnections, 3);
    }
}
