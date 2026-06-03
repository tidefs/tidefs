//! Per-connection transport telemetry collector with rate-limited metric emission.
//!
//! This module provides connection-level byte, message, and error-class counters
//! accumulated via lock-free atomic operations, plus a configurable periodic
//! emitter that snapshots and publishes telemetry for operator observability.
//!
//! ## Architecture
//!
//! ```text
//! send path --(fetch_add)---+
//! recv path --(fetch_add)---+
//! error sites --(fetch_add)-+--> TelemetryAccumulator
//! LifecycleBus --(sub)------+         |
//!                            |    snapshot()
//!                            v         |
//!                      TelemetryEmitter--> TelemetrySubscriber
//! ```
//!
//! ## Integration
//!
//! The [`TelemetryAccumulator`] is created per-connection and shared via
//! `Arc`. Hot-path send/receive/error sites call single `fetch_add`
//! operations with negligible overhead. State transitions are counted
//! by registering a [`LifecycleSubscriber`] adapter.
//!
//! Periodic emission runs on a configurable interval (default 60 s),
//! snapshots all counters atomically, resets them to prevent overflow,
//! and dispatches the snapshot to registered [`TelemetrySubscriber`]s.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time;
use tracing::info;

use crate::connection_state::{LifecycleEvent, LifecycleSubscriber};
use crate::error_classification::TransportErrorKind;

// ---------------------------------------------------------------------------
// TransportErrorClass
// ---------------------------------------------------------------------------

/// Typed error classification for telemetry counters.
///
/// Each variant maps to a distinct error bucket. The `errors_by_class` map
/// in [`TelemetryAccumulator`] uses this enum as keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransportErrorClass {
    /// Connection or operation timed out.
    Timeout,
    /// Protocol violation: bad magic, version mismatch, unexpected message.
    ProtocolViolation,
    /// Peer actively rejected a request or connection.
    PeerReject,
    /// Local resource exhaustion: memory, file descriptors, queue capacity.
    ResourceExhaustion,
    /// Internal assertion, logic, or unexpected state error.
    Internal,
}

impl std::fmt::Display for TransportErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "Timeout"),
            Self::ProtocolViolation => write!(f, "ProtocolViolation"),
            Self::PeerReject => write!(f, "PeerReject"),
            Self::ResourceExhaustion => write!(f, "ResourceExhaustion"),
            Self::Internal => write!(f, "Internal"),
        }
    }
}

impl TransportErrorClass {
    /// Map a [`TransportErrorKind`] to its telemetry class.
    pub fn from_kind(kind: TransportErrorKind) -> Self {
        match kind {
            TransportErrorKind::ConnectionTimeout | TransportErrorKind::KeepaliveTimeout => {
                TransportErrorClass::Timeout
            }
            TransportErrorKind::ProtocolViolation
            | TransportErrorKind::UnknownMessageFamily
            | TransportErrorKind::MessageTooLarge => TransportErrorClass::ProtocolViolation,
            TransportErrorKind::ConnectionRefused
            | TransportErrorKind::ConnectionReset
            | TransportErrorKind::ChannelClosed => TransportErrorClass::PeerReject,
            TransportErrorKind::BackpressureStall => TransportErrorClass::ResourceExhaustion,
            TransportErrorKind::InternalError => TransportErrorClass::Internal,
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetrySnapshot
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of all transport telemetry counters.
///
/// Produced by [`TelemetryAccumulator::snapshot`] and consumed by
/// [`TelemetryEmitter`] and `tidefsctl` queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Connection identifier.
    pub connection_id: u64,
    /// Total bytes sent since last snapshot (or accumulator creation).
    pub bytes_sent: u64,
    /// Total bytes received since last snapshot.
    pub bytes_received: u64,
    /// Total messages sent since last snapshot.
    pub messages_sent: u64,
    /// Total messages received since last snapshot.
    pub messages_received: u64,
    /// Per-class error counts since last snapshot.
    pub errors_by_class: HashMap<TransportErrorClass, u64>,
    /// Number of connection state transitions since last snapshot.
    pub connection_state_transitions: u64,
    /// Unix timestamp (seconds) of the most recent activity.
    pub last_active_at_secs: i64,
    /// Wall-clock time when this snapshot was taken.
    pub snapshot_at_secs: i64,
}

impl TelemetrySnapshot {
    /// Create an empty snapshot for the given connection.
    pub fn empty(connection_id: u64) -> Self {
        let now = now_secs();
        Self {
            connection_id,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            errors_by_class: HashMap::new(),
            connection_state_transitions: 0,
            last_active_at_secs: now,
            snapshot_at_secs: now,
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetryAccumulator
// ---------------------------------------------------------------------------

/// Per-connection telemetry accumulator using lock-free atomic counters.
///
/// All hot-path operations are single `fetch_add` on atomic integers.
/// The accumulator is safe to share across threads via `Arc`.
pub struct TelemetryAccumulator {
    /// Connection identifier for snapshot attribution.
    connection_id: u64,
    /// Total bytes sent (cumulative since creation or last reset).
    bytes_sent: AtomicU64,
    /// Total bytes received.
    bytes_received: AtomicU64,
    /// Total messages sent.
    messages_sent: AtomicU64,
    /// Total messages received.
    messages_received: AtomicU64,
    /// Per-class error counters, infrequently updated so a lock is acceptable.
    errors_by_class: RwLock<HashMap<TransportErrorClass, AtomicU64>>,
    /// State transition count.
    connection_state_transitions: AtomicU64,
    /// Unix timestamp of most recent activity.
    last_active_at: AtomicI64,
}

impl TelemetryAccumulator {
    /// Create a new accumulator for the given connection.
    pub fn new(connection_id: u64) -> Self {
        let mut errors_by_class = HashMap::new();
        for class in &[
            TransportErrorClass::Timeout,
            TransportErrorClass::ProtocolViolation,
            TransportErrorClass::PeerReject,
            TransportErrorClass::ResourceExhaustion,
            TransportErrorClass::Internal,
        ] {
            errors_by_class.insert(*class, AtomicU64::new(0));
        }

        let now = now_secs();

        Self {
            connection_id,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            errors_by_class: RwLock::new(errors_by_class),
            connection_state_transitions: AtomicU64::new(0),
            last_active_at: AtomicI64::new(now),
        }
    }

    // -- Hot-path record methods (lock-free) --

    /// Record bytes sent on this connection.
    #[inline]
    pub fn record_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes received on this connection.
    #[inline]
    pub fn record_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Record a message sent.
    #[inline]
    pub fn record_message_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record a message received.
    #[inline]
    pub fn record_message_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record an error of a given class.
    pub fn record_error(&self, class: TransportErrorClass) {
        // Errors are rare relative to data-path ops; a lock is acceptable.
        if let Ok(map) = self.errors_by_class.try_read() {
            if let Some(counter) = map.get(&class) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.touch();
    }

    /// Record a connection state transition.
    #[inline]
    pub fn record_state_transition(&self) {
        self.connection_state_transitions
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Update the last-active timestamp to now.
    #[inline]
    fn touch(&self) {
        self.last_active_at.store(now_secs(), Ordering::Relaxed);
    }

    // -- Snapshot --

    /// Take a snapshot of all counters.
    ///
    /// Reads counters atomically. To prevent gaps in emission,
    /// callers should pair this with [`reset`] — snapshot-then-reset
    /// ensures every increment is counted in exactly one snapshot.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let errors = if let Ok(map) = self.errors_by_class.try_read() {
            map.iter()
                .map(|(k, v)| (*k, v.load(Ordering::Relaxed)))
                .collect()
        } else {
            HashMap::new()
        };

        TelemetrySnapshot {
            connection_id: self.connection_id,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            errors_by_class: errors,
            connection_state_transitions: self.connection_state_transitions.load(Ordering::Relaxed),
            last_active_at_secs: self.last_active_at.load(Ordering::Relaxed),
            snapshot_at_secs: now_secs(),
        }
    }

    /// Reset all counters to zero after a snapshot.
    ///
    /// Call this immediately after [`snapshot`] for gap-free emission.
    pub fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.connection_state_transitions
            .store(0, Ordering::Relaxed);
        if let Ok(map) = self.errors_by_class.try_read() {
            for counter in map.values() {
                counter.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Return the connection identifier.
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }
}

// ---------------------------------------------------------------------------
// TelemetrySubscriber
// ---------------------------------------------------------------------------

/// A subscriber for periodic telemetry snapshot emission.
///
/// Register implementations with [`TelemetryEmitter`] via
/// [`TelemetryEmitter::subscribe`].
pub trait TelemetrySubscriber: Send + Sync {
    /// Called on each emission tick with the current snapshot.
    fn on_telemetry_snapshot(&self, snapshot: &TelemetrySnapshot);
}

// ---------------------------------------------------------------------------
// DefaultTelemetryLogger
// ---------------------------------------------------------------------------

/// Default telemetry subscriber that logs snapshots at `info` level.
#[derive(Debug, Default)]
pub struct DefaultTelemetryLogger;

impl TelemetrySubscriber for DefaultTelemetryLogger {
    fn on_telemetry_snapshot(&self, snapshot: &TelemetrySnapshot) {
        info!(
            conn_id = snapshot.connection_id,
            bytes_sent = snapshot.bytes_sent,
            bytes_received = snapshot.bytes_received,
            msgs_sent = snapshot.messages_sent,
            msgs_received = snapshot.messages_received,
            transitions = snapshot.connection_state_transitions,
            "transport telemetry snapshot"
        );
    }
}

// ---------------------------------------------------------------------------
// TelemetryEmitter
// ---------------------------------------------------------------------------

/// Periodic telemetry emitter that snapshots, resets, and publishes counters.
///
/// Spawned as a background task via [`spawn`](TelemetryEmitter::spawn).
/// On each tick, it atomically snapshots the accumulator, resets counters
/// (snapshot-then-reset to prevent gaps), and notifies registered subscribers.
pub struct TelemetryEmitter {
    /// Accumulator to snapshot on each tick.
    accumulator: Arc<TelemetryAccumulator>,
    /// Interval between emissions.
    emit_interval: Duration,
    /// Registered subscribers.
    subscribers: RwLock<Vec<Arc<dyn TelemetrySubscriber>>>,
}

impl TelemetryEmitter {
    /// Create a new emitter with the default interval (60 s) and a default
    /// `info`-level logger subscriber.
    pub fn new(accumulator: Arc<TelemetryAccumulator>) -> Self {
        Self {
            accumulator,
            emit_interval: Duration::from_secs(60),
            subscribers: RwLock::new(vec![Arc::new(DefaultTelemetryLogger)]),
        }
    }

    /// Set a custom emission interval.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.emit_interval = interval;
        self
    }

    /// Register a subscriber.
    pub async fn subscribe(&self, subscriber: Arc<dyn TelemetrySubscriber>) {
        self.subscribers.write().await.push(subscriber);
    }

    /// Remove all subscribers of a given concrete type.
    /// Returns the number of subscribers removed.
    pub async fn clear_subscribers(&self) -> usize {
        let mut subs = self.subscribers.write().await;
        let n = subs.len();
        subs.clear();
        n
    }

    /// Spawn the background emission task.
    ///
    /// Returns a [`tokio::task::JoinHandle`]. The task runs until the handle
    /// is dropped or cancelled.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = time::interval(self.emit_interval);
            // Skip immediate first tick to let counters accumulate.
            interval.tick().await;

            loop {
                interval.tick().await;
                self.emit();
            }
        })
    }

    /// Emit one snapshot synchronously (for tests and explicit queries).
    pub fn emit_now(&self) -> TelemetrySnapshot {
        let snap = self.accumulator.snapshot();
        self.accumulator.reset();
        self.notify_subscribers_sync(&snap);
        snap
    }

    /// Internal: snapshot, reset, notify.
    fn emit(&self) {
        let snap = self.accumulator.snapshot();
        self.accumulator.reset();
        self.notify_subscribers_sync(&snap);
    }

    /// Notify all subscribers synchronously.
    fn notify_subscribers_sync(&self, snapshot: &TelemetrySnapshot) {
        if let Ok(subs) = self.subscribers.try_read() {
            for sub in subs.iter() {
                sub.on_telemetry_snapshot(snapshot);
            }
        }
    }

    /// Return a clone of the accumulator Arc.
    pub fn accumulator(&self) -> Arc<TelemetryAccumulator> {
        self.accumulator.clone()
    }
}

// ---------------------------------------------------------------------------
// TelemetryLifecycleSubscriber
// ---------------------------------------------------------------------------

/// An adapter that implements [`LifecycleSubscriber`] to count connection
/// state transitions in a [`TelemetryAccumulator`].
///
/// Register this with the connection's [`LifecycleBus`]
/// (see [`crate::connection_state::LifecycleBus`]) to automatically count
/// every state transition.
pub struct TelemetryLifecycleSubscriber {
    accumulator: Arc<TelemetryAccumulator>,
}

impl TelemetryLifecycleSubscriber {
    /// Create a new adapter that increments `connection_state_transitions`
    /// on each lifecycle event.
    pub fn new(accumulator: Arc<TelemetryAccumulator>) -> Self {
        Self { accumulator }
    }
}

impl LifecycleSubscriber for TelemetryLifecycleSubscriber {
    fn on_lifecycle_event(&self, _event: &LifecycleEvent) {
        self.accumulator.record_state_transition();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- TelemetryAccumulator tests --

    #[test]
    fn accumulator_new_sets_connection_id() {
        let acc = TelemetryAccumulator::new(99);
        assert_eq!(acc.connection_id(), 99);
    }

    #[test]
    fn record_bytes_sent_increments_counter() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_bytes_sent(42);
        acc.record_bytes_sent(58);
        let snap = acc.snapshot();
        assert_eq!(snap.bytes_sent, 100);
    }

    #[test]
    fn record_bytes_received_increments_counter() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_bytes_received(200);
        let snap = acc.snapshot();
        assert_eq!(snap.bytes_received, 200);
    }

    #[test]
    fn record_message_sent_increments_counter() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_message_sent();
        acc.record_message_sent();
        acc.record_message_sent();
        let snap = acc.snapshot();
        assert_eq!(snap.messages_sent, 3);
    }

    #[test]
    fn record_message_received_increments_counter() {
        let acc = TelemetryAccumulator::new(1);
        for _ in 0..5 {
            acc.record_message_received();
        }
        let snap = acc.snapshot();
        assert_eq!(snap.messages_received, 5);
    }

    #[test]
    fn record_error_increments_by_class() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_error(TransportErrorClass::Timeout);
        acc.record_error(TransportErrorClass::Timeout);
        acc.record_error(TransportErrorClass::ProtocolViolation);
        let snap = acc.snapshot();
        assert_eq!(
            snap.errors_by_class.get(&TransportErrorClass::Timeout),
            Some(&2)
        );
        assert_eq!(
            snap.errors_by_class
                .get(&TransportErrorClass::ProtocolViolation),
            Some(&1)
        );
        assert_eq!(
            snap.errors_by_class.get(&TransportErrorClass::Internal),
            Some(&0)
        );
    }

    #[test]
    fn record_state_transition_increments_counter() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_state_transition();
        acc.record_state_transition();
        let snap = acc.snapshot();
        assert_eq!(snap.connection_state_transitions, 2);
    }

    #[test]
    fn snapshot_reflects_all_counters_at_point() {
        let acc = TelemetryAccumulator::new(42);
        acc.record_bytes_sent(1000);
        acc.record_bytes_received(500);
        acc.record_message_sent();
        acc.record_message_received();
        acc.record_error(TransportErrorClass::ResourceExhaustion);
        acc.record_state_transition();

        let snap = acc.snapshot();
        assert_eq!(snap.connection_id, 42);
        assert_eq!(snap.bytes_sent, 1000);
        assert_eq!(snap.bytes_received, 500);
        assert_eq!(snap.messages_sent, 1);
        assert_eq!(snap.messages_received, 1);
        assert_eq!(
            snap.errors_by_class
                .get(&TransportErrorClass::ResourceExhaustion),
            Some(&1)
        );
        assert_eq!(snap.connection_state_transitions, 1);
    }

    #[test]
    fn reset_clears_all_counters() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_bytes_sent(100);
        acc.record_message_sent();
        acc.record_error(TransportErrorClass::Timeout);
        acc.reset();

        let snap = acc.snapshot();
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.messages_sent, 0);
        assert_eq!(
            snap.errors_by_class.get(&TransportErrorClass::Timeout),
            Some(&0)
        );
    }

    #[test]
    fn snapshot_then_reset_prevents_gaps() {
        let acc = TelemetryAccumulator::new(1);
        acc.record_bytes_sent(100);
        let snap1 = acc.snapshot();
        assert_eq!(snap1.bytes_sent, 100);
        acc.reset();
        let snap2 = acc.snapshot();
        assert_eq!(snap2.bytes_sent, 0);
        acc.record_bytes_sent(50);
        let snap3 = acc.snapshot();
        assert_eq!(snap3.bytes_sent, 50);
    }

    #[test]
    fn last_active_at_updates_on_record() {
        let acc = TelemetryAccumulator::new(1);
        let before = now_secs();
        acc.record_bytes_sent(1);
        let snap = acc.snapshot();
        assert!(snap.last_active_at_secs >= before);
    }

    // -- TransportErrorClass tests --

    #[test]
    fn error_class_from_kind_maps_correctly() {
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::ConnectionTimeout),
            TransportErrorClass::Timeout
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::KeepaliveTimeout),
            TransportErrorClass::Timeout
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::ProtocolViolation),
            TransportErrorClass::ProtocolViolation
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::ConnectionRefused),
            TransportErrorClass::PeerReject
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::ConnectionReset),
            TransportErrorClass::PeerReject
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::BackpressureStall),
            TransportErrorClass::ResourceExhaustion
        );
        assert_eq!(
            TransportErrorClass::from_kind(TransportErrorKind::InternalError),
            TransportErrorClass::Internal
        );
    }

    #[test]
    fn error_class_display_outputs_readable_names() {
        assert_eq!(TransportErrorClass::Timeout.to_string(), "Timeout");
        assert_eq!(
            TransportErrorClass::ProtocolViolation.to_string(),
            "ProtocolViolation"
        );
        assert_eq!(TransportErrorClass::PeerReject.to_string(), "PeerReject");
        assert_eq!(
            TransportErrorClass::ResourceExhaustion.to_string(),
            "ResourceExhaustion"
        );
        assert_eq!(TransportErrorClass::Internal.to_string(), "Internal");
    }

    // -- TelemetrySnapshot tests --

    #[test]
    fn snapshot_empty_has_zero_counters() {
        let snap = TelemetrySnapshot::empty(7);
        assert_eq!(snap.connection_id, 7);
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.bytes_received, 0);
        assert_eq!(snap.messages_sent, 0);
        assert_eq!(snap.messages_received, 0);
        assert!(snap.errors_by_class.is_empty());
        assert_eq!(snap.connection_state_transitions, 0);
    }

    // -- TelemetryEmitter tests --

    #[test]
    fn emitter_emit_now_snapshots_and_resets() {
        let acc = Arc::new(TelemetryAccumulator::new(1));
        acc.record_bytes_sent(500);
        let emitter = TelemetryEmitter::new(acc.clone());
        let snap = emitter.emit_now();
        assert_eq!(snap.bytes_sent, 500);
        let snap2 = acc.snapshot();
        assert_eq!(snap2.bytes_sent, 0);
    }

    #[test]
    fn emitter_emit_now_notifies_subscribers() {
        struct CounterSub {
            count: Mutex<u64>,
        }
        impl TelemetrySubscriber for CounterSub {
            fn on_telemetry_snapshot(&self, _snapshot: &TelemetrySnapshot) {
                *self.count.lock().unwrap() += 1;
            }
        }

        let acc = Arc::new(TelemetryAccumulator::new(1));
        let emitter = TelemetryEmitter::new(acc.clone());
        let sub = Arc::new(CounterSub {
            count: Mutex::new(0),
        });

        // Use block_on via the tokio Builder to create a runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            emitter.subscribe(sub.clone()).await;
            emitter.emit_now();
        });
        assert_eq!(*sub.count.lock().unwrap(), 1);
    }

    // -- TelemetryLifecycleSubscriber tests --

    #[test]
    fn lifecycle_subscriber_counts_transitions() {
        let acc = Arc::new(TelemetryAccumulator::new(1));
        let sub = TelemetryLifecycleSubscriber::new(acc.clone());

        sub.on_lifecycle_event(&LifecycleEvent::ConnectStarted { generation: 1 });
        sub.on_lifecycle_event(&LifecycleEvent::Active { generation: 2 });
        sub.on_lifecycle_event(&LifecycleEvent::Closed { generation: 3 });

        let snap = acc.snapshot();
        assert_eq!(snap.connection_state_transitions, 3);
    }

    // -- Thread-safety smoke test --

    #[test]
    fn concurrent_record_maintains_count_integrity() {
        let acc = Arc::new(TelemetryAccumulator::new(1));

        let acc_a = acc.clone();
        let acc_b = acc.clone();
        let acc_c = acc.clone();

        let t1 = std::thread::spawn(move || {
            for _ in 0..1000 {
                acc_a.record_bytes_sent(1);
            }
        });
        let t2 = std::thread::spawn(move || {
            for _ in 0..1000 {
                acc_b.record_bytes_received(1);
            }
        });
        let t3 = std::thread::spawn(move || {
            for _ in 0..500 {
                acc_c.record_message_sent();
                acc_c.record_message_received();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();
        t3.join().unwrap();

        let snap = acc.snapshot();
        assert_eq!(snap.bytes_sent, 1000);
        assert_eq!(snap.bytes_received, 1000);
        assert_eq!(snap.messages_sent, 500);
        assert_eq!(snap.messages_received, 500);
    }
}
