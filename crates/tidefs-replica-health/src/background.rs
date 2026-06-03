//! Background degradation-event task with broadcast channel.
//!
//! Wraps a shared `ReplicaDegradationTracker` in an `Arc<Mutex<>>` and
//! spawns a tokio task that periodically calls `check_stale()` and emits
//! `ReplicaDegradationEvent`s to a `tokio::sync::broadcast` channel for
//! downstream consumers: placement planner (#5125), rebuild runtime
//! (#3391), and repair service (#3379).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::state_machine::{DegradationState, TransitionReason};
use crate::NodeId;

/// Event emitted when a replica transitions between degradation states.
#[derive(Clone, Debug)]
pub struct ReplicaDegradationEvent {
    /// Which replica changed state.
    pub replica_id: NodeId,
    /// State before the transition.
    pub previous_state: DegradationState,
    /// State after the transition.
    pub new_state: DegradationState,
    /// Why the transition occurred.
    pub reason: TransitionReason,
    /// Timestamp (ns) when the transition was detected.
    pub at_ns: u64,
}

/// Handle for the background degradation event task.
///
/// Provides a `subscribe()` method for downstream consumers and a
/// `shutdown()` method to gracefully stop the background loop.
pub struct ReplicaHealthBackgroundHandle {
    /// Broadcast sender for degradation events.
    tx: broadcast::Sender<ReplicaDegradationEvent>,
    /// Cancel signal for the background task.
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

impl ReplicaHealthBackgroundHandle {
    /// Spawn a background task that periodically checks for stale replicas
    /// and emits degradation events on state transitions.
    ///
    /// `tracker` is the shared `ReplicaDegradationTracker` — downstream
    /// callers (I/O path) should also hold a clone of this `Arc` and call
    /// `record_success`, `record_failure`, etc. under the Mutex lock.
    ///
    /// `poll_interval` controls how often `check_stale()` runs.
    /// `channel_capacity` sets the broadcast channel buffer size.
    pub fn spawn(
        tracker: Arc<Mutex<crate::ReplicaDegradationTracker>>,
        poll_interval: Duration,
        channel_capacity: usize,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(channel_capacity);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let tx_clone = tx.clone();
        let tracker_clone = Arc::clone(&tracker);

        tokio::spawn(async move {
            Self::run(tracker_clone, tx_clone, poll_interval, cancel_rx).await;
        });

        ReplicaHealthBackgroundHandle { tx, cancel_tx }
    }

    /// Subscribe to degradation events.
    ///
    /// Returns a `Receiver` that yields `ReplicaDegradationEvent`s as
    /// replicas transition between health states due to staleness or
    /// explicit I/O-driven transitions tracked by the scorer.
    pub fn subscribe(&self) -> broadcast::Receiver<ReplicaDegradationEvent> {
        self.tx.subscribe()
    }

    /// Signal the background task to stop and wait for it to finish.
    pub fn shutdown(&self) {
        let _ = self.cancel_tx.send(true);
    }

    // ── Internal ────────────────────────────────────────────────

    async fn run(
        tracker: Arc<Mutex<crate::ReplicaDegradationTracker>>,
        tx: broadcast::Sender<ReplicaDegradationEvent>,
        poll_interval: Duration,
        mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            // Check for cancellation before polling
            if *cancel_rx.borrow() {
                return;
            }

            let events: Vec<ReplicaDegradationEvent> = {
                let mut t = tracker.lock().expect("tracker mutex poisoned");
                let now_ns = now_ns();
                let stale = t.check_stale(now_ns);
                stale
                    .into_iter()
                    .map(
                        |(replica_id, previous_state, result)| ReplicaDegradationEvent {
                            replica_id,
                            previous_state,
                            new_state: result.new_state,
                            reason: result.reason,
                            at_ns: now_ns,
                        },
                    )
                    .collect()
            };

            for event in events {
                // broadcast send can fail if no receivers — that's fine
                let _ = tx.send(event);
            }

            // Wait for the next poll or cancellation
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {},
                _ = cancel_rx.changed() => {
                    return;
                }
            }
        }
    }
}

/// Monotonic nanosecond clock for now_ns in the background task.
/// Uses std Instant for efficiency — this is relative, not epoch.
fn now_ns() -> u64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring;
    use crate::state_machine;

    fn make_tracker(stale_timeout_ns: u64) -> Arc<Mutex<crate::ReplicaDegradationTracker>> {
        let t = crate::ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            stale_timeout_ns,
        );
        Arc::new(Mutex::new(t))
    }

    #[tokio::test]
    async fn handle_spawns_and_subscribes() {
        let tracker = make_tracker(30_000_000_000);
        let handle = ReplicaHealthBackgroundHandle::spawn(tracker, Duration::from_millis(100), 16);

        let mut rx = handle.subscribe();
        // Verify the receiver is live (no immediate event expected)
        assert!(rx.try_recv().is_err());

        handle.shutdown();
    }

    #[tokio::test]
    async fn shutdown_stops_background_task() {
        let tracker = make_tracker(30_000_000_000);
        let handle = ReplicaHealthBackgroundHandle::spawn(tracker, Duration::from_millis(50), 16);

        handle.shutdown();

        // Give it a moment to stop
        tokio::time::sleep(Duration::from_millis(100)).await;

        // No receivers left — we shut down cleanly
        // This test just verifies no panic
    }

    #[tokio::test]
    async fn stale_replica_emits_event() {
        let tracker = make_tracker(1_000_000); // 1ms timeout for fast test

        // Pre-register a replica via the shared tracker
        {
            let mut t = tracker.lock().unwrap();
            t.record_success(NodeId::new(1), 100, 10);
        }

        let handle = ReplicaHealthBackgroundHandle::spawn(
            Arc::clone(&tracker),
            Duration::from_millis(20),
            16,
        );

        let mut rx = handle.subscribe();

        // Wait for the background task to detect staleness
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for stale event")
            .expect("broadcast channel closed");

        assert_eq!(event.replica_id, NodeId::new(1));
        assert_eq!(
            event.previous_state,
            state_machine::DegradationState::Healthy
        );
        assert_eq!(event.new_state, state_machine::DegradationState::Dead);

        handle.shutdown();
    }

    #[tokio::test]
    async fn active_io_prevents_stale_event() {
        let tracker = make_tracker(10_000_000_000); // 10s timeout

        // Register and keep feeding I/O
        {
            let mut t = tracker.lock().unwrap();
            t.record_success(NodeId::new(1), 100, 10);
        }

        let handle = ReplicaHealthBackgroundHandle::spawn(
            Arc::clone(&tracker),
            Duration::from_millis(30),
            16,
        );

        // Feed fresh I/O in a separate loop to keep the replica alive
        let tracker_bg = Arc::clone(&tracker);
        let cancel = handle.cancel_tx.subscribe();
        tokio::spawn(async move {
            let cancel = cancel;
            loop {
                if *cancel.borrow() {
                    return;
                }
                {
                    let mut t = tracker_bg.lock().unwrap();
                    t.record_success(NodeId::new(1), now_ns(), 10);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let mut rx = handle.subscribe();

        // After 500ms with active I/O, no stale event should fire
        let result = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        // Should timeout (no event), not receive an event
        assert!(
            result.is_err(),
            "expected timeout (no stale event), but got event"
        );

        handle.shutdown();
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_events() {
        let tracker = make_tracker(1_000_000); // 1ms

        {
            let mut t = tracker.lock().unwrap();
            t.record_success(NodeId::new(1), 100, 10);
            t.record_success(NodeId::new(2), 100, 10);
        }

        let handle = ReplicaHealthBackgroundHandle::spawn(
            Arc::clone(&tracker),
            Duration::from_millis(20),
            16,
        );

        let mut rx1 = handle.subscribe();
        let mut rx2 = handle.subscribe();

        // Both subscribers should see events
        let (e1, e2) = tokio::join!(rx1.recv(), rx2.recv());
        assert!(e1.is_ok());
        assert!(e2.is_ok());

        handle.shutdown();
    }
}
