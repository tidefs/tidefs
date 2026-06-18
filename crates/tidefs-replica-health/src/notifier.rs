// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Push-based health change notification interface.
//!
//! Defines the `ReplicaHealthChangeNotifier` trait that consumers
//! (rebuild planner, placement planner, quorum-write runtime) implement
//! to receive health state change callbacks without polling.

use crate::health_state::ReplicaHealthState;
use crate::NodeId;

/// Callback trait for push-based replica health change notification.
///
/// Implementors register with a health tracker and receive `on_health_change`
/// when a replica transitions between health states. This enables the
/// rebuild planner (#3391), placement planner (#5157), and quorum-write
/// runtime (#5160) to react immediately instead of polling.
pub trait ReplicaHealthChangeNotifier: Send + Sync {
    /// Called when a replica transitions between health states.
    ///
    /// `replica_id` identifies the replica whose health changed.
    /// `old_state` is the state before the transition.
    /// `new_state` is the state after the transition.
    /// `reason` provides a human-readable description of the transition cause.
    fn on_health_change(
        &self,
        replica_id: NodeId,
        old_state: &ReplicaHealthState,
        new_state: &ReplicaHealthState,
        reason: &str,
    );
}

/// A no-op notifier for use when no consumer is registered.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpNotifier;

impl ReplicaHealthChangeNotifier for NoOpNotifier {
    fn on_health_change(
        &self,
        _replica_id: NodeId,
        _old_state: &ReplicaHealthState,
        _new_state: &ReplicaHealthState,
        _reason: &str,
    ) {
        // Intentionally empty.
    }
}

/// A notifier that records callbacks for testing.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    /// All recorded health change notifications.
    pub calls: std::sync::Mutex<Vec<(NodeId, ReplicaHealthState, ReplicaHealthState, String)>>,
}

impl RecordingNotifier {
    pub fn new() -> Self {
        RecordingNotifier {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Drain all recorded notifications.
    pub fn drain(&self) -> Vec<(NodeId, ReplicaHealthState, ReplicaHealthState, String)> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

impl ReplicaHealthChangeNotifier for RecordingNotifier {
    fn on_health_change(
        &self,
        replica_id: NodeId,
        old_state: &ReplicaHealthState,
        new_state: &ReplicaHealthState,
        reason: &str,
    ) {
        self.calls.lock().unwrap().push((
            replica_id,
            old_state.clone(),
            new_state.clone(),
            reason.to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_notifier_accepts_any_call() {
        let notifier = NoOpNotifier;
        notifier.on_health_change(
            NodeId::new(1),
            &ReplicaHealthState::Absent,
            &ReplicaHealthState::Healthy {
                receipt_id: 1,
                last_verified_ns: 1000,
            },
            "test",
        );
        // No panic.
    }

    #[test]
    fn recording_notifier_captures_calls() {
        let notifier = RecordingNotifier::new();
        let old = ReplicaHealthState::Absent;
        let new = ReplicaHealthState::Healthy {
            receipt_id: 1,
            last_verified_ns: 1000,
        };

        notifier.on_health_change(NodeId::new(1), &old, &new, "probe success");
        notifier.on_health_change(
            NodeId::new(2),
            &new,
            &ReplicaHealthState::Degraded {
                degraded_since_ns: 2000,
                missing_chunks: 1,
                corrupt_chunks: 0,
            },
            "probe failure",
        );

        let calls = notifier.drain();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, NodeId::new(1));
        assert_eq!(calls[1].0, NodeId::new(2));
        assert_eq!(calls[0].3, "probe success");
        assert_eq!(calls[1].3, "probe failure");
    }

    #[test]
    fn recording_notifier_drain_clears() {
        let notifier = RecordingNotifier::new();
        notifier.on_health_change(
            NodeId::new(1),
            &ReplicaHealthState::Absent,
            &ReplicaHealthState::Healthy {
                receipt_id: 1,
                last_verified_ns: 1000,
            },
            "test",
        );
        assert_eq!(notifier.drain().len(), 1);
        assert_eq!(notifier.drain().len(), 0);
    }
}
