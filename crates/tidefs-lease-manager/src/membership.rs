// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_membership_epoch::{EpochId, MemberId};

/// Events from the cluster membership layer that the lease manager reacts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipEvent {
    /// A node has been detected as failed (no heartbeat within timeout).
    NodeFailed { node_id: MemberId },
    /// A node has been administratively removed.
    NodeRemoved { node_id: MemberId },
    /// The cluster epoch has advanced.
    EpochAdvanced {
        new_epoch: EpochId,
        old_epoch: EpochId,
    },
    /// A node has gracefully departed (not a failure).
    NodeDeparted { node_id: MemberId },
}

/// Observer trait for membership events.
///
/// The [`crate::LeaseManager`] implements this trait (or an adapter does)
/// to react to cluster membership changes by automatically revoking leases
/// held by failed nodes.
pub trait MembershipObserver {
    /// Handle a membership event.
    ///
    /// Returns the IDs of leases that were revoked in response.
    fn on_membership_event(&mut self, event: &MembershipEvent) -> Vec<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn m(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    // ── MembershipEvent construction and equality ───────────────────

    #[test]
    fn test_node_failed_construction() {
        let event = MembershipEvent::NodeFailed { node_id: m(42) };
        match event {
            MembershipEvent::NodeFailed { node_id } => assert_eq!(node_id, m(42)),
            _ => panic!("expected NodeFailed"),
        }
    }

    #[test]
    fn test_node_removed_construction() {
        let event = MembershipEvent::NodeRemoved { node_id: m(7) };
        match event {
            MembershipEvent::NodeRemoved { node_id } => assert_eq!(node_id, m(7)),
            _ => panic!("expected NodeRemoved"),
        }
    }

    #[test]
    fn test_node_departed_construction() {
        let event = MembershipEvent::NodeDeparted { node_id: m(99) };
        match event {
            MembershipEvent::NodeDeparted { node_id } => assert_eq!(node_id, m(99)),
            _ => panic!("expected NodeDeparted"),
        }
    }

    #[test]
    fn test_epoch_advanced_construction() {
        let event = MembershipEvent::EpochAdvanced {
            new_epoch: epoch(5),
            old_epoch: epoch(3),
        };
        match event {
            MembershipEvent::EpochAdvanced {
                new_epoch,
                old_epoch,
            } => {
                assert_eq!(new_epoch, epoch(5));
                assert_eq!(old_epoch, epoch(3));
            }
            _ => panic!("expected EpochAdvanced"),
        }
    }

    #[test]
    fn test_membership_event_equality() {
        let a = MembershipEvent::NodeFailed { node_id: m(1) };
        let b = MembershipEvent::NodeFailed { node_id: m(1) };
        let c = MembershipEvent::NodeFailed { node_id: m(2) };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_membership_event_variants_not_equal() {
        let failed = MembershipEvent::NodeFailed { node_id: m(1) };
        let removed = MembershipEvent::NodeRemoved { node_id: m(1) };
        assert_ne!(failed, removed);
    }

    #[test]
    fn test_membership_event_clone() {
        let event = MembershipEvent::EpochAdvanced {
            new_epoch: epoch(10),
            old_epoch: epoch(9),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // ── MembershipObserver mock ─────────────────────────────────────

    /// A mock observer that records events and returns configurable lease IDs.
    struct MockObserver {
        events: Vec<MembershipEvent>,
        next_revoked: Vec<u64>,
    }

    impl MockObserver {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                next_revoked: Vec::new(),
            }
        }

        fn with_revoked(mut self, ids: Vec<u64>) -> Self {
            self.next_revoked = ids;
            self
        }
    }

    impl MembershipObserver for MockObserver {
        fn on_membership_event(&mut self, event: &MembershipEvent) -> Vec<u64> {
            self.events.push(event.clone());
            self.next_revoked.clone()
        }
    }

    #[test]
    fn test_mock_observer_records_node_failed() {
        let mut obs = MockObserver::new().with_revoked(vec![10, 20]);
        let event = MembershipEvent::NodeFailed { node_id: m(5) };

        let revoked = obs.on_membership_event(&event);
        assert_eq!(revoked, vec![10, 20]);
        assert_eq!(obs.events.len(), 1);
        assert_eq!(obs.events[0], event);
    }

    #[test]
    fn test_mock_observer_records_node_removed() {
        let mut obs = MockObserver::new();
        let event = MembershipEvent::NodeRemoved { node_id: m(3) };

        obs.on_membership_event(&event);
        assert_eq!(obs.events.len(), 1);
        assert_eq!(obs.events[0], event);
    }

    #[test]
    fn test_mock_observer_records_node_departed() {
        let mut obs = MockObserver::new();
        let event = MembershipEvent::NodeDeparted { node_id: m(8) };

        obs.on_membership_event(&event);
        assert_eq!(obs.events.len(), 1);
        assert_eq!(obs.events[0], event);
    }

    #[test]
    fn test_mock_observer_records_epoch_advanced() {
        let mut obs = MockObserver::new();
        let event = MembershipEvent::EpochAdvanced {
            new_epoch: epoch(3),
            old_epoch: epoch(2),
        };

        obs.on_membership_event(&event);
        assert_eq!(obs.events.len(), 1);
        assert_eq!(obs.events[0], event);
    }

    #[test]
    fn test_mock_observer_records_multiple_events() {
        let mut obs = MockObserver::new();
        let e1 = MembershipEvent::NodeFailed { node_id: m(1) };
        let e2 = MembershipEvent::EpochAdvanced {
            new_epoch: epoch(2),
            old_epoch: epoch(1),
        };
        let e3 = MembershipEvent::NodeDeparted { node_id: m(3) };

        obs.on_membership_event(&e1);
        obs.on_membership_event(&e2);
        obs.on_membership_event(&e3);

        assert_eq!(obs.events.len(), 3);
        assert_eq!(obs.events[0], e1);
        assert_eq!(obs.events[1], e2);
        assert_eq!(obs.events[2], e3);
    }
}
