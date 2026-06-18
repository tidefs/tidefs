// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport session lifecycle bridge from membership epoch transitions to
//! transport session management.
//!
//! [`MembershipTransportBridge`] subscribes to committed epoch views from the
//! [`crate::epoch_coordinator::EpochAdvanceCoordinator`] and, on each epoch
//! commit, computes the diff between the previous and new member set. Removed
//! peers have their transport sessions closed; added peers are registered for
//! session acceptance.
//!
//! ## Trait
//!
//! The bridge dispatches through a [`TransportSessionManager`] trait that
//! `tidefs-transport` implements, keeping the dependency direction clean:
//! membership defines the trait, transport provides the implementation.
//!
//! ## Integration
//!
//! ```ignore
//! use tidefs_membership_live::transport_bridge::{
//!     MembershipTransportBridge, TransportSessionManager,
//! };
//!
//! let bridge = MembershipTransportBridge::new(session_manager);
//! coordinator.subscribe(Box::new(bridge));
//! ```

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::MemberId;
use tidefs_transport::addr::TransportAddr;
use tidefs_transport::peer_address_registry::PeerAddressRegistry;

use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};

// ---------------------------------------------------------------------------
// TransportSessionManager
// ---------------------------------------------------------------------------

/// Manages transport session lifecycle in response to membership changes.
///
/// Implementations close sessions for evicted peers and register new peers
/// for session acceptance. `tidefs-transport` provides the production
/// implementation; tests use a mock.
pub trait TransportSessionManager: Send + Sync {
    /// Close all transport sessions associated with a peer.
    ///
    /// Called when a peer is removed from the committed epoch member set.
    /// The implementation should drain in-flight messages with a bounded
    /// grace period before forcible teardown, and must not disrupt
    /// sessions belonging to other peers.
    fn close_peer_sessions(&self, peer_id: MemberId);

    /// Register a peer for transport session acceptance.
    ///
    /// Called when a new peer is added to the committed epoch member set.
    /// `addresses` carries the peer's transport endpoint addresses so the
    /// transport layer can accept inbound sessions and optionally initiate
    /// outbound connections.
    fn register_peer(&self, peer_id: MemberId, addresses: Vec<TransportAddr>);
}

// ---------------------------------------------------------------------------
// MembershipTransportBridge
// ---------------------------------------------------------------------------

/// Bridges membership epoch transitions to transport session management.
///
/// Implements [`EpochCommitSubscriber`] so it can be registered with an
/// [`crate::epoch_coordinator::EpochAdvanceCoordinator`]. On each committed
/// epoch view, the bridge diffs the previous and new member sets and calls
/// the appropriate [`TransportSessionManager`] methods for removed and
/// added peers.
///
/// # Peer addresses
///
/// Newly-added peers are registered with addresses from the shared
/// [`PeerAddressRegistry`]. Call [`Self::update_peer_addresses`] to
/// populate the registry before peers appear in epoch diffs. If a peer
/// has no known addresses at registration time, `register_peer` is
/// called with an empty `Vec`; the transport implementation is expected
/// to handle this case gracefully (e.g., accept inbound connections only).
pub struct MembershipTransportBridge {
    /// The transport session manager implementation.
    session_manager: Box<dyn TransportSessionManager>,
    /// The previous committed member set, used to detect additions and
    /// removals on the next epoch commit.
    previous_member_set: Mutex<BTreeSet<MemberId>>,
    /// Shared peer address registry mapping node IDs to endpoint addresses.
    /// Thread-safe; shared with [`SessionEstablishment`] for outbound
    /// connection address resolution.
    address_registry: Arc<PeerAddressRegistry>,
}

impl MembershipTransportBridge {
    /// Create a new bridge with the given session manager and address
    /// registry.
    ///
    /// The previous member set starts empty; the first epoch commit after
    /// the coordinator has been initialized will detect all members as
    /// additions. Call [`Self::set_initial_member_set`] if the coordinator
    /// was already initialized before the bridge was registered.
    pub fn new(
        session_manager: Box<dyn TransportSessionManager>,
        address_registry: Arc<PeerAddressRegistry>,
    ) -> Self {
        Self {
            session_manager,
            previous_member_set: Mutex::new(BTreeSet::new()),
            address_registry,
        }
    }

    /// Set the initial member set so the first epoch diff is computed
    /// correctly.
    ///
    /// Call this after construction if the coordinator has already been
    /// initialized with members. Without this call, the first epoch
    /// commit would treat all members as additions.
    pub fn set_initial_member_set(&self, members: &BTreeSet<MemberId>) {
        let mut prev = self.previous_member_set.lock().unwrap();
        *prev = members.clone();
    }

    /// Update the peer address map with a new or changed address set.
    ///
    /// Called externally when peer addresses are learned (e.g., from the
    /// join handshake or configuration). If a peer already has registered
    /// addresses, this replaces them.
    pub fn update_peer_addresses(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
        self.address_registry.register(peer_id, addresses);
    }

    /// Remove a peer's addresses from the map.
    pub fn remove_peer_addresses(&self, peer_id: MemberId) {
        self.address_registry.deregister(peer_id);
    }

    /// Get the addresses registered for a peer, if any.
    pub fn peer_addresses(&self, peer_id: MemberId) -> Option<Vec<TransportAddr>> {
        self.address_registry.lookup(peer_id)
    }

    // -- private --

    /// Compute the diff between the previous and new member set and
    /// dispatch to the session manager.
    fn process_epoch_diff(&self, new_members: &BTreeSet<MemberId>) {
        let mut prev = self.previous_member_set.lock().unwrap();

        // Detect removals: peers in previous but not in new
        let removed: Vec<MemberId> = prev.difference(new_members).copied().collect();

        // Detect additions: peers in new but not in previous
        let added: Vec<MemberId> = new_members.difference(&prev).copied().collect();

        // Dispatch removals
        for peer_id in &removed {
            self.session_manager.close_peer_sessions(*peer_id);
        }

        // Dispatch additions with addresses from the shared registry
        for peer_id in &added {
            let addresses = self.address_registry.lookup(*peer_id).unwrap_or_default();
            self.session_manager.register_peer(*peer_id, addresses);
        }

        // Update previous set for next diff
        *prev = new_members.clone();
    }
}

impl EpochCommitSubscriber for MembershipTransportBridge {
    fn on_epoch_committed(&self, view: &EpochView) {
        let new_members: BTreeSet<MemberId> = view.member_set.iter().copied().collect();
        self.process_epoch_diff(&new_members);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex as StdMutex};

    use tidefs_membership_epoch::EpochId;

    // ------------------------------------------------------------------
    // Mock TransportSessionManager
    // ------------------------------------------------------------------

    /// Call record captured by the mock session manager.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MockCall {
        ClosePeerSessions(u64),
        RegisterPeer { peer_id: u64, address_count: usize },
    }

    /// A mock [`TransportSessionManager`] that records calls for test
    /// assertions. Wraps state in `Arc<Mutex<Vec<MockCall>>>` for
    /// shared access across the test and the bridge.
    struct MockSessionManager {
        calls: Arc<StdMutex<Vec<MockCall>>>,
    }

    impl MockSessionManager {
        fn new_with_handle() -> (Self, Arc<StdMutex<Vec<MockCall>>>) {
            let handle = Arc::new(StdMutex::new(Vec::new()));
            let mgr = Self {
                calls: Arc::clone(&handle),
            };
            (mgr, handle)
        }
    }

    impl TransportSessionManager for MockSessionManager {
        fn close_peer_sessions(&self, peer_id: MemberId) {
            self.calls
                .lock()
                .unwrap()
                .push(MockCall::ClosePeerSessions(peer_id.0));
        }

        fn register_peer(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
            self.calls.lock().unwrap().push(MockCall::RegisterPeer {
                peer_id: peer_id.0,
                address_count: addresses.len(),
            });
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    fn tcp_addr(port: u16) -> TransportAddr {
        TransportAddr::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    fn make_view(members: &[u64], epoch: u64) -> EpochView {
        EpochView::new(
            EpochId::new(epoch),
            members.iter().map(|&id| mid(id)).collect(),
            1_700_000_000_000,
        )
    }

    fn btreeset_from(ids: &[u64]) -> BTreeSet<MemberId> {
        ids.iter().map(|&id| mid(id)).collect()
    }

    // ------------------------------------------------------------------
    // First epoch commit: all members are additions
    // ------------------------------------------------------------------

    #[test]
    fn first_epoch_commit_registers_all_members_as_additions() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        // Register addresses for peer 1 and 3
        bridge.update_peer_addresses(mid(1), vec![tcp_addr(9001)]);
        bridge.update_peer_addresses(mid(3), vec![tcp_addr(9003)]);

        // Simulate first epoch commit with members 1,2,3
        let view = make_view(&[1, 2, 3], 0);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        // All three should be registered; peer 2 has no addresses
        assert_eq!(recorded.len(), 3);
        assert!(recorded.contains(&MockCall::RegisterPeer {
            peer_id: 1,
            address_count: 1,
        }));
        assert!(recorded.contains(&MockCall::RegisterPeer {
            peer_id: 2,
            address_count: 0,
        }));
        assert!(recorded.contains(&MockCall::RegisterPeer {
            peer_id: 3,
            address_count: 1,
        }));
        // No removals
        assert!(!recorded
            .iter()
            .any(|c| matches!(c, MockCall::ClosePeerSessions(_))));
    }

    // ------------------------------------------------------------------
    // set_initial_member_set prevents all-addition on first epoch
    // ------------------------------------------------------------------

    #[test]
    fn initial_member_set_prevents_all_addition() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3]);
        bridge.set_initial_member_set(&initial);

        // Same members, same epoch → no calls
        let view = make_view(&[1, 2, 3], 0);
        bridge.on_epoch_committed(&view);

        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Peer removal
    // ------------------------------------------------------------------

    #[test]
    fn peer_removal_triggers_close_sessions() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3]);
        bridge.set_initial_member_set(&initial);

        // Epoch commit removes peer 2
        let view = make_view(&[1, 3], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], MockCall::ClosePeerSessions(2));
    }

    // ------------------------------------------------------------------
    // Peer addition with addresses
    // ------------------------------------------------------------------

    #[test]
    fn peer_addition_registers_with_addresses() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2]);
        bridge.set_initial_member_set(&initial);

        bridge.update_peer_addresses(mid(3), vec![tcp_addr(9003), tcp_addr(9004)]);

        // Epoch commit adds peer 3
        let view = make_view(&[1, 2, 3], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            MockCall::RegisterPeer {
                peer_id: 3,
                address_count: 2,
            }
        );
    }

    // ------------------------------------------------------------------
    // Both addition and removal in same epoch
    // ------------------------------------------------------------------

    #[test]
    fn mixed_addition_and_removal_in_same_epoch() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3]);
        bridge.set_initial_member_set(&initial);

        bridge.update_peer_addresses(mid(4), vec![tcp_addr(9004)]);

        // Remove peer 2, add peer 4
        let view = make_view(&[1, 3, 4], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);

        let has_removal = recorded.contains(&MockCall::ClosePeerSessions(2));
        let has_addition = recorded.contains(&MockCall::RegisterPeer {
            peer_id: 4,
            address_count: 1,
        });
        assert!(has_removal, "should close sessions for removed peer 2");
        assert!(has_addition, "should register added peer 4");
    }

    // ------------------------------------------------------------------
    // No changes → no calls
    // ------------------------------------------------------------------

    #[test]
    fn no_changes_produces_no_calls() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3]);
        bridge.set_initial_member_set(&initial);

        // Same member set
        let view = make_view(&[1, 2, 3], 1);
        bridge.on_epoch_committed(&view);

        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Empty member set
    // ------------------------------------------------------------------

    #[test]
    fn empty_member_set_closes_all() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2]);
        bridge.set_initial_member_set(&initial);

        // Empty member set → all removed
        let view = make_view(&[], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        assert!(recorded.contains(&MockCall::ClosePeerSessions(1)));
        assert!(recorded.contains(&MockCall::ClosePeerSessions(2)));
    }

    // ------------------------------------------------------------------
    // Multiple consecutive epochs
    // ------------------------------------------------------------------

    #[test]
    fn consecutive_epochs_produce_correct_diffs() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3, 4]);
        bridge.set_initial_member_set(&initial);

        bridge.update_peer_addresses(mid(5), vec![tcp_addr(9005)]);
        bridge.update_peer_addresses(mid(6), vec![tcp_addr(9006)]);

        // Epoch 1: remove 3, add 5
        let view1 = make_view(&[1, 2, 4, 5], 1);
        bridge.on_epoch_committed(&view1);

        let r1 = calls.lock().unwrap().clone();
        assert!(r1.contains(&MockCall::ClosePeerSessions(3)));
        assert!(r1.contains(&MockCall::RegisterPeer {
            peer_id: 5,
            address_count: 1,
        }));
        assert_eq!(r1.len(), 2);

        // Epoch 2: remove 1, 4; add 6
        calls.lock().unwrap().clear();
        let view2 = make_view(&[2, 5, 6], 2);
        bridge.on_epoch_committed(&view2);

        let r2 = calls.lock().unwrap().clone();
        assert!(r2.contains(&MockCall::ClosePeerSessions(1)));
        assert!(r2.contains(&MockCall::ClosePeerSessions(4)));
        assert!(r2.contains(&MockCall::RegisterPeer {
            peer_id: 6,
            address_count: 1,
        }));
        assert_eq!(r2.len(), 3);

        // Peer 2 and 5 should not have been touched
        assert!(!r2
            .iter()
            .any(|c| matches!(c, MockCall::ClosePeerSessions(2))));
        assert!(!r2
            .iter()
            .any(|c| matches!(c, MockCall::RegisterPeer { peer_id, .. } if *peer_id == 5)));
    }

    // ------------------------------------------------------------------
    // update_peer_addresses overwrites
    // ------------------------------------------------------------------

    #[test]
    fn update_peer_addresses_overwrites() {
        let bridge = MembershipTransportBridge::new(
            Box::new(MockSessionManager::new_with_handle().0),
            Arc::new(PeerAddressRegistry::new()),
        );

        bridge.update_peer_addresses(mid(1), vec![tcp_addr(9001)]);
        assert_eq!(bridge.peer_addresses(mid(1)).unwrap().len(), 1);

        bridge.update_peer_addresses(mid(1), vec![tcp_addr(9002), tcp_addr(9003)]);
        assert_eq!(bridge.peer_addresses(mid(1)).unwrap().len(), 2);
    }

    // ------------------------------------------------------------------
    // remove_peer_addresses
    // ------------------------------------------------------------------

    #[test]
    fn remove_peer_addresses_clears() {
        let bridge = MembershipTransportBridge::new(
            Box::new(MockSessionManager::new_with_handle().0),
            Arc::new(PeerAddressRegistry::new()),
        );

        bridge.update_peer_addresses(mid(1), vec![tcp_addr(9001)]);
        assert!(bridge.peer_addresses(mid(1)).is_some());

        bridge.remove_peer_addresses(mid(1));
        assert!(bridge.peer_addresses(mid(1)).is_none());
    }

    // ------------------------------------------------------------------
    // Multiple peers removed at once
    // ------------------------------------------------------------------

    #[test]
    fn multiple_peers_removed_at_once() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1, 2, 3, 4, 5]);
        bridge.set_initial_member_set(&initial);

        // Remove 2, 3, 5
        let view = make_view(&[1, 4], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        assert!(recorded.contains(&MockCall::ClosePeerSessions(2)));
        assert!(recorded.contains(&MockCall::ClosePeerSessions(3)));
        assert!(recorded.contains(&MockCall::ClosePeerSessions(5)));
    }

    // ------------------------------------------------------------------
    // Multiple peers added at once
    // ------------------------------------------------------------------

    #[test]
    fn multiple_peers_added_at_once() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1]);
        bridge.set_initial_member_set(&initial);

        bridge.update_peer_addresses(mid(2), vec![tcp_addr(9002)]);
        bridge.update_peer_addresses(mid(3), vec![tcp_addr(9003)]);

        // Add 2 and 3
        let view = make_view(&[1, 2, 3], 1);
        bridge.on_epoch_committed(&view);

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        assert!(recorded.contains(&MockCall::RegisterPeer {
            peer_id: 2,
            address_count: 1,
        }));
        assert!(recorded.contains(&MockCall::RegisterPeer {
            peer_id: 3,
            address_count: 1,
        }));
    }

    // ------------------------------------------------------------------
    // Addresses update after set_initial_member_set works for later epoch
    // ------------------------------------------------------------------

    #[test]
    fn address_update_after_init_works_for_later_epoch() {
        let (mock, calls) = MockSessionManager::new_with_handle();
        let bridge =
            MembershipTransportBridge::new(Box::new(mock), Arc::new(PeerAddressRegistry::new()));

        let initial = btreeset_from(&[1]);
        bridge.set_initial_member_set(&initial);

        // First, add peer 2 without addresses
        let view1 = make_view(&[1, 2], 1);
        bridge.on_epoch_committed(&view1);

        let r1 = calls.lock().unwrap().clone();
        assert!(r1.contains(&MockCall::RegisterPeer {
            peer_id: 2,
            address_count: 0,
        }));

        // Now supply addresses for peer 2
        bridge.update_peer_addresses(mid(2), vec![tcp_addr(9002)]);

        // Remove and re-add peer 2 (simulate a recovery cycle)
        let view2 = make_view(&[1], 2);
        bridge.on_epoch_committed(&view2);
        calls.lock().unwrap().clear();

        let view3 = make_view(&[1, 2], 3);
        bridge.on_epoch_committed(&view3);

        let r3 = calls.lock().unwrap().clone();
        assert!(r3.contains(&MockCall::RegisterPeer {
            peer_id: 2,
            address_count: 1,
        }));
    }
}
