//! Roster-scoped capability discovery for placement and transport selection.
//!
//! [`MembershipCapabilityView`] provides a read-only snapshot of per-peer
//! operational capabilities extracted from the membership roster. Placement
//! planners and transport carrier selection query this view to make informed
//! decisions without out-of-band discovery.
//!
use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;
pub use tidefs_membership_types::capabilities::PeerCapabilities;

// ---------------------------------------------------------------------------
// MembershipCapabilityView
// ---------------------------------------------------------------------------

/// A point-in-time read-only view of per-peer operational capabilities.
///
/// Built from the committed roster's capability advertisements. Callers
/// (placement, transport) query this view to discover storage capacity,
/// transport carriers, failure-domain topology, and coordinator eligibility.
///
/// # Example
///
/// ```
/// use tidefs_membership_live::capability_view::MembershipCapabilityView;
/// use tidefs_membership_epoch::MemberId;
/// use tidefs_membership_types::capabilities::{PeerCapabilities, TransportCarrier};
///
/// let view = MembershipCapabilityView::new();
/// assert!(view.is_empty());
/// ```
#[derive(Clone, Debug, Default)]
pub struct MembershipCapabilityView {
    /// Per-member capabilities, keyed by MemberId.
    entries: BTreeMap<MemberId, PeerCapabilities>,
}

impl MembershipCapabilityView {
    /// Create an empty capability view.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Create a view from an iterator of (MemberId, PeerCapabilities) pairs.
    #[must_use]
    pub fn from_entries<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (MemberId, PeerCapabilities)>,
    {
        Self {
            entries: iter.into_iter().collect(),
        }
    }

    /// Insert or update capabilities for a member.
    pub fn insert(&mut self, member_id: MemberId, caps: PeerCapabilities) {
        self.entries.insert(member_id, caps);
    }

    /// Remove capabilities for a member (e.g., on leave/failure).
    pub fn remove(&mut self, member_id: &MemberId) {
        self.entries.remove(member_id);
    }

    // ── Query API ──────────────────────────────────────────────────

    /// Look up capabilities for a single member.
    #[must_use]
    pub fn lookup(&self, member_id: MemberId) -> Option<&PeerCapabilities> {
        self.entries.get(&member_id)
    }

    /// Check whether a member has registered capabilities.
    #[must_use]
    pub fn contains(&self, member_id: MemberId) -> bool {
        self.entries.contains_key(&member_id)
    }

    /// Iterate over all (MemberId, PeerCapabilities) pairs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&MemberId, &PeerCapabilities)> {
        self.entries.iter()
    }

    /// Number of members with capability entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the view is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CapabilityUpdateHandler — inbound message handler
// ---------------------------------------------------------------------------

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use std::sync::{Arc, Mutex};

/// An inbound message handler that processes [`CapabilityUpdate`] messages.
///
/// On receipt, it extracts the (member_id, capabilities) pair from the
/// message and calls [`MembershipCapabilityView::insert`] to refresh the
/// roster-scoped capability snapshot. Callers register this handler with
/// the [`crate::membership_inbound_dispatch::HandlerSet`] at discriminant 28.
///
/// # Thread safety
///
/// The inner view is protected by an `Arc<Mutex<>>` so it can be shared
/// with placement and transport query callers.
pub struct CapabilityUpdateHandler {
    view: Arc<Mutex<MembershipCapabilityView>>,
}

impl CapabilityUpdateHandler {
    /// Create a new handler backed by the given capability view.
    #[must_use]
    pub fn new(view: Arc<Mutex<MembershipCapabilityView>>) -> Self {
        Self { view }
    }

    /// Return a clone of the shared view for external queries.
    #[must_use]
    pub fn view(&self) -> Arc<Mutex<MembershipCapabilityView>> {
        Arc::clone(&self.view)
    }
}

impl MembershipMessageHandler for CapabilityUpdateHandler {
    fn handle_capability_update(
        &self,
        msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        let (member_id, capabilities) = match msg {
            MembershipMessage::CapabilityUpdate {
                member_id,
                capabilities,
                ..
            } => (*member_id, capabilities.clone()),
            _ => return Ok(()),
        };

        let mut view = self.view.lock().map_err(|_| {
            MembershipDispatchError::HandlerError("capability view lock poisoned".to_string())
        })?;
        view.insert(member_id, capabilities);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(n: u64) -> MemberId {
        MemberId::new(n)
    }

    fn caps(storage: u64, available: u64) -> PeerCapabilities {
        PeerCapabilities::new(storage, available)
    }

    #[test]
    fn empty_view() {
        let view = MembershipCapabilityView::new();
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert!(view.lookup(mid(1)).is_none());
        assert!(!view.contains(mid(1)));
    }

    #[test]
    fn insert_and_lookup() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        assert_eq!(view.len(), 1);
        assert!(view.contains(mid(1)));

        let c = view.lookup(mid(1)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 1000);
        assert_eq!(c.available_bytes, 500);
    }

    #[test]
    fn insert_overwrites() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(1), caps(2000, 1500));
        let c = view.lookup(mid(1)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 2000);
        assert_eq!(c.available_bytes, 1500);
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn remove_clears() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(2), caps(2000, 1000));
        view.remove(&mid(1));
        assert!(!view.contains(mid(1)));
        assert!(view.contains(mid(2)));
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn remove_nonexistent_noop() {
        let mut view = MembershipCapabilityView::new();
        view.remove(&mid(42));
        assert!(view.is_empty());
    }

    #[test]
    fn iter_deterministic_order() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(3), caps(3000, 2500));
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(2), caps(2000, 1500));

        let ids: Vec<u64> = view.iter().map(|(m, _)| m.0).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn iter_on_empty() {
        let view = MembershipCapabilityView::new();
        let count = view.iter().count();
        assert_eq!(count, 0);
    }

    #[test]
    fn from_entries() {
        let view = MembershipCapabilityView::from_entries(vec![
            (mid(1), caps(1000, 500)),
            (mid(2), caps(2000, 1000)),
        ]);
        assert_eq!(view.len(), 2);
        assert_eq!(view.lookup(mid(1)).unwrap().storage_capacity_bytes, 1000);
    }

    #[test]
    fn default_is_empty() {
        let view = MembershipCapabilityView::default();
        assert!(view.is_empty());
    }

    #[test]
    fn full_lifecycle() {
        let mut view = MembershipCapabilityView::new();
        assert!(view.is_empty());

        // Insert
        view.insert(mid(1), caps(1000, 500));
        assert!(!view.is_empty());
        assert_eq!(view.len(), 1);

        // Update
        view.insert(mid(1), caps(900, 200));
        assert_eq!(view.lookup(mid(1)).unwrap().available_bytes, 200);

        // Remove
        view.remove(&mid(1));
        assert!(view.is_empty());

        // Re-insert
        view.insert(mid(1), caps(500, 100));
        assert!(view.contains(mid(1)));
    }

    // ── Capability-merge roster-operation tests ───────────────────

    #[test]
    fn add_peer_with_capabilities() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(10), caps(1_000_000, 800_000));
        assert_eq!(view.len(), 1);
        let c = view.lookup(mid(10)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 1_000_000);
        assert_eq!(c.available_bytes, 800_000);
    }

    #[test]
    fn add_multiple_peers_each_with_capabilities() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(2), caps(2000, 1500));
        view.insert(mid(3), caps(3000, 2500));
        assert_eq!(view.len(), 3);
        assert!(view.contains(mid(1)));
        assert!(view.contains(mid(2)));
        assert!(view.contains(mid(3)));
    }

    #[test]
    fn update_existing_peer_capabilities() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        // Simulate capability refresh: peer reports updated available_bytes
        view.insert(mid(1), caps(1000, 200));
        let c = view.lookup(mid(1)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 1000);
        assert_eq!(c.available_bytes, 200);
        assert_eq!(view.len(), 1); // no duplicate entries
    }

    #[test]
    fn remove_peer_clears_capabilities() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(2), caps(2000, 1500));
        view.remove(&mid(1));
        assert!(!view.contains(mid(1)));
        assert!(view.contains(mid(2)));
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn remove_last_peer_returns_to_empty() {
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.remove(&mid(1));
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert!(view.lookup(mid(1)).is_none());
    }

    #[test]
    fn rejoin_restores_capabilities() {
        // Peer leaves (remove) and rejoins with new capabilities
        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps(1000, 500));
        view.remove(&mid(1));
        assert!(view.is_empty());
        // Rejoin with different capabilities
        view.insert(mid(1), caps(2000, 1800));
        assert_eq!(view.len(), 1);
        let c = view.lookup(mid(1)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 2000);
        assert_eq!(c.available_bytes, 1800);
    }

    #[test]
    fn join_leave_join_preserves_correct_state() {
        let mut view = MembershipCapabilityView::new();
        // Three peers join
        view.insert(mid(1), caps(1000, 500));
        view.insert(mid(2), caps(2000, 1500));
        view.insert(mid(3), caps(3000, 2500));
        // Peer 2 leaves
        view.remove(&mid(2));
        assert!(!view.contains(mid(2)));
        assert_eq!(view.len(), 2);
        // Peer 2 rejoins with new capacity
        view.insert(mid(2), caps(2500, 2200));
        assert!(view.contains(mid(2)));
        assert_eq!(view.len(), 3);
        let c = view.lookup(mid(2)).unwrap();
        assert_eq!(c.storage_capacity_bytes, 2500);
    }

    #[test]
    fn coordinator_eligibility_preserved_on_update() {
        let mut caps = PeerCapabilities::new(5000, 4000);
        caps.coordinator_eligible = true;
        caps.transport_carriers = tidefs_membership_types::capabilities::TransportCarrier::TCP
            .union(tidefs_membership_types::capabilities::TransportCarrier::RDMA);

        let mut view = MembershipCapabilityView::new();
        view.insert(mid(1), caps.clone());

        let c = view.lookup(mid(1)).unwrap();
        assert!(c.coordinator_eligible);
        assert!(c
            .transport_carriers
            .contains(tidefs_membership_types::capabilities::TransportCarrier::RDMA));
    }
}
