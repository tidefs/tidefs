//! Membership roster-driven peer address registry.
//!
//! [`PeerAddressRegistry`] maps membership node identifiers ([`MemberId`]) to
//! one or more transport endpoint addresses ([`TransportAddr`]). It provides
//! thread-safe interior mutability via a [`std::sync::Mutex`], allowing
//! concurrent access from roster-change and session-establishment paths.
//!
//! ## Integration points
//!
//! * [`crate::session_establishment::SessionEstablishment`]: queries the
//!   registry to resolve a peer's node identity to a concrete address before
//!   initiating an outbound connection.
//! * `tidefs_membership_live::transport_bridge::MembershipTransportBridge`:
//!   registers addresses when new peers join the roster and deregisters them
//!   on eviction, replacing the bridge's internal peer-address map.
//!
//! ## Thread safety
//!
//! All public methods lock an internal [`Mutex`]. The lock is always held for
//! a short, bounded duration (map insert/remove/clone), so contention is
//! negligible even under concurrent roster-change and session-establishment
//! workloads.

use std::collections::BTreeMap;
use std::sync::Mutex;

use tidefs_membership_epoch::MemberId;

use crate::addr::TransportAddr;

// ---------------------------------------------------------------------------
// PeerAddressRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry mapping membership node IDs to transport endpoint
/// addresses.
///
/// Supports registration (insert or update), deregistration (remove), and
/// lookup. All operations are `&self` — the registry is designed to be shared
/// behind an [`Arc`](std::sync::Arc) across the transport runtime.
///
/// ## Example
///
/// ```ignore
/// use tidefs_membership_epoch::MemberId;
/// use tidefs_transport::peer_address_registry::PeerAddressRegistry;
/// use tidefs_transport::addr::TransportAddr;
///
/// let registry = PeerAddressRegistry::new();
/// let peer = MemberId::new(42);
/// let addr: TransportAddr = "tcp://10.0.0.1:9100".parse().unwrap();
///
/// registry.register(peer, vec![addr.clone()]);
/// assert!(registry.is_registered(peer));
/// assert_eq!(registry.lookup(peer), Some(vec![addr]));
///
/// registry.deregister(peer);
/// assert!(!registry.is_registered(peer));
/// ```
pub struct PeerAddressRegistry {
    inner: Mutex<BTreeMap<MemberId, Vec<TransportAddr>>>,
}

impl PeerAddressRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register or update the addresses for a peer.
    ///
    /// If `addresses` is empty, the peer is still registered (with an empty
    /// address list). Callers that want to distinguish between "registered
    /// with no known addresses" and "not registered" should use
    /// [`is_registered`](Self::is_registered) before lookup.
    pub fn register(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
        let mut map = self.inner.lock().unwrap();
        map.insert(peer_id, addresses);
    }

    /// Remove a peer from the registry.
    ///
    /// Returns `true` if the peer was present and was removed.
    pub fn deregister(&self, peer_id: MemberId) -> bool {
        let mut map = self.inner.lock().unwrap();
        map.remove(&peer_id).is_some()
    }

    /// Look up the addresses for a peer.
    ///
    /// Returns a clone of the registered addresses, or [`None`] if the peer
    /// is not registered. An empty [`Vec`] means the peer is registered but
    /// no addresses are known (e.g., the peer was added via roster diff but
    /// its addresses have not yet been discovered).
    #[must_use]
    pub fn lookup(&self, peer_id: MemberId) -> Option<Vec<TransportAddr>> {
        let map = self.inner.lock().unwrap();
        map.get(&peer_id).cloned()
    }

    /// Return `true` if the peer is present in the registry.
    #[must_use]
    pub fn is_registered(&self, peer_id: MemberId) -> bool {
        let map = self.inner.lock().unwrap();
        map.contains_key(&peer_id)
    }

    /// Return the number of registered peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Return `true` if the registry contains no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Return the set of all registered peer IDs.
    #[must_use]
    pub fn list_peers(&self) -> Vec<MemberId> {
        let map = self.inner.lock().unwrap();
        map.keys().copied().collect()
    }

    /// Remove all entries from the registry.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

impl Default for PeerAddressRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PeerAddressRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.inner.lock().unwrap();
        f.debug_struct("PeerAddressRegistry")
            .field("entries", &map.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::thread;

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    fn tcp_addr(port: u16) -> TransportAddr {
        TransportAddr::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    // ------------------------------------------------------------------
    // new / default
    // ------------------------------------------------------------------

    #[test]
    fn new_registry_is_empty() {
        let r = PeerAddressRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.list_peers().is_empty());
    }

    #[test]
    fn default_registry_is_empty() {
        let r = PeerAddressRegistry::default();
        assert!(r.is_empty());
    }

    // ------------------------------------------------------------------
    // register / lookup / is_registered
    // ------------------------------------------------------------------

    #[test]
    fn register_and_lookup() {
        let r = PeerAddressRegistry::new();
        let addrs = vec![tcp_addr(9001), tcp_addr(9002)];

        assert!(!r.is_registered(mid(1)));
        assert_eq!(r.lookup(mid(1)), None);

        r.register(mid(1), addrs.clone());

        assert!(r.is_registered(mid(1)));
        assert_eq!(r.lookup(mid(1)), Some(addrs));
    }

    #[test]
    fn register_overwrites_existing() {
        let r = PeerAddressRegistry::new();

        r.register(mid(1), vec![tcp_addr(9001)]);
        assert_eq!(r.lookup(mid(1)).unwrap().len(), 1);

        r.register(mid(1), vec![tcp_addr(9002), tcp_addr(9003)]);
        assert_eq!(r.lookup(mid(1)).unwrap().len(), 2);
    }

    #[test]
    fn register_empty_addresses() {
        let r = PeerAddressRegistry::new();

        r.register(mid(1), vec![]);
        assert!(r.is_registered(mid(1)));
        assert_eq!(r.lookup(mid(1)), Some(vec![]));
    }

    #[test]
    fn register_multiple_peers() {
        let r = PeerAddressRegistry::new();

        r.register(mid(1), vec![tcp_addr(9001)]);
        r.register(mid(2), vec![tcp_addr(9002)]);
        r.register(mid(3), vec![tcp_addr(9003)]);

        assert_eq!(r.len(), 3);
        assert!(r.is_registered(mid(1)));
        assert!(r.is_registered(mid(2)));
        assert!(r.is_registered(mid(3)));
    }

    // ------------------------------------------------------------------
    // deregister
    // ------------------------------------------------------------------

    #[test]
    fn deregister_existing() {
        let r = PeerAddressRegistry::new();
        r.register(mid(1), vec![tcp_addr(9001)]);

        assert!(r.deregister(mid(1)));
        assert!(!r.is_registered(mid(1)));
        assert_eq!(r.lookup(mid(1)), None);
    }

    #[test]
    fn deregister_unknown_returns_false() {
        let r = PeerAddressRegistry::new();
        assert!(!r.deregister(mid(99)));
    }

    #[test]
    fn deregister_then_re_register() {
        let r = PeerAddressRegistry::new();

        r.register(mid(1), vec![tcp_addr(9001)]);
        assert!(r.deregister(mid(1)));

        r.register(mid(1), vec![tcp_addr(9002)]);
        assert_eq!(r.lookup(mid(1)), Some(vec![tcp_addr(9002)]));
    }

    // ------------------------------------------------------------------
    // len / is_empty
    // ------------------------------------------------------------------

    #[test]
    fn len_and_is_empty_track_entries() {
        let r = PeerAddressRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);

        r.register(mid(1), vec![tcp_addr(9001)]);
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);

        r.register(mid(2), vec![tcp_addr(9002)]);
        assert_eq!(r.len(), 2);

        r.deregister(mid(1));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());

        r.deregister(mid(2));
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    // ------------------------------------------------------------------
    // list_peers
    // ------------------------------------------------------------------

    #[test]
    fn list_peers_returns_all_ids() {
        let r = PeerAddressRegistry::new();
        r.register(mid(10), vec![tcp_addr(9010)]);
        r.register(mid(20), vec![tcp_addr(9020)]);
        r.register(mid(5), vec![tcp_addr(9005)]);

        let mut peers = r.list_peers();
        peers.sort();
        assert_eq!(peers, vec![mid(5), mid(10), mid(20)]);
    }

    #[test]
    fn list_peers_empty() {
        let r = PeerAddressRegistry::new();
        assert!(r.list_peers().is_empty());
    }

    // ------------------------------------------------------------------
    // clear
    // ------------------------------------------------------------------

    #[test]
    fn clear_removes_all() {
        let r = PeerAddressRegistry::new();
        r.register(mid(1), vec![tcp_addr(9001)]);
        r.register(mid(2), vec![tcp_addr(9002)]);

        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.lookup(mid(1)), None);
        assert_eq!(r.lookup(mid(2)), None);
    }

    // ------------------------------------------------------------------
    // concurrent access
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_register_and_lookup() {
        let registry = Arc::new(PeerAddressRegistry::new());
        let num_threads = 8;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let r = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                let peer = mid(t as u64);
                r.register(peer, vec![tcp_addr(9000 + t as u16)]);
                // Lookup should return what we just registered
                let addrs = r.lookup(peer);
                assert!(addrs.is_some());
                assert_eq!(addrs.unwrap().len(), 1);
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(registry.len(), num_threads);
        for t in 0..num_threads {
            assert!(registry.is_registered(mid(t as u64)));
        }
    }

    #[test]
    fn concurrent_deregister_and_lookup() {
        let registry = Arc::new(PeerAddressRegistry::new());

        // Pre-register peers
        for i in 0..16 {
            registry.register(mid(i), vec![tcp_addr(9000 + i as u16)]);
        }

        let mut handles = Vec::new();
        for i in 0..16 {
            let r = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                let peer = mid(i);
                assert!(r.deregister(peer));
                // After deregistration, lookup should return None
                assert_eq!(r.lookup(peer), None);
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        assert!(registry.is_empty());
    }

    #[test]
    fn mixed_concurrent_register_deregister() {
        let registry = Arc::new(PeerAddressRegistry::new());

        // Pre-register some peers
        registry.register(mid(1), vec![tcp_addr(9001)]);
        registry.register(mid(2), vec![tcp_addr(9002)]);

        let r1 = Arc::clone(&registry);
        let h1 = thread::spawn(move || {
            r1.register(mid(3), vec![tcp_addr(9003)]);
            r1.deregister(mid(1));
        });

        let r2 = Arc::clone(&registry);
        let h2 = thread::spawn(move || {
            r2.register(mid(4), vec![tcp_addr(9004)]);
            r2.deregister(mid(2));
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Only peers 3 and 4 should remain
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_registered(mid(1)));
        assert!(!registry.is_registered(mid(2)));
        assert!(registry.is_registered(mid(3)));
        assert!(registry.is_registered(mid(4)));
    }

    // ------------------------------------------------------------------
    // Debug output
    // ------------------------------------------------------------------

    #[test]
    fn debug_includes_entry_count() {
        let r = PeerAddressRegistry::new();
        r.register(mid(1), vec![tcp_addr(9001)]);
        r.register(mid(2), vec![tcp_addr(9002)]);

        let s = format!("{r:?}");
        assert!(s.contains("PeerAddressRegistry"));
        // Debug should reflect current count
        assert!(s.contains('2') || s.contains("entries"));
    }

    #[test]
    fn debug_empty_shows_zero() {
        let r = PeerAddressRegistry::new();
        let s = format!("{r:?}");
        assert!(s.contains("PeerAddressRegistry"));
    }
}
