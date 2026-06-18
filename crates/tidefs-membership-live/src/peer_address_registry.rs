// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Peer address registry for membership-to-transport endpoint resolution.
//!
//! Provides a shared [`PeerAddressRegistry`] that maps peer [`MemberId`]s to
//! [`TransportAddr`] vectors, updated by roster change events. Outbound
//! message dispatch and transport session establishment resolve peer
//! endpoints through this single authority, eliminating duplicated address
//! state across the membership and transport layers.
//!
//! ## Thread safety
//!
//! All interior state is behind `RwLock<HashMap>`. Concurrent reads for
//! dispatch/session-establishment are serviced without blocking each other;
//! roster-update writes acquire exclusive access.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;

use tidefs_membership_epoch::MemberId;
use tidefs_transport::addr::TransportAddr;

// ---------------------------------------------------------------------------
// PeerAddressRegistry
// ---------------------------------------------------------------------------

/// Shared peer address registry for membership-to-transport endpoint
/// resolution.
///
/// Owned by the membership runtime and shared with outbound dispatch,
/// session establishment, and roster-change handling subsystems.
///
/// # Example
///
/// ```ignore
/// use tidefs_membership_live::peer_address_registry::PeerAddressRegistry;
/// use tidefs_membership_epoch::MemberId;
/// use tidefs_transport::addr::TransportAddr;
///
/// let reg = PeerAddressRegistry::new();
/// let peer = MemberId(1);
/// let addr: TransportAddr = "tcp://10.0.0.2:9100".parse().unwrap();
/// reg.register(peer, vec![addr]);
/// assert!(reg.resolve(peer).is_some());
/// ```
#[derive(Debug, Default)]
pub struct PeerAddressRegistry {
    inner: RwLock<HashMap<MemberId, Vec<TransportAddr>>>,
}

impl PeerAddressRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Register (or replace) addresses for a peer.
    ///
    /// Called when a peer joins or its addresses change.
    pub fn register(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
        let mut map = self
            .inner
            .write()
            .expect("PeerAddressRegistry lock poisoned");
        map.insert(peer_id, addresses);
    }

    /// Remove a peer from the registry.
    ///
    /// Called on peer removal, eviction, or drain completion.
    pub fn deregister(&self, peer_id: MemberId) {
        let mut map = self
            .inner
            .write()
            .expect("PeerAddressRegistry lock poisoned");
        map.remove(&peer_id);
    }

    /// Atomically replace the address set for a peer.
    ///
    /// Unlike [`register`](Self::register), callers signal that this is a
    /// known-peer address mutation, not an initial registration.
    pub fn update(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
        self.register(peer_id, addresses);
    }

    /// Resolve all known addresses for a peer.
    ///
    /// Returns `None` if the peer is not registered.
    #[must_use]
    pub fn resolve(&self, peer_id: MemberId) -> Option<Vec<TransportAddr>> {
        let map = self
            .inner
            .read()
            .expect("PeerAddressRegistry lock poisoned");
        map.get(&peer_id).cloned()
    }

    /// Resolve the first known address for a peer.
    ///
    /// Returns `None` if the peer is not registered or has an empty address
    /// list.
    #[must_use]
    pub fn resolve_first(&self, peer_id: MemberId) -> Option<TransportAddr> {
        let map = self
            .inner
            .read()
            .expect("PeerAddressRegistry lock poisoned");
        map.get(&peer_id).and_then(|addrs| addrs.first().cloned())
    }

    /// Resolve the first TCP [`SocketAddr`] for a peer, if any.
    ///
    /// Convenience for callers that only operate over TCP and need a bare
    /// socket address. Returns `None` if the peer is not registered, has
    /// no addresses, or its first address is not a TCP variant.
    #[must_use]
    pub fn resolve_one(&self, peer_id: MemberId) -> Option<SocketAddr> {
        self.resolve_first(peer_id)
            .and_then(|addr| addr.as_socket_addr())
    }

    /// Return the number of registered peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("PeerAddressRegistry lock poisoned")
            .len()
    }

    /// Return `true` if no peers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .expect("PeerAddressRegistry lock poisoned")
            .is_empty()
    }

    /// Return `true` if the peer is registered.
    #[must_use]
    pub fn contains(&self, peer_id: MemberId) -> bool {
        let map = self
            .inner
            .read()
            .expect("PeerAddressRegistry lock poisoned");
        map.contains_key(&peer_id)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::thread;

    // -- helpers

    fn tcp_addr(ip: &str, port: u16) -> TransportAddr {
        let addr: SocketAddr = format!("{ip}:{port}").parse().unwrap();
        TransportAddr::Tcp(addr)
    }

    // -- tests

    #[test]
    fn register_and_resolve_single_peer() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(1);
        let addrs = vec![tcp_addr("10.0.0.2", 9100), tcp_addr("10.0.0.2", 9101)];

        reg.register(peer, addrs.clone());
        let resolved = reg.resolve(peer);
        assert_eq!(resolved, Some(addrs));
    }

    #[test]
    fn deregister_removes_peer() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(42);
        reg.register(peer, vec![tcp_addr("10.0.0.3", 8000)]);
        assert!(reg.contains(peer));

        reg.deregister(peer);
        assert!(!reg.contains(peer));
        assert_eq!(reg.resolve(peer), None);
    }

    #[test]
    fn update_replaces_addresses() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(7);
        let old = vec![tcp_addr("10.0.0.1", 9000)];
        let new = vec![tcp_addr("10.0.0.2", 9000), tcp_addr("10.0.0.3", 9000)];

        reg.register(peer, old);
        reg.update(peer, new.clone());
        assert_eq!(reg.resolve(peer), Some(new));
    }

    #[test]
    fn resolve_nonexistent_peer_returns_none() {
        let reg = PeerAddressRegistry::new();
        assert_eq!(reg.resolve(MemberId(999)), None);
        assert_eq!(reg.resolve_one(MemberId(999)), None);
        assert_eq!(reg.resolve_first(MemberId(999)), None);
    }

    #[test]
    fn resolve_one_returns_first_tcp_socket_addr() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(10);
        let addr: SocketAddr = "10.0.0.10:9100".parse().unwrap();
        reg.register(peer, vec![TransportAddr::Tcp(addr)]);

        assert_eq!(reg.resolve_one(peer), Some(addr));
    }

    #[test]
    fn resolve_one_returns_none_for_rdma_first() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(11);
        let rdma_addr = TransportAddr::Rdma {
            gid: [0u8; 16],
            qpn: 1,
            service_id: 0,
        };
        reg.register(peer, vec![rdma_addr]);
        assert_eq!(reg.resolve_one(peer), None);
    }

    #[test]
    fn resolve_first_returns_first_regardless_of_carrier() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(12);
        let rdma_addr = TransportAddr::Rdma {
            gid: [0u8; 16],
            qpn: 1,
            service_id: 0,
        };
        reg.register(peer, vec![rdma_addr.clone()]);
        assert_eq!(reg.resolve_first(peer), Some(rdma_addr));
    }

    #[test]
    fn len_and_is_empty() {
        let reg = PeerAddressRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        reg.register(MemberId(1), vec![tcp_addr("10.0.0.1", 9100)]);
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);

        reg.register(MemberId(2), vec![tcp_addr("10.0.0.2", 9100)]);
        assert_eq!(reg.len(), 2);

        reg.deregister(MemberId(1));
        assert_eq!(reg.len(), 1);

        reg.deregister(MemberId(2));
        assert!(reg.is_empty());
    }

    #[test]
    fn contains_checks_registration() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(5);
        assert!(!reg.contains(peer));

        reg.register(peer, vec![tcp_addr("10.0.0.5", 9100)]);
        assert!(reg.contains(peer));

        reg.deregister(peer);
        assert!(!reg.contains(peer));
    }

    #[test]
    fn re_register_overwrites() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(8);
        let first = vec![tcp_addr("10.0.0.1", 9100)];
        let second = vec![tcp_addr("10.0.0.2", 9100)];

        reg.register(peer, first);
        reg.register(peer, second.clone());
        assert_eq!(reg.resolve(peer), Some(second));
    }

    #[test]
    fn concurrent_reads_do_not_block() {
        let reg = Arc::new(PeerAddressRegistry::new());
        let peer = MemberId(100);
        reg.register(peer, vec![tcp_addr("10.0.0.100", 9100)]);

        let mut handles = vec![];
        for _ in 0..8 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = reg.resolve(peer);
                }
            }));
        }

        for h in handles {
            h.join().expect("reader thread panicked");
        }
    }

    #[test]
    fn concurrent_read_write_no_deadlock() {
        let reg = Arc::new(PeerAddressRegistry::new());

        // Pre-register a peer so readers have something to resolve.
        reg.register(MemberId(1), vec![tcp_addr("10.0.0.1", 9100)]);

        let reg_reader = Arc::clone(&reg);
        let reader = thread::spawn(move || {
            for _ in 0..2000 {
                let _ = reg_reader.resolve(MemberId(1));
                let _ = reg_reader.contains(MemberId(2));
            }
        });

        let reg_writer = Arc::clone(&reg);
        let writer = thread::spawn(move || {
            for i in 0..2000 {
                let peer = MemberId(i % 10);
                reg_writer.register(peer, vec![tcp_addr("10.0.0.1", 9100)]);
                if i % 3 == 0 {
                    reg_writer.deregister(peer);
                }
            }
        });

        reader.join().expect("reader panicked");
        writer.join().expect("writer panicked");
    }

    #[test]
    fn deregister_nonexistent_is_noop() {
        let reg = PeerAddressRegistry::new();
        reg.deregister(MemberId(12345));
        assert!(reg.is_empty());
    }

    #[test]
    fn empty_address_vec_is_valid_registration() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(99);
        reg.register(peer, vec![]);
        assert!(reg.contains(peer));
        assert_eq!(reg.resolve(peer), Some(vec![]));
        assert_eq!(reg.resolve_first(peer), None);
        assert_eq!(reg.resolve_one(peer), None);
    }

    #[test]
    fn default_creates_empty_registry() {
        let reg = PeerAddressRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn resolve_clones_data() {
        let reg = PeerAddressRegistry::new();
        let peer = MemberId(55);
        let addrs = vec![tcp_addr("10.0.0.55", 9100)];
        reg.register(peer, addrs);

        // The returned vec should be independent of internal state.
        let mut resolved = reg.resolve(peer).unwrap();
        resolved.push(tcp_addr("10.0.0.56", 9100));

        // Internal state unchanged.
        assert_eq!(reg.resolve(peer).unwrap().len(), 1);
    }

    #[test]
    fn multiple_peers_independent() {
        let reg = PeerAddressRegistry::new();
        let a = MemberId(1);
        let b = MemberId(2);
        let addr_a = tcp_addr("10.0.0.1", 9100);
        let addr_b = tcp_addr("10.0.0.2", 9100);

        reg.register(a, vec![addr_a.clone()]);
        reg.register(b, vec![addr_b.clone()]);

        assert_eq!(reg.resolve(a), Some(vec![addr_a.clone()]));
        assert_eq!(reg.resolve(b), Some(vec![addr_b.clone()]));

        reg.deregister(a);
        assert_eq!(reg.resolve(a), None);
        assert_eq!(reg.resolve(b), Some(vec![addr_b.clone()]));
    }
}
