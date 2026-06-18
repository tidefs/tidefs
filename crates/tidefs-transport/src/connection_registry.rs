// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Connection registry for tracking active transport connections.
//!
//! [`ConnectionRegistry`] is the central in-memory bookkeeping structure
//! that tracks every active transport connection by peer ID and connection
//! ID, exposes lookup for send/receive dispatch, and mirrors lifecycle
//! state transitions so upper layers can discover, iterate, and drain
//! connections without maintaining their own bookkeeping.
//!
//! # Architecture
//!
//! - [`ConnectionRegistry`] — `HashMap<PeerId, ConnectionEntry>` plus a
//!   secondary `HashMap<ConnectionId, PeerId>` for reverse lookup,
//!   protected by `RwLock` for concurrent read-heavy access.
//! - [`ConnectionEntry`] — holds the connection handle, current lifecycle
//!   state, admitted epoch, endpoint address, and creation timestamp.
//! - [`ConnectionState`] — lifecycle states mirroring the transport
//!   connection state machine: `Connecting`, `Accepted`, `Connected`,
//!   `Draining`, `Drained`, `Closed`.
//!
//! # Integration points
//!
//! - Peer admission (#5785): after admission succeeds, the
//!   [`AdmittedPeer`] is inserted into the registry.
//! - Send/receive dispatch (#5778, #5780): look up connections by peer
//!   ID or connection ID for frame delivery.
//! - Keepalive (#5789): iterate active connections for heartbeat probes.
//! - Graceful drain: `drain_all()` returns all entries for coordinated
//!   shutdown.

use crate::peer_send_queue::PeerQueueSender;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

use crate::peer_admission::AdmittedPeer;

// ---------------------------------------------------------------------------
// ConnectionId
// ---------------------------------------------------------------------------

/// Unique identifier for a transport connection.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    /// Create a new ConnectionId from a u64 value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// ConnectionState
// ---------------------------------------------------------------------------

/// Lifecycle state of a transport connection.
///
/// Mirrors the transport connection lifecycle state machine (#5788).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection attempt in progress (TCP/TLS handshake).
    Connecting,
    /// Connection accepted but not yet fully established.
    Accepted,
    /// Connection fully established and ready for message exchange.
    Connected,
    /// Graceful drain in progress; no new messages accepted.
    Draining,
    /// Drain complete; connection may be torn down.
    Drained,
    /// Connection closed (terminal state).
    Closed,
}

impl ConnectionState {
    /// Whether this state represents an active (usable) connection.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Accepted | ConnectionState::Connected)
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "Connecting"),
            Self::Accepted => write!(f, "Accepted"),
            Self::Connected => write!(f, "Connected"),
            Self::Draining => write!(f, "Draining"),
            Self::Drained => write!(f, "Drained"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionEntry
// ---------------------------------------------------------------------------

/// An entry in the connection registry describing one active transport
/// connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEntry {
    /// The peer identifier for the remote node.
    pub peer_id: u64,
    /// Unique connection identifier.
    pub connection_id: ConnectionId,
    /// Current lifecycle state of the connection.
    pub state: ConnectionState,
    /// Network endpoint address for this connection.
    pub endpoint: SocketAddr,
    /// Network endpoint address for this connection.
    /// The membership epoch under which this connection was admitted.
    pub admitted_epoch: u64,
    /// When this entry was created (inserted into the registry).
    pub created_at: Instant,
}

impl ConnectionEntry {
    /// Create a new [`ConnectionEntry`] from an admitted peer and
    /// connection identifier.
    #[must_use]
    pub fn new(admitted: &AdmittedPeer, connection_id: ConnectionId, endpoint: SocketAddr) -> Self {
        Self {
            peer_id: admitted.peer_id,
            connection_id,
            endpoint,
            state: ConnectionState::Accepted,
            admitted_epoch: admitted.admitted_epoch,
            created_at: Instant::now(),
        }
    }

    /// Whether this connection is in an active (usable) state.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

// ---------------------------------------------------------------------------
// RegistryError
// ---------------------------------------------------------------------------

/// Errors returned by [`ConnectionRegistry`] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// A connection for this peer already exists in the registry.
    DuplicatePeer(u64),
    /// No connection found for the given peer ID.
    PeerNotFound(u64),
    /// No connection found for the given connection ID.
    ConnectionNotFound(ConnectionId),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePeer(peer) => {
                write!(f, "duplicate peer {peer} already in registry")
            }
            Self::PeerNotFound(peer) => {
                write!(f, "peer {peer} not found in registry")
            }
            Self::ConnectionNotFound(id) => {
                write!(f, "connection {id} not found in registry")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------------
// ConnectionRegistry
// ---------------------------------------------------------------------------

/// Central registry tracking all active transport connections.
///
/// Uses a [`RwLock`] for concurrent read-heavy access: multiple callers
/// can look up connections simultaneously, while insert/remove/drain
/// operations take an exclusive write lock.
#[derive(Default)]
pub struct ConnectionRegistry {
    /// Primary mapping: peer ID to connection entry.
    by_peer: RwLock<HashMap<u64, ConnectionEntry>>,
    /// Reverse mapping: connection ID to peer ID.
    by_conn: RwLock<HashMap<ConnectionId, u64>>,
    /// Per-peer keepalive state machines (peer_id -> lifecycle).
    keepalive_states: RwLock<HashMap<u64, crate::keepalive::KeepaliveLifecycle>>,
    /// Keepalive config template. When `Some`, keepalive is enabled.
    keepalive_config: RwLock<Option<crate::config::KeepaliveConfig>>,
    /// Per-peer ping senders for the keepalive tick loop.
    ping_senders: RwLock<HashMap<u64, PeerQueueSender<Vec<u8>>>>,
    /// Guards against double-spawning the keepalive tick loop.
    keepalive_tick_spawned: std::sync::atomic::AtomicBool,
}

impl ConnectionRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_peer: RwLock::new(HashMap::new()),
            by_conn: RwLock::new(HashMap::new()),
            keepalive_states: RwLock::new(HashMap::new()),
            keepalive_config: RwLock::new(None),
            ping_senders: RwLock::new(HashMap::new()),
            keepalive_tick_spawned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    // -----------------------------------------------------------------------
    // Insert
    // -----------------------------------------------------------------------

    /// Insert a newly admitted connection into the registry.
    ///
    /// Returns an error if a connection for this peer already exists.
    /// Both the peer-to-entry and connection-to-peer maps are updated
    /// atomically under a single write lock acquisition.
    pub fn insert(
        &self,
        admitted: &AdmittedPeer,
        connection_id: ConnectionId,
        endpoint: SocketAddr,
    ) -> Result<(), RegistryError> {
        let mut by_peer = self.by_peer.write().expect("RwLock poisoned");
        let mut by_conn = self.by_conn.write().expect("RwLock poisoned");

        if by_peer.contains_key(&admitted.peer_id) {
            return Err(RegistryError::DuplicatePeer(admitted.peer_id));
        }

        let entry = ConnectionEntry::new(admitted, connection_id, endpoint);
        by_conn.insert(connection_id, admitted.peer_id);
        by_peer.insert(admitted.peer_id, entry);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Remove
    // -----------------------------------------------------------------------

    /// Remove a connection by peer ID.
    ///
    /// Returns the removed [`ConnectionEntry`] if found, or
    /// [`RegistryError::PeerNotFound`].
    pub fn remove(&self, peer_id: u64) -> Result<ConnectionEntry, RegistryError> {
        let mut by_peer = self.by_peer.write().expect("RwLock poisoned");
        let mut by_conn = self.by_conn.write().expect("RwLock poisoned");

        let entry = by_peer
            .remove(&peer_id)
            .ok_or(RegistryError::PeerNotFound(peer_id))?;
        by_conn.remove(&entry.connection_id);
        Ok(entry)
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Look up a connection entry by peer ID.
    ///
    /// Returns `None` if no entry exists for this peer.
    #[must_use]
    pub fn get(&self, peer_id: u64) -> Option<ConnectionEntry> {
        let by_peer = self.by_peer.read().expect("RwLock poisoned");
        by_peer.get(&peer_id).cloned()
    }

    /// Look up the network endpoint address for a peer.
    ///
    /// Returns `None` if no entry exists for this peer.
    /// Used by connection teardown to resolve peer ID to the transport
    /// address needed by [`crate::connection::ConnectionManager`].
    #[must_use]
    pub fn get_endpoint(&self, peer_id: u64) -> Option<SocketAddr> {
        let by_peer = self.by_peer.read().expect("RwLock poisoned");
        by_peer.get(&peer_id).map(|entry| entry.endpoint)
    }

    /// Look up the peer ID for a given connection ID.
    ///
    /// Returns `None` if the connection ID is not known.
    #[must_use]
    pub fn get_by_conn(&self, connection_id: ConnectionId) -> Option<u64> {
        let by_conn = self.by_conn.read().expect("RwLock poisoned");
        by_conn.get(&connection_id).copied()
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    /// Return a list of peer IDs for all active connections.
    ///
    /// Active connections are those in `Accepted` or `Connected` state.
    #[must_use]
    pub fn list_active(&self) -> Vec<u64> {
        let by_peer = self.by_peer.read().expect("RwLock poisoned");
        by_peer
            .iter()
            .filter(|(_, entry)| entry.is_active())
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Return all connection entries and clear the registry.
    ///
    /// After this call, the registry is empty. This is the coordinated
    /// drain operation for graceful shutdown.
    #[must_use]
    pub fn drain_all(&self) -> Vec<ConnectionEntry> {
        let mut by_peer = self.by_peer.write().expect("RwLock poisoned");
        let mut by_conn = self.by_conn.write().expect("RwLock poisoned");

        let entries: Vec<ConnectionEntry> = by_peer.drain().map(|(_, entry)| entry).collect();
        by_conn.clear();
        entries
    }

    // -----------------------------------------------------------------------
    // State updates
    // -----------------------------------------------------------------------

    /// Update the lifecycle state of a connection.
    ///
    /// Returns the previous state on success, or an error if the peer is
    /// not found.
    pub fn set_state(
        &self,
        peer_id: u64,
        new_state: ConnectionState,
    ) -> Result<ConnectionState, RegistryError> {
        let mut by_peer = self.by_peer.write().expect("RwLock poisoned");
        let entry = by_peer
            .get_mut(&peer_id)
            .ok_or(RegistryError::PeerNotFound(peer_id))?;
        let old_state = entry.state;
        entry.state = new_state;
        Ok(old_state)
    }

    /// Return the number of connections currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        let by_peer = self.by_peer.read().expect("RwLock poisoned");
        by_peer.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    // -------------------------------------------------------------------
    // Keepalive integration
    // -------------------------------------------------------------------

    /// Enable keepalive for future peer connections.
    ///
    /// Stores the config template. When a peer connects and
    /// `record_activity` is first called, a per-peer
    /// [`KeepaliveLifecycle`] is created from this config.
    /// Call before accepting connections or connecting to peers.
    pub fn enable_keepalive(&self, config: crate::config::KeepaliveConfig) {
        let mut cfg = self.keepalive_config.write().expect("RwLock poisoned");
        *cfg = Some(config);
    }

    /// Whether keepalive is enabled.
    #[must_use]
    pub fn keepalive_enabled(&self) -> bool {
        self.keepalive_config
            .read()
            .expect("RwLock poisoned")
            .is_some()
    }

    /// Register a ping sender for a peer so the keepalive tick loop
    /// can send heartbeat pings through the peer's send queue.
    pub fn register_ping_sender(&self, peer_id: u64, sender: PeerQueueSender<Vec<u8>>) {
        let mut senders = self.ping_senders.write().expect("RwLock poisoned");
        senders.insert(peer_id, sender);
    }

    /// Remove the ping sender for a peer (call on disconnect/drain).
    pub fn deregister_ping_sender(&self, peer_id: u64) {
        let mut senders = self.ping_senders.write().expect("RwLock poisoned");
        senders.remove(&peer_id);
    }

    /// Get or create a per-peer keepalive lifecycle, then record activity.
    ///
    /// Called by the receive path on every successfully decoded frame.
    /// Resets the idle timer in the keepalive state machine.
    /// Does nothing if keepalive is not enabled.
    pub fn record_activity(&self, peer_id: u64) {
        if !self.keepalive_enabled() {
            return;
        }
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        if let Some(lifecycle) = states.get_mut(&peer_id) {
            lifecycle.record_activity();
        } else {
            // Lazy init: create lifecycle from stored config
            let config_guard = self.keepalive_config.read().expect("RwLock poisoned");
            if let Some(ref cfg) = *config_guard {
                let engine_cfg: crate::keepalive::KeepaliveConfig = cfg.clone().into();
                let mut lifecycle = crate::keepalive::KeepaliveLifecycle::new(engine_cfg);
                lifecycle.on_active();
                lifecycle.record_activity();
                drop(config_guard);
                states.insert(peer_id, lifecycle);
            }
        }
    }

    /// Record a keepalive pong response for a peer.
    ///
    /// Called by the receive path when a `HeartbeatAck` pong arrives.
    /// Resets the miss counter and returns the peer to Healthy.
    pub fn on_keepalive_pong(&self, peer_id: u64, seq: u64) {
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        if let Some(lifecycle) = states.get_mut(&peer_id) {
            lifecycle.on_pong(seq);
        }
    }

    /// Check whether the keepalive engine for a peer is currently
    /// expecting a pong response (i.e. in Probing state). Reads via
    /// a shared lock so the receive path can query without blocking.
    #[must_use]
    pub fn is_expecting_pong(&self, peer_id: u64) -> bool {
        let states = self.keepalive_states.read().expect("RwLock poisoned");
        states
            .get(&peer_id)
            .map(|lc| lc.is_expecting_pong())
            .unwrap_or(false)
    }

    /// Arm keepalive for a peer when its connection reaches Connected.
    pub fn activate_keepalive(&self, peer_id: u64) {
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        if let Some(lifecycle) = states.get_mut(&peer_id) {
            lifecycle.on_active();
        }
    }

    /// Disarm keepalive when a peer leaves Connected.
    pub fn deactivate_keepalive(&self, peer_id: u64) {
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        if let Some(lifecycle) = states.get_mut(&peer_id) {
            lifecycle.on_inactive();
        }
    }

    /// Remove keepalive state on disconnect.
    pub fn remove_keepalive(&self, peer_id: u64) {
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        states.remove(&peer_id);
        self.deregister_ping_sender(peer_id);
    }

    /// Tick the keepalive state machines for all peers.
    ///
    /// Returns peers whose keepalive declared them dead and pending
    /// ping sequences (peer_id, seq) to send.
    pub fn tick_keepalive(&self) -> (Vec<u64>, Vec<(u64, u64)>) {
        let mut dead_peers = Vec::new();
        let mut pending_pings = Vec::new();
        let mut states = self.keepalive_states.write().expect("RwLock poisoned");
        for (peer, lifecycle) in states.iter_mut() {
            match lifecycle.tick() {
                crate::keepalive::KeepaliveAction::Drain => {
                    dead_peers.push(*peer);
                }
                crate::keepalive::KeepaliveAction::SendPing(seq) => {
                    pending_pings.push((*peer, seq));
                }
                crate::keepalive::KeepaliveAction::None => {}
            }
        }
        (dead_peers, pending_pings)
    }

    /// Spawn a tokio background task that periodically ticks keepalive.
    ///
    /// Returns `None` if keepalive is not enabled.
    /// The loop runs once per second. On each tick, dead peers
    /// are transitioned to `Draining` and their keepalive state is
    /// removed; pending pings are sent through registered ping senders.
    pub fn spawn_keepalive_tick_loop(
        self: &std::sync::Arc<Self>,
    ) -> Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )> {
        if !self.keepalive_enabled() {
            return None;
        }
        // Ensure only one tick loop is spawned per registry.
        if self
            .keepalive_tick_spawned
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let registry = std::sync::Arc::clone(self);
        let tick_interval = Duration::from_secs(1);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tick_interval) => {}
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                }
                let (dead_peers, pending_pings) = registry.tick_keepalive();

                // Transition dead peers to Draining and remove keepalive state.
                for peer in &dead_peers {
                    let _ = registry.set_state(*peer, ConnectionState::Draining);
                    registry.remove_keepalive(*peer);
                }

                // Send pending pings through registered per-peer senders.
                let senders = registry.ping_senders.read().expect("RwLock poisoned");
                for (peer, seq) in pending_pings {
                    if let Some(sender) = senders.get(&peer) {
                        let ping = crate::keepalive::build_ping(seq);
                        let _ = sender.try_send(ping);
                    }
                }
            }
        });
        Some((shutdown_tx, handle))
    }
}

// Manual Debug impl: skip ping_senders (PeerQueueSender not Debug).
impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionRegistry")
            .field("by_peer", &self.by_peer)
            .field("by_conn", &self.by_conn)
            .field("keepalive_states", &self.keepalive_states)
            .field("keepalive_config", &self.keepalive_config)
            .field(
                "ping_senders",
                &format_args!(
                    "<{} senders>",
                    self.ping_senders.read().map(|m| m.len()).unwrap_or(0)
                ),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_endpoint() -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        )
    }

    fn make_admitted(peer_id: u64, epoch: u64) -> AdmittedPeer {
        AdmittedPeer::new(peer_id, epoch)
    }

    // -- insert / lookup / remove round-trip ----------------------------------

    #[test]
    fn insert_and_lookup() {
        let reg = ConnectionRegistry::new();
        let admitted = make_admitted(1, 5);
        let conn_id = ConnectionId::new(100);

        reg.insert(&admitted, conn_id, test_endpoint()).unwrap();

        let entry = reg.get(1).expect("peer 1 should be present");
        assert_eq!(entry.peer_id, 1);
        assert_eq!(entry.connection_id, ConnectionId::new(100));
        assert_eq!(entry.admitted_epoch, 5);
        assert_eq!(entry.state, ConnectionState::Accepted);
        assert!(entry.is_active());
    }

    #[test]
    fn endpoint_is_stored() {
        let reg = ConnectionRegistry::new();
        let admitted = make_admitted(42, 3);
        let conn_id = ConnectionId::new(999);
        let ep = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            9000,
        );

        reg.insert(&admitted, conn_id, ep).unwrap();

        let entry = reg.get(42).unwrap();
        assert_eq!(entry.endpoint, ep);
        assert_eq!(reg.get_endpoint(42), Some(ep));
    }

    #[test]
    fn get_endpoint_nonexistent() {
        let reg = ConnectionRegistry::new();
        assert_eq!(reg.get_endpoint(99), None);
    }

    #[test]
    fn reverse_lookup_by_connection_id() {
        let reg = ConnectionRegistry::new();
        let admitted = make_admitted(42, 3);
        let conn_id = ConnectionId::new(999);

        reg.insert(&admitted, conn_id, test_endpoint()).unwrap();

        let peer = reg
            .get_by_conn(ConnectionId::new(999))
            .expect("connection 999 should resolve");
        assert_eq!(peer, 42);

        // Unknown connection ID
        assert!(reg.get_by_conn(ConnectionId::new(1)).is_none());
    }

    #[test]
    fn remove_existing_peer() {
        let reg = ConnectionRegistry::new();
        let admitted = make_admitted(7, 1);
        let conn_id = ConnectionId::new(700);

        reg.insert(&admitted, conn_id, test_endpoint()).unwrap();
        assert_eq!(reg.len(), 1);

        let removed = reg.remove(7).expect("peer 7 should be removable");
        assert_eq!(removed.peer_id, 7);
        assert_eq!(removed.connection_id, ConnectionId::new(700));
        assert_eq!(reg.len(), 0);
        assert!(reg.get(7).is_none());
        assert!(reg.get_by_conn(ConnectionId::new(700)).is_none());
    }

    #[test]
    fn remove_nonexistent_peer() {
        let reg = ConnectionRegistry::new();
        let result = reg.remove(99);
        assert_eq!(result, Err(RegistryError::PeerNotFound(99)));
    }

    // -- duplicate rejection --------------------------------------------------

    #[test]
    fn reject_duplicate_peer() {
        let reg = ConnectionRegistry::new();
        let a1 = make_admitted(10, 1);
        let a2 = make_admitted(10, 2); // same peer, different epoch

        reg.insert(&a1, ConnectionId::new(1), test_endpoint())
            .unwrap();
        let result = reg.insert(&a2, ConnectionId::new(2), test_endpoint());
        assert_eq!(result, Err(RegistryError::DuplicatePeer(10)));
    }

    // -- list_active ----------------------------------------------------------

    #[test]
    fn list_active_filters_by_state() {
        let reg = ConnectionRegistry::new();

        // Insert three peers
        reg.insert(
            &make_admitted(1, 1),
            ConnectionId::new(101),
            test_endpoint(),
        )
        .unwrap();
        reg.insert(
            &make_admitted(2, 1),
            ConnectionId::new(102),
            test_endpoint(),
        )
        .unwrap();
        reg.insert(
            &make_admitted(3, 1),
            ConnectionId::new(103),
            test_endpoint(),
        )
        .unwrap();

        // Set peer 2 to Draining
        reg.set_state(2, ConnectionState::Draining).unwrap();

        let active = reg.list_active();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&1));
        assert!(active.contains(&3));
        assert!(!active.contains(&2));
    }

    #[test]
    fn list_active_excludes_closed() {
        let reg = ConnectionRegistry::new();
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();

        reg.set_state(1, ConnectionState::Closed).unwrap();
        assert!(reg.list_active().is_empty());
    }

    // -- drain_all ------------------------------------------------------------

    #[test]
    fn drain_all_empties_registry() {
        let reg = ConnectionRegistry::new();
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.insert(&make_admitted(2, 1), ConnectionId::new(2), test_endpoint())
            .unwrap();
        reg.insert(&make_admitted(3, 1), ConnectionId::new(3), test_endpoint())
            .unwrap();
        assert_eq!(reg.len(), 3);

        let drained = reg.drain_all();
        assert_eq!(drained.len(), 3);
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());

        // Reverse lookup should also be empty
        assert!(reg.get_by_conn(ConnectionId::new(1)).is_none());
        assert!(reg.get_by_conn(ConnectionId::new(2)).is_none());
        assert!(reg.get_by_conn(ConnectionId::new(3)).is_none());
    }

    // -- set_state ------------------------------------------------------------

    #[test]
    fn set_state_transitions() {
        let reg = ConnectionRegistry::new();
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();

        // Accepted -> Connected
        let old = reg.set_state(1, ConnectionState::Connected).unwrap();
        assert_eq!(old, ConnectionState::Accepted);
        assert_eq!(reg.get(1).unwrap().state, ConnectionState::Connected);

        // Connected -> Draining
        let old = reg.set_state(1, ConnectionState::Draining).unwrap();
        assert_eq!(old, ConnectionState::Connected);

        // Draining -> Drained
        let old = reg.set_state(1, ConnectionState::Drained).unwrap();
        assert_eq!(old, ConnectionState::Draining);

        // Drained -> Closed
        let old = reg.set_state(1, ConnectionState::Closed).unwrap();
        assert_eq!(old, ConnectionState::Drained);

        assert!(!reg.get(1).unwrap().is_active());
    }

    #[test]
    fn set_state_peer_not_found() {
        let reg = ConnectionRegistry::new();
        let result = reg.set_state(42, ConnectionState::Connected);
        assert_eq!(result, Err(RegistryError::PeerNotFound(42)));
    }

    // -- concurrent read safety -----------------------------------------------

    #[test]
    fn concurrent_reads_under_rwlock() {
        let reg = ConnectionRegistry::new();
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.insert(&make_admitted(2, 1), ConnectionId::new(2), test_endpoint())
            .unwrap();

        // Simulate concurrent reads: multiple get calls
        let e1 = reg.get(1);
        let e2 = reg.get(2);
        let active = reg.list_active();

        assert!(e1.is_some());
        assert!(e2.is_some());
        assert_eq!(active.len(), 2);
    }

    // -- ConnectionState::is_active -------------------------------------------

    #[test]
    fn connection_state_is_active() {
        assert!(!ConnectionState::Connecting.is_active());
        assert!(ConnectionState::Accepted.is_active());
        assert!(ConnectionState::Connected.is_active());
        assert!(!ConnectionState::Draining.is_active());
        assert!(!ConnectionState::Drained.is_active());
        assert!(!ConnectionState::Closed.is_active());
    }

    // -- keepalive integration tests -----------------------------------------

    #[test]
    fn keepalive_disabled_by_default() {
        let reg = ConnectionRegistry::new();
        assert!(!reg.keepalive_enabled());
    }

    #[test]
    fn enable_keepalive_then_enabled() {
        let reg = ConnectionRegistry::new();
        let cfg = crate::config::KeepaliveConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            probe_count: 2,
        };
        reg.enable_keepalive(cfg);
        assert!(reg.keepalive_enabled());
    }

    #[test]
    fn record_activity_lazy_inits_lifecycle() {
        let reg = ConnectionRegistry::new();
        let cfg = crate::config::KeepaliveConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            probe_count: 2,
        };
        reg.enable_keepalive(cfg);
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.set_state(1, ConnectionState::Connected).ok();
        reg.record_activity(1);
        // No panic means lifecycle was created
    }

    #[test]
    fn record_activity_noop_when_disabled() {
        let reg = ConnectionRegistry::new();
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.record_activity(1);
        // Should not panic when keepalive is disabled
    }

    #[test]
    fn activate_and_deactivate_keepalive() {
        let reg = ConnectionRegistry::new();
        let cfg = crate::config::KeepaliveConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            probe_count: 2,
        };
        reg.enable_keepalive(cfg);
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.set_state(1, ConnectionState::Connected).ok();
        reg.record_activity(1); // lazy init
        reg.activate_keepalive(1);
        reg.deactivate_keepalive(1);
        // No panic
    }

    #[test]
    fn remove_keepalive_cleans_up() {
        let reg = ConnectionRegistry::new();
        let cfg = crate::config::KeepaliveConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            probe_count: 2,
        };
        reg.enable_keepalive(cfg);
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.set_state(1, ConnectionState::Connected).ok();
        reg.record_activity(1); // lazy init
        reg.remove_keepalive(1);
        // After remove, record_activity is a no-op (no lifecycle)
        reg.record_activity(1);
    }

    #[test]
    fn tick_keepalive_when_disabled_returns_empty() {
        let reg = ConnectionRegistry::new();
        let (dead, pings) = reg.tick_keepalive();
        assert!(dead.is_empty());
        assert!(pings.is_empty());
    }

    #[test]
    fn tick_keepalive_with_active_lifecycle_returns_none() {
        let reg = ConnectionRegistry::new();
        let cfg = crate::config::KeepaliveConfig {
            interval: Duration::from_secs(3600), // long interval
            timeout: Duration::from_secs(5),
            probe_count: 3,
        };
        reg.enable_keepalive(cfg);
        reg.insert(&make_admitted(1, 1), ConnectionId::new(1), test_endpoint())
            .unwrap();
        reg.set_state(1, ConnectionState::Connected).ok();
        reg.record_activity(1); // lazy init + record
        let (dead, pings) = reg.tick_keepalive();
        // With a 1-hour interval and freshly recorded activity, should not fire
        assert!(dead.is_empty());
        assert!(pings.is_empty());
    }

    #[test]
    fn spawn_keepalive_tick_loop_disabled_returns_none() {
        let reg = std::sync::Arc::new(ConnectionRegistry::new());
        assert!(reg.spawn_keepalive_tick_loop().is_none());
    }

    #[test]
    fn spawn_keepalive_tick_loop_guards_double_spawn() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = std::sync::Arc::new(ConnectionRegistry::new());
            let cfg = crate::config::KeepaliveConfig {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(3),
                probe_count: 2,
            };
            reg.enable_keepalive(cfg);
            let first = reg.spawn_keepalive_tick_loop();
            assert!(first.is_some());
            let second = reg.spawn_keepalive_tick_loop();
            assert!(second.is_none());
            drop(first);
        });
    }
}
